const QdrantService = require('./qdrantService');
const NotesQdrantService = require('./notesQdrantService');
const SuperChatNote = require('../models/SuperChatNote');
const prompts = require('./prompts');
const CourseModel = require('../models/Course');
const SuperchatModel = require('../models/Superchat');
const { publicKeySummary } = require('./llmKeyStore');

const SUPER_COURSE_SETTINGS_ID = 'superCourseChat';

// Default share of retrieval slots given to Super Chat Notes (1/4 of TopK).
const DEFAULT_NOTE_RETRIEVAL_RATIO = 0.25;
// Notes scoring below this cosine similarity are not worth a retrieval slot;
// any unused note slots are donated back to lecture retrieval.
// Calibrated for text-embedding-3-small, which produces low absolute cosine
// scores (strong matches ~0.5-0.7, moderate ~0.25-0.45). A 0.25 floor keeps
// clearly-unrelated notes out while letting moderately-relevant ones through.
// (Lecture retrieval applies no floor, so this stays intentionally permissive.)
const NOTE_MIN_SCORE = 0.25;

function normalizeNoteRatio(value, fallback) {
    const num = Number(value);
    if (!Number.isFinite(num) || num < 0 || num > 1) return fallback;
    return num;
}

// Keep only the known level keys and coerce each modifier to a string,
// falling back to the default modifier text when a value is missing.
function normalizeLevelModifiers(value, keys, defaults) {
    const source = value && typeof value === 'object' ? value : {};
    const result = {};
    for (const key of keys) {
        result[key] = typeof source[key] === 'string' ? source[key] : defaults[key];
    }
    return result;
}

function resolveSuperCourseChatSettings(settingsDoc = {}) {
    const defaults = prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS;

    return {
        studentTopK: CourseModel.normalizeRagTopK(settingsDoc.studentTopK, defaults.studentTopK),
        instructorTopK: CourseModel.normalizeRagTopK(settingsDoc.instructorTopK, defaults.instructorTopK),
        includeInactiveCourses: settingsDoc.includeInactiveCourses === true,
        showStudentSuperCourse: settingsDoc.showStudentSuperCourse === true,
        // Notes are instructor-only and on by default; admins can toggle/tune.
        includeNotesInRetrieval: settingsDoc.includeNotesInRetrieval !== false,
        noteRetrievalRatio: normalizeNoteRatio(
            settingsDoc.noteRetrievalRatio,
            normalizeNoteRatio(defaults.noteRetrievalRatio, DEFAULT_NOTE_RETRIEVAL_RATIO)
        ),
        noteMinScore: normalizeNoteRatio(
            settingsDoc.noteMinScore,
            normalizeNoteRatio(defaults.noteMinScore, NOTE_MIN_SCORE)
        ),
        instructorPrompt: typeof settingsDoc.instructorPrompt === 'string' && settingsDoc.instructorPrompt.trim()
            ? settingsDoc.instructorPrompt
            : defaults.instructorPrompt,
        studentPrompt: typeof settingsDoc.studentPrompt === 'string' && settingsDoc.studentPrompt.trim()
            ? settingsDoc.studentPrompt
            : defaults.studentPrompt,
        studentLevelModifiers: normalizeLevelModifiers(
            settingsDoc.studentLevelModifiers,
            prompts.STUDENT_LEVEL_KEYS,
            defaults.studentLevelModifiers
        ),
        instructorLevelModifiers: normalizeLevelModifiers(
            settingsDoc.instructorLevelModifiers,
            prompts.INSTRUCTOR_LEVEL_KEYS,
            defaults.instructorLevelModifiers
        )
    };
}

async function getSuperCourseChatSettings(db) {
    const settingsDoc = await db.collection('settings').findOne({ _id: SUPER_COURSE_SETTINGS_ID });
    return resolveSuperCourseChatSettings(settingsDoc || {});
}

/**
 * Resolve a single superchat bucket: its identity (name/yearLevel/showToStudents)
 * plus its normalized chat settings. Returns null when the bucket is missing or
 * soft-deleted.
 * @param {Object} db
 * @param {string} superchatId
 * @returns {Promise<Object|null>}
 */
async function getSuperchat(db, superchatId) {
    const doc = await SuperchatModel.getSuperchatById(db, superchatId);
    if (!doc) return null;
    return {
        superchatId: doc.superchatId,
        name: doc.name,
        description: doc.description || '',
        yearLevel: doc.yearLevel ?? null,
        showToStudents: doc.showToStudents === true,
        llmKey: publicKeySummary(doc.llmApiKey),
        aiAvailable: publicKeySummary(doc.llmApiKey).status === 'valid',
        settings: resolveSuperCourseChatSettings(doc)
    };
}

/**
 * List superchat buckets as lightweight summaries (no resolved settings).
 * @param {Object} db
 * @param {Object} options - { studentVisibleOnly: boolean }
 * @returns {Promise<Array<{superchatId, name, description, yearLevel, showToStudents}>>}
 */
async function listSuperchats(db, options = {}) {
    const docs = await SuperchatModel.listSuperchats(db);
    return docs
        .filter(doc => !options.studentVisibleOnly || doc.showToStudents === true)
        .map(doc => ({
            superchatId: doc.superchatId,
            name: doc.name,
            description: doc.description || '',
            yearLevel: doc.yearLevel ?? null,
            showToStudents: doc.showToStudents === true,
            llmKey: publicKeySummary(doc.llmApiKey),
            aiAvailable: publicKeySummary(doc.llmApiKey).status === 'valid'
        }));
}

/**
 * Course IDs a student is actively enrolled in (studentEnrollment.<id>.enrolled).
 * Drives both the student superchat picker and per-request access checks.
 * @param {Object} db
 * @param {string} studentId
 * @returns {Promise<string[]>}
 */
async function getEnrolledCourseIds(db, studentId) {
    if (!db || !studentId) return [];
    const courses = await db.collection('courses')
        .find(
            {
                status: { $ne: 'deleted' },
                [`studentEnrollment.${studentId}.enrolled`]: true
            },
            { projection: { courseId: 1 } }
        )
        .toArray();
    return courses.map(course => course.courseId).filter(Boolean);
}

/**
 * Set of superchat bucket IDs a student can access: the union of superchatIds
 * across every course they are actively enrolled in. This is the enrollment-derived
 * visibility gate (a student sees a bucket if enrolled in ≥1 of its courses).
 * @param {Object} db
 * @param {string} studentId
 * @returns {Promise<Set<string>>}
 */
async function getStudentAccessibleSuperchatIds(db, studentId) {
    const enrolledCourseIds = await getEnrolledCourseIds(db, studentId);
    if (!enrolledCourseIds.length) return new Set();

    const courses = await db.collection('courses')
        .find(
            { courseId: { $in: enrolledCourseIds } },
            { projection: { superchatIds: 1 } }
        )
        .toArray();

    const ids = new Set();
    for (const course of courses) {
        for (const id of CourseModel.getCourseSuperchatIds(course)) ids.add(id);
    }
    return ids;
}

function buildSuperCoursePoolQuery(superchatId, includeInactiveCourses = false) {
    const query = {
        // A specific bucket filters to its members; no bucket id means "any bucket"
        // (used by instructor chat, which spans all opted-in courses).
        superchatIds: superchatId ? superchatId : { $exists: true, $ne: [] },
        status: { $ne: 'deleted' }
    };

    if (!includeInactiveCourses) {
        query.$or = [
            { status: { $exists: false } },
            { status: null },
            { status: 'active' }
        ];
    }

    return query;
}

async function getSuperCourseRetrievalPool(db, options = {}) {
    const includeInactiveCourses = options.includeInactiveCourses === true;
    const courses = await db.collection('courses')
        .find(buildSuperCoursePoolQuery(options.superchatId, includeInactiveCourses), {
            projection: {
                courseId: 1,
                courseName: 1,
                courseCode: 1,
                status: 1,
                yearLevel: 1,
                approvedStruggleTopics: 1
            }
        })
        .sort({ courseName: 1, courseId: 1 })
        .toArray();

    return courses.filter(course => course && course.courseId);
}

/**
 * Gather each Super Course pool course's approved struggle topics, tagged with
 * the owning course. Feeds the cross-course struggle tracker so a struggle in
 * the Super Chat can be mapped to a topic and attributed back to its course.
 *
 * @param {Object} db - MongoDB database instance
 * @param {Object} options - { includeInactiveCourses }
 * @returns {Promise<Array<{courseId: string, courseName: string, approvedTopics: Array<string>}>>}
 */
async function getSuperCourseApprovedTopics(db, options = {}) {
    const pool = await getSuperCourseRetrievalPool(db, options);

    return pool
        .map(course => ({
            courseId: course.courseId,
            courseName: course.courseName || course.courseCode || course.courseId,
            approvedTopics: CourseModel.normalizeTopicList(course.approvedStruggleTopics || [])
        }))
        .filter(entry => entry.approvedTopics.length > 0);
}

/**
 * Merge per-course search results into a single ranked list that guarantees each
 * course a minimum number of slots before filling the rest by raw score.
 *
 * Each course is first allotted a floor of ⌊target / nCourses⌋ (at least 1) of
 * its own top chunks; these are front-loaded (interleaved by rank) so that when
 * the caller slices the list down to its final budget, every course keeps its
 * representation. Any remaining slots up to `target` go to the globally
 * highest-scoring leftover chunks. Courses that returned nothing are skipped so
 * their floor isn't wasted.
 *
 * @param {Map<string, Array<Object>>} resultsByCourse - courseId -> hits (score desc)
 * @param {number} target - Maximum number of merged results to return
 * @returns {Array<Object>} Front-loaded, deduped, length <= target
 */
function mergeBalancedCourseResults(resultsByCourse, target) {
    const lists = [...resultsByCourse.values()].filter(list => list.length > 0);
    if (lists.length === 0) return [];

    const floor = Math.max(1, Math.floor(target / lists.length));

    const taken = new Set();
    const guaranteed = [];
    // Round-robin by rank: each course's #1 chunk, then each course's #2, ... up
    // to the floor — so the front of the list is balanced across courses.
    for (let rank = 0; rank < floor; rank++) {
        for (const list of lists) {
            const item = list[rank];
            if (item && !taken.has(item.id)) {
                taken.add(item.id);
                guaranteed.push(item);
            }
        }
    }

    // Everything not already taken, ranked globally by score, fills the remainder.
    const remainder = [];
    for (const list of lists) {
        for (const item of list) {
            if (!taken.has(item.id)) remainder.push(item);
        }
    }
    remainder.sort((a, b) => (b.score || 0) - (a.score || 0));

    return [...guaranteed, ...remainder].slice(0, target);
}

async function searchSuperCourse(db, query, limit, options = {}) {
    const pool = await getSuperCourseRetrievalPool(db, options);
    const courseIds = pool.map(course => course.courseId);

    const totalK = Number(limit) > 0 ? Number(limit) : 8;

    // Notes only participate when the caller explicitly opts in (instructor chat).
    // Student Super Chat never pulls instructor notes.
    const includeNotes = options.includeNotes === true;
    const noteRatio = includeNotes
        ? normalizeNoteRatio(options.noteRatio, DEFAULT_NOTE_RETRIEVAL_RATIO)
        : 0;

    let noteSlots = includeNotes ? Math.round(totalK * noteRatio) : 0;
    // Always leave at least one lecture slot when courses are available.
    if (courseIds.length > 0 && noteSlots >= totalK) {
        noteSlots = Math.max(0, totalK - 1);
    }
    const lectureSlots = totalK - noteSlots;

    // --- Lecture retrieval (over-fetch so we can backfill unused note slots) ---
    // Search each pool course independently and merge with a per-course floor so
    // every opted-in course is represented. A single pooled top-K search lets a
    // course with denser/more-similar chunks win every slot, silently shutting
    // the others out (see the Super Course "only one course ever cited" bug).
    let lectureResults = [];
    if (courseIds.length > 0 && lectureSlots > 0) {
        const qdrant = options.qdrant || new QdrantService();
        if (!qdrant.client) await qdrant.initialize();
        const resultsByCourse = await qdrant.searchDocumentsByCourse(query, courseIds, totalK);
        lectureResults = mergeBalancedCourseResults(resultsByCourse, totalK);
    }

    // --- Notes retrieval ---
    let noteResults = [];
    if (includeNotes && noteSlots > 0) {
        try {
            const minScore = normalizeNoteRatio(options.noteMinScore, NOTE_MIN_SCORE);
            const notesQdrant = new NotesQdrantService();
            if (options.qdrant) {
                await notesQdrant.initialize(options.qdrant);
            }
            noteResults = await notesQdrant.searchNotes(query, noteSlots, { minScore });
        } catch (error) {
            if (error && error.name === 'LlmKeyError') {
                throw error;
            }
            console.error('Super Course note retrieval failed:', error.message);
            noteResults = [];
        }
    }

    // Donate any unfilled note slots back to lectures.
    const usedNoteSlots = noteResults.length;
    const finalLectureCount = lectureSlots + (noteSlots - usedNoteSlots);

    const taggedLectures = lectureResults
        .slice(0, finalLectureCount)
        .map(result => ({ ...result, sourceType: 'lecture' }));

    const taggedNotes = noteResults.slice(0, usedNoteSlots); // already tagged sourceType: 'note'

    // Fire-and-forget usage counter bump for the notes we actually used.
    if (taggedNotes.length) {
        const noteIds = taggedNotes.map(note => note.noteId).filter(Boolean);
        SuperChatNote.incrementUsage(db, noteIds).catch(error =>
            console.error('Failed to increment note usage:', error.message)
        );
    }

    return { pool, results: [...taggedLectures, ...taggedNotes] };
}

function buildCourseNameLookup(pool = []) {
    return new Map(pool.map(course => [
        course.courseId,
        course.courseName || course.courseCode || course.courseId
    ]));
}

function formatNoteDate(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return date.toLocaleDateString('en-CA');
}

function buildSuperCourseContext(searchResults = [], pool = []) {
    const courseNameById = buildCourseNameLookup(pool);
    return searchResults
        .map(result => {
            if (result.sourceType === 'note') {
                const author = result.authorName || 'an instructor';
                const dateLabel = formatNoteDate(result.createdAt);
                const header = dateLabel
                    ? `From an instructor note by ${author} (${dateLabel})`
                    : `From an instructor note by ${author}`;
                return `${header}:\n${result.chunkText || ''}`;
            }
            const courseName = courseNameById.get(result.courseId) || result.courseId || 'Unknown course';
            const lectureName = result.lectureName || 'Unknown unit';
            const fileName = result.fileName || 'Unknown source';
            return `From ${courseName} / ${lectureName} (${fileName}):\n${result.chunkText || ''}`;
        })
        .join('\n\n---\n\n');
}

function buildSuperCoursePoolSummary(pool = []) {
    if (!pool.length) {
        return 'No courses are currently included in the Super Course source pool.';
    }

    return pool
        .map(course => `${course.courseName || course.courseCode || course.courseId} (${course.courseId})`)
        .join('; ');
}

function buildSuperCourseCitations(searchResults = [], pool = []) {
    const courseNameById = buildCourseNameLookup(pool);
    return searchResults.map(result => {
        if (result.sourceType === 'note') {
            const dateLabel = formatNoteDate(result.createdAt);
            return {
                sourceType: 'note',
                noteId: result.noteId || null,
                authorName: result.authorName || null,
                title: result.title || null,
                createdAt: result.createdAt || null,
                label: `Note by ${result.authorName || 'instructor'}${dateLabel ? `, ${dateLabel}` : ''}`,
                score: result.score
            };
        }
        return {
            sourceType: 'lecture',
            courseId: result.courseId || null,
            courseName: courseNameById.get(result.courseId) || result.courseId || null,
            lectureName: result.lectureName || null,
            fileName: result.fileName || null,
            documentId: result.documentId || null,
            score: result.score
        };
    });
}

function buildSuperCourseSourceAttribution(searchResults = [], pool = []) {
    const poolCourses = pool.map(course => ({
        courseId: course.courseId,
        courseName: course.courseName || course.courseCode || course.courseId,
        status: course.status || null
    }));

    if (!searchResults.length) {
        return {
            source: 'general-biochemistry',
            description: poolCourses.length
                ? 'No indexed Super Course chunks were retrieved for this question'
                : 'No courses are currently included in the Super Course source pool',
            documents: [],
            poolCourses
        };
    }

    const courseNameById = buildCourseNameLookup(pool);
    const seen = new Set();
    const documents = [];

    for (const result of searchResults) {
        if (result.sourceType === 'note') {
            const key = `note:${result.noteId || result.id}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const dateLabel = formatNoteDate(result.createdAt);
            documents.push({
                sourceType: 'note',
                courseId: null,
                courseName: `Note by ${result.authorName || 'instructor'}`,
                unitName: dateLabel || 'Instructor note',
                noteId: result.noteId || null,
                fileName: result.title || null,
                documentType: 'note',
                score: result.score
            });
            continue;
        }

        const key = result.documentId || `${result.courseId}:${result.lectureName}:${result.fileName}`;
        if (seen.has(key)) continue;
        seen.add(key);

        documents.push({
            sourceType: 'lecture',
            courseId: result.courseId || null,
            courseName: courseNameById.get(result.courseId) || result.courseId || null,
            unitName: result.lectureName || null,
            documentId: result.documentId || null,
            fileName: result.fileName || null,
            documentType: result.documentType || result.type || null,
            score: result.score
        });
    }

    const description = documents
        .slice(0, 3)
        .map(doc => `${doc.courseName || doc.courseId || 'Course'}${doc.unitName ? ` / ${doc.unitName}` : ''}`)
        .join('; ');

    return {
        source: 'super-course',
        description: description ? `From: ${description}` : 'From uploaded Super Course material',
        documents,
        poolCourses
    };
}

module.exports = {
    SUPER_COURSE_SETTINGS_ID,
    resolveSuperCourseChatSettings,
    getSuperCourseChatSettings,
    getSuperchat,
    listSuperchats,
    getEnrolledCourseIds,
    getStudentAccessibleSuperchatIds,
    buildSuperCoursePoolQuery,
    getSuperCourseRetrievalPool,
    getSuperCourseApprovedTopics,
    searchSuperCourse,
    mergeBalancedCourseResults,
    buildSuperCourseContext,
    buildSuperCoursePoolSummary,
    buildSuperCourseCitations,
    buildSuperCourseSourceAttribution
};
