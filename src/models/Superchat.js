/**
 * Superchat Model
 *
 * A "superchat" (a.k.a. bucket) is an instructor/admin-curated grouping of courses
 * that students can chat across. There can be many of them (e.g. "2nd Year Biochem",
 * "3rd Year Biochem", "Graduate").
 *
 * Membership is stored course-side as `course.superchatIds: []` (see Course.js), not
 * here — this document holds the bucket's identity and chat settings only. Chat
 * settings are resolved/normalized by superCourseService.resolveSuperCourseChatSettings
 * on read; this model stores the raw fields.
 */

const CourseModel = require('./Course');

const COLLECTION_NAME = 'superchats';

// Display labels for year-level buckets. 5 == Graduate (mirrors Course yearLevel).
const YEAR_LABELS = {
    1: '1st Year',
    2: '2nd Year',
    3: '3rd Year',
    4: '4th Year',
    5: 'Graduate'
};

// Stable id used for the catch-all bucket that holds opted-in courses with no
// usable year level (so legacy super-course courses are never dropped).
const UNGROUPED_SUPERCHAT_ID = 'ungrouped';

// Legacy global settings doc id (pre-multi-superchat). Read once during migration.
const LEGACY_SETTINGS_ID = 'superCourseChat';

function getCollection(db) {
    return db.collection(COLLECTION_NAME);
}

/**
 * Generate a unique superchat ID.
 * @returns {string} e.g. "sc_1717363200000_a1b2c3d4e"
 */
function generateSuperchatId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 11);
    return `sc_${timestamp}_${random}`;
}

function yearLabel(yearLevel) {
    return YEAR_LABELS[yearLevel] || null;
}

function normalizeName(value, fallback = 'Untitled Super Course') {
    const name = typeof value === 'string' ? value.trim() : '';
    return name || fallback;
}

/**
 * Pull the chat-settings fields out of an input object, leaving validation/defaults
 * to superCourseService.resolveSuperCourseChatSettings. Only keeps recognized keys.
 */
function pickChatSettings(input = {}) {
    const out = {};
    const keys = [
        'studentTopK', 'instructorTopK', 'includeInactiveCourses',
        'includeNotesInRetrieval', 'noteRetrievalRatio', 'noteMinScore',
        'instructorPrompt', 'studentPrompt',
        'studentLevelModifiers', 'instructorLevelModifiers'
    ];
    for (const key of keys) {
        if (input[key] !== undefined) out[key] = input[key];
    }
    return out;
}

/**
 * Ensure indexes exist. Safe to call repeatedly.
 * @param {Object} db
 */
async function ensureIndexes(db) {
    const collection = getCollection(db);
    await collection.createIndex({ superchatId: 1 }, { unique: true });
    await collection.createIndex({ isDeleted: 1, yearLevel: 1, name: 1 });
}

/**
 * Create a new superchat bucket.
 * @param {Object} db
 * @param {Object} data - { superchatId?, name, description?, yearLevel?, showToStudents?, ...chatSettings }
 * @param {string|null} createdById
 * @returns {Promise<Object>} The created superchat document
 */
async function createSuperchat(db, data = {}, createdById = null) {
    const collection = getCollection(db);
    const now = new Date();
    const yearLevel = CourseModel.normalizeYearLevel(data.yearLevel);

    const doc = {
        superchatId: data.superchatId || generateSuperchatId(),
        name: normalizeName(data.name, yearLevel ? yearLabel(yearLevel) : 'Untitled Super Course'),
        description: typeof data.description === 'string' ? data.description.trim() : '',
        yearLevel, // 1-5 or null
        // Hidden from students by default; an instructor enables "Show Students
        // This Bucket" once the bucket is set up. Pass showToStudents:true to
        // create it visible.
        showToStudents: data.showToStudents === true,
        ...pickChatSettings(data),
        createdBy: createdById,
        createdAt: now,
        updatedAt: now,
        isDeleted: false
    };

    if (data.llmApiKey && typeof data.llmApiKey === 'object') {
        doc.llmApiKey = data.llmApiKey;
    }

    await collection.insertOne(doc);
    return doc;
}

/**
 * List superchat buckets.
 * @param {Object} db
 * @param {Object} options - { includeDeleted: boolean }
 * @returns {Promise<Array>} Raw superchat documents (settings unresolved)
 */
async function listSuperchats(db, options = {}) {
    const collection = getCollection(db);
    const query = options.includeDeleted ? {} : { isDeleted: { $ne: true } };
    return collection
        .find(query)
        // Year-ordered (nulls last), then by name, so the picker/admin list reads
        // "1st Year, 2nd Year, ... Graduate, <ungrouped>".
        .sort({ yearLevel: 1, name: 1 })
        .toArray();
}

/**
 * Get a single superchat by id.
 * @param {Object} db
 * @param {string} superchatId
 * @param {Object} options - { includeDeleted: boolean }
 * @returns {Promise<Object|null>}
 */
async function getSuperchatById(db, superchatId, options = {}) {
    if (!superchatId) return null;
    const collection = getCollection(db);
    const query = { superchatId };
    if (!options.includeDeleted) query.isDeleted = { $ne: true };
    return collection.findOne(query);
}

/**
 * Update mutable fields on a superchat.
 * @param {Object} db
 * @param {string} superchatId
 * @param {Object} updates - { name?, description?, yearLevel?, showToStudents?, ...chatSettings }
 * @returns {Promise<Object|null>} The updated document, or null if not found
 */
async function updateSuperchat(db, superchatId, updates = {}) {
    const collection = getCollection(db);
    const set = { updatedAt: new Date() };

    if (updates.name !== undefined) set.name = normalizeName(updates.name);
    if (updates.description !== undefined) {
        set.description = typeof updates.description === 'string' ? updates.description.trim() : '';
    }
    if (updates.yearLevel !== undefined) {
        set.yearLevel = updates.yearLevel === null ? null : CourseModel.normalizeYearLevel(updates.yearLevel);
    }
    if (updates.showToStudents !== undefined) set.showToStudents = updates.showToStudents === true;
    Object.assign(set, pickChatSettings(updates));

    const result = await collection.updateOne(
        { superchatId, isDeleted: { $ne: true } },
        { $set: set }
    );
    if (result.matchedCount === 0) return null;
    return getSuperchatById(db, superchatId);
}

/**
 * Soft-delete a superchat and remove its id from every course's superchatIds.
 * Soft-delete (not hard) so historical flags/struggle records can still resolve
 * the bucket name.
 * @param {Object} db
 * @param {string} superchatId
 * @returns {Promise<{ success: boolean, coursesUpdated: number }>}
 */
async function softDeleteSuperchat(db, superchatId) {
    const collection = getCollection(db);
    const result = await collection.updateOne(
        { superchatId },
        { $set: { isDeleted: true, deletedAt: new Date(), updatedAt: new Date() } }
    );

    // Detach from all courses so it stops appearing in pools/checklists.
    const coursesResult = await db.collection('courses').updateMany(
        { superchatIds: superchatId },
        { $pull: { superchatIds: superchatId } }
    );

    return {
        success: result.matchedCount > 0,
        coursesUpdated: coursesResult.modifiedCount || 0
    };
}

/**
 * Migration: seed superchat buckets from existing data and convert the legacy
 * per-course `allowInSuperCourse` boolean into `course.superchatIds`.
 *
 * Idempotent — safe to run on every boot:
 *  - Buckets are upserted by stable id (year-<n> / ungrouped).
 *  - Course membership uses $addToSet.
 *  - Skips entirely once any superchat already exists AND no legacy opted-in
 *    courses remain to convert.
 *
 * @param {Object} db
 */
async function ensureSuperchatsFromLegacy(db) {
    const collection = getCollection(db);
    await ensureIndexes(db);

    const coursesCol = db.collection('courses');

    // Legacy opted-in courses that haven't been converted yet (no superchatIds).
    const legacyCourses = await coursesCol.find(
        {
            allowInSuperCourse: true,
            status: { $ne: 'deleted' },
            $or: [
                { superchatIds: { $exists: false } },
                { superchatIds: { $size: 0 } }
            ]
        },
        { projection: { courseId: 1, courseName: 1, yearLevel: 1 } }
    ).toArray();

    const existingCount = await collection.countDocuments({});

    // Nothing to seed and nothing to convert → done.
    if (existingCount > 0 && legacyCourses.length === 0) {
        return;
    }

    // Carry over the old global chat settings (prompts/topK/visibility) so the
    // seeded buckets behave like today's single super course.
    const legacySettings = await db.collection('settings').findOne({ _id: LEGACY_SETTINGS_ID }) || {};
    const showToStudents = legacySettings.showStudentSuperCourse === true;
    const sharedSettings = pickChatSettings(legacySettings);

    // Group legacy courses by resolved year level (null → ungrouped bucket).
    const byYear = new Map(); // yearLevel|('ungrouped') -> [courseId]
    for (const course of legacyCourses) {
        const level = CourseModel.normalizeYearLevel(course.yearLevel)
            ?? CourseModel.parseYearLevelFromName(course.courseName);
        const key = level === null ? UNGROUPED_SUPERCHAT_ID : `year-${level}`;
        if (!byYear.has(key)) byYear.set(key, { yearLevel: level, courseIds: [] });
        byYear.get(key).courseIds.push(course.courseId);
    }

    if (legacyCourses.length > 0) {
        console.log(`Migrating ${legacyCourses.length} opted-in course(s) into ${byYear.size} superchat bucket(s)...`);
    }

    for (const [bucketId, { yearLevel, courseIds }] of byYear.entries()) {
        const name = yearLevel ? yearLabel(yearLevel) : 'Other Biochemistry';
        // Upsert the bucket (create if missing, never clobber an admin-edited one).
        await collection.updateOne(
            { superchatId: bucketId },
            {
                $setOnInsert: {
                    superchatId: bucketId,
                    name,
                    description: '',
                    yearLevel: yearLevel || null,
                    showToStudents,
                    ...sharedSettings,
                    createdBy: null,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    isDeleted: false
                }
            },
            { upsert: true }
        );

        // Attach courses to the bucket (idempotent).
        await coursesCol.updateMany(
            { courseId: { $in: courseIds } },
            { $addToSet: { superchatIds: bucketId } }
        );
    }
}

module.exports = {
    COLLECTION_NAME,
    YEAR_LABELS,
    UNGROUPED_SUPERCHAT_ID,
    yearLabel,
    generateSuperchatId,
    ensureIndexes,
    createSuperchat,
    listSuperchats,
    getSuperchatById,
    updateSuperchat,
    softDeleteSuperchat,
    ensureSuperchatsFromLegacy
};
