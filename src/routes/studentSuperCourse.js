const express = require('express');
const router = express.Router();
const {
    getSuperchat,
    listSuperchats,
    getStudentAccessibleSuperchatIds,
    getSuperCourseRetrievalPool,
    getSuperCourseApprovedTopics,
    searchSuperCourse,
    buildSuperCourseContext,
    buildSuperCoursePoolSummary,
    buildSuperCourseCitations,
    buildSuperCourseSourceAttribution
} = require('../services/superCourseService');
const prompts = require('../services/prompts');
const TrackerService = require('../services/tracker');
const User = require('../models/User');
const StruggleActivity = require('../models/StruggleActivity');
const CourseModel = require('../models/Course');

// Resolve a course's effective year level: prefer the stored value, fall back to
// deriving it from the course name (covers courses created before yearLevel
// existed). Returns null when neither yields a usable level.
function resolveCourseYearLevel(course = {}) {
    return CourseModel.normalizeYearLevel(course.yearLevel)
        ?? CourseModel.parseYearLevelFromName(course.courseName);
}

// Highest year level among the courses a student is actively enrolled in. This
// is the student's effective "level" for the Super Course (which spans many
// courses). Returns null when the student has no enrolled course with a level.
async function getStudentYearLevel(db, studentId) {
    if (!db || !studentId) return null;

    const enrolledCourses = await db.collection('courses')
        .find(
            {
                status: { $ne: 'deleted' },
                [`studentEnrollment.${studentId}.enrolled`]: true
            },
            { projection: { yearLevel: 1, courseName: 1 } }
        )
        .toArray();

    let maxLevel = null;
    for (const course of enrolledCourses) {
        const level = resolveCourseYearLevel(course);
        if (level !== null && (maxLevel === null || level > maxLevel)) {
            maxLevel = level;
        }
    }
    return maxLevel;
}

// Lazily-initialized tracker, shared across requests once the LLM is ready
// (mirrors the per-course chat route in src/routes/chat.js).
let localTrackerService;

/**
 * Detect cross-course struggle in a Super Chat message and record it against the
 * source course that owns the matched topic. See build spec — Option B (per-event
 * logging). Records the struggle for dashboards but does NOT enter Directive Mode:
 * the Super Chat never switches into directive answering. Never throws.
 *
 * @param {Object} params - { db, llmService, user, message, superchatId, includeInactiveCourses }
 * @returns {Promise<void>}
 */
async function trackSuperCourseStruggle({ db, llmService, user, message, superchatId, includeInactiveCourses }) {
    try {
        if (!db || !llmService || !user || !user.userId || !message) return;

        if (!localTrackerService) {
            localTrackerService = new TrackerService(llmService);
        }

        // Scope candidate topics to THIS bucket's courses — fewer candidates means
        // more accurate cross-course attribution.
        const courseTopics = await getSuperCourseApprovedTopics(db, { superchatId, includeInactiveCourses });
        if (!courseTopics.length) return;

        const analysis = await localTrackerService.analyzeMessageAcrossCourses(message, courseTopics);
        if (!analysis.isStruggling || !analysis.isMapped || !analysis.courseId) {
            return;
        }

        const studentName = user.displayName || user.username || user.email || 'Unknown Student';

        // Update the student's GLOBAL topic counter and persistence, but suppress the
        // activation-only row — we log every event ourselves below so the global Super
        // Chat dashboard shows real volume.
        const updateResult = await User.updateUserStruggleState(
            db,
            user.userId,
            { topic: analysis.topic, isStruggling: true },
            analysis.courseId,
            { source: 'superCourse', skipActivityLog: true }
        );

        // A topic counts as "Active" for the dashboards once its struggle count hits
        // the threshold (>= 3); below that it is recorded but Inactive. This only
        // affects the logged state — the Super Chat does not switch to Directive Mode.
        const isActive = !!(updateResult && updateResult.success && updateResult.state && updateResult.state.isActive);

        // Per-event record, attributed to the source course and tagged superCourse,
        // plus the bucket it came from (for per-superchat dashboards).
        await StruggleActivity.createActivityEntry(db, {
            userId: user.userId,
            studentName,
            courseId: analysis.courseId,
            topic: analysis.topic,
            state: isActive ? 'Active' : 'Inactive',
            source: 'superCourse',
            superchatId: superchatId || null
        });

        console.log(`🕵️ [SUPER_STRUGGLE] Recorded "${analysis.topic}" (${isActive ? 'Active' : 'Inactive'}) for ${studentName} → course ${analysis.courseId} (conf ${analysis.matchConfidence})`);
    } catch (error) {
        console.error('❌ [SUPER_STRUGGLE] Error tracking Super Chat struggle:', error);
    }
}

// Resolve a user-selected answer level to its configured modifier, falling back
// to the default level when the requested one is unknown. Empty modifier (the
// neutral middle level) appends nothing.
function appendLevelModifier(basePrompt, requestedLevel, validKeys, defaultLevel, modifiers) {
    const level = validKeys.includes(requestedLevel) ? requestedLevel : defaultLevel;
    const modifier = modifiers && typeof modifiers[level] === 'string' ? modifiers[level].trim() : '';
    return modifier ? `${basePrompt}\n\n${modifier}` : basePrompt;
}

// Resolve and authorize the superchat bucket for a student request. Reads the
// bucket id from query (?superchatId=) or body, confirms it is student-visible,
// and confirms the student is enrolled in ≥1 of its courses. Returns
// { db, superchat, settings } or null (after sending an error response).
async function resolveStudentSuperchat(req, res) {
    const db = req.app.locals.db;
    if (!db) {
        res.status(503).json({ success: false, message: 'Database connection not available' });
        return null;
    }

    const studentId = req.user && req.user.userId;
    if (!studentId) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return null;
    }

    const superchatId = (req.query && req.query.superchatId) || (req.body && req.body.superchatId);
    if (!superchatId) {
        res.status(400).json({ success: false, message: 'superchatId is required' });
        return null;
    }

    const superchat = await getSuperchat(db, superchatId);
    if (!superchat || superchat.showToStudents !== true) {
        res.status(404).json({ success: false, message: 'Super Course not found' });
        return null;
    }

    const accessibleIds = await getStudentAccessibleSuperchatIds(db, studentId);
    if (!accessibleIds.has(superchatId)) {
        res.status(403).json({ success: false, message: 'You do not have access to this Super Course' });
        return null;
    }

    return { db, superchat, settings: superchat.settings, superchatId };
}

// GET /status — used by the nav to decide whether to show the Super Course link.
// "enabled" means the student can access at least one bucket.
router.get('/status', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const studentId = req.user && req.user.userId;
        if (!studentId) {
            return res.json({ success: true, enabled: false });
        }

        const accessibleIds = await getStudentAccessibleSuperchatIds(db, studentId);
        if (!accessibleIds.size) {
            return res.json({ success: true, enabled: false });
        }
        const visible = await listSuperchats(db, { studentVisibleOnly: true });
        const enabled = visible.some(b => accessibleIds.has(b.superchatId));
        res.json({ success: true, enabled });
    } catch (error) {
        console.error('Error checking student Super Course status:', error);
        res.status(500).json({ success: false, message: 'Failed to check status' });
    }
});

// GET /list — the buckets this student can pick from (enrollment-derived +
// student-visible), ordered by year level with the student's own year first.
router.get('/list', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const studentId = req.user && req.user.userId;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        const [accessibleIds, visible, studentYearLevel] = await Promise.all([
            getStudentAccessibleSuperchatIds(db, studentId),
            listSuperchats(db, { studentVisibleOnly: true }),
            getStudentYearLevel(db, studentId)
        ]);

        const superchats = visible
            .filter(b => accessibleIds.has(b.superchatId))
            .map(b => ({
                superchatId: b.superchatId,
                name: b.name,
                description: b.description || '',
                yearLevel: b.yearLevel ?? null,
                // Flag buckets aimed above the student's level so the UI can hint
                // "ahead of your year" without blocking access.
                aboveStudentLevel: studentYearLevel !== null && b.yearLevel !== null && b.yearLevel > studentYearLevel
            }));

        // Order: the student's own year first, then ascending year (nulls last).
        superchats.sort((a, b) => {
            const av = a.yearLevel === studentYearLevel ? -1 : (a.yearLevel ?? 99);
            const bv = b.yearLevel === studentYearLevel ? -1 : (b.yearLevel ?? 99);
            if (av !== bv) return av - bv;
            return a.name.localeCompare(b.name);
        });

        res.json({ success: true, superchats, studentYearLevel });
    } catch (error) {
        console.error('Error listing student Super Courses:', error);
        res.status(500).json({ success: false, message: 'Failed to list Super Courses' });
    }
});

router.get('/pool', async (req, res) => {
    try {
        const ctx = await resolveStudentSuperchat(req, res);
        if (!ctx) return;

        const pool = await getSuperCourseRetrievalPool(ctx.db, {
            superchatId: ctx.superchatId,
            includeInactiveCourses: ctx.settings.includeInactiveCourses
        });

        // Determine whether the source pool reaches above the student's own
        // level so the client can reassure them that some material may be
        // ahead of where they are. Highest pool level vs. the student's highest
        // enrolled-course level.
        const studentId = req.user && req.user.userId;
        const studentYearLevel = await getStudentYearLevel(ctx.db, studentId);

        let poolMaxYearLevel = null;
        for (const course of pool) {
            const level = resolveCourseYearLevel(course);
            if (level !== null && (poolMaxYearLevel === null || level > poolMaxYearLevel)) {
                poolMaxYearLevel = level;
            }
        }

        const hasHigherLevelCourses = studentYearLevel !== null
            && poolMaxYearLevel !== null
            && poolMaxYearLevel > studentYearLevel;

        res.json({
            success: true,
            superchatId: ctx.superchatId,
            superchatName: ctx.superchat.name,
            courses: pool.map(course => ({
                courseId: course.courseId,
                courseName: course.courseName || course.courseCode || course.courseId,
                status: course.status || null
            })),
            topK: ctx.settings.studentTopK,
            studentYearLevel,
            poolMaxYearLevel,
            hasHigherLevelCourses
        });
    } catch (error) {
        console.error('Error loading student Super Course pool:', error);
        res.status(500).json({ success: false, message: 'Failed to load Super Course source pool' });
    }
});

router.post('/save', async (req, res) => {
    try {
        const ctx = await resolveStudentSuperchat(req, res);
        if (!ctx) return;

        const {
            sessionId,
            title,
            messageCount,
            duration,
            savedAt,
            chatData
        } = req.body || {};

        if (!sessionId || !chatData || typeof chatData !== 'object') {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: sessionId, chatData'
            });
        }

        const studentId = req.user && req.user.userId;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        const sessionData = {
            sessionId,
            studentId,
            superchatId: ctx.superchatId,
            studentName: req.user.displayName || req.user.username || req.user.email || studentId,
            title: title || `Super Course Chat ${new Date().toLocaleDateString()}`,
            messageCount: messageCount || 0,
            duration: duration || '0s',
            savedAt: savedAt || new Date().toISOString(),
            chatData,
            isDeleted: false,
            updatedAt: new Date(),
            createdAt: new Date()
        };

        await ctx.db.collection('student_super_course_chat_sessions').replaceOne(
            { sessionId, studentId },
            sessionData,
            { upsert: true }
        );

        res.json({
            success: true,
            message: 'Student Super Course chat session saved successfully',
            data: { sessionId, studentId }
        });
    } catch (error) {
        console.error('Error saving student Super Course chat session:', error);
        res.status(500).json({ success: false, message: 'Failed to save Super Course chat session' });
    }
});

router.get('/sessions', async (req, res) => {
    try {
        const ctx = await resolveStudentSuperchat(req, res);
        if (!ctx) return;

        const studentId = req.user && req.user.userId;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        const sessions = await ctx.db.collection('student_super_course_chat_sessions')
            .find({
                studentId,
                superchatId: ctx.superchatId,
                $or: [
                    { isDeleted: { $exists: false } },
                    { isDeleted: false }
                ]
            })
            .sort({ updatedAt: -1, savedAt: -1 })
            .toArray();

        res.json({
            success: true,
            data: {
                sessions: sessions.map(session => ({
                    sessionId: session.sessionId,
                    title: session.title,
                    messageCount: session.messageCount || 0,
                    duration: session.duration || '0s',
                    savedAt: session.savedAt,
                    updatedAt: session.updatedAt,
                    chatData: session.chatData || {}
                }))
            }
        });
    } catch (error) {
        console.error('Error listing student Super Course chat sessions:', error);
        res.status(500).json({ success: false, message: 'Failed to load Super Course chat sessions' });
    }
});

router.get('/sessions/:sessionId', async (req, res) => {
    try {
        const ctx = await resolveStudentSuperchat(req, res);
        if (!ctx) return;

        const studentId = req.user && req.user.userId;
        const session = await ctx.db.collection('student_super_course_chat_sessions').findOne({
            sessionId: req.params.sessionId,
            studentId,
            $or: [
                { isDeleted: { $exists: false } },
                { isDeleted: false }
            ]
        });

        if (!session) {
            return res.status(404).json({ success: false, message: 'Super Course chat session not found' });
        }

        res.json({ success: true, session });
    } catch (error) {
        console.error('Error loading student Super Course chat session:', error);
        res.status(500).json({ success: false, message: 'Failed to load Super Course chat session' });
    }
});

router.delete('/sessions/:sessionId', async (req, res) => {
    try {
        const ctx = await resolveStudentSuperchat(req, res);
        if (!ctx) return;

        const studentId = req.user && req.user.userId;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        await ctx.db.collection('student_super_course_chat_sessions').updateOne(
            { sessionId: req.params.sessionId, studentId },
            { $set: { isDeleted: true, deletedAt: new Date() } }
        );

        res.json({ success: true, data: { sessionId: req.params.sessionId } });
    } catch (error) {
        console.error('Error deleting student Super Course chat session:', error);
        res.status(500).json({ success: false, message: 'Failed to delete Super Course chat session' });
    }
});

router.post('/chat', async (req, res) => {
    try {
        const ctx = await resolveStudentSuperchat(req, res);
        if (!ctx) return;

        const llmService = req.app.locals.llm;
        if (!llmService) {
            return res.status(503).json({ success: false, message: 'LLM service is not initialized' });
        }

        const message = req.body && req.body.message;
        const conversationMessages = Array.isArray(req.body && req.body.conversationMessages)
            ? req.body.conversationMessages
            : [];

        if (!message || typeof message !== 'string' || !message.trim()) {
            return res.status(400).json({ success: false, message: 'Message is required' });
        }

        // Struggle tracking runs in parallel with retrieval so its own LLM call
        // overlaps; we await it before responding only to ensure the record is
        // written. It does not affect the answer — the Super Chat never enters
        // Directive Mode.
        const strugglePromise = req.user
            ? trackSuperCourseStruggle({
                db: ctx.db,
                llmService,
                user: req.user,
                message,
                superchatId: ctx.superchatId,
                includeInactiveCourses: ctx.settings.includeInactiveCourses
            })
            : Promise.resolve();

        const { pool, results } = await searchSuperCourse(
            ctx.db,
            message,
            ctx.settings.studentTopK,
            { superchatId: ctx.superchatId, includeInactiveCourses: ctx.settings.includeInactiveCourses }
        );

        await strugglePromise;

        const contextText = buildSuperCourseContext(results, pool);
        const poolSummary = buildSuperCoursePoolSummary(pool);
        const citations = buildSuperCourseCitations(results, pool);
        const sourceAttribution = buildSuperCourseSourceAttribution(results, pool);

        const trimmedHistory = conversationMessages
            .filter(item => item && (item.role === 'user' || item.role === 'assistant') && typeof item.content === 'string')
            .slice(-8)
            .map(item => `${item.role === 'user' ? 'Student' : 'BiocBot'}: ${item.content}`)
            .join('\n\n');

        const prompt = [
            'Answer the student using the Super Course context when it is relevant.',
            'If the context is thin or missing, answer from established general biochemistry and say when you are going beyond uploaded material.',
            `Configured Super Course source pool:\n${poolSummary}`,
            contextText ? `Super Course context:\n${contextText}` : 'Super Course context: No uploaded course chunks were retrieved for this question.',
            trimmedHistory ? `Recent conversation:\n${trimmedHistory}` : '',
            `Student question: ${message}`
        ].filter(Boolean).join('\n\n');

        let systemPrompt = appendLevelModifier(
            ctx.settings.studentPrompt,
            req.body && req.body.level,
            prompts.STUDENT_LEVEL_KEYS,
            prompts.DEFAULT_STUDENT_LEVEL,
            ctx.settings.studentLevelModifiers
        );

        const response = await llmService.sendMessage(prompt, {
            temperature: 0.4,
            maxTokens: 32768,
            systemPrompt
        });

        res.json({
            success: true,
            message: response && response.content ? response.content : '',
            model: response && response.model,
            usage: response && response.usage,
            timestamp: new Date().toISOString(),
            citations,
            sourceAttribution
        });
    } catch (error) {
        console.error('Error in student Super Course chat:', error);
        res.status(500).json({ success: false, message: 'Failed to process chat message' });
    }
});

module.exports = router;
// Exposed for unit testing (router is a function; attaching a prop is harmless).
module.exports.trackSuperCourseStruggle = trackSuperCourseStruggle;
