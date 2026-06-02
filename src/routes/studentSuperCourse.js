const express = require('express');
const router = express.Router();
const {
    getSuperCourseChatSettings,
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

// Lazily-initialized tracker, shared across requests once the LLM is ready
// (mirrors the per-course chat route in src/routes/chat.js).
let localTrackerService;

/**
 * Detect cross-course struggle in a Super Chat message and record it against the
 * source course that owns the matched topic. See build spec — Option B (per-event
 * logging). Never throws: on any error it resolves to a "no directive" result.
 *
 * @param {Object} params - { db, llmService, user, message, includeInactiveCourses }
 * @returns {Promise<{directiveModeActive: boolean, identifiedTopic: string|null}>}
 */
async function trackSuperCourseStruggle({ db, llmService, user, message, includeInactiveCourses }) {
    const noDirective = { directiveModeActive: false, identifiedTopic: null };
    try {
        if (!db || !llmService || !user || !user.userId || !message) return noDirective;

        if (!localTrackerService) {
            localTrackerService = new TrackerService(llmService);
        }

        const courseTopics = await getSuperCourseApprovedTopics(db, { includeInactiveCourses });
        if (!courseTopics.length) return noDirective;

        const analysis = await localTrackerService.analyzeMessageAcrossCourses(message, courseTopics);
        if (!analysis.isStruggling || !analysis.isMapped || !analysis.courseId) {
            return noDirective;
        }

        const studentName = user.displayName || user.username || user.email || 'Unknown Student';

        // Update the student's GLOBAL topic counter (blended Directive Mode) and
        // persistence, but suppress the activation-only row — we log every event
        // ourselves below so the global Super Chat dashboard shows real volume.
        const updateResult = await User.updateUserStruggleState(
            db,
            user.userId,
            { topic: analysis.topic, isStruggling: true },
            analysis.courseId,
            { source: 'superCourse', skipActivityLog: true }
        );

        // The topic only enters Directive Mode at count >= 3; until then the
        // struggle is recorded but NOT active. Reflect that in the logged state
        // instead of always writing 'Active'.
        const isActive = !!(updateResult && updateResult.success && updateResult.state && updateResult.state.isActive);

        // Per-event record, attributed to the source course and tagged superCourse.
        await StruggleActivity.createActivityEntry(db, {
            userId: user.userId,
            studentName,
            courseId: analysis.courseId,
            topic: analysis.topic,
            state: isActive ? 'Active' : 'Inactive',
            source: 'superCourse'
        });

        console.log(`🕵️ [SUPER_STRUGGLE] Recorded "${analysis.topic}" (${isActive ? 'Active' : 'Inactive'}) for ${studentName} → course ${analysis.courseId} (conf ${analysis.matchConfidence})`);

        // Mirror the per-course chat: directive mode applies to THIS response
        // only when the current message's topic is now active.
        return {
            directiveModeActive: isActive,
            identifiedTopic: isActive ? analysis.topic : null
        };
    } catch (error) {
        console.error('❌ [SUPER_STRUGGLE] Error tracking Super Chat struggle:', error);
        return noDirective;
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

async function ensureStudentSuperCourseEnabled(req, res) {
    const db = req.app.locals.db;
    if (!db) {
        res.status(503).json({ success: false, message: 'Database connection not available' });
        return null;
    }

    const settings = await getSuperCourseChatSettings(db);
    if (!settings.showStudentSuperCourse) {
        res.status(403).json({ success: false, message: 'Student Super Course is not enabled' });
        return null;
    }

    return { db, settings };
}

router.get('/status', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const settings = await getSuperCourseChatSettings(db);
        res.json({ success: true, enabled: settings.showStudentSuperCourse === true });
    } catch (error) {
        console.error('Error checking student Super Course status:', error);
        res.status(500).json({ success: false, message: 'Failed to check status' });
    }
});

router.get('/pool', async (req, res) => {
    try {
        const ctx = await ensureStudentSuperCourseEnabled(req, res);
        if (!ctx) return;

        const pool = await getSuperCourseRetrievalPool(ctx.db, {
            includeInactiveCourses: ctx.settings.includeInactiveCourses
        });

        res.json({
            success: true,
            courses: pool.map(course => ({
                courseId: course.courseId,
                courseName: course.courseName || course.courseCode || course.courseId,
                status: course.status || null
            })),
            topK: ctx.settings.studentTopK
        });
    } catch (error) {
        console.error('Error loading student Super Course pool:', error);
        res.status(500).json({ success: false, message: 'Failed to load Super Course source pool' });
    }
});

router.post('/save', async (req, res) => {
    try {
        const ctx = await ensureStudentSuperCourseEnabled(req, res);
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
        const ctx = await ensureStudentSuperCourseEnabled(req, res);
        if (!ctx) return;

        const studentId = req.user && req.user.userId;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'Authentication required' });
        }

        const sessions = await ctx.db.collection('student_super_course_chat_sessions')
            .find({
                studentId,
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
        const ctx = await ensureStudentSuperCourseEnabled(req, res);
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
        const ctx = await ensureStudentSuperCourseEnabled(req, res);
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
        const ctx = await ensureStudentSuperCourseEnabled(req, res);
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
        // overlaps; we await it before building the prompt so we can switch the
        // Super Chat into Directive Mode when the current topic is active.
        const strugglePromise = req.user
            ? trackSuperCourseStruggle({
                db: ctx.db,
                llmService,
                user: req.user,
                message,
                includeInactiveCourses: ctx.settings.includeInactiveCourses
            })
            : Promise.resolve({ directiveModeActive: false, identifiedTopic: null });

        const { pool, results } = await searchSuperCourse(
            ctx.db,
            message,
            ctx.settings.studentTopK,
            { includeInactiveCourses: ctx.settings.includeInactiveCourses }
        );

        const { directiveModeActive, identifiedTopic } = await strugglePromise;

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

        // Directive Mode: when the student's current topic has hit the struggle
        // threshold, switch the Super Chat into guided/directive answering, the
        // same way the per-course chat does. The Super Chat spans courses, so we
        // use the platform-default directive prompt (no single course prompt).
        if (directiveModeActive && identifiedTopic) {
            systemPrompt += `\n\nCRITICAL INSTRUCTION: The student is struggling significantly with the topic "${identifiedTopic}".\nSwitch to DIRECTIVE MODE:\n${prompts.DEFAULT_PROMPTS.directive}`;
        }

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
            sourceAttribution,
            // Per-response directive state: true only for THIS query (when the
            // current message's topic is active). The client shows the badge
            // for the specific response, not the whole session.
            directiveModeActive,
            struggleTopic: identifiedTopic
        });
    } catch (error) {
        console.error('Error in student Super Course chat:', error);
        res.status(500).json({ success: false, message: 'Failed to process chat message' });
    }
});

module.exports = router;
// Exposed for unit testing (router is a function; attaching a prop is harmless).
module.exports.trackSuperCourseStruggle = trackSuperCourseStruggle;
