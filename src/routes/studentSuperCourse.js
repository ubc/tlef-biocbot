const express = require('express');
const router = express.Router();
const {
    getSuperCourseChatSettings,
    getSuperCourseRetrievalPool,
    searchSuperCourse,
    buildSuperCourseContext,
    buildSuperCoursePoolSummary,
    buildSuperCourseCitations,
    buildSuperCourseSourceAttribution
} = require('../services/superCourseService');

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

        const { pool, results } = await searchSuperCourse(
            ctx.db,
            message,
            ctx.settings.studentTopK,
            { includeInactiveCourses: ctx.settings.includeInactiveCourses }
        );

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

        const response = await llmService.sendMessage(prompt, {
            temperature: 0.4,
            maxTokens: 32768,
            systemPrompt: ctx.settings.studentPrompt
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
