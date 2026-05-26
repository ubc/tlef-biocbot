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
