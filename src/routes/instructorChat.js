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

router.get('/pool', async (req, res) => {
    try {
        const db = req.app.locals.db;

        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const settings = await getSuperCourseChatSettings(db);
        const pool = await getSuperCourseRetrievalPool(db, {
            includeInactiveCourses: settings.includeInactiveCourses
        });

        res.json({
            success: true,
            courses: pool.map(course => ({
                courseId: course.courseId,
                courseName: course.courseName || course.courseCode || course.courseId,
                status: course.status || null
            })),
            includeInactiveCourses: settings.includeInactiveCourses,
            showStudentSuperCourse: settings.showStudentSuperCourse,
            topK: settings.instructorTopK
        });
    } catch (error) {
        console.error('Error loading instructor Super Course pool:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to load Super Course source pool'
        });
    }
});

router.post('/', async (req, res) => {
    try {
        const db = req.app.locals.db;
        const llmService = req.app.locals.llm;

        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

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

        const settings = await getSuperCourseChatSettings(db);
        const { pool, results } = await searchSuperCourse(
            db,
            message,
            settings.instructorTopK,
            { includeInactiveCourses: settings.includeInactiveCourses }
        );

        const contextText = buildSuperCourseContext(results, pool);
        const poolSummary = buildSuperCoursePoolSummary(pool);
        const citations = buildSuperCourseCitations(results, pool);
        const sourceAttribution = buildSuperCourseSourceAttribution(results, pool);

        const trimmedHistory = conversationMessages
            .filter(item => item && (item.role === 'user' || item.role === 'assistant') && typeof item.content === 'string')
            .slice(-8)
            .map(item => `${item.role === 'user' ? 'Instructor' : 'BiocBot'}: ${item.content}`)
            .join('\n\n');

        const prompt = [
            'Answer the instructor using the Super Course context when it is relevant.',
            'If the context is thin or missing, answer from established general biochemistry and say when you are going beyond uploaded material.',
            `Configured Super Course source pool:\n${poolSummary}`,
            contextText ? `Super Course context:\n${contextText}` : 'Super Course context: No uploaded course chunks were retrieved for this question.',
            trimmedHistory ? `Recent conversation:\n${trimmedHistory}` : '',
            `Instructor question: ${message}`
        ].filter(Boolean).join('\n\n');

        const response = await llmService.sendMessage(prompt, {
            temperature: 0.4,
            maxTokens: 32768,
            systemPrompt: settings.instructorPrompt
        });

        res.json({
            success: true,
            message: response && response.content ? response.content : '',
            model: response && response.model,
            usage: response && response.usage,
            timestamp: new Date().toISOString(),
            citations,
            sourceAttribution,
            retrieval: {
                topK: settings.instructorTopK,
                includeInactiveCourses: settings.includeInactiveCourses,
                poolCourseIds: pool.map(course => course.courseId),
                poolCourses: sourceAttribution.poolCourses,
                resultCount: results.length
            }
        });
    } catch (error) {
        console.error('Error in instructor Super Course chat:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to process instructor chat message'
        });
    }
});

module.exports = router;
