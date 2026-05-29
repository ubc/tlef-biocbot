/**
 * Settings Routes
 * Handles settings-related API endpoints
 */

const express = require('express');
const router = express.Router();
const prompts = require('../services/prompts');
const CourseModel = require('../models/Course');
const { hasSystemAdminAccess, normalizeEmail } = require('../services/authorization');
const {
    listSystemAdmins,
    grantSystemAdminByEmail,
    revokeSystemAdminByEmail
} = require('../services/systemAdmin');

function requireSystemAdmin(req, res) {
    if (!req.user) {
        res.status(401).json({ success: false, error: 'Not authenticated' });
        return false;
    }

    if (!hasSystemAdminAccess(req.user)) {
        res.status(403).json({ success: false, error: 'Access denied' });
        return false;
    }

    return true;
}

const SUPER_COURSE_SETTINGS_ID = 'superCourseChat';

function normalizeTopKForSettings(value) {
    return CourseModel.normalizeRagTopK(value, null);
}

function buildAiSettingsResponse(course) {
    return {
        allowInSuperCourse: CourseModel.getAllowInSuperCourse(course),
        ragSettings: CourseModel.resolveRagSettings(course),
        defaults: {
            allowInSuperCourse: false,
            studentTopK: CourseModel.DEFAULT_STUDENT_RAG_TOP_K,
            minTopK: CourseModel.MIN_RAG_TOP_K,
            maxTopK: CourseModel.MAX_RAG_TOP_K
        }
    };
}

function normalizeNoteRatioForSettings(value, fallback) {
    const num = Number(value);
    if (!Number.isFinite(num) || num < 0 || num > 1) return fallback;
    // Snap to 2 decimals to keep stored values clean.
    return Math.round(num * 100) / 100;
}

function resolveSuperCourseChatSettings(settingsDoc = {}) {
    const defaults = prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS;
    return {
        studentTopK: CourseModel.normalizeRagTopK(settingsDoc.studentTopK, defaults.studentTopK),
        instructorTopK: CourseModel.normalizeRagTopK(settingsDoc.instructorTopK, defaults.instructorTopK),
        includeInactiveCourses: settingsDoc.includeInactiveCourses === true,
        showStudentSuperCourse: settingsDoc.showStudentSuperCourse === true,
        includeNotesInRetrieval: settingsDoc.includeNotesInRetrieval !== false,
        noteRetrievalRatio: normalizeNoteRatioForSettings(settingsDoc.noteRetrievalRatio, defaults.noteRetrievalRatio),
        noteMinScore: normalizeNoteRatioForSettings(settingsDoc.noteMinScore, defaults.noteMinScore),
        instructorPrompt: typeof settingsDoc.instructorPrompt === 'string' && settingsDoc.instructorPrompt.trim()
            ? settingsDoc.instructorPrompt
            : defaults.instructorPrompt,
        studentPrompt: typeof settingsDoc.studentPrompt === 'string' && settingsDoc.studentPrompt.trim()
            ? settingsDoc.studentPrompt
            : defaults.studentPrompt
    };
}

function buildSuperCourseChatDefaults() {
    return {
        ...prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS,
        minTopK: CourseModel.MIN_RAG_TOP_K,
        maxTopK: CourseModel.MAX_RAG_TOP_K
    };
}

async function requireInstructorForCourseSettings(db, req, res, courseId) {
    if (!req.user) {
        res.status(401).json({ success: false, error: 'Not authenticated' });
        return false;
    }

    if (req.user.role !== 'instructor') {
        res.status(403).json({ success: false, error: 'Instructor access required' });
        return false;
    }

    // Distinguish "course does not exist" (400) from "course exists but you can't touch it" (403).
    const existing = await db.collection('courses').findOne(
        { courseId, status: { $ne: 'deleted' } },
        { projection: { instructorId: 1, instructors: 1 } }
    );

    if (!existing) {
        res.status(400).json({ success: false, message: 'Course not found' });
        return false;
    }

    const owns = existing.instructorId === req.user.userId
        || (Array.isArray(existing.instructors) && existing.instructors.includes(req.user.userId));

    if (!owns) {
        res.status(403).json({ success: false, error: 'Access denied for this course' });
        return false;
    }

    return true;
}

/**
 * GET /api/settings/can-delete-all
 * Check if the current user has system admin access
 */
router.get('/can-delete-all', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Not authenticated',
                canDeleteAll: false
            });
        }

        const canDeleteAll = hasSystemAdminAccess(req.user);

        res.json({
            success: true,
            canDeleteAll,
            isSystemAdmin: canDeleteAll
        });

    } catch (error) {
        console.error('Error checking delete all permission:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to check delete all permission',
            canDeleteAll: false
        });
    }
});

router.get('/system-admins', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const admins = await listSystemAdmins(db);

        res.json({
            success: true,
            admins
        });
    } catch (error) {
        console.error('Error fetching system admins:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch system admins'
        });
    }
});

router.post('/system-admins', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const email = normalizeEmail(req.body && req.body.email);
        const result = await grantSystemAdminByEmail(db, email, {
            grantedBy: normalizeEmail(req.user.email)
        });

        if (!result.success) {
            return res.status(400).json(result);
        }

        res.json({
            success: true,
            email: result.email,
            message: 'System admin access granted.'
        });
    } catch (error) {
        console.error('Error granting system admin access:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to grant system admin access'
        });
    }
});

router.post('/system-admins/revoke', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const email = normalizeEmail(req.body && req.body.email);
        const result = await revokeSystemAdminByEmail(db, email);

        if (!result.success) {
            return res.status(400).json(result);
        }

        res.json({
            success: true,
            email: result.email,
            message: 'System admin access revoked.'
        });
    } catch (error) {
        console.error('Error revoking system admin access:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to revoke system admin access'
        });
    }
});

router.get('/ai-settings', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const courseId = req.query.courseId;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        const course = await db.collection('courses').findOne(
            { courseId, status: { $ne: 'deleted' } },
            { projection: { courseId: 1, ragSettings: 1, allowInSuperCourse: 1 } }
        );

        if (!course) {
            return res.status(404).json({ success: false, message: 'Course not found' });
        }

        res.json({
            success: true,
            courseId,
            settings: buildAiSettingsResponse(course)
        });
    } catch (error) {
        console.error('Error fetching AI settings:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch AI settings' });
    }
});

router.put('/ai-settings', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { courseId, allowInSuperCourse, studentTopK } = req.body || {};
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        const topK = normalizeTopKForSettings(studentTopK);
        if (topK === null) {
            return res.status(400).json({
                success: false,
                message: `Student Chat Top-K must be an integer from ${CourseModel.MIN_RAG_TOP_K} to ${CourseModel.MAX_RAG_TOP_K}`
            });
        }

        const result = await db.collection('courses').updateOne(
            { courseId, status: { $ne: 'deleted' } },
            {
                $set: {
                    allowInSuperCourse: allowInSuperCourse === true,
                    'ragSettings.student.topK': topK,
                    updatedAt: new Date(),
                    lastUpdatedById: req.user.userId
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: 'Course not found' });
        }

        res.json({
            success: true,
            courseId,
            message: 'AI settings saved',
            settings: {
                allowInSuperCourse: allowInSuperCourse === true,
                ragSettings: { student: { topK } },
                defaults: buildAiSettingsResponse({}).defaults
            }
        });
    } catch (error) {
        console.error('Error saving AI settings:', error);
        res.status(500).json({ success: false, message: 'Failed to save AI settings' });
    }
});

router.post('/ai-settings/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { courseId } = req.body || {};
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        const result = await db.collection('courses').updateOne(
            { courseId, status: { $ne: 'deleted' } },
            {
                $set: {
                    allowInSuperCourse: false,
                    'ragSettings.student.topK': CourseModel.DEFAULT_STUDENT_RAG_TOP_K,
                    updatedAt: new Date(),
                    lastUpdatedById: req.user.userId
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: 'Course not found' });
        }

        res.json({
            success: true,
            courseId,
            message: 'AI settings reset to defaults',
            settings: {
                allowInSuperCourse: false,
                ragSettings: { student: { topK: CourseModel.DEFAULT_STUDENT_RAG_TOP_K } },
                defaults: buildAiSettingsResponse({}).defaults
            }
        });
    } catch (error) {
        console.error('Error resetting AI settings:', error);
        res.status(500).json({ success: false, message: 'Failed to reset AI settings' });
    }
});

router.get('/super-course-chat', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const settingsDoc = await db.collection('settings').findOne({ _id: SUPER_COURSE_SETTINGS_ID });
        res.json({
            success: true,
            settings: resolveSuperCourseChatSettings(settingsDoc || {}),
            defaults: buildSuperCourseChatDefaults()
        });
    } catch (error) {
        console.error('Error fetching super course chat settings:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch super course chat settings' });
    }
});

router.put('/super-course-chat', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const body = req.body || {};
        const studentTopK = normalizeTopKForSettings(body.studentTopK);
        const instructorTopK = normalizeTopKForSettings(body.instructorTopK);

        if (studentTopK === null || instructorTopK === null) {
            return res.status(400).json({
                success: false,
                message: `Top-K values must be integers from ${CourseModel.MIN_RAG_TOP_K} to ${CourseModel.MAX_RAG_TOP_K}`
            });
        }

        if (typeof body.instructorPrompt !== 'string' || !body.instructorPrompt.trim()
            || typeof body.studentPrompt !== 'string' || !body.studentPrompt.trim()) {
            return res.status(400).json({ success: false, message: 'Instructor and student prompts are required' });
        }

        const settings = {
            studentTopK,
            instructorTopK,
            includeInactiveCourses: body.includeInactiveCourses === true,
            showStudentSuperCourse: body.showStudentSuperCourse === true,
            includeNotesInRetrieval: body.includeNotesInRetrieval !== false,
            noteRetrievalRatio: normalizeNoteRatioForSettings(
                body.noteRetrievalRatio,
                prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS.noteRetrievalRatio
            ),
            noteMinScore: normalizeNoteRatioForSettings(
                body.noteMinScore,
                prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS.noteMinScore
            ),
            instructorPrompt: body.instructorPrompt,
            studentPrompt: body.studentPrompt
        };

        await db.collection('settings').updateOne(
            { _id: SUPER_COURSE_SETTINGS_ID },
            {
                $set: {
                    ...settings,
                    updatedAt: new Date(),
                    updatedBy: normalizeEmail(req.user.email)
                },
                $setOnInsert: { createdAt: new Date() }
            },
            { upsert: true }
        );

        res.json({
            success: true,
            message: 'Super Course chat settings saved',
            settings
        });
    } catch (error) {
        console.error('Error saving super course chat settings:', error);
        res.status(500).json({ success: false, message: 'Failed to save super course chat settings' });
    }
});

router.post('/super-course-chat/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const settings = { ...prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS };
        await db.collection('settings').updateOne(
            { _id: SUPER_COURSE_SETTINGS_ID },
            {
                $set: {
                    ...settings,
                    updatedAt: new Date(),
                    updatedBy: normalizeEmail(req.user.email)
                },
                $setOnInsert: { createdAt: new Date() }
            },
            { upsert: true }
        );

        res.json({
            success: true,
            message: 'Super Course chat settings reset to defaults',
            settings,
            defaults: buildSuperCourseChatDefaults()
        });
    } catch (error) {
        console.error('Error resetting super course chat settings:', error);
        res.status(500).json({ success: false, message: 'Failed to reset super course chat settings' });
    }
});


/**
 * GET /api/settings/prompts
 * Get current system prompts (merged with defaults) for a specific course
 */
router.get('/prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const courseId = req.query.courseId;
        
        // If no courseId provided, return defaults (or could return global default if we kept it)
        if (!courseId) {
            return res.json({
                success: true,
                prompts: { ...prompts.DEFAULT_PROMPTS, additiveRetrieval: false },
                isCourseSpecific: false,
                courseId: null
            });
        }

        // Query the course document
        const course = await db.collection('courses').findOne({ courseId });

        // Retrieve prompts from course or use defaults
        const coursePrompts = course ? (course.prompts || {}) : {};
        
        const result = {
            base: coursePrompts.base || prompts.DEFAULT_PROMPTS.base,
            protege: coursePrompts.protege || prompts.DEFAULT_PROMPTS.protege,
            tutor: coursePrompts.tutor || prompts.DEFAULT_PROMPTS.tutor,
            explain: coursePrompts.explain || prompts.DEFAULT_PROMPTS.explain,
            directive: coursePrompts.directive || prompts.DEFAULT_PROMPTS.directive,
            quizHelp: coursePrompts.quizHelp || prompts.DEFAULT_PROMPTS.quizHelp,
            // Course-level additive retrieval setting
            additiveRetrieval: course ? !!course.isAdditiveRetrieval : false,
            // Student idle timeout (seconds), default to 4 minutes (240s)
            studentIdleTimeout: coursePrompts.studentIdleTimeout || 240
        };

        res.json({
            success: true,
            prompts: result,
            isCourseSpecific: true,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error fetching prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch prompts'
        });
    }
});

/**
 * POST /api/settings/prompts
 * Save custom system prompts for a specific course
 */
router.post('/prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const { base, protege, tutor, explain, directive, quizHelp, additiveRetrieval, studentIdleTimeout, courseId } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to save settings' });
        }

        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }

        // Validation - ensure they are strings (prompts) and boolean (additiveRetrieval)
        if (typeof base !== 'string' || typeof protege !== 'string' || typeof tutor !== 'string' || typeof explain !== 'string' || typeof directive !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid prompt format' });
        }

        // Validate timeout if present
        let timeoutVal = 240; // Default
        if (studentIdleTimeout !== undefined) {
             timeoutVal = parseInt(studentIdleTimeout);
             if (isNaN(timeoutVal) || timeoutVal < 30 || timeoutVal > 1200) { // 30s to 20m
                 return res.status(400).json({ success: false, message: 'Invalid idle timeout value' });
             }
        }

        // Update the course document directly
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $set: { 
                    'prompts.base': base, 
                    'prompts.protege': protege, 
                    'prompts.tutor': tutor,
                    'prompts.explain': explain,
                    'prompts.directive': directive,
                    'prompts.quizHelp': quizHelp || prompts.DEFAULT_PROMPTS.quizHelp,
                    'prompts.studentIdleTimeout': timeoutVal,
                    isAdditiveRetrieval: !!additiveRetrieval,
                    updatedAt: new Date()
                } 
            }
        );

        res.json({
            success: true,
            message: 'Course settings saved successfully',
            courseId: courseId
        });
    } catch (error) {
        console.error('Error saving prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save prompts'
        });
    }
});

/**
 * POST /api/settings/prompts/reset
 * Reset system prompts to defaults for a specific course
 */
router.post('/prompts/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const { courseId } = req.body;
        
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to reset settings' });
        }

        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }

        // Unset the prompts field and isAdditiveRetrieval in the course document
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $unset: { prompts: "" },
                $set: { isAdditiveRetrieval: true } // Default to true
            }
        );

        res.json({
            success: true,
            message: 'Course settings reset to user defaults',
            prompts: prompts.DEFAULT_PROMPTS,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error resetting prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset prompts'
        });
    }
});

/**
 * GET /api/settings/global
 * Get global settings (e.g. login restrictions)
 * Requires system admin access
 */
router.get('/global', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        // Get global settings
        const settings = await db.collection('settings').findOne({ _id: 'global' });

        res.json({
            success: true,
            settings: settings || { allowLocalLogin: true } // Default to true
        });

    } catch (error) {
        console.error('Error fetching global settings:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch global settings' });
    }
});

/**
 * POST /api/settings/global
 * Update global settings
 * Requires system admin access
 */
router.post('/global', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { allowLocalLogin } = req.body;

        // Update settings
        await db.collection('settings').updateOne(
            { _id: 'global' },
            { 
                $set: { 
                    allowLocalLogin: !!allowLocalLogin,
                    updatedAt: new Date(),
                    updatedBy: normalizeEmail(req.user.email)
                } 
            },
            { upsert: true }
        );

        res.json({
            success: true,
            message: 'Global settings updated',
            settings: { allowLocalLogin: !!allowLocalLogin }
        });

    } catch (error) {
        console.error('Error updating global settings:', error);
        res.status(500).json({ success: false, error: 'Failed to update global settings' });
    }
});

const ALLOWED_LLM_MODELS = ['gpt-4.1-mini', 'gpt-5-nano', 'gpt-5.4-nano'];
const ALLOWED_REASONING_EFFORTS = ['minimal', 'low', 'medium', 'high'];

function isGpt5Family(model) {
    return typeof model === 'string' && model.startsWith('gpt-5');
}

// Obfuscated index maps for the body-class debug tag.
// Numbers are intentionally meaningless to end users; only the dev team
// knows that e.g. "llm-2 reasoning-1" = gpt-5-nano + minimal.
// Non-reasoning models (gpt-4.1-mini) intentionally omit reasoning-*.
const LLM_TAG_INDEX = {
    'gpt-4.1-mini': 1,
    'gpt-5-nano': 2,
    'gpt-5.4-nano': 3
};
const REASONING_TAG_INDEX = {
    minimal: 1,
    low: 2,
    medium: 3,
    high: 4
};

/**
 * GET /api/settings/llm-tag
 * Public endpoint returning obfuscated indices for the active LLM model
 * and reasoning effort. Used by the frontend to add hidden body classes
 * (llm-N and, when supported, reasoning-N) so the dev team can identify
 * the active config from DevTools without exposing model names to end users.
 */
router.get('/llm-tag', async (req, res) => {
    try {
        const db = req.app.locals.db;
        const envDefault = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
        const fallbackModel = ALLOWED_LLM_MODELS.includes(envDefault) ? envDefault : 'gpt-4.1-mini';

        let model = fallbackModel;
        let reasoningEffort = 'minimal';

        if (db) {
            const settingsDoc = await db.collection('settings').findOne({ _id: 'llm' });
            if (settingsDoc) {
                if (ALLOWED_LLM_MODELS.includes(settingsDoc.model)) model = settingsDoc.model;
                if (ALLOWED_REASONING_EFFORTS.includes(settingsDoc.reasoningEffort)) {
                    reasoningEffort = settingsDoc.reasoningEffort;
                }
            }
        }

        res.json({
            success: true,
            llmIndex: LLM_TAG_INDEX[model] || 0,
            reasoningIndex: isGpt5Family(model) ? (REASONING_TAG_INDEX[reasoningEffort] || 0) : 0
        });
    } catch (error) {
        console.error('Error fetching LLM tag:', error);
        res.status(500).json({ success: false });
    }
});

/**
 * GET /api/settings/llm
 * Get the global LLM model settings (system admins only)
 */
router.get('/llm', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const settingsDoc = await db.collection('settings').findOne({ _id: 'llm' });
        const envDefault = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
        const fallbackModel = ALLOWED_LLM_MODELS.includes(envDefault) ? envDefault : 'gpt-4.1-mini';

        const model = (settingsDoc && ALLOWED_LLM_MODELS.includes(settingsDoc.model))
            ? settingsDoc.model
            : fallbackModel;
        const reasoningEffort = (settingsDoc && ALLOWED_REASONING_EFFORTS.includes(settingsDoc.reasoningEffort))
            ? settingsDoc.reasoningEffort
            : 'minimal';

        res.json({
            success: true,
            settings: {
                model,
                reasoningEffort,
                supportsReasoning: isGpt5Family(model),
                allowedModels: ALLOWED_LLM_MODELS,
                allowedReasoningEfforts: ALLOWED_REASONING_EFFORTS
            }
        });
    } catch (error) {
        console.error('Error fetching LLM settings:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch LLM settings' });
    }
});

/**
 * POST /api/settings/llm
 * Update the global LLM model settings (system admins only)
 */
router.post('/llm', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { model, reasoningEffort } = req.body || {};

        if (!ALLOWED_LLM_MODELS.includes(model)) {
            return res.status(400).json({
                success: false,
                error: `Invalid model. Allowed: ${ALLOWED_LLM_MODELS.join(', ')}`
            });
        }

        const update = {
            model,
            updatedAt: new Date(),
            updatedBy: normalizeEmail(req.user.email)
        };

        if (isGpt5Family(model)) {
            const effort = ALLOWED_REASONING_EFFORTS.includes(reasoningEffort) ? reasoningEffort : 'minimal';
            update.reasoningEffort = effort;
        } else {
            update.reasoningEffort = 'minimal';
        }

        await db.collection('settings').updateOne(
            { _id: 'llm' },
            { $set: update },
            { upsert: true }
        );

        // Invalidate the LLM service cache so the next call picks up the new settings
        const llmService = req.app.locals.llm;
        if (llmService && typeof llmService.invalidateModelSettingsCache === 'function') {
            llmService.invalidateModelSettingsCache();
        }

        res.json({
            success: true,
            message: 'LLM settings updated',
            settings: {
                model: update.model,
                reasoningEffort: update.reasoningEffort,
                supportsReasoning: isGpt5Family(update.model)
            }
        });
    } catch (error) {
        console.error('Error updating LLM settings:', error);
        res.status(500).json({ success: false, error: 'Failed to update LLM settings' });
    }
});

/**
 * GET /api/settings/question-prompts
 * Get question generation prompts for a specific course
 * Requires system admin access
 */
router.get('/question-prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const courseId = req.query.courseId;
        
        // If no courseId provided, return defaults
        if (!courseId) {
            return res.json({
                success: true,
                prompts: prompts.DEFAULT_QUESTION_PROMPTS,
                isCourseSpecific: false,
                courseId: null
            });
        }

        // Query the course document
        const course = await db.collection('courses').findOne({ courseId });

        // Retrieve question prompts from course or use defaults
        const courseQuestionPrompts = course ? (course.questionPrompts || {}) : {};
        
        const result = {
            systemPrompt: courseQuestionPrompts.systemPrompt || prompts.DEFAULT_QUESTION_PROMPTS.systemPrompt,
            trueFalse: courseQuestionPrompts.trueFalse || prompts.DEFAULT_QUESTION_PROMPTS.trueFalse,
            multipleChoice: courseQuestionPrompts.multipleChoice || prompts.DEFAULT_QUESTION_PROMPTS.multipleChoice,
            shortAnswer: courseQuestionPrompts.shortAnswer || prompts.DEFAULT_QUESTION_PROMPTS.shortAnswer
        };

        res.json({
            success: true,
            prompts: result,
            isCourseSpecific: true,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error fetching question prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch question prompts'
        });
    }
});

/**
 * POST /api/settings/question-prompts
 * Save custom question generation prompts for a specific course
 * Requires system admin access
 */
router.post('/question-prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { systemPrompt, trueFalse, multipleChoice, shortAnswer, courseId } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to save question prompts' });
        }

        // Validation - ensure they are all strings
        if (typeof systemPrompt !== 'string' || typeof trueFalse !== 'string' || 
            typeof multipleChoice !== 'string' || typeof shortAnswer !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid prompt format - all prompts must be strings' });
        }

        // Update the course document with question prompts
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $set: { 
                    'questionPrompts.systemPrompt': systemPrompt,
                    'questionPrompts.trueFalse': trueFalse,
                    'questionPrompts.multipleChoice': multipleChoice,
                    'questionPrompts.shortAnswer': shortAnswer,
                    updatedAt: new Date()
                } 
            }
        );

        res.json({
            success: true,
            message: 'Question generation prompts saved successfully',
            courseId: courseId
        });
    } catch (error) {
        console.error('Error saving question prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save question prompts'
        });
    }
});

/**
 * POST /api/settings/question-prompts/reset
 * Reset question generation prompts to defaults for a specific course
 * Requires system admin access
 */
router.post('/question-prompts/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { courseId } = req.body;
        
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to reset question prompts' });
        }

        // Unset the questionPrompts field in the course document
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $unset: { questionPrompts: "" }
            }
        );

        res.json({
            success: true,
            message: 'Question generation prompts reset to defaults',
            prompts: prompts.DEFAULT_QUESTION_PROMPTS,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error resetting question prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset question prompts'
        });
    }
});

/**
 * GET /api/settings/quiz
 * Get quiz practice settings for a course
 */
router.get('/quiz', async (req, res) => {
    try {
        const { courseId } = req.query;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId parameter' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const CourseModel = require('../models/Course');
        const settings = await CourseModel.getQuizSettings(db, courseId);

        res.json({ success: true, settings });
    } catch (error) {
        console.error('Error fetching quiz settings:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch quiz settings' });
    }
});

/**
 * POST /api/settings/quiz
 * Save quiz practice settings for a course
 */
router.post('/quiz', async (req, res) => {
    try {
        const {
            courseId,
            enabled,
            testableUnits,
            allowLectureMaterialAccess,
            allowSourceAttributionDownloads
        } = req.body;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }

        const instructorId = req.user ? req.user.userId : null;
        const CourseModel = require('../models/Course');
        const result = await CourseModel.updateQuizSettings(db, courseId, {
            enabled,
            testableUnits,
            allowLectureMaterialAccess,
            allowSourceAttributionDownloads
        }, instructorId);

        if (result.success) {
            res.json({ success: true, message: 'Quiz settings saved successfully' });
        } else {
            res.status(400).json({ success: false, message: result.error || 'Failed to save quiz settings' });
        }
    } catch (error) {
        console.error('Error saving quiz settings:', error);
        res.status(500).json({ success: false, message: 'Failed to save quiz settings' });
    }
});

/**
 * GET /api/settings/anonymize-students
 * Get the anonymize students setting for the current instructor and course
 */
router.get('/anonymize-students', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        const courseId = req.query.courseId;
        if (!courseId) {
            return res.status(400).json({ success: false, error: 'courseId is required' });
        }
        const db = req.app.locals.db;
        const CourseModel = require('../models/Course');
        const result = await CourseModel.getAnonymizeStudents(db, courseId, req.user.userId);
        res.json({ success: true, enabled: result.enabled || false });
    } catch (error) {
        console.error('Error fetching anonymize students setting:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch setting' });
    }
});

/**
 * POST /api/settings/anonymize-students
 * Update the anonymize students setting for the current instructor and course
 */
router.post('/anonymize-students', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        const { courseId, enabled } = req.body;
        if (!courseId) {
            return res.status(400).json({ success: false, error: 'courseId is required' });
        }
        const db = req.app.locals.db;
        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }
        const CourseModel = require('../models/Course');
        const result = await CourseModel.updateAnonymizeStudents(db, courseId, req.user.userId, !!enabled);
        if (result.success) {
            res.json({ success: true, message: 'Anonymize students setting saved' });
        } else {
            res.status(400).json({ success: false, message: result.error || 'Failed to save setting' });
        }
    } catch (error) {
        console.error('Error saving anonymize students setting:', error);
        res.status(500).json({ success: false, error: 'Failed to save setting' });
    }
});

/**
 * GET /api/settings/mental-health-prompt
 * Get mental health detection prompt for a course (or default)
 */
router.get('/mental-health-prompt', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const courseId = req.query.courseId;

        if (!courseId) {
            return res.json({
                success: true,
                prompt: prompts.DEFAULT_MENTAL_HEALTH_DETECTION_PROMPT,
                isCourseSpecific: false
            });
        }

        const course = await db.collection('courses').findOne({ courseId });
        const prompt = (course && course.mentalHealthDetectionPrompt) || prompts.DEFAULT_MENTAL_HEALTH_DETECTION_PROMPT;

        res.json({
            success: true,
            prompt,
            isCourseSpecific: !!(course && course.mentalHealthDetectionPrompt),
            courseId
        });
    } catch (error) {
        console.error('Error fetching mental health detection prompt:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch mental health detection prompt' });
    }
});

/**
 * POST /api/settings/mental-health-prompt
 * Save custom mental health detection prompt for a course
 */
router.post('/mental-health-prompt', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { prompt, courseId } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }
        if (typeof prompt !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid prompt format' });
        }

        await db.collection('courses').updateOne(
            { courseId },
            { $set: { mentalHealthDetectionPrompt: prompt, updatedAt: new Date() } }
        );

        res.json({ success: true, message: 'Mental health detection prompt saved', courseId });
    } catch (error) {
        console.error('Error saving mental health detection prompt:', error);
        res.status(500).json({ success: false, message: 'Failed to save mental health detection prompt' });
    }
});

/**
 * POST /api/settings/mental-health-prompt/reset
 * Reset mental health detection prompt to default for a course
 */
router.post('/mental-health-prompt/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { courseId } = req.body;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        await db.collection('courses').updateOne(
            { courseId },
            { $unset: { mentalHealthDetectionPrompt: '' } }
        );

        res.json({
            success: true,
            message: 'Mental health detection prompt reset to default',
            prompt: prompts.DEFAULT_MENTAL_HEALTH_DETECTION_PROMPT,
            courseId
        });
    } catch (error) {
        console.error('Error resetting mental health detection prompt:', error);
        res.status(500).json({ success: false, message: 'Failed to reset mental health detection prompt' });
    }
});

module.exports = router;
