/**
 * Settings Routes
 * Handles settings-related API endpoints
 */

const express = require('express');
const router = express.Router();
const prompts = require('../services/prompts');
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
