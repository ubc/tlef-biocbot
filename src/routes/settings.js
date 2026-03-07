/**
 * Settings Routes
 * Handles settings-related API endpoints
 */

const express = require('express');
const router = express.Router();
const configService = require('../services/config');
const prompts = require('../services/prompts');

/**
 * GET /api/settings/can-delete-all
 * Check if the current user is allowed to see the delete all button
 * Returns true if the user's email is in the CAN_SEE_DELETE_ALL_BUTTON env variable
 */
router.get('/can-delete-all', async (req, res) => {
    try {
        // Check if user is authenticated
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Not authenticated',
                canDeleteAll: false
            });
        }

        // Get user's email
        const userEmail = req.user.email;
        if (!userEmail) {
            return res.json({
                success: true,
                canDeleteAll: false
            });
        }

        // Get allowed emails from config
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        
        // Check if user's email is in the allowed list
        const canDeleteAll = allowedEmails.includes(userEmail);

        res.json({
            success: true,
            canDeleteAll: canDeleteAll
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
 * Requires can-delete-all permission to view
 */
router.get('/global', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check authentication
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }

        // Check permission
        const userEmail = req.user.email;
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        const hasPermission = userEmail && allowedEmails.includes(userEmail);

        if (!hasPermission) {
            return res.status(403).json({ success: false, error: 'Access denied' });
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
 * Requires can-delete-all permission
 */
router.post('/global', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check authentication
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }

        // Check permission
        const userEmail = req.user.email;
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        const hasPermission = userEmail && allowedEmails.includes(userEmail);

        if (!hasPermission) {
            return res.status(403).json({ success: false, error: 'Access denied' });
        }

        const { allowLocalLogin } = req.body;

        // Update settings
        await db.collection('settings').updateOne(
            { _id: 'global' },
            { 
                $set: { 
                    allowLocalLogin: !!allowLocalLogin,
                    updatedAt: new Date(),
                    updatedBy: userEmail
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
 * Requires CAN_SEE_DELETE_ALL_BUTTON permission
 */
router.get('/question-prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check authentication
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }

        // Check permission - only privileged users can access question prompts
        const userEmail = req.user.email;
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        const hasPermission = userEmail && allowedEmails.includes(userEmail);

        if (!hasPermission) {
            return res.status(403).json({ success: false, error: 'Access denied' });
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
 * Requires CAN_SEE_DELETE_ALL_BUTTON permission
 */
router.post('/question-prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check authentication
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }

        // Check permission - only privileged users can modify question prompts
        const userEmail = req.user.email;
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        const hasPermission = userEmail && allowedEmails.includes(userEmail);

        if (!hasPermission) {
            return res.status(403).json({ success: false, error: 'Access denied' });
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
 * Requires CAN_SEE_DELETE_ALL_BUTTON permission
 */
router.post('/question-prompts/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check authentication
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }

        // Check permission
        const userEmail = req.user.email;
        const allowedEmails = configService.getAllowedDeleteButtonEmails();
        const hasPermission = userEmail && allowedEmails.includes(userEmail);

        if (!hasPermission) {
            return res.status(403).json({ success: false, error: 'Access denied' });
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

module.exports = router;
