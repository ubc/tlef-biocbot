/**
 * Struggle Activity Routes
 *
 * API endpoints for fetching struggle activity history from MongoDB.
 * Used by instructor dashboard for polling and displaying student struggle activity.
 *
 * IMPORTANT: Specific prefix routes (/student, /persistence, /weekly) must be
 * defined BEFORE the generic /:courseId catch-all route.
 */

const express = require('express');
const router = express.Router();
const StruggleActivity = require('../models/StruggleActivity');
const PersistenceTopic = require('../models/PersistenceTopic');

/**
 * GET /api/struggle-activity/student/:userId
 * Fetch struggle activity history for a specific student
 *
 * Query params:
 * - limit: Maximum number of entries to return (default: 50)
 */
router.get('/student/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 50;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        if (req.user?.role === 'student' && req.user.userId !== userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only view your own struggle activity'
            });
        }

        const db = req.app.locals.db;

        const activities = await StruggleActivity.getActivityByStudent(db, userId, {
            limit
        });

        res.json({
            success: true,
            data: activities,
            count: activities.length
        });

    } catch (error) {
        console.error('Error fetching student struggle activity:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch student struggle activity',
            error: error.message
        });
    }
});

/**
 * GET /api/struggle-activity/persistence/:courseId
 * Fetch persistence struggle topics (cumulative unique students) for a specific course
 */
router.get('/persistence/:courseId', async (req, res) => {
    try {
        const { courseId } = req.params;

        if (!courseId) {
            return res.status(400).json({
                success: false,
                message: 'Course ID is required'
            });
        }

        const db = req.app.locals.db;

        const topics = await PersistenceTopic.getPersistenceTopics(db, courseId);

        res.json({
            success: true,
            data: topics,
            count: topics.length
        });

    } catch (error) {
        console.error('Error fetching persistence topics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch persistence topics',
            error: error.message
        });
    }
});

/**
 * GET /api/struggle-activity/weekly/:courseId
 * Fetch weekly active struggle topics aggregated by ISO week
 *
 * Query params:
 * - weeks: Number of weeks to look back (default: 8)
 */
router.get('/weekly/:courseId', async (req, res) => {
    try {
        const { courseId } = req.params;
        const weeks = parseInt(req.query.weeks) || 8;

        if (!courseId) {
            return res.status(400).json({
                success: false,
                message: 'Course ID is required'
            });
        }

        const db = req.app.locals.db;

        const weeklyData = await StruggleActivity.getWeeklyActiveTopics(db, courseId, {
            weeks
        });

        res.json({
            success: true,
            data: weeklyData,
            count: weeklyData.length
        });

    } catch (error) {
        console.error('Error fetching weekly struggle topics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch weekly struggle topics',
            error: error.message
        });
    }
});

/**
 * GET /api/struggle-activity/:courseId
 * Fetch struggle activity history for a specific course
 *
 * NOTE: This catch-all route MUST be last to avoid shadowing specific routes above.
 *
 * Query params:
 * - limit: Maximum number of entries to return (default: 100)
 * - state: Filter by state ('Active' or 'Inactive')
 */
router.get('/:courseId', async (req, res) => {
    try {
        const { courseId } = req.params;
        const limit = parseInt(req.query.limit) || 100;
        const state = req.query.state; // Optional filter

        if (!courseId) {
            return res.status(400).json({
                success: false,
                message: 'Course ID is required'
            });
        }

        const db = req.app.locals.db;

        const activities = await StruggleActivity.getActivityByCourse(db, courseId, {
            limit,
            state
        });

        res.json({
            success: true,
            data: activities,
            count: activities.length
        });

    } catch (error) {
        console.error('Error fetching struggle activity:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch struggle activity',
            error: error.message
        });
    }
});

module.exports = router;
