const express = require('express');
const router = express.Router();
const User = require('../models/User');

/**
 * GET /api/student/struggle
 * Retrieve the current struggle state for the authenticated student.
 */
router.get('/', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const db = req.app.locals.db;
        const user = await User.getUserById(db, req.user.userId);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const rawState = user.struggleState || { topics: [] };
        const requestedCourseId = req.query.courseId || null;

        // Scope topics to the requested course when one is supplied. Topics
        // saved without a courseId predate the per-course tracking and remain
        // visible everywhere for backwards compatibility.
        let topics = Array.isArray(rawState.topics) ? rawState.topics : [];
        if (requestedCourseId) {
            topics = topics.filter(t => !t.courseId || t.courseId === requestedCourseId);
        }

        res.json({
            success: true,
            struggleState: { ...rawState, topics }
        });

    } catch (error) {
        console.error('❌ Error fetching struggle state:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * POST /api/student/struggle/reset
 * Reset struggle state for a specific topic or all topics.
 * Body: { topic: 'Microbiology' | 'ALL' }
 */
router.post('/reset', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, message: 'Unauthorized' });
        }

        const { topic, courseId: requestCourseId } = req.body;
        if (!topic) {
            return res.status(400).json({ success: false, message: 'Topic is required' });
        }

        const db = req.app.locals.db;

        // Use courseId from request body (sent by frontend) or fallback to user preferences
        const courseId = requestCourseId || req.user.preferences?.courseId || null;

        // If we have a specific course, refuse the reset when the student's
        // access to that course has been revoked. Otherwise a revoked student
        // could still clear their struggle history for a course they're locked
        // out of, which the dashboard UI no longer lets them do.
        if (courseId) {
            const courseDoc = await db.collection('courses').findOne(
                { courseId },
                { projection: { studentEnrollment: 1 } }
            );
            const enrollment = courseDoc && courseDoc.studentEnrollment
                ? courseDoc.studentEnrollment[req.user.userId]
                : null;
            if (enrollment && enrollment.enrolled === false) {
                return res.status(403).json({
                    success: false,
                    message: 'Your access to this course has been revoked.'
                });
            }
        }

        console.log(`🔄 [TRACKER_API] Resetting struggle for user ${req.user.userId}, topic: ${topic}, courseId: ${courseId}`);

        const result = await User.resetUserStruggleState(db, req.user.userId, topic, courseId);

        if (result.success) {
            res.json({ success: true, message: 'Struggle state reset successfully' });
        } else {
            res.status(500).json({ success: false, message: 'Failed to reset state' });
        }

    } catch (error) {
        console.error('❌ Error resetting struggle state:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

module.exports = router;
