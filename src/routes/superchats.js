/**
 * Superchats Routes
 *
 * CRUD for superchat buckets (instructor/admin-curated groupings of courses that
 * students chat across). Membership lives course-side (course.superchatIds); these
 * endpoints manage the bucket identity + chat settings only.
 *
 * Buckets are shared/global, and any instructor (or admin) may create, edit, and
 * delete them — instructors curate their own Super Course groupings rather than
 * depending on a system admin.
 *
 * - GET    /api/superchats        list summaries (instructor or admin)
 * - GET    /api/superchats/:id    full bucket + resolved settings (instructor or admin)
 * - POST   /api/superchats        create (instructor or admin)
 * - PUT    /api/superchats/:id    update (instructor or admin)
 * - DELETE /api/superchats/:id    soft-delete + detach from courses (instructor or admin)
 */

const express = require('express');
const router = express.Router();
const SuperchatModel = require('../models/Superchat');
const { resolveSuperCourseChatSettings } = require('../services/superCourseService');
const { hasSystemAdminAccess } = require('../services/authorization');

function requireInstructorOrAdmin(req, res) {
    if (!req.user) {
        res.status(401).json({ success: false, message: 'Not authenticated' });
        return false;
    }
    if (req.user.role !== 'instructor' && !hasSystemAdminAccess(req.user)) {
        res.status(403).json({ success: false, message: 'Access denied' });
        return false;
    }
    return true;
}

// Count of courses currently in each bucket — handy for the admin list ("3 courses").
async function getCourseCounts(db) {
    const rows = await db.collection('courses').aggregate([
        { $match: { status: { $ne: 'deleted' }, superchatIds: { $exists: true, $ne: [] } } },
        { $unwind: '$superchatIds' },
        { $group: { _id: '$superchatIds', count: { $sum: 1 } } }
    ]).toArray();
    const map = {};
    for (const row of rows) map[row._id] = row.count;
    return map;
}

function summarize(doc, courseCount = 0) {
    return {
        superchatId: doc.superchatId,
        name: doc.name,
        description: doc.description || '',
        yearLevel: doc.yearLevel ?? null,
        showToStudents: doc.showToStudents === true,
        courseCount
    };
}

// GET /api/superchats — list summaries (instructor or admin)
router.get('/', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const [docs, counts] = await Promise.all([
            SuperchatModel.listSuperchats(db),
            getCourseCounts(db)
        ]);

        res.json({
            success: true,
            superchats: docs.map(doc => summarize(doc, counts[doc.superchatId] || 0))
        });
    } catch (error) {
        console.error('Error listing superchats:', error);
        res.status(500).json({ success: false, message: 'Failed to list superchats' });
    }
});

// GET /api/superchats/:id — full bucket + resolved chat settings (admin editor)
router.get('/:id', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const doc = await SuperchatModel.getSuperchatById(db, req.params.id);
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });

        res.json({
            success: true,
            superchat: {
                superchatId: doc.superchatId,
                name: doc.name,
                description: doc.description || '',
                yearLevel: doc.yearLevel ?? null,
                showToStudents: doc.showToStudents === true,
                settings: resolveSuperCourseChatSettings(doc)
            }
        });
    } catch (error) {
        console.error('Error fetching superchat:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch superchat' });
    }
});

// POST /api/superchats — create (admin)
router.post('/', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const body = req.body || {};
        if (typeof body.name !== 'string' || !body.name.trim()) {
            return res.status(400).json({ success: false, message: 'name is required' });
        }

        const doc = await SuperchatModel.createSuperchat(db, body, req.user.userId);
        res.status(201).json({ success: true, superchat: summarize(doc, 0) });
    } catch (error) {
        console.error('Error creating superchat:', error);
        res.status(500).json({ success: false, message: 'Failed to create superchat' });
    }
});

// PUT /api/superchats/:id — update (admin)
router.put('/:id', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const doc = await SuperchatModel.updateSuperchat(db, req.params.id, req.body || {});
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });

        res.json({
            success: true,
            superchat: {
                superchatId: doc.superchatId,
                name: doc.name,
                description: doc.description || '',
                yearLevel: doc.yearLevel ?? null,
                showToStudents: doc.showToStudents === true,
                settings: resolveSuperCourseChatSettings(doc)
            }
        });
    } catch (error) {
        console.error('Error updating superchat:', error);
        res.status(500).json({ success: false, message: 'Failed to update superchat' });
    }
});

// DELETE /api/superchats/:id — soft-delete + detach from courses (admin)
router.delete('/:id', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const result = await SuperchatModel.softDeleteSuperchat(db, req.params.id);
        if (!result.success) return res.status(404).json({ success: false, message: 'Superchat not found' });

        res.json({ success: true, coursesUpdated: result.coursesUpdated });
    } catch (error) {
        console.error('Error deleting superchat:', error);
        res.status(500).json({ success: false, message: 'Failed to delete superchat' });
    }
});

module.exports = router;
