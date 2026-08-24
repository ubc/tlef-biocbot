const express = require('express');
const { hasSystemAdminAccess } = require('../services/authorization');
const pseudonyms = require('../services/studentPseudonyms');

const router = express.Router();

function requireSystemAdmin(req, res) {
    if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return false;
    }
    if (!hasSystemAdminAccess(req.user)) {
        res.status(403).json({ success: false, message: 'Only system admins can manage student pseudonyms' });
        return false;
    }
    return true;
}

function sendError(res, error) {
    const status = error.statusCode || (error.code === 11000 ? 409 : 500);
    if (status >= 500) console.error('Student pseudonym route error:', error);
    res.status(status).json({
        success: false,
        message: error.message || 'Student pseudonym operation failed',
        errors: error.validationErrors || undefined
    });
}

router.use((req, res, next) => {
    if (!requireSystemAdmin(req, res)) return;
    next();
});

router.get('/scopes', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        const [courses, superchats] = await Promise.all([
            db.collection('courses').find({ status: { $ne: 'deleted' } })
                .project({ courseId: 1, courseName: 1, status: 1 })
                .sort({ courseName: 1 })
                .toArray(),
            db.collection('superchats').find({ isDeleted: { $ne: true } })
                .project({ superchatId: 1, name: 1 })
                .sort({ name: 1 })
                .toArray()
        ]);
        res.json({ success: true, data: { courses, superchats } });
    } catch (error) {
        sendError(res, error);
    }
});

router.get('/:scopeType/:scopeId', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        const data = await pseudonyms.getMappingRows(db, req.params.scopeType, req.params.scopeId);
        res.json({ success: true, data });
    } catch (error) {
        sendError(res, error);
    }
});

router.post('/:scopeType/:scopeId/generate', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        const result = await pseudonyms.generateMissingMappings(
            db,
            req.params.scopeType,
            req.params.scopeId,
            req.user.userId
        );
        res.json({ success: true, data: result });
    } catch (error) {
        sendError(res, error);
    }
});

router.post('/course/:scopeId/import', express.text({ type: ['text/csv', 'text/plain'], limit: '2mb' }), async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        const result = await pseudonyms.importCourseCsv(db, req.params.scopeId, req.body, req.user.userId);
        res.json({ success: true, data: result });
    } catch (error) {
        sendError(res, error);
    }
});

router.get('/course/:scopeId/template.csv', (req, res) => {
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="BiocBot_${req.params.scopeId}_Pseudonym_Template.csv"`);
    res.send('Student,Student_ID\n0042,user_1770000000000_example\n');
});

router.get('/:scopeType/:scopeId/mapping.csv', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        const data = await pseudonyms.getMappingRows(db, req.params.scopeType, req.params.scopeId);
        const safeScopeId = req.params.scopeId.replace(/[^A-Za-z0-9_-]/g, '_');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="BiocBot_${safeScopeId}_Pseudonym_Mapping.csv"`);
        res.send(pseudonyms.mappingRowsToCsv(data.mappings));
    } catch (error) {
        sendError(res, error);
    }
});

module.exports = router;
