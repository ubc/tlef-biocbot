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
 *
 * Chat session downloads (system admin only — matches /api/students download gating,
 * since bucket transcripts span students from multiple courses):
 * - GET /api/superchats/:id/chat-sessions                        students grouped with session metadata
 * - GET /api/superchats/:id/chat-sessions/export[?studentId=]    bulk export with full chatData
 * - GET /api/superchats/:id/chat-sessions/:studentId/:sessionId  single session with full chatData
 */

const express = require('express');
const router = express.Router();
const SuperchatModel = require('../models/Superchat');
const { resolveSuperCourseChatSettings } = require('../services/superCourseService');
const { hasSystemAdminAccess } = require('../services/authorization');
const {
    buildKeySubdocument,
    decryptApiKey,
    publicKeySummary,
    validateApiKey
} = require('../services/llmKeyStore');

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

// Same gate as the per-course chat downloads in routes/students.js.
function requireDownloadAdmin(req, res) {
    if (!req.user) {
        res.status(401).json({ success: false, message: 'Authentication required' });
        return false;
    }
    if (req.user.role !== 'instructor' || !hasSystemAdminAccess(req.user)) {
        res.status(403).json({ success: false, message: 'Only system admins can access student chat download data' });
        return false;
    }
    return true;
}

const SESSIONS_COLLECTION = 'student_super_course_chat_sessions';
const notDeletedFilter = { $or: [{ isDeleted: { $exists: false } }, { isDeleted: false }] };

// First student message to last bot reply, from actual message timestamps
// (stored durations are client-reported and unreliable).
function calculateSessionDuration(session) {
    const messages = (session && session.chatData && session.chatData.messages) || [];
    const first = messages.find(msg => msg.type === 'user');
    const isSyntheticBotMessage = (msg) => {
        if (!msg || msg.type !== 'bot') return false;
        if (msg.sourceAttribution?.source === 'System') return true;
        const content = typeof msg.content === 'string' ? msg.content : '';
        return content.includes('Welcome to BiocBot!') &&
            content.includes('I can see you have access to published units');
    };
    const lastBot = messages.slice().reverse().find(
        msg => msg.type === 'bot' && !isSyntheticBotMessage(msg)
    );
    const last = lastBot || messages.slice().reverse().find(msg => !isSyntheticBotMessage(msg));
    if (!first || !first.timestamp || !last || !last.timestamp) return '0s';

    const diffMs = new Date(last.timestamp) - new Date(first.timestamp);
    if (!Number.isFinite(diffMs) || diffMs < 0) return '0s';

    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diffMs % (1000 * 60)) / 1000);
    if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

function normalizeStudentName(raw) {
    if (typeof raw === 'string' && raw.trim()) return raw;
    if (raw && typeof raw === 'object') {
        return raw.displayName || raw.name || raw.studentName || 'Unknown Student';
    }
    return 'Unknown Student';
}

// Group a flat session list by student, newest activity first.
function groupSessionsByStudent(sessions, mapSession) {
    const studentsMap = new Map();
    for (const session of sessions) {
        if (!studentsMap.has(session.studentId)) {
            studentsMap.set(session.studentId, {
                studentId: session.studentId,
                studentName: normalizeStudentName(session.studentName),
                totalSessions: 0,
                lastActivity: null,
                sessions: []
            });
        }
        const student = studentsMap.get(session.studentId);
        student.totalSessions++;
        student.sessions.push(mapSession(session));
        if (!student.lastActivity || new Date(session.savedAt) > new Date(student.lastActivity)) {
            student.lastActivity = session.savedAt;
        }
    }
    return Array.from(studentsMap.values()).sort(
        (a, b) => new Date(b.lastActivity) - new Date(a.lastActivity)
    );
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
        courseCount,
        llmKey: publicKeySummary(doc.llmApiKey),
        aiAvailable: publicKeySummary(doc.llmApiKey).status === 'valid'
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

// GET /api/superchats/defaults — default chat settings for a bucket. Used by the
// settings page's per-bucket "reset to defaults" (instructor or admin); must be
// registered before /:id so "defaults" is not treated as a bucket id.
router.get('/defaults', (req, res) => {
    if (!requireInstructorOrAdmin(req, res)) return;
    res.json({ success: true, settings: resolveSuperCourseChatSettings({}) });
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
                llmKey: publicKeySummary(doc.llmApiKey),
                aiAvailable: publicKeySummary(doc.llmApiKey).status === 'valid',
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

        const validation = await validateApiKey(body.apiKey);
        if (!validation.ok) {
            return res.status(400).json({
                success: false,
                code: validation.status === 'quota_exhausted' ? 'LLM_KEY_QUOTA' : 'LLM_KEY_INVALID',
                message: validation.message || 'A valid OpenAI API key is required to create a bucket.',
                detail: validation.detail
            });
        }

        const llmApiKey = buildKeySubdocument(body.apiKey, req.user.userId);
        const doc = await SuperchatModel.createSuperchat(db, { ...body, llmApiKey }, req.user.userId);
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
                llmKey: publicKeySummary(doc.llmApiKey),
                aiAvailable: publicKeySummary(doc.llmApiKey).status === 'valid',
                settings: resolveSuperCourseChatSettings(doc)
            }
        });
    } catch (error) {
        console.error('Error updating superchat:', error);
        res.status(500).json({ success: false, message: 'Failed to update superchat' });
    }
});

router.put('/:id/llm-key', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const doc = await SuperchatModel.getSuperchatById(db, req.params.id);
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });

        const validation = await validateApiKey(req.body && req.body.apiKey);
        if (!validation.ok) {
            return res.status(400).json({
                success: false,
                code: validation.status === 'quota_exhausted' ? 'LLM_KEY_QUOTA' : 'LLM_KEY_INVALID',
                message: validation.message || 'API key validation failed',
                detail: validation.detail
            });
        }

        const llmApiKey = buildKeySubdocument(req.body.apiKey, req.user.userId);
        await db.collection('superchats').updateOne(
            { superchatId: req.params.id, isDeleted: { $ne: true } },
            { $set: { llmApiKey, updatedAt: new Date() } }
        );

        if (req.app.locals.llmRegistry) {
            req.app.locals.llmRegistry.evictSuperchat(req.params.id);
        }

        res.json({
            success: true,
            message: 'Bucket API key saved',
            llmKey: publicKeySummary(llmApiKey),
            aiAvailable: true
        });
    } catch (error) {
        console.error('Error saving superchat API key:', error);
        res.status(500).json({ success: false, message: 'Failed to save bucket API key' });
    }
});

router.post('/:id/llm-key/test', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireInstructorOrAdmin(req, res)) return;

        const doc = await SuperchatModel.getSuperchatById(db, req.params.id);
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });
        if (!doc.llmApiKey || !doc.llmApiKey.ciphertext) {
            return res.status(400).json({
                success: false,
                code: 'LLM_KEY_MISSING',
                message: 'No API key is saved for this bucket.'
            });
        }

        const apiKey = decryptApiKey(doc.llmApiKey.ciphertext);
        const validation = await validateApiKey(apiKey);
        const now = new Date();
        const status = validation.ok ? 'valid' : validation.status;
        const set = {
            'llmApiKey.status': status,
            'llmApiKey.updatedAt': now
        };
        if (validation.ok) {
            set['llmApiKey.validatedAt'] = now;
        }

        await db.collection('superchats').updateOne(
            { superchatId: req.params.id, isDeleted: { $ne: true } },
            { $set: set }
        );

        if (req.app.locals.llmRegistry) {
            req.app.locals.llmRegistry.evictSuperchat(req.params.id);
        }

        res.status(validation.ok ? 200 : 400).json({
            success: validation.ok,
            code: validation.ok ? undefined : (status === 'quota_exhausted' ? 'LLM_KEY_QUOTA' : 'LLM_KEY_INVALID'),
            message: validation.ok ? 'Bucket API key is valid' : validation.message,
            llmKey: {
                ...publicKeySummary(doc.llmApiKey),
                status,
                validatedAt: validation.ok ? now : doc.llmApiKey.validatedAt,
                updatedAt: now
            },
            aiAvailable: validation.ok
        });
    } catch (error) {
        console.error('Error testing superchat API key:', error);
        res.status(500).json({ success: false, message: 'Failed to test bucket API key' });
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

// GET /api/superchats/:id/chat-sessions — students with saved sessions in this bucket (admin)
router.get('/:id/chat-sessions', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireDownloadAdmin(req, res)) return;

        const doc = await SuperchatModel.getSuperchatById(db, req.params.id);
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });

        const sessions = await db.collection(SESSIONS_COLLECTION)
            .find({ superchatId: doc.superchatId, ...notDeletedFilter })
            .sort({ savedAt: -1 })
            .toArray();

        const students = groupSessionsByStudent(sessions, session => ({
            sessionId: session.sessionId,
            studentId: session.studentId,
            title: session.title || 'Super Course Chat',
            savedAt: session.savedAt,
            messageCount: session.messageCount || 0,
            duration: calculateSessionDuration(session)
        }));

        res.json({
            success: true,
            data: {
                superchatId: doc.superchatId,
                superchatName: doc.name,
                students,
                totalStudents: students.length,
                totalSessions: sessions.length
            }
        });
    } catch (error) {
        console.error('Error fetching superchat chat sessions:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch superchat chat sessions' });
    }
});

// GET /api/superchats/:id/chat-sessions/export — full transcripts for the whole bucket,
// or one student via ?studentId= (admin). Single round-trip so the client doesn't need
// an N+1 fetch loop across a bucket spanning several courses.
router.get('/:id/chat-sessions/export', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireDownloadAdmin(req, res)) return;

        const doc = await SuperchatModel.getSuperchatById(db, req.params.id);
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });

        const query = { superchatId: doc.superchatId, ...notDeletedFilter };
        if (req.query.studentId) query.studentId = req.query.studentId;

        const sessions = await db.collection(SESSIONS_COLLECTION)
            .find(query, { projection: { _id: 0 } })
            .sort({ savedAt: -1 })
            .toArray();

        const students = groupSessionsByStudent(sessions, session => ({
            ...session,
            duration: calculateSessionDuration(session)
        }));

        res.json({
            success: true,
            data: {
                superchatId: doc.superchatId,
                superchatName: doc.name,
                exportDate: new Date().toISOString(),
                students,
                totalStudents: students.length,
                totalSessions: sessions.length
            }
        });
    } catch (error) {
        console.error('Error exporting superchat chat sessions:', error);
        res.status(500).json({ success: false, message: 'Failed to export superchat chat sessions' });
    }
});

// GET /api/superchats/:id/chat-sessions/:studentId/:sessionId — single full session (admin)
router.get('/:id/chat-sessions/:studentId/:sessionId', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireDownloadAdmin(req, res)) return;

        const doc = await SuperchatModel.getSuperchatById(db, req.params.id);
        if (!doc) return res.status(404).json({ success: false, message: 'Superchat not found' });

        const session = await db.collection(SESSIONS_COLLECTION).findOne(
            {
                superchatId: doc.superchatId,
                studentId: req.params.studentId,
                sessionId: req.params.sessionId,
                ...notDeletedFilter
            },
            { projection: { _id: 0 } }
        );
        if (!session) return res.status(404).json({ success: false, message: 'Chat session not found' });

        res.json({
            success: true,
            data: {
                ...session,
                superchatName: doc.name,
                duration: calculateSessionDuration(session)
            }
        });
    } catch (error) {
        console.error('Error fetching superchat chat session:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch superchat chat session' });
    }
});

module.exports = router;
