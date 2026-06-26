/**
 * In-process route tests for src/routes/settings.js (supertest).
 * Load-safe: the router's requires (prompts, Course, Superchat, systemAdmin,
 * llmKeyStore) have no network/DB side effects at load, so nothing is mocked —
 * the real systemAdmin service + Course model run over the in-memory Mongo.
 * Covers can-delete-all, the system-admins endpoints, and ai-settings get/put/reset.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const settingsRouter = require('../../../src/routes/settings');

const admin = { userId: 'a1', role: 'instructor', email: 'admin@x.com', permissions: { systemAdmin: true } };
const instructor = { userId: 'i1', role: 'instructor' };
const student = { userId: 's1', role: 'student' };

const app = (opts) => makeRouteApp(settingsRouter, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /can-delete-all', () => {
    test('401 without a user', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/can-delete-all')).status).toBe(401);
    });

    test('true for a system admin, false for a plain instructor', async () => {
        const a = await request(app({ db: memoryDb({}), user: admin })).get('/can-delete-all');
        expect(a.body).toMatchObject({ success: true, canDeleteAll: true, isSystemAdmin: true });

        const i = await request(app({ db: memoryDb({}), user: instructor })).get('/can-delete-all');
        expect(i.body).toMatchObject({ success: true, canDeleteAll: false });
    });
});

describe('GET /system-admins', () => {
    test('403 for a non-admin, 200 with the admin list for an admin', async () => {
        const db = memoryDb({ users: [
            { userId: 'a1', email: 'admin@x.com', role: 'instructor', isActive: true, permissions: { systemAdmin: true } },
        ] });
        expect((await request(app({ db, user: instructor })).get('/system-admins')).status).toBe(403);

        const res = await request(app({ db, user: admin })).get('/system-admins');
        expect(res.status).toBe(200);
        expect(res.body.admins.map(a => a.email)).toContain('admin@x.com');
    });

    test('503 when the db is unavailable', async () => {
        expect((await request(app({ db: null, user: admin })).get('/system-admins')).status).toBe(503);
    });
});

describe('POST /system-admins (grant) and /revoke', () => {
    test('grants admin to an existing user', async () => {
        const db = memoryDb({ users: [{ _id: 'u1', userId: 'u1', email: 'new@x.com', permissions: {} }] });
        const res = await request(app({ db, user: admin })).post('/system-admins').send({ email: '  NEW@x.com ' });
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, email: 'new@x.com' });
        expect((await db.collection('users').findOne({ userId: 'u1' })).permissions.systemAdmin).toBe(true);
    });

    test('400 when granting to an unknown email', async () => {
        const db = memoryDb({ users: [] });
        const res = await request(app({ db, user: admin })).post('/system-admins').send({ email: 'nobody@x.com' });
        expect(res.status).toBe(400);
        expect(res.body.success).toBe(false);
    });

    test('403 for a non-admin attempting to grant', async () => {
        const res = await request(app({ db: memoryDb({ users: [] }), user: instructor })).post('/system-admins').send({ email: 'x@x.com' });
        expect(res.status).toBe(403);
    });

    test('revoke refuses to remove the last remaining admin (400)', async () => {
        const db = memoryDb({ users: [
            { _id: 'a1', userId: 'a1', email: 'admin@x.com', isActive: true, permissions: { systemAdmin: true } },
        ] });
        const res = await request(app({ db, user: admin })).post('/system-admins/revoke').send({ email: 'admin@x.com' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/last remaining system admin/i);
    });

    test('revoke succeeds when another admin remains', async () => {
        const db = memoryDb({ users: [
            { _id: 'a1', userId: 'a1', email: 'admin@x.com', isActive: true, permissions: { systemAdmin: true } },
            { _id: 'a2', userId: 'a2', email: 'other@x.com', isActive: true, permissions: { systemAdmin: true } },
        ] });
        const res = await request(app({ db, user: admin })).post('/system-admins/revoke').send({ email: 'other@x.com' });
        expect(res.status).toBe(200);
        expect((await db.collection('users').findOne({ userId: 'a2' })).permissions.systemAdmin).toBeUndefined();
    });
});

describe('GET /ai-settings', () => {
    test('400 when courseId is missing', async () => {
        expect((await request(app({ db: memoryDb({}), user: admin })).get('/ai-settings')).status).toBe(400);
    });

    test('a plain instructor is denied a course they do not own (403)', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'someone-else' }] });
        const res = await request(app({ db, user: instructor })).get('/ai-settings?courseId=C1');
        expect(res.status).toBe(403);
    });

    test('returns resolved settings + available buckets for the course owner', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1', ragSettings: { student: { topK: 8 } }, superchatIds: ['sc1'] }],
            superchats: [{ superchatId: 'sc1', name: 'Bucket A', yearLevel: 2 }],
        });
        const res = await request(app({ db, user: instructor })).get('/ai-settings?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.settings.ragSettings).toEqual({ student: { topK: 8 } });
        expect(res.body.settings.superchatIds).toEqual(['sc1']);
        expect(res.body.availableSuperchats).toEqual([{ superchatId: 'sc1', name: 'Bucket A', yearLevel: 2 }]);
    });
});

describe('PUT /ai-settings', () => {
    test('400 for an out-of-range studentTopK', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: admin })).put('/ai-settings').send({ courseId: 'C1', studentTopK: 99 });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/Top-K must be an integer/);
    });

    test('404 (admin) when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: admin }))
            .put('/ai-settings').send({ courseId: 'NOPE', studentTopK: 5 });
        expect(res.status).toBe(404);
    });

    test('persists normalized superchatIds + topK and echoes the saved settings', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: admin }))
            .put('/ai-settings').send({ courseId: 'C1', superchatIds: ['sc1', ' sc1 ', 'sc2'], studentTopK: 7 });
        expect(res.status).toBe(200);
        expect(res.body.settings).toMatchObject({ superchatIds: ['sc1', 'sc2'], ragSettings: { student: { topK: 7 } } });

        const stored = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(stored.superchatIds).toEqual(['sc1', 'sc2']);
        expect(stored.ragSettings.student.topK).toBe(7);
    });
});

describe('POST /ai-settings/reset', () => {
    test('resets superchatIds to [] and topK to the default', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', superchatIds: ['sc1'], ragSettings: { student: { topK: 9 } } }] });
        const res = await request(app({ db, user: admin })).post('/ai-settings/reset').send({ courseId: 'C1' });
        expect(res.status).toBe(200);

        const stored = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(stored.superchatIds).toEqual([]);
        expect(stored.ragSettings.student.topK).toBe(3); // DEFAULT_STUDENT_RAG_TOP_K
    });
});
