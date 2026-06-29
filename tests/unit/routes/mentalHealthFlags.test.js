/**
 * In-process route tests for src/routes/mentalHealthFlags.js (supertest).
 *
 * No heavy deps: the router reads the MentalHealthFlag model over the in-memory
 * Mongo double and the pure `authorization` service for the admin check. Covers
 * anonymization for non-admins, the admin-only status transitions, and the db guard.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/mentalHealthFlags');

const instructor = { userId: 'i1', role: 'instructor' };
const admin = { userId: 'a1', role: 'instructor', permissions: { systemAdmin: true } };
const app = (opts) => makeRouteApp(router, opts);

const flag = (over = {}) => ({
    flagId: 'mhf_1', studentId: 's1', studentName: 'Jane Student', courseId: 'C1',
    unitName: 'Unit 1', message: 'I feel hopeless', concernLevel: 'high concern',
    status: 'pending', createdAt: new Date('2026-06-20T10:00:00Z'), ...over,
});

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /course/:courseId', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: instructor })).get('/course/C1');
        expect(res.status).toBe(503);
    });

    test('non-admin gets anonymized flags (no studentId, generic name) and isAdmin:false', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag()] });
        const res = await request(app({ db, user: instructor })).get('/course/C1');
        expect(res.status).toBe(200);
        expect(res.body.isAdmin).toBe(false);
        expect(res.body.flags[0].studentName).toBe('Anonymous Student');
        expect(res.body.flags[0].studentId).toBeUndefined();
        expect(res.body.stats).toMatchObject({ total: 1, pending: 1 });
    });

    test('admin sees real student identity and isAdmin:true', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag()] });
        const res = await request(app({ db, user: admin })).get('/course/C1');
        expect(res.status).toBe(200);
        expect(res.body.isAdmin).toBe(true);
        expect(res.body.flags[0]).toMatchObject({ studentId: 's1', studentName: 'Jane Student' });
    });

    test('status query param filters the returned flags', async () => {
        const db = memoryDb({ mentalHealthFlags: [
            flag({ flagId: 'a', status: 'pending' }),
            flag({ flagId: 'b', status: 'escalated' }),
        ] });
        const res = await request(app({ db, user: admin })).get('/course/C1?status=escalated');
        expect(res.status).toBe(200);
        expect(res.body.flags.map(f => f.flagId)).toEqual(['b']);
    });
});

describe('PUT /:flagId/escalate', () => {
    test('escalates a flag and records the escalating instructor', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag()] });
        const res = await request(app({ db, user: instructor })).put('/mhf_1/escalate');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        const saved = await db.collection('mentalHealthFlags').findOne({ flagId: 'mhf_1' });
        expect(saved).toMatchObject({ status: 'escalated', escalatedBy: 'i1' });
    });

    test('reports failure (success:false) when the flag does not exist', async () => {
        const db = memoryDb({ mentalHealthFlags: [] });
        const res = await request(app({ db, user: instructor })).put('/missing/escalate');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(false);
    });
});

describe('PUT /:flagId/dismiss', () => {
    test('marks a flag dismissed', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag()] });
        const res = await request(app({ db, user: instructor })).put('/mhf_1/dismiss');
        expect(res.status).toBe(200);
        expect((await db.collection('mentalHealthFlags').findOne({ flagId: 'mhf_1' })).status).toBe('dismissed');
    });
});

describe('PUT /:flagId/resolve — admin only', () => {
    test('403 for a non-admin instructor', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag({ status: 'escalated' })] });
        const res = await request(app({ db, user: instructor })).put('/mhf_1/resolve');
        expect(res.status).toBe(403);
        // Unchanged.
        expect((await db.collection('mentalHealthFlags').findOne({ flagId: 'mhf_1' })).status).toBe('escalated');
    });

    test('admin resolves and is recorded as resolvedBy', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag({ status: 'escalated' })] });
        const res = await request(app({ db, user: admin })).put('/mhf_1/resolve');
        expect(res.status).toBe(200);
        const saved = await db.collection('mentalHealthFlags').findOne({ flagId: 'mhf_1' });
        expect(saved).toMatchObject({ status: 'resolved', resolvedBy: 'a1' });
    });
});

describe('PUT /:flagId/disregard — admin only', () => {
    test('403 for a non-admin instructor', async () => {
        const res = await request(app({ db: memoryDb({ mentalHealthFlags: [flag()] }), user: instructor })).put('/mhf_1/disregard');
        expect(res.status).toBe(403);
    });

    test('admin disregards and is recorded as resolvedBy', async () => {
        const db = memoryDb({ mentalHealthFlags: [flag({ status: 'escalated' })] });
        const res = await request(app({ db, user: admin })).put('/mhf_1/disregard');
        expect(res.status).toBe(200);
        expect((await db.collection('mentalHealthFlags').findOne({ flagId: 'mhf_1' })).resolvedBy).toBe('a1');
    });
});
