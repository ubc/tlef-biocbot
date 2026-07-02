/**
 * In-process route tests for src/routes/student-tracker.js (supertest).
 *
 * No heavy deps: the router reads the User model over the in-memory Mongo double
 * and req.user. Covers the auth gate, per-course topic scoping on GET /, and the
 * reset flow including the revoked-enrollment guard.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/student-tracker');

const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(router, opts);

// A user doc as stored in `users`; getUserById requires isActive: true.
const userDoc = (struggleState) => ({
    userId: 's1', username: 'stu', displayName: 'Stu', role: 'student',
    isActive: true, struggleState,
});

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET / — current struggle state', () => {
    test('401 when unauthenticated', async () => {
        const res = await request(app({ db: memoryDb({}) })).get('/');
        expect(res.status).toBe(401);
    });

    test('404 when the authenticated user has no DB record', async () => {
        const res = await request(app({ db: memoryDb({ users: [] }), user: student })).get('/');
        expect(res.status).toBe(404);
    });

    test('returns the full topic list when no courseId is supplied', async () => {
        const db = memoryDb({ users: [userDoc({ topics: [
            { topic: 'glycolysis', courseId: 'C1' },
            { topic: 'krebs', courseId: 'C2' },
        ] })] });
        const res = await request(app({ db, user: student })).get('/');
        expect(res.status).toBe(200);
        expect(res.body.struggleState.topics.map(t => t.topic)).toEqual(['glycolysis', 'krebs']);
    });

    test('scopes topics to the requested course, keeping course-less legacy topics', async () => {
        const db = memoryDb({ users: [userDoc({ topics: [
            { topic: 'glycolysis', courseId: 'C1' },
            { topic: 'krebs', courseId: 'C2' },
            { topic: 'legacy' }, // no courseId → visible everywhere
        ] })] });
        const res = await request(app({ db, user: student })).get('/?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.struggleState.topics.map(t => t.topic).sort()).toEqual(['glycolysis', 'legacy']);
    });

    test('defaults to an empty topics array when struggleState is absent', async () => {
        const db = memoryDb({ users: [userDoc(undefined)] });
        const res = await request(app({ db, user: student })).get('/');
        expect(res.status).toBe(200);
        expect(res.body.struggleState.topics).toEqual([]);
    });
});

describe('POST /reset', () => {
    test('401 when unauthenticated', async () => {
        const res = await request(app({ db: memoryDb({}) })).post('/reset').send({ topic: 'ALL' });
        expect(res.status).toBe(401);
    });

    test('400 when no topic is provided', async () => {
        const res = await request(app({ db: memoryDb({}), user: student })).post('/reset').send({});
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/topic is required/i);
    });

    test('403 when the student\'s enrollment in the course has been revoked', async () => {
        const db = memoryDb({
            users: [userDoc({ topics: [] })],
            courses: [{ courseId: 'C1', studentEnrollment: { s1: { enrolled: false } } }],
        });
        const res = await request(app({ db, user: student })).post('/reset').send({ topic: 'ALL', courseId: 'C1' });
        expect(res.status).toBe(403);
        expect(res.body.message).toMatch(/revoked/i);
    });

    test('resets a single topic for an enrolled student', async () => {
        const db = memoryDb({
            users: [userDoc({ topics: [{ topic: 'glycolysis' }, { topic: 'krebs' }] })],
            courses: [{ courseId: 'C1', studentEnrollment: { s1: { enrolled: true } } }],
        });
        const res = await request(app({ db, user: student })).post('/reset').send({ topic: 'Glycolysis', courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        // The matching topic (lower-cased) was pulled; the other remains.
        const saved = await db.collection('users').findOne({ userId: 's1' });
        expect(saved.struggleState.topics.map(t => t.topic)).toEqual(['krebs']);
    });

    test('resets ALL topics, clearing the array', async () => {
        const db = memoryDb({
            users: [userDoc({ topics: [{ topic: 'glycolysis' }, { topic: 'krebs' }] })],
        });
        const res = await request(app({ db, user: student })).post('/reset').send({ topic: 'ALL' });
        expect(res.status).toBe(200);
        const saved = await db.collection('users').findOne({ userId: 's1' });
        expect(saved.struggleState.topics).toEqual([]);
    });

    test('500 when the user has no DB record (resetUserStruggleState reports failure)', async () => {
        // resetUserStruggleState returns { success:false } for an unknown user, and
        // the route maps any non-success result to a 500 (no 404 branch here).
        const res = await request(app({ db: memoryDb({ users: [] }), user: student })).post('/reset').send({ topic: 'ALL' });
        expect(res.status).toBe(500);
    });
});

describe('model failure paths (500)', () => {
    const User = require('../../../src/models/User');

    test('GET / 500 when the user lookup throws', async () => {
        const spy = jest.spyOn(User, 'getUserById').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: student })).get('/');
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Internal server error');
        spy.mockRestore();
    });

    test('POST /reset 500 when the reset throws', async () => {
        const spy = jest.spyOn(User, 'resetUserStruggleState').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: student })).post('/reset').send({ topic: 'ALL' });
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Internal server error');
        spy.mockRestore();
    });
});
