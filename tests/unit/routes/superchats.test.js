/**
 * In-process route tests for src/routes/superchats.js (supertest).
 *
 * Real: the Superchat model over the in-memory Mongo double.
 * Mocked: superCourseService (pulls Qdrant) and llmKeyStore (network/crypto).
 * These mocks must be declared before the router is require()d.
 */
jest.mock('../../../src/services/superCourseService', () => ({
    resolveSuperCourseChatSettings: jest.fn(() => ({ topK: 5 })),
}));
jest.mock('../../../src/services/llmKeyStore', () => ({
    buildKeySubdocument: jest.fn(() => ({ enc: 'stub-key' })),
    decryptApiKey: jest.fn(() => 'sk-decrypted'),
    publicKeySummary: jest.fn((key) => (key ? { status: 'valid' } : { status: 'none' })),
    validateApiKey: jest.fn(async () => ({ ok: true })),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const superchatsRouter = require('../../../src/routes/superchats');
const llmKeyStore = require('../../../src/services/llmKeyStore');

const instructor = { userId: 'i1', role: 'instructor' };
const student = { userId: 's1', role: 'student' };
const admin = { userId: 'a1', role: 'student', permissions: { systemAdmin: true } };
const downloadAdmin = { userId: 'a2', role: 'instructor', permissions: { systemAdmin: true } };

beforeAll(() => { jest.spyOn(console, 'error').mockImplementation(() => {}); });
afterAll(() => jest.restoreAllMocks());
beforeEach(() => llmKeyStore.validateApiKey.mockReset().mockResolvedValue({ ok: true }));

describe('superchats — auth gate', () => {
    test('401 when unauthenticated', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}) })).get('/');
        expect(res.status).toBe(401);
        expect(res.body).toMatchObject({ success: false, message: 'Not authenticated' });
    });

    test('403 for a student', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}), user: student })).get('/');
        expect(res.status).toBe(403);
        expect(res.body).toMatchObject({ message: 'Access denied' });
    });

    test('a system admin (non-instructor) is allowed through', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}), user: admin })).get('/');
        expect(res.status).toBe(200);
    });

    test('503 when the db is unavailable', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: null, user: instructor })).get('/');
        expect(res.status).toBe(503);
    });
});

describe('GET /', () => {
    test('lists bucket summaries with a per-bucket course count', async () => {
        const db = memoryDb({
            superchats: [{ superchatId: 'sc1', name: 'Bucket A', showToStudents: true, llmApiKey: { enc: 'k' } }],
            courses: [
                { courseId: 'c1', superchatIds: ['sc1'], status: 'active' },
                { courseId: 'c2', superchatIds: ['sc1'], status: 'active' },
                { courseId: 'c3', superchatIds: ['sc1'], status: 'deleted' }, // excluded by $match
            ],
        });
        const res = await request(makeRouteApp(superchatsRouter, { db, user: instructor })).get('/');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.superchats).toHaveLength(1);
        expect(res.body.superchats[0]).toMatchObject({
            superchatId: 'sc1', name: 'Bucket A', courseCount: 2, showToStudents: true, aiAvailable: true,
        });
    });
});

describe('GET /defaults', () => {
    test('returns the resolved default chat settings', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}), user: instructor })).get('/defaults');
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, settings: { topK: 5 } });
    });
});

describe('GET /:id', () => {
    test('404 for an unknown bucket', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [] }), user: instructor })).get('/nope');
        expect(res.status).toBe(404);
    });

    test('returns the bucket with resolved settings', async () => {
        const db = memoryDb({ superchats: [{ superchatId: 'sc1', name: 'A', llmApiKey: { enc: 'k' } }] });
        const res = await request(makeRouteApp(superchatsRouter, { db, user: instructor })).get('/sc1');
        expect(res.status).toBe(200);
        expect(res.body.superchat).toMatchObject({ superchatId: 'sc1', name: 'A', settings: { topK: 5 } });
    });
});

describe('POST /', () => {
    test('400 when name is missing', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}), user: instructor })).post('/').send({});
        expect(res.status).toBe(400);
        expect(res.body.message).toBe('name is required');
    });

    test('400 LLM_KEY_INVALID when the key fails validation', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'invalid', message: 'bad key' });
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}), user: instructor }))
            .post('/').send({ name: 'New', apiKey: 'sk-bad' });
        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ code: 'LLM_KEY_INVALID' });
    });

    test('400 LLM_KEY_QUOTA when the key is quota-exhausted', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'quota_exhausted' });
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({}), user: instructor }))
            .post('/').send({ name: 'New', apiKey: 'sk' });
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });

    test('201 creates and persists a bucket on a valid key', async () => {
        const db = memoryDb({});
        const res = await request(makeRouteApp(superchatsRouter, { db, user: instructor }))
            .post('/').send({ name: 'New Bucket', apiKey: 'sk-good' });
        expect(res.status).toBe(201);
        expect(res.body.superchat).toMatchObject({ name: 'New Bucket' });
        expect(await db.collection('superchats').findOne({ name: 'New Bucket' })).toBeTruthy();
    });
});

describe('PUT /:id', () => {
    test('404 for an unknown bucket', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [] }), user: instructor }))
            .put('/nope').send({ name: 'x' });
        expect(res.status).toBe(404);
    });

    test('updates an existing bucket', async () => {
        const db = memoryDb({ superchats: [{ superchatId: 'sc1', name: 'Old' }] });
        const res = await request(makeRouteApp(superchatsRouter, { db, user: instructor }))
            .put('/sc1').send({ name: 'Renamed' });
        expect(res.status).toBe(200);
        expect(res.body.superchat.name).toBe('Renamed');
    });
});

describe('DELETE /:id', () => {
    test('404 for an unknown bucket', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [] }), user: instructor })).delete('/nope');
        expect(res.status).toBe(404);
    });

    test('soft-deletes an existing bucket', async () => {
        const db = memoryDb({ superchats: [{ superchatId: 'sc1', name: 'A' }] });
        const res = await request(makeRouteApp(superchatsRouter, { db, user: instructor })).delete('/sc1');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
    });
});

describe('bucket LLM key management — mocked validation', () => {
    const keyed = { superchatId: 'sc1', name: 'Bucket', llmApiKey: { ciphertext: 'encrypted', status: 'unknown' } };

    test('PUT validates bucket and API key', async () => {
        expect((await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [] }), user: instructor })).put('/missing/llm-key').send({ apiKey: 'sk' })).status).toBe(404);
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'quota_exhausted', message: 'spent' });
        const res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [keyed] }), user: instructor })).put('/sc1/llm-key').send({ apiKey: 'spent' });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });

    test('PUT saves the key and evicts the bucket cache', async () => {
        const db = memoryDb({ superchats: [keyed] });
        const registry = { evictSuperchat: jest.fn() };
        const res = await request(makeRouteApp(superchatsRouter, { db, user: instructor, locals: { llmRegistry: registry } })).put('/sc1/llm-key').send({ apiKey: 'sk-new' });
        expect(res.status).toBe(200);
        expect((await db.collection('superchats').findOne({ superchatId: 'sc1' })).llmApiKey).toEqual({ enc: 'stub-key' });
        expect(registry.evictSuperchat).toHaveBeenCalledWith('sc1');
    });

    test('POST key test handles missing, valid, and invalid saved keys', async () => {
        let res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [{ superchatId: 'sc1' }] }), user: instructor })).post('/sc1/llm-key/test');
        expect(res.body.code).toBe('LLM_KEY_MISSING');
        res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [keyed] }), user: instructor })).post('/sc1/llm-key/test');
        expect(res).toMatchObject({ status: 200, body: expect.objectContaining({ success: true, aiAvailable: true }) });
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'invalid', message: 'bad' });
        res = await request(makeRouteApp(superchatsRouter, { db: memoryDb({ superchats: [keyed] }), user: instructor })).post('/sc1/llm-key/test');
        expect(res.body).toMatchObject({ success: false, code: 'LLM_KEY_INVALID', aiAvailable: false });
    });
});

describe('system-admin Super Chat session downloads', () => {
    const sessionsDb = () => memoryDb({
        superchats: [{ superchatId: 'sc1', name: 'Bucket' }],
        student_super_course_chat_sessions: [
            {
                sessionId: 'sess1', superchatId: 'sc1', studentId: 's1', studentName: { displayName: 'Alice' },
                title: 'ATP chat', savedAt: '2026-01-02T00:00:00Z', messageCount: 2, isDeleted: false,
                chatData: { messages: [
                    { type: 'user', timestamp: '2026-01-02T00:00:00Z' },
                    { type: 'bot', timestamp: '2026-01-02T00:01:05Z' },
                ] },
            },
            { sessionId: 'deleted', superchatId: 'sc1', studentId: 's1', savedAt: '2026-01-03T00:00:00Z', isDeleted: true },
        ],
    });

    test('requires a system admin who is also an instructor', async () => {
        expect((await request(makeRouteApp(superchatsRouter, { db: sessionsDb(), user: instructor })).get('/sc1/chat-sessions')).status).toBe(403);
        expect((await request(makeRouteApp(superchatsRouter, { db: sessionsDb(), user: admin })).get('/sc1/chat-sessions')).status).toBe(403);
    });

    test('groups sessions by student and computes timestamp duration', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: sessionsDb(), user: downloadAdmin })).get('/sc1/chat-sessions');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ totalStudents: 1, totalSessions: 1 });
        expect(res.body.data.students[0]).toMatchObject({ studentId: 's1', studentName: 'Alice', totalSessions: 1 });
        expect(res.body.data.students[0].sessions[0].duration).toBe('1m 5s');
    });

    test('bulk export can filter one student', async () => {
        const res = await request(makeRouteApp(superchatsRouter, { db: sessionsDb(), user: downloadAdmin })).get('/sc1/chat-sessions/export?studentId=s1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ superchatId: 'sc1', totalStudents: 1, totalSessions: 1 });
        expect(res.body.data.students[0].sessions[0].chatData.messages).toHaveLength(2);
    });

    test('single session returns transcript or 404', async () => {
        let res = await request(makeRouteApp(superchatsRouter, { db: sessionsDb(), user: downloadAdmin })).get('/sc1/chat-sessions/s1/sess1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ sessionId: 'sess1', superchatName: 'Bucket', duration: '1m 5s' });
        res = await request(makeRouteApp(superchatsRouter, { db: sessionsDb(), user: downloadAdmin })).get('/sc1/chat-sessions/s1/missing');
        expect(res.status).toBe(404);
    });
});
