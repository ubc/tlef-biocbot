/**
 * In-process route tests for src/routes/instructorChat.js (supertest).
 *
 * Real: the instructor_chat_sessions CRUD over the in-memory Mongo double + req.user.
 * Mocked: superCourseService (pulls Qdrant at load) so we control the resolved
 * superchat / retrieval pool. The LLM answer path (`POST /`) is only exercised up to
 * its validation + key-availability gate; the full retrieval+sendMessage flow is
 * LLM/vector-heavy and left to e2e.
 */
jest.mock('../../../src/services/superCourseService', () => ({
    getSuperchat: jest.fn(),
    getInstructorSuperCourseChat: jest.fn(),
    getSuperCourseRetrievalPool: jest.fn(),
    searchSuperCourse: jest.fn(),
    buildSuperCourseContext: jest.fn(),
    buildSuperCoursePoolSummary: jest.fn(),
    buildSuperCourseCitations: jest.fn(),
    buildSuperCourseSourceAttribution: jest.fn(),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const superCourseService = require('../../../src/services/superCourseService');
const router = require('../../../src/routes/instructorChat');

const instructor = { userId: 'i1', role: 'instructor', displayName: 'Dr I' };
const app = (opts) => makeRouteApp(router, opts);

const SESSIONS = 'instructor_chat_sessions';
const availableSuperchat = {
    superchatId: null, name: 'Global Instructor Chat', aiAvailable: true, showToStudents: true,
    settings: { includeInactiveCourses: false, instructorTopK: 5 },
};

beforeAll(() => { jest.spyOn(console, 'error').mockImplementation(() => {}); });
afterAll(() => jest.restoreAllMocks());

describe('GET /pool', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: instructor })).get('/pool');
        expect(res.status).toBe(503);
    });

    test('403 with a structured key error when no usable key is available', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce({ aiAvailable: false, llmKey: { status: 'missing' } });
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/pool');
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_MISSING');
    });

    test('200 maps the resolved retrieval pool', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce(availableSuperchat);
        superCourseService.getSuperCourseRetrievalPool.mockResolvedValueOnce([
            { courseId: 'C1', courseName: 'Biochem', status: 'active' },
            { courseId: 'C2', courseCode: 'BIOC200', status: null },
        ]);
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/pool');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ superchatName: 'Global Instructor Chat', topK: 5, showStudentSuperCourse: true });
        expect(res.body.courses).toEqual([
            { courseId: 'C1', courseName: 'Biochem', status: 'active' },
            { courseId: 'C2', courseName: 'BIOC200', status: null }, // falls back to courseCode
        ]);
    });

    test('a requested superchatId resolves that specific bucket', async () => {
        superCourseService.getSuperchat.mockResolvedValueOnce(availableSuperchat);
        superCourseService.getSuperCourseRetrievalPool.mockResolvedValueOnce([]);
        await request(app({ db: memoryDb({}), user: instructor })).get('/pool?superchatId=sc1');
        expect(superCourseService.getSuperchat).toHaveBeenCalledWith(expect.anything(), 'sc1');
    });
});

describe('POST /save', () => {
    test('400 when sessionId or chatData is missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/save').send({ sessionId: 'sess1' });
        expect(res.status).toBe(400);
    });

    test('401 when there is no authenticated instructor', async () => {
        const res = await request(app({ db: memoryDb({}) })).post('/save').send({ sessionId: 'sess1', chatData: {} });
        expect(res.status).toBe(401);
    });

    test('200 upserts the session document', async () => {
        const db = memoryDb({});
        const res = await request(app({ db, user: instructor }))
            .post('/save').send({ sessionId: 'sess1', title: 'My chat', chatData: { messages: [] } });
        expect(res.status).toBe(200);
        const saved = await db.collection(SESSIONS).findOne({ sessionId: 'sess1', instructorId: 'i1' });
        expect(saved).toMatchObject({ title: 'My chat', instructorId: 'i1', isDeleted: false });
    });
});

describe('GET /sessions', () => {
    test('401 without a user', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/sessions')).status).toBe(401);
    });

    test('lists the instructor\'s non-deleted sessions only', async () => {
        const db = memoryDb({ [SESSIONS]: [
            { sessionId: 's1', instructorId: 'i1', title: 'Keep', isDeleted: false, updatedAt: new Date('2026-06-02') },
            { sessionId: 's2', instructorId: 'i1', title: 'Gone', isDeleted: true, updatedAt: new Date('2026-06-03') },
            { sessionId: 's3', instructorId: 'other', title: 'NotMine', isDeleted: false },
        ] });
        const res = await request(app({ db, user: instructor })).get('/sessions');
        expect(res.status).toBe(200);
        expect(res.body.data.sessions.map(s => s.sessionId)).toEqual(['s1']);
    });
});

describe('GET /sessions/:sessionId', () => {
    test('404 when the session is missing or not the instructor\'s', async () => {
        const db = memoryDb({ [SESSIONS]: [{ sessionId: 's1', instructorId: 'other', isDeleted: false }] });
        const res = await request(app({ db, user: instructor })).get('/sessions/s1');
        expect(res.status).toBe(404);
    });

    test('200 returns the full session', async () => {
        const db = memoryDb({ [SESSIONS]: [{ sessionId: 's1', instructorId: 'i1', title: 'Mine', isDeleted: false }] });
        const res = await request(app({ db, user: instructor })).get('/sessions/s1');
        expect(res.status).toBe(200);
        expect(res.body.session).toMatchObject({ sessionId: 's1', title: 'Mine' });
    });
});

describe('DELETE /sessions/:sessionId', () => {
    test('soft-deletes the instructor\'s session', async () => {
        const db = memoryDb({ [SESSIONS]: [{ sessionId: 's1', instructorId: 'i1', isDeleted: false }] });
        const res = await request(app({ db, user: instructor })).delete('/sessions/s1');
        expect(res.status).toBe(200);
        expect((await db.collection(SESSIONS).findOne({ sessionId: 's1' })).isDeleted).toBe(true);
    });
});

describe('POST / — chat (validation + key gate only)', () => {
    test('503 when the db is unavailable', async () => {
        expect((await request(app({ db: null, user: instructor })).post('/').send({ message: 'hi' })).status).toBe(503);
    });

    test('400 when the message is empty', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ message: '   ' });
        expect(res.status).toBe(400);
    });

    test('403 when no usable key is available for the resolved superchat', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce({ aiAvailable: false, llmKey: { status: 'invalid' } });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ message: 'Explain ATP' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_INVALID');
    });
});
