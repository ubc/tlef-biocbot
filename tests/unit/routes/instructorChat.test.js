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

const failingDb = (error = new Error('db failed')) => ({
    collection: () => new Proxy({}, {
        get: () => () => { throw error; },
    }),
});

const fullSettings = {
    instructorTopK: 3,
    includeInactiveCourses: true,
    includeNotesInRetrieval: true,
    noteRetrievalRatio: 0.25,
    noteMinScore: 0.7,
    instructorPrompt: 'Base instructor prompt',
    instructorLevelModifiers: {
        overview: '  Keep it brief.  ',
        standard: '',
    },
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

    test('403 when no superchat record exists', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce(null);
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

    test('uses fallback course names and defaults a missing status to null', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce(availableSuperchat);
        superCourseService.getSuperCourseRetrievalPool.mockResolvedValueOnce([{ courseId: 'C3' }]);
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/pool');
        expect(res.body.courses).toEqual([{ courseId: 'C3', courseName: 'C3', status: null }]);
    });

    test('500 when resolving the pool fails', async () => {
        superCourseService.getInstructorSuperCourseChat.mockRejectedValueOnce(new Error('boom'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/pool');
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to load Super Course source pool');
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

    test('applies identity and session defaults', async () => {
        const db = memoryDb({});
        const user = { userId: 'i2', username: 'teacher' };
        await request(app({ db, user })).post('/save').send({ sessionId: 'sess2', chatData: {} });
        const saved = await db.collection(SESSIONS).findOne({ sessionId: 'sess2' });
        expect(saved).toMatchObject({ instructorName: 'teacher', messageCount: 0, duration: '0s' });
        expect(saved.title).toMatch(/^Super Course Chat /);
        expect(saved.savedAt).toEqual(expect.any(String));
    });

    test.each([
        [{ userId: 'i3', email: 'teacher@example.test' }, 'teacher@example.test'],
        [{ userId: 'i4' }, 'i4'],
    ])('falls back through remaining instructor names', async (user, expectedName) => {
        const db = memoryDb({});
        await request(app({ db, user })).post('/save').send({ sessionId: user.userId, chatData: {} });
        expect((await db.collection(SESSIONS).findOne({ sessionId: user.userId })).instructorName).toBe(expectedName);
    });

    test('503 without a db and 500 when persistence fails', async () => {
        expect((await request(app({ db: null, user: instructor })).post('/save').send({ sessionId: 's', chatData: {} })).status).toBe(503);
        const res = await request(app({ db: failingDb(), user: instructor })).post('/save').send({ sessionId: 's', chatData: {} });
        expect(res.status).toBe(500);
    });
});

describe('GET /sessions', () => {
    test('503 without a db', async () => {
        expect((await request(app({ db: null, user: instructor })).get('/sessions')).status).toBe(503);
    });
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

    test('maps missing optional session values to defaults', async () => {
        const db = memoryDb({ [SESSIONS]: [{ sessionId: 's1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).get('/sessions');
        expect(res.body.data.sessions[0]).toMatchObject({ messageCount: 0, duration: '0s', chatData: {} });
    });

    test('500 when listing fails', async () => {
        expect((await request(app({ db: failingDb(), user: instructor })).get('/sessions')).status).toBe(500);
    });
});

describe('GET /sessions/:sessionId', () => {
    test('503 without a db', async () => {
        expect((await request(app({ db: null, user: instructor })).get('/sessions/s1')).status).toBe(503);
    });
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

    test('500 when loading fails', async () => {
        expect((await request(app({ db: failingDb(), user: instructor })).get('/sessions/s1')).status).toBe(500);
    });
});

describe('DELETE /sessions/:sessionId', () => {
    test('503 without a db', async () => {
        expect((await request(app({ db: null, user: instructor })).delete('/sessions/s1')).status).toBe(503);
    });
    test('soft-deletes the instructor\'s session', async () => {
        const db = memoryDb({ [SESSIONS]: [{ sessionId: 's1', instructorId: 'i1', isDeleted: false }] });
        const res = await request(app({ db, user: instructor })).delete('/sessions/s1');
        expect(res.status).toBe(200);
        expect((await db.collection(SESSIONS).findOne({ sessionId: 's1' })).isDeleted).toBe(true);
    });

    test('500 when deletion fails', async () => {
        expect((await request(app({ db: failingDb(), user: instructor })).delete('/sessions/s1')).status).toBe(500);
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

    test('400 when the request has no body', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).post('/')).status).toBe(400);
    });

    test('403 when no usable key is available for the resolved superchat', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce({ aiAvailable: false, llmKey: { status: 'invalid' } });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ message: 'Explain ATP' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_INVALID');
    });

    test('runs retrieval, builds the prompt, and returns attribution metadata', async () => {
        const superchat = { superchatId: null, name: 'Global', aiAvailable: true, settings: fullSettings };
        const pool = [{ courseId: 'C1' }, { courseId: 'C2' }];
        const results = [{ id: 'chunk-1' }];
        const sourceAttribution = { poolCourses: [{ courseId: 'C1' }] };
        const sendMessage = jest.fn().mockResolvedValue({ content: 'ATP answer', model: 'mock-model', usage: { total: 9 } });
        const registry = { forSuperCourseChat: jest.fn().mockResolvedValue({ llm: { sendMessage }, qdrant: { fake: true } }) };
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce(superchat);
        superCourseService.searchSuperCourse.mockResolvedValueOnce({ pool, results });
        superCourseService.buildSuperCourseContext.mockReturnValueOnce('retrieved context');
        superCourseService.buildSuperCoursePoolSummary.mockReturnValueOnce('C1 and C2');
        superCourseService.buildSuperCourseCitations.mockReturnValueOnce([{ id: 'citation' }]);
        superCourseService.buildSuperCourseSourceAttribution.mockReturnValueOnce(sourceAttribution);

        const history = Array.from({ length: 10 }, (_, i) => ({ role: i % 2 ? 'assistant' : 'user', content: `m${i}` }));
        history.unshift(null, { role: 'system', content: 'ignore me' }, { role: 'user', content: 4 });
        const res = await request(app({ db: memoryDb({}), user: instructor, locals: { llmRegistry: registry } }))
            .post('/').send({ message: 'Explain ATP', level: 'overview', conversationMessages: history });

        expect(res.status).toBe(200);
        expect(superCourseService.searchSuperCourse).toHaveBeenCalledWith(expect.anything(), 'Explain ATP', 3, {
            superchatId: null, includeInactiveCourses: true, includeNotes: true,
            noteRatio: 0.25, noteMinScore: 0.7, qdrant: { fake: true },
        });
        const [prompt, options] = sendMessage.mock.calls[0];
        expect(prompt).toContain('Super Course context:\nretrieved context');
        expect(prompt).not.toContain('m0');
        expect(prompt).toContain('Instructor: m2');
        expect(options).toEqual({ temperature: 0.4, maxTokens: 32768, systemPrompt: 'Base instructor prompt\n\nKeep it brief.' });
        expect(res.body).toMatchObject({
            success: true, message: 'ATP answer', model: 'mock-model', citations: [{ id: 'citation' }],
            retrieval: { resultCount: 1, poolCourseIds: ['C1', 'C2'], poolCourses: [{ courseId: 'C1' }] },
        });
    });

    test('uses a selected bucket, query id, empty-context text, and response defaults', async () => {
        const superchat = { superchatId: 'sc1', name: 'Bucket', aiAvailable: true, settings: fullSettings };
        const sendMessage = jest.fn().mockResolvedValue(null);
        const registry = { forSuperchat: jest.fn().mockResolvedValue({ llm: { sendMessage }, qdrant: {} }) };
        superCourseService.getSuperchat.mockResolvedValueOnce(superchat);
        superCourseService.searchSuperCourse.mockResolvedValueOnce({ pool: [], results: [] });
        superCourseService.buildSuperCourseContext.mockReturnValueOnce('');
        superCourseService.buildSuperCoursePoolSummary.mockReturnValueOnce('none');
        superCourseService.buildSuperCourseCitations.mockReturnValueOnce([]);
        superCourseService.buildSuperCourseSourceAttribution.mockReturnValueOnce({ poolCourses: [] });
        const res = await request(app({ db: memoryDb({}), user: instructor, locals: { llmRegistry: registry } }))
            .post('/?superchatId=sc1').send({ message: 'Question', level: 'unknown', conversationMessages: 'invalid' });
        expect(res.status).toBe(200);
        expect(registry.forSuperchat).toHaveBeenCalledWith(expect.anything(), 'sc1');
        expect(sendMessage.mock.calls[0][0]).toContain('No uploaded course chunks were retrieved');
        expect(sendMessage.mock.calls[0][1].systemPrompt).toBe('Base instructor prompt');
        expect(res.body.message).toBe('');
    });

    test('stops after the middleware response when the registry is unavailable', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce({ ...availableSuperchat, settings: fullSettings });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ message: 'Question' });
        expect(res.status).toBe(503);
        expect(superCourseService.searchSuperCourse).not.toHaveBeenCalled();
    });

    test('maps LLM key errors and otherwise returns the generic 500', async () => {
        const superchat = { ...availableSuperchat, settings: fullSettings };
        superCourseService.getInstructorSuperCourseChat
            .mockResolvedValueOnce(superchat)
            .mockResolvedValueOnce(superchat);
        const keyRegistry = { forSuperCourseChat: jest.fn().mockRejectedValue({ code: 'LLM_KEY_INVALID', status: 'invalid' }) };
        const keyRes = await request(app({ db: memoryDb({}), user: instructor, locals: { llmRegistry: keyRegistry } }))
            .post('/').send({ message: 'Question' });
        expect(keyRes.status).toBe(403);
        expect(keyRes.body.code).toBe('LLM_KEY_INVALID');

        const badRegistry = { forSuperCourseChat: jest.fn().mockRejectedValue(new Error('provider failed')) };
        const res = await request(app({ db: memoryDb({}), user: instructor, locals: { llmRegistry: badRegistry } }))
            .post('/').send({ message: 'Question' });
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to process instructor chat message');
    });

    test('maps a key error thrown after AI resolution', async () => {
        superCourseService.getInstructorSuperCourseChat.mockResolvedValueOnce({ ...availableSuperchat, settings: fullSettings });
        superCourseService.searchSuperCourse.mockRejectedValueOnce({ code: 'LLM_KEY_MISSING', status: 'missing' });
        const registry = { forSuperCourseChat: jest.fn().mockResolvedValue({ llm: {}, qdrant: {} }) };
        const res = await request(app({ db: memoryDb({}), user: instructor, locals: { llmRegistry: registry } }))
            .post('/').send({ message: 'Question' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_MISSING');
    });
});
