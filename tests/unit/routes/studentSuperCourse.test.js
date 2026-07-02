jest.mock('../../../src/services/superCourseService', () => ({
    getSuperchat: jest.fn(),
    listSuperchats: jest.fn(),
    getStudentAccessibleSuperchatIds: jest.fn(),
    getSuperCourseRetrievalPool: jest.fn(),
    getSuperCourseApprovedTopics: jest.fn(),
    searchSuperCourse: jest.fn(),
    buildSuperCourseContext: jest.fn(),
    buildSuperCoursePoolSummary: jest.fn(),
    buildSuperCourseCitations: jest.fn(),
    buildSuperCourseSourceAttribution: jest.fn(),
}));
jest.mock('../../../src/services/tracker', () => jest.fn().mockImplementation(() => ({
    analyzeMessageAcrossCourses: jest.fn(async () => ({ isStruggling: false })),
})));
jest.mock('../../../src/models/User', () => ({ updateUserStruggleState: jest.fn() }));
jest.mock('../../../src/models/StruggleActivity', () => ({ createActivityEntry: jest.fn() }));
jest.mock('../../../src/models/Course', () => ({
    normalizeYearLevel: jest.fn(value => Number.isInteger(value) ? value : null),
    parseYearLevelFromName: jest.fn(name => name && name.includes('300') ? 3 : null),
}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveSuperchatAi: jest.fn(),
    sendLlmKeyError: jest.fn(() => false),
}));
jest.mock('../../../src/services/llmKeyStore', () => ({
    structuredKeyError: jest.fn(status => ({ success: false, code: `LLM_KEY_${String(status).toUpperCase()}` })),
}));

const services = require('../../../src/services/superCourseService');
const { resolveSuperchatAi } = require('../../../src/routes/llmKeyMiddleware');
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/studentSuperCourse');

const student = { userId: 's1', role: 'student', displayName: 'Student One' };
const app = options => makeRouteApp(router, options);
const superchat = {
    superchatId: 'sc1', name: 'Biochemistry', showToStudents: true, aiAvailable: true,
    settings: {
        includeInactiveCourses: false, studentTopK: 4, studentPrompt: 'Tutor safely.',
        studentLevelModifiers: { intro: 'Use simple language.', undergraduate: '', graduate: 'Use advanced detail.' },
    },
};

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});

beforeEach(() => {
    services.getSuperchat.mockReset().mockResolvedValue(superchat);
    services.getStudentAccessibleSuperchatIds.mockReset().mockResolvedValue(new Set(['sc1']));
    services.listSuperchats.mockReset().mockResolvedValue([superchat]);
    services.getSuperCourseRetrievalPool.mockReset().mockResolvedValue([]);
    services.getSuperCourseApprovedTopics.mockReset().mockResolvedValue([]);
    services.searchSuperCourse.mockReset().mockResolvedValue({ pool: [], results: [] });
    services.buildSuperCourseContext.mockReset().mockReturnValue('context');
    services.buildSuperCoursePoolSummary.mockReset().mockReturnValue('pool summary');
    services.buildSuperCourseCitations.mockReset().mockReturnValue([]);
    services.buildSuperCourseSourceAttribution.mockReset().mockReturnValue({ source: 'GPT' });
    resolveSuperchatAi.mockReset();
});

afterAll(() => jest.restoreAllMocks());

describe('student Super Course discovery', () => {
    test('status handles DB, anonymous, inaccessible, and enabled states', async () => {
        expect((await request(app({ db: null, user: student })).get('/status')).status).toBe(503);
        expect((await request(app({ db: memoryDb({}) })).get('/status')).body.enabled).toBe(false);
        services.getStudentAccessibleSuperchatIds.mockResolvedValueOnce(new Set());
        expect((await request(app({ db: memoryDb({}), user: student })).get('/status')).body.enabled).toBe(false);
        expect((await request(app({ db: memoryDb({}), user: student })).get('/status')).body.enabled).toBe(true);
    });

    test('list requires authentication and sorts own year first', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/list')).status).toBe(401);
        const db = memoryDb({ courses: [{ courseId: 'C300', courseName: 'BIOC 300', studentEnrollment: { s1: { enrolled: true } } }] });
        services.getStudentAccessibleSuperchatIds.mockResolvedValueOnce(new Set(['sc1', 'sc2', 'sc3']));
        services.listSuperchats.mockResolvedValueOnce([
            { ...superchat, superchatId: 'sc2', name: 'Year Four', yearLevel: 4 },
            { ...superchat, superchatId: 'sc1', name: 'Year Three', yearLevel: 3 },
            { ...superchat, superchatId: 'sc3', name: 'Unlevelled', yearLevel: null },
        ]);
        const res = await request(app({ db, user: student })).get('/list');
        expect(res.status).toBe(200);
        expect(res.body.studentYearLevel).toBe(3);
        expect(res.body.superchats.map(item => item.superchatId)).toEqual(['sc1', 'sc2', 'sc3']);
        expect(res.body.superchats[1].aboveStudentLevel).toBe(true);
    });

    test('pool validates selection, visibility, key, and enrollment access', async () => {
        expect((await request(app({ db: memoryDb({}), user: student })).get('/pool')).status).toBe(400);
        services.getSuperchat.mockResolvedValueOnce(null);
        expect((await request(app({ db: memoryDb({}), user: student })).get('/pool?superchatId=missing')).status).toBe(404);
        services.getSuperchat.mockResolvedValueOnce({ ...superchat, aiAvailable: false, llmKey: { status: 'missing' } });
        expect((await request(app({ db: memoryDb({}), user: student })).get('/pool?superchatId=sc1')).status).toBe(403);
        services.getStudentAccessibleSuperchatIds.mockResolvedValueOnce(new Set());
        expect((await request(app({ db: memoryDb({}), user: student })).get('/pool?superchatId=sc1')).status).toBe(403);
    });

    test('pool maps courses and level comparison', async () => {
        const db = memoryDb({ courses: [{ courseName: 'BIOC 200', yearLevel: 2, studentEnrollment: { s1: { enrolled: true } } }] });
        services.getSuperCourseRetrievalPool.mockResolvedValueOnce([{ courseId: 'C4', courseName: 'Advanced', yearLevel: 4, status: 'active' }]);
        const res = await request(app({ db, user: student })).get('/pool?superchatId=sc1');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ studentYearLevel: 2, poolMaxYearLevel: 4, hasHigherLevelCourses: true, topK: 4 });
        expect(res.body.courses).toEqual([{ courseId: 'C4', courseName: 'Advanced', status: 'active' }]);
    });
});

describe('student Super Course sessions', () => {
    const dbWithSession = () => memoryDb({ student_super_course_chat_sessions: [
        { sessionId: 'sess1', studentId: 's1', superchatId: 'sc1', title: 'Mine', messageCount: 2, isDeleted: false, updatedAt: new Date('2026-01-01'), chatData: { messages: [] } },
        { sessionId: 'gone', studentId: 's1', superchatId: 'sc1', isDeleted: true },
    ] });

    test('save validates payload and upserts the authenticated student session', async () => {
        const db = memoryDb({});
        expect((await request(app({ db, user: student })).post('/save').send({ superchatId: 'sc1' })).status).toBe(400);
        const res = await request(app({ db, user: student })).post('/save').send({ superchatId: 'sc1', sessionId: 'sess1', title: 'New', chatData: { messages: [] } });
        expect(res.status).toBe(200);
        expect(await db.collection('student_super_course_chat_sessions').findOne({ sessionId: 'sess1' })).toMatchObject({ studentId: 's1', superchatId: 'sc1', title: 'New' });
    });

    test('sessions list excludes deleted records', async () => {
        const res = await request(app({ db: dbWithSession(), user: student })).get('/sessions?superchatId=sc1');
        expect(res.status).toBe(200);
        expect(res.body.data.sessions.map(item => item.sessionId)).toEqual(['sess1']);
    });

    test('session detail enforces ownership and deletion state', async () => {
        const db = dbWithSession();
        expect((await request(app({ db, user: student })).get('/sessions/sess1?superchatId=sc1')).status).toBe(200);
        expect((await request(app({ db, user: student })).get('/sessions/gone?superchatId=sc1')).status).toBe(404);
    });

    test('session delete performs a soft delete', async () => {
        const db = dbWithSession();
        const res = await request(app({ db, user: student })).delete('/sessions/sess1?superchatId=sc1');
        expect(res.status).toBe(200);
        expect((await db.collection('student_super_course_chat_sessions').findOne({ sessionId: 'sess1' })).isDeleted).toBe(true);
    });
});

describe('student Super Course chat with mocked LLM', () => {
    test('validates message before retrieval', async () => {
        resolveSuperchatAi.mockResolvedValueOnce({ llm: {}, qdrant: {} });
        const res = await request(app({ db: memoryDb({}), user: student })).post('/chat').send({ superchatId: 'sc1', message: '   ' });
        expect(res.status).toBe(400);
        expect(services.searchSuperCourse).not.toHaveBeenCalled();
    });

    test('builds a grounded prompt and returns the mocked LLM response', async () => {
        const llm = { sendMessage: jest.fn(async () => ({ content: 'Mock answer', model: 'fake-model', usage: { tokens: 5 } })) };
        resolveSuperchatAi.mockResolvedValueOnce({ llm, qdrant: { fake: true } });
        services.searchSuperCourse.mockResolvedValueOnce({ pool: [{ courseId: 'C1' }], results: [{ score: 1 }] });
        services.buildSuperCourseCitations.mockReturnValueOnce([{ courseId: 'C1' }]);
        const res = await request(app({ db: memoryDb({}), user: student })).post('/chat').send({
            superchatId: 'sc1', message: 'Explain ATP', level: 'intro',
            conversationMessages: [{ role: 'user', content: 'Earlier question' }, { role: 'system', content: 'ignore me' }],
        });
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, message: 'Mock answer', model: 'fake-model' });
        expect(llm.sendMessage.mock.calls[0][0]).toContain('Explain ATP');
        expect(llm.sendMessage.mock.calls[0][1].systemPrompt).toContain('Use simple language.');
        expect(services.searchSuperCourse).toHaveBeenCalledWith(expect.anything(), 'Explain ATP', 4, expect.objectContaining({ qdrant: { fake: true } }));
    });

    test('maps mocked LLM failures without making provider calls', async () => {
        resolveSuperchatAi.mockResolvedValueOnce({ llm: { sendMessage: jest.fn(async () => { throw new Error('mock failure'); }) }, qdrant: {} });
        const res = await request(app({ db: memoryDb({}), user: student })).post('/chat').send({ superchatId: 'sc1', message: 'ATP' });
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to process chat message');
    });
});

describe('coverage: resolver guards, list tiebreak, struggle tracker branches, failure paths', () => {
    const User = require('../../../src/models/User');

    test('resolver: 503 without a db and 401 without a user', async () => {
        expect((await request(app({ db: null, user: student })).get('/pool?superchatId=sc1')).status).toBe(503);
        expect((await request(app({ db: memoryDb({}) })).get('/pool?superchatId=sc1')).status).toBe(401);
    });

    test('list breaks year-level ties alphabetically by name', async () => {
        services.getStudentAccessibleSuperchatIds.mockResolvedValueOnce(new Set(['b1', 'b2']));
        services.listSuperchats.mockResolvedValueOnce([
            { ...superchat, superchatId: 'b2', name: 'Zeta', yearLevel: 4 },
            { ...superchat, superchatId: 'b1', name: 'Alpha', yearLevel: 4 },
        ]);
        const res = await request(app({ db: memoryDb({}), user: student })).get('/list');
        expect(res.status).toBe(200);
        expect(res.body.superchats.map(b => b.name)).toEqual(['Alpha', 'Zeta']);
    });

    test('status and list return 500 when the accessibility lookup throws', async () => {
        services.getStudentAccessibleSuperchatIds.mockRejectedValueOnce(new Error('mongo down'));
        expect((await request(app({ db: memoryDb({}), user: student })).get('/status')).status).toBe(500);
        expect((await request(app({ db: null, user: student })).get('/list')).status).toBe(503);
        services.getStudentAccessibleSuperchatIds.mockRejectedValueOnce(new Error('mongo down'));
        expect((await request(app({ db: memoryDb({}), user: student })).get('/list')).status).toBe(500);
    });

    test('pool returns 500 when the retrieval pool lookup throws', async () => {
        services.getSuperCourseRetrievalPool.mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: student })).get('/pool?superchatId=sc1');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/source pool/i);
    });

    test('session persistence routes return 500 when the collection operations throw', async () => {
        const throwingDb = { collection: () => ({
            replaceOne: async () => { throw new Error('mongo down'); },
            updateOne: async () => { throw new Error('mongo down'); },
            findOne: async () => { throw new Error('mongo down'); },
            find: () => { throw new Error('mongo down'); },
        }) };
        const save = await request(app({ db: throwingDb, user: student }))
            .post('/save').send({ superchatId: 'sc1', sessionId: 'x', chatData: {} });
        expect(save.status).toBe(500);
        expect((await request(app({ db: throwingDb, user: student })).get('/sessions?superchatId=sc1')).status).toBe(500);
        expect((await request(app({ db: throwingDb, user: student })).get('/sessions/x?superchatId=sc1')).status).toBe(500);
        expect((await request(app({ db: throwingDb, user: student })).delete('/sessions/x?superchatId=sc1')).status).toBe(500);
    });

    test('trackSuperCourseStruggle stops after analysis when the student is not struggling', async () => {
        services.getSuperCourseApprovedTopics.mockResolvedValueOnce([{ courseId: 'C1', topics: ['atp'] }]);
        await router.trackSuperCourseStruggle({
            db: memoryDb({}), llmService: {}, user: student, message: 'what is ATP?', superchatId: 'sc1',
        });
        expect(User.updateUserStruggleState).not.toHaveBeenCalled();
    });

    test('trackSuperCourseStruggle swallows internal failures', async () => {
        services.getSuperCourseApprovedTopics.mockRejectedValueOnce(new Error('mongo down'));
        await expect(router.trackSuperCourseStruggle({
            db: memoryDb({}), llmService: {}, user: student, message: 'help', superchatId: 'sc1',
        })).resolves.toBeUndefined();
    });
});

describe('coverage: struggle tracking success paths', () => {
    const TrackerService = require('../../../src/services/tracker');
    const User = require('../../../src/models/User');
    const StruggleActivity = require('../../../src/models/StruggleActivity');

    const strugglingAnalysis = { isStruggling: true, isMapped: true, courseId: 'C1', topic: 'ATP', matchConfidence: 0.9 };

    test('records an Inactive event when the topic is below the activation threshold', async () => {
        TrackerService.mockImplementationOnce(() => ({
            analyzeMessageAcrossCourses: jest.fn(async () => strugglingAnalysis),
        }));
        services.getSuperCourseApprovedTopics.mockResolvedValueOnce([{ courseId: 'C1', topics: ['atp'] }]);
        User.updateUserStruggleState.mockResolvedValueOnce({ success: true, state: { isActive: false } });

        const db = memoryDb({});
        await router.trackSuperCourseStruggle({ db, llmService: {}, user: student, message: 'I am lost on ATP', superchatId: 'sc1' });

        expect(User.updateUserStruggleState).toHaveBeenCalledWith(
            db, 's1', { topic: 'ATP', isStruggling: true }, 'C1', { source: 'superCourse', skipActivityLog: true }
        );
        expect(StruggleActivity.createActivityEntry).toHaveBeenCalledWith(db, expect.objectContaining({
            userId: 's1', courseId: 'C1', topic: 'ATP', state: 'Inactive', source: 'superCourse', superchatId: 'sc1',
        }));
    });

    test('records an Active event once the struggle state reports activation', async () => {
        TrackerService.mockImplementationOnce(() => ({
            analyzeMessageAcrossCourses: jest.fn(async () => strugglingAnalysis),
        }));
        services.getSuperCourseApprovedTopics.mockResolvedValueOnce([{ courseId: 'C1', topics: ['atp'] }]);
        User.updateUserStruggleState.mockResolvedValueOnce({ success: true, state: { isActive: true } });

        // No displayName/username → the entry falls back to the email, then 'Unknown Student'.
        const bareUser = { userId: 's1' };
        await router.trackSuperCourseStruggle({ db: memoryDb({}), llmService: {}, user: bareUser, message: 'stuck', superchatId: null });

        expect(StruggleActivity.createActivityEntry).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
            state: 'Active', studentName: 'Unknown Student', superchatId: null,
        }));
    });
});
