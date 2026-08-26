/// <reference types="node" />
/// <reference types="jest" />

/**
 * Route-level proof that the Super Course and instructor chat session endpoints
 * work through the encrypted database wrapper.
 *
 * The point of these cases is that the routes contain no encrypt/decrypt calls
 * at all: they receive `app.locals.db` already wrapped (as src/server.js wires
 * it) and keep issuing ordinary collection operations. So each test drives the
 * real router with a real ProtectedDb and then inspects the underlying store to
 * confirm MongoDB holds an envelope while the HTTP response holds the
 * transcript.
 *
 * Mocked: superCourseService and the LLM key middleware, which pull Qdrant and
 * provider clients at load time. Everything on the persistence path — router,
 * encryption toolkit, filters, sorts — is real.
 */
jest.mock('../../../src/services/superCourseService', () => ({
    getSuperchat: jest.fn(),
    listSuperchats: jest.fn(),
    getStudentAccessibleSuperchatIds: jest.fn(),
    getInstructorSuperCourseChat: jest.fn(),
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
    normalizeYearLevel: jest.fn(value => (Number.isInteger(value) ? value : null)),
    parseYearLevelFromName: jest.fn(() => null),
}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveSuperchatAi: jest.fn(),
    resolveSuperCourseChatAi: jest.fn(),
    sendLlmKeyError: jest.fn(() => false),
}));
jest.mock('../../../src/services/llmKeyStore', () => ({
    structuredKeyError: jest.fn(status => ({ success: false, code: `LLM_KEY_${String(status).toUpperCase()}` })),
}));

const services = require('../../../src/services/superCourseService');
const { encryptedMemoryDb } = require('../helpers/encrypted-memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const { initializeChatEncryption } = require('../../../src/services/chatEncryption');
const { loadEncryptionToolkit } = require('../../../src/config/chatEncryption');

const studentRouter = require('../../../src/routes/studentSuperCourse');
const instructorRouter = require('../../../src/routes/instructorChat');

// The toolkit is an optional dependency published to GitHub Packages, so a
// clone without a registry token does not have it.
const describeWithToolkit = loadEncryptionToolkit() ? describe : describe.skip;

const SYNTHETIC_KEY = Buffer.alloc(32, 7).toString('base64');
const STUDENT_SESSIONS = 'student_super_course_chat_sessions';
const INSTRUCTOR_SESSIONS = 'instructor_chat_sessions';

const student = { userId: 's1', role: 'student', displayName: 'Student One' };
const instructor = { userId: 'i1', role: 'instructor', displayName: 'Dr I' };
const superchat = {
    superchatId: 'sc1',
    name: 'Biochemistry',
    showToStudents: true,
    aiAvailable: true,
    settings: { includeInactiveCourses: false, studentTopK: 4, instructorTopK: 5 },
};

const TRANSCRIPT = {
    messages: [
        { type: 'user', content: 'A confidential student question' },
        { type: 'bot', content: 'A confidential BiocBot answer' },
    ],
};

/** Wrap an envelope-safe store the way src/server.js wraps the real Db. */
async function encryptedApp(router, user, seed = {}) {
    const rawDb = encryptedMemoryDb(seed);
    const db = await initializeChatEncryption(rawDb, {
        BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true',
        BIOCBOT_CHAT_ENCRYPTION_KEY: SYNTHETIC_KEY,
    });
    return { rawDb, app: makeRouteApp(router, { db, user }) };
}

function expectEnvelope(stored) {
    expect(stored.chatData).toMatchObject({ __ubc_enc: 1, alg: 'A256GCM', kid: 'student-chat-2026-01' });
    expect(stored.chatData.messages).toBeUndefined();
    expect(JSON.stringify(stored)).not.toContain('confidential');
}

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => jest.restoreAllMocks());

beforeEach(() => {
    services.getSuperchat.mockReset().mockResolvedValue(superchat);
    services.getStudentAccessibleSuperchatIds.mockReset().mockResolvedValue(new Set(['sc1']));
    services.getInstructorSuperCourseChat.mockReset().mockResolvedValue({
        superchatId: null, name: 'Global Instructor Chat', aiAvailable: true, showToStudents: true,
        settings: { includeInactiveCourses: false, instructorTopK: 5 },
    });
});

describeWithToolkit('student Super Course chat sessions through the encrypted wrapper', () => {
    test('POST /save stores an envelope and leaves operational fields plaintext', async () => {
        const { rawDb, app } = await encryptedApp(studentRouter, student);

        const res = await request(app).post('/save?superchatId=sc1').send({
            sessionId: 'sess-1',
            title: 'My Super Course chat',
            messageCount: 2,
            duration: '45s',
            savedAt: '2026-08-26T10:00:00.000Z',
            chatData: TRANSCRIPT,
        });

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, data: { sessionId: 'sess-1', studentId: 's1' } });

        const [stored] = rawDb.stored(STUDENT_SESSIONS);
        expectEnvelope(stored);
        expect(stored).toMatchObject({
            sessionId: 'sess-1',
            studentId: 's1',
            superchatId: 'sc1',
            title: 'My Super Course chat',
            messageCount: 2,
            duration: '45s',
            savedAt: '2026-08-26T10:00:00.000Z',
            isDeleted: false,
        });
    });

    test('GET /sessions lists saved sessions with the transcript decrypted', async () => {
        const { app } = await encryptedApp(studentRouter, student);

        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-old', title: 'Older', savedAt: '2026-01-01T00:00:00.000Z', chatData: TRANSCRIPT });
        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-new', title: 'Newer', savedAt: '2026-06-01T00:00:00.000Z', chatData: TRANSCRIPT });

        const res = await request(app).get('/sessions?superchatId=sc1');

        expect(res.status).toBe(200);
        expect(res.body.data.sessions).toHaveLength(2);
        expect(res.body.data.sessions.map(s => s.title).sort()).toEqual(['Newer', 'Older']);
        for (const session of res.body.data.sessions) {
            expect(session.chatData).toEqual(TRANSCRIPT);
        }
    });

    test('GET /sessions/:sessionId returns the original transcript', async () => {
        const { app } = await encryptedApp(studentRouter, student);
        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-1', chatData: TRANSCRIPT });

        const res = await request(app).get('/sessions/sess-1?superchatId=sc1');

        expect(res.status).toBe(200);
        expect(res.body.session.chatData).toEqual(TRANSCRIPT);
        expect(res.body.session.sessionId).toBe('sess-1');
    });

    test('mixed reads still serve a legacy plaintext session saved before the migration', async () => {
        const legacy = {
            sessionId: 'legacy-1',
            studentId: 's1',
            superchatId: 'sc1',
            title: 'Written before encryption',
            savedAt: '2025-12-01T00:00:00.000Z',
            isDeleted: false,
            chatData: TRANSCRIPT,
        };
        const { app } = await encryptedApp(studentRouter, student, { [STUDENT_SESSIONS]: [legacy] });

        const single = await request(app).get('/sessions/legacy-1?superchatId=sc1');
        expect(single.status).toBe(200);
        expect(single.body.session.chatData).toEqual(TRANSCRIPT);

        // A newly saved (encrypted) session and the legacy plaintext one list together.
        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-new', title: 'After', chatData: TRANSCRIPT });
        const listed = await request(app).get('/sessions?superchatId=sc1');
        expect(listed.status).toBe(200);
        expect(listed.body.data.sessions.map(s => s.sessionId).sort()).toEqual(['legacy-1', 'sess-new']);
        for (const session of listed.body.data.sessions) {
            expect(session.chatData).toEqual(TRANSCRIPT);
        }
    });

    test('DELETE soft-deletes without disturbing the envelope, and the session drops out of the list', async () => {
        const { rawDb, app } = await encryptedApp(studentRouter, student);
        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-1', chatData: TRANSCRIPT });
        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-2', chatData: TRANSCRIPT });

        const del = await request(app).delete('/sessions/sess-1?superchatId=sc1');
        expect(del.status).toBe(200);

        const listed = await request(app).get('/sessions?superchatId=sc1');
        expect(listed.body.data.sessions.map(s => s.sessionId)).toEqual(['sess-2']);

        const deleted = rawDb.stored(STUDENT_SESSIONS).find(doc => doc.sessionId === 'sess-1');
        expect(deleted.isDeleted).toBe(true);
        expectEnvelope(deleted);
    });

    test('another student cannot read the session, and the store never held plaintext', async () => {
        const { rawDb, app } = await encryptedApp(studentRouter, student);
        await request(app).post('/save?superchatId=sc1').send({ sessionId: 'sess-1', chatData: TRANSCRIPT });

        const other = makeRouteApp(studentRouter, {
            db: await initializeChatEncryption(rawDb, {
                BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true',
                BIOCBOT_CHAT_ENCRYPTION_KEY: SYNTHETIC_KEY,
            }),
            user: { userId: 's2', role: 'student', displayName: 'Student Two' },
        });

        const res = await request(other).get('/sessions/sess-1?superchatId=sc1');
        expect(res.status).toBe(404);
    });
});

describeWithToolkit('instructor chat sessions through the encrypted wrapper', () => {
    test('POST /save stores an envelope and leaves operational fields plaintext', async () => {
        const { rawDb, app } = await encryptedApp(instructorRouter, instructor);

        const res = await request(app).post('/save').send({
            sessionId: 'isess-1',
            title: 'Instructor chat',
            messageCount: 4,
            duration: '2m',
            savedAt: '2026-08-26T10:00:00.000Z',
            chatData: TRANSCRIPT,
        });

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, data: { sessionId: 'isess-1', instructorId: 'i1' } });

        const [stored] = rawDb.stored(INSTRUCTOR_SESSIONS);
        expectEnvelope(stored);
        expect(stored).toMatchObject({
            sessionId: 'isess-1',
            instructorId: 'i1',
            instructorName: 'Dr I',
            title: 'Instructor chat',
            messageCount: 4,
            duration: '2m',
            savedAt: '2026-08-26T10:00:00.000Z',
            isDeleted: false,
        });
    });

    test('GET /sessions lists saved sessions with the transcript decrypted', async () => {
        const { app } = await encryptedApp(instructorRouter, instructor);
        await request(app).post('/save').send({ sessionId: 'isess-old', title: 'Older', savedAt: '2026-01-01T00:00:00.000Z', chatData: TRANSCRIPT });
        await request(app).post('/save').send({ sessionId: 'isess-new', title: 'Newer', savedAt: '2026-06-01T00:00:00.000Z', chatData: TRANSCRIPT });

        const res = await request(app).get('/sessions');

        expect(res.status).toBe(200);
        expect(res.body.data.sessions).toHaveLength(2);
        expect(res.body.data.sessions.map(s => s.title).sort()).toEqual(['Newer', 'Older']);
        for (const session of res.body.data.sessions) {
            expect(session.chatData).toEqual(TRANSCRIPT);
        }
    });

    test('GET /sessions/:sessionId returns the original transcript', async () => {
        const { app } = await encryptedApp(instructorRouter, instructor);
        await request(app).post('/save').send({ sessionId: 'isess-1', chatData: TRANSCRIPT });

        const res = await request(app).get('/sessions/isess-1');

        expect(res.status).toBe(200);
        expect(res.body.session.chatData).toEqual(TRANSCRIPT);
        expect(res.body.session.instructorId).toBe('i1');
    });

    test('mixed reads still serve a legacy plaintext instructor session', async () => {
        const legacy = {
            sessionId: 'ilegacy-1',
            instructorId: 'i1',
            instructorName: 'Dr I',
            title: 'Written before encryption',
            savedAt: '2025-12-01T00:00:00.000Z',
            isDeleted: false,
            chatData: TRANSCRIPT,
        };
        const { app } = await encryptedApp(instructorRouter, instructor, { [INSTRUCTOR_SESSIONS]: [legacy] });

        const single = await request(app).get('/sessions/ilegacy-1');
        expect(single.status).toBe(200);
        expect(single.body.session.chatData).toEqual(TRANSCRIPT);

        await request(app).post('/save').send({ sessionId: 'isess-new', title: 'After', chatData: TRANSCRIPT });
        const listed = await request(app).get('/sessions');
        expect(listed.body.data.sessions.map(s => s.sessionId).sort()).toEqual(['ilegacy-1', 'isess-new']);
        for (const session of listed.body.data.sessions) {
            expect(session.chatData).toEqual(TRANSCRIPT);
        }
    });

    test('DELETE soft-deletes without disturbing the envelope', async () => {
        const { rawDb, app } = await encryptedApp(instructorRouter, instructor);
        await request(app).post('/save').send({ sessionId: 'isess-1', chatData: TRANSCRIPT });
        await request(app).post('/save').send({ sessionId: 'isess-2', chatData: TRANSCRIPT });

        expect((await request(app).delete('/sessions/isess-1')).status).toBe(200);

        const listed = await request(app).get('/sessions');
        expect(listed.body.data.sessions.map(s => s.sessionId)).toEqual(['isess-2']);

        const deleted = rawDb.stored(INSTRUCTOR_SESSIONS).find(doc => doc.sessionId === 'isess-1');
        expect(deleted.isDeleted).toBe(true);
        expectEnvelope(deleted);
    });

    test('another instructor cannot read the session', async () => {
        const { rawDb, app } = await encryptedApp(instructorRouter, instructor);
        await request(app).post('/save').send({ sessionId: 'isess-1', chatData: TRANSCRIPT });

        const other = makeRouteApp(instructorRouter, {
            db: await initializeChatEncryption(rawDb, {
                BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true',
                BIOCBOT_CHAT_ENCRYPTION_KEY: SYNTHETIC_KEY,
            }),
            user: { userId: 'i2', role: 'instructor', displayName: 'Dr Two' },
        });

        expect((await request(other).get('/sessions/isess-1')).status).toBe(404);
    });
});

describeWithToolkit('routes keep working when encryption is disabled', () => {
    test('an unwrapped db still saves and reads plaintext for both collections', async () => {
        const rawDb = encryptedMemoryDb();
        const db = await initializeChatEncryption(rawDb, { BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'false' });
        expect(db).toBe(rawDb);

        const studentApp = makeRouteApp(studentRouter, { db, user: student });
        await request(studentApp).post('/save?superchatId=sc1').send({ sessionId: 'sess-1', chatData: TRANSCRIPT });
        expect(rawDb.stored(STUDENT_SESSIONS)[0].chatData).toEqual(TRANSCRIPT);

        const instructorApp = makeRouteApp(instructorRouter, { db, user: instructor });
        await request(instructorApp).post('/save').send({ sessionId: 'isess-1', chatData: TRANSCRIPT });
        expect(rawDb.stored(INSTRUCTOR_SESSIONS)[0].chatData).toEqual(TRANSCRIPT);
    });
});
