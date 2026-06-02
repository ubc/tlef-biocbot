// @ts-check
/**
 * Focused harness coverage for remaining src route/model defensive branches.
 *
 * These cases mount real production modules in a child process and swap only
 * request-local dependencies (app.locals, Passport callbacks, fake DB throws).
 * No production code is modified and no real CWL/Shibboleth IdP is contacted.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { spawn } = require('child_process');
const path = require('path');
const net = require('net');
const { once } = require('events');
const CourseModel = require('../../src/models/Course');

/** @type {import('child_process').ChildProcess|null} */
let harnessProc = null;
/** @type {import('@playwright/test').APIRequestContext|null} */
let api = null;

function getFreePort() {
    return /** @type {Promise<number>} */ (new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.unref();
        srv.on('error', reject);
        srv.listen(0, () => {
            const addr = /** @type {any} */ (srv.address());
            srv.close(() => resolve(addr.port));
        });
    }));
}

async function configure(mode) {
    if (!api) throw new Error('Harness API not ready');
    const res = await api.post('/__configure', { data: { mode }, failOnStatusCode: false });
    expect(res.ok()).toBeTruthy();
}

async function postJson(pathname, data = {}) {
    if (!api) throw new Error('Harness API not ready');
    return api.post(pathname, { data, failOnStatusCode: false, maxRedirects: 0 });
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
    const port = await getFreePort();
    const env = {
        ...process.env,
        SRC_HARNESS_PORT: String(port),
        NODE_V8_COVERAGE: path.resolve(__dirname, '../../coverage-reports/.v8-server'),
        BIOCBOT_COVERAGE_RUN_ID: process.env.BIOCBOT_COVERAGE_RUN_ID || String(Date.now()),
    };

    harnessProc = spawn(process.execPath, [
        path.resolve(__dirname, 'helpers/src-route-model-harness.js'),
    ], { env, stdio: ['ignore', 'inherit', 'inherit'] });

    api = await request.newContext({ baseURL: `http://127.0.0.1:${port}` });
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        try {
            const res = await api.get('/__ping', { failOnStatusCode: false });
            if (res.ok()) return;
        } catch {
            // Harness process is still binding.
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('src route/model harness did not become ready in time');
});

test.afterAll(async () => {
    if (api) {
        try {
            await api.dispose();
        } catch {
            // A failed request can remove Playwright trace artifacts before
            // APIRequestContext finalization. Harness shutdown still matters.
        }
        api = null;
    }
    if (harnessProc && harnessProc.pid && !harnessProc.killed) {
        harnessProc.kill('SIGTERM');
        await once(harnessProc, 'exit');
    }
});

test.beforeEach(async () => {
    await configure('');
});

test('authService exported helpers and default-user failure paths are covered', async () => {
    let res = await postJson('/__auth-service/login-missing');
    expect(await res.json()).toMatchObject({ success: false });

    res = await postJson('/__auth-service/login-db-throw', { throwingDb: true });
    expect(await res.json()).toMatchObject({ success: false, error: /Login failed/i });

    res = await postJson('/__auth-service/set-course-missing-user');
    expect(await res.json()).toMatchObject({ success: false, error: 'User not found' });

    res = await postJson('/__auth-service/session-and-role-helpers');
    expect(await res.json()).toMatchObject({
        nullSession: null,
        hasNoRole: false,
        student: true,
        instructor: true,
        admin: true,
        noCourse: null,
        course: 'BIOC-H',
    });

    res = await postJson('/__auth-service/initialize-default-users');
    expect(await res.json()).toMatchObject({ success: true, users: { instructor: expect.any(String), student: expect.any(String) } });

    res = await postJson('/__auth-service/initialize-instructor-fails');
    expect(await res.json()).toMatchObject({ success: false, error: 'Failed to create default instructor' });

    res = await postJson('/__auth-service/initialize-student-fails');
    expect(await res.json()).toMatchObject({ success: false, error: 'Failed to create default student' });
});

test('UserAgreement defensive defaults and exported stats helpers are covered', async () => {
    const dbRequired = await postJson('/__user-agreement/db-required');
    expect(dbRequired.status()).toBe(500);
    expect((await dbRequired.json()).error).toContain('Database object is undefined');

    const res = await postJson('/__user-agreement/defaults-and-stats');
    expect(await res.json()).toMatchObject({
        created: { success: true, hasAgreed: false, agreementVersion: '1.0', isNew: false },
        agreed: false,
        emptyStats: { totalUsers: 0, agreedUsers: 0, pendingUsers: 0, agreementRate: 0 },
        stats: { totalUsers: 2, agreedUsers: 1, pendingUsers: 1, agreementRate: 50 },
    });
});

test('Course RAG settings helpers default and validate Top-K without database migration', async () => {
    expect(CourseModel.resolveRagSettings({})).toEqual({ student: { topK: 3 } });
    expect(CourseModel.resolveRagSettings({ ragSettings: { student: { topK: 12 } } })).toEqual({ student: { topK: 12 } });
    expect(CourseModel.resolveRagSettings({ ragSettings: { student: { topK: 0 } } })).toEqual({ student: { topK: 3 } });
    expect(CourseModel.resolveRagSettings({ ragSettings: { student: { topK: 21 } } })).toEqual({ student: { topK: 3 } });
    expect(CourseModel.getAllowInSuperCourse({})).toBe(false);
    expect(CourseModel.getAllowInSuperCourse({ allowInSuperCourse: false })).toBe(false);
    expect(CourseModel.getAllowInSuperCourse({ allowInSuperCourse: true })).toBe(true);

    // Superchat membership (the multi-bucket replacement for the boolean).
    expect(CourseModel.getCourseSuperchatIds({})).toEqual([]);
    expect(CourseModel.getCourseSuperchatIds({ superchatIds: ['a', 'b'] })).toEqual(['a', 'b']);
    // normalizeSuperchatIds trims, drops non-strings/empties, and dedupes.
    expect(CourseModel.normalizeSuperchatIds(['a', ' a ', '', null, 7, 'b'])).toEqual(['a', 'b']);
    expect(CourseModel.normalizeSuperchatIds('not-an-array')).toEqual([]);
});

test('chat route sends the course RAG Top-K to Qdrant search', async () => {
    await configure('chat-rag-topk');

    const res = await postJson('/api/chat', {
        message: 'What is ATP?',
        mode: 'default',
        unitName: 'Unit 1',
        courseId: 'BIOC-H',
    });
    expect(res.ok()).toBeTruthy();
    expect(await res.json()).toMatchObject({ success: true, message: 'Harness chat response' });

    const searchRes = await /** @type {any} */ (api).get('/__last-qdrant-search', { failOnStatusCode: false });
    expect(await searchRes.json()).toMatchObject({
        query: 'What is ATP?',
        filters: {
            courseId: 'BIOC-H',
            lectureNames: ['Unit 1'],
        },
        limit: 5,
    });
});

test('instructor Super Course chat searches only opted-in active courses by default', async () => {
    await configure('instructor-super-chat');

    const res = await postJson('/api/instructor/chat', {
        message: 'Compare glycolysis and beta oxidation',
        conversationMessages: [{ role: 'user', content: 'Previous context' }],
    });
    expect(res.ok()).toBeTruthy();
    expect(await res.json()).toMatchObject({
        success: true,
        message: 'Harness instructor super answer',
        retrieval: {
            topK: 6,
            includeInactiveCourses: false,
            poolCourseIds: ['BIOC-A'],
            poolCourses: [{ courseId: 'BIOC-A', courseName: 'Biochemistry A' }],
            resultCount: 1,
        },
        citations: [{ courseId: 'BIOC-A', courseName: 'Biochemistry A' }],
    });

    const searchRes = await /** @type {any} */ (api).get('/__last-qdrant-search', { failOnStatusCode: false });
    expect(await searchRes.json()).toMatchObject({
        query: 'Compare glycolysis and beta oxidation',
        filters: { courseId: ['BIOC-A'] },
        limit: 6,
    });

    const llmRes = await /** @type {any} */ (api).get('/__last-llm-request', { failOnStatusCode: false });
    expect((await llmRes.json()).prompt).toContain('Configured Super Course source pool:\nBiochemistry A (BIOC-A)');
});

test('instructor Super Course chat includes inactive courses when the global setting is enabled', async () => {
    await configure('instructor-super-chat-inactive');

    const res = await postJson('/api/instructor/chat', {
        message: 'What material is available?',
    });
    expect(res.ok()).toBeTruthy();
    expect(await res.json()).toMatchObject({
        success: true,
        retrieval: {
            includeInactiveCourses: true,
            poolCourseIds: ['BIOC-A', 'BIOC-B'],
        },
    });

    const searchRes = await /** @type {any} */ (api).get('/__last-qdrant-search', { failOnStatusCode: false });
    expect(await searchRes.json()).toMatchObject({
        filters: { courseId: ['BIOC-A', 'BIOC-B'] },
        limit: 6,
    });
});

test('instructor Super Course pool endpoint exposes configured course names', async () => {
    await configure('instructor-super-chat-inactive');

    const res = await /** @type {any} */ (api).get('/api/instructor/chat/pool', { failOnStatusCode: false });
    expect(res.ok()).toBeTruthy();
    expect(await res.json()).toMatchObject({
        success: true,
        includeInactiveCourses: true,
        topK: 6,
        courses: [
            { courseId: 'BIOC-A', courseName: 'Biochemistry A', status: 'active' },
            { courseId: 'BIOC-B', courseName: 'Biochemistry B', status: 'inactive' },
        ],
    });
});

test('instructor Super Course pool filters inactive courses unless the global setting includes them', async () => {
    await configure('instructor-super-chat');

    const defaultRes = await /** @type {any} */ (api).get('/api/instructor/chat/pool', { failOnStatusCode: false });
    expect(defaultRes.ok()).toBeTruthy();
    const defaultBody = await defaultRes.json();
    expect(defaultBody).toMatchObject({
        success: true,
        includeInactiveCourses: false,
    });
    expect(defaultBody.courses.map(course => course.courseId)).toEqual(['BIOC-A']);

    await configure('instructor-super-chat-inactive');

    const inactiveRes = await /** @type {any} */ (api).get('/api/instructor/chat/pool', { failOnStatusCode: false });
    expect(inactiveRes.ok()).toBeTruthy();
    const inactiveBody = await inactiveRes.json();
    expect(inactiveBody).toMatchObject({
        success: true,
        includeInactiveCourses: true,
    });
    expect(inactiveBody.courses.map(course => course.courseId)).toEqual(['BIOC-A', 'BIOC-B']);
});

test('instructor Super Course chat sessions save, reload, and soft-delete for the instructor', async () => {
    await configure('instructor-super-chat');

    const sessionId = 'inst-super-session-1';
    const save = await postJson('/api/instructor/chat/save', {
        sessionId,
        title: 'Super Course - ATP',
        messageCount: 2,
        duration: '3s',
        savedAt: '2026-05-25T00:00:00.000Z',
        chatData: {
            metadata: {
                instructorId: 'inst',
                instructorName: 'Harness User',
                courseId: 'SUPER_COURSE',
                courseName: 'Super Course',
                totalMessages: 2,
            },
            messages: [
                { type: 'user', content: 'What is ATP?', timestamp: '2026-05-25T00:00:00.000Z' },
                { type: 'bot', content: 'ATP stores transferable energy.', timestamp: '2026-05-25T00:00:03.000Z' },
            ],
            sessionInfo: { sessionId, duration: '3s' },
        },
    });
    expect(save.ok()).toBeTruthy();
    expect(await save.json()).toMatchObject({ success: true, data: { sessionId, instructorId: 'inst' } });

    const listed = await /** @type {any} */ (api).get('/api/instructor/chat/sessions', { failOnStatusCode: false });
    expect(listed.ok()).toBeTruthy();
    expect(await listed.json()).toMatchObject({
        success: true,
        data: {
            sessions: [
                {
                    sessionId,
                    title: 'Super Course - ATP',
                    messageCount: 2,
                    chatData: {
                        messages: [
                            { type: 'user', content: 'What is ATP?' },
                            { type: 'bot', content: 'ATP stores transferable energy.' },
                        ],
                    },
                },
            ],
        },
    });

    const loaded = await /** @type {any} */ (api).get(`/api/instructor/chat/sessions/${sessionId}`, { failOnStatusCode: false });
    expect(loaded.ok()).toBeTruthy();
    expect(await loaded.json()).toMatchObject({
        success: true,
        session: {
            sessionId,
            instructorId: 'inst',
            title: 'Super Course - ATP',
            chatData: {
                messages: [
                    { type: 'user', content: 'What is ATP?' },
                    { type: 'bot', content: 'ATP stores transferable energy.' },
                ],
            },
        },
    });

    const deleted = await /** @type {any} */ (api).delete(`/api/instructor/chat/sessions/${sessionId}`, { failOnStatusCode: false });
    expect(deleted.ok()).toBeTruthy();

    const afterDelete = await /** @type {any} */ (api).get(`/api/instructor/chat/sessions/${sessionId}`, { failOnStatusCode: false });
    expect(afterDelete.status()).toBe(404);
});

test('instructor Super Chat history lists saved sessions and hides deleted sessions', async () => {
    await configure('instructor-super-chat');

    const sessions = [
        {
            sessionId: 'inst-super-history-keep',
            title: 'Super Course - Enzymes',
            messageCount: 2,
            duration: '4s',
            savedAt: '2026-05-26T20:00:00.000Z',
            chatData: {
                metadata: { instructorId: 'inst', courseId: 'SUPER_COURSE', totalMessages: 2 },
                messages: [
                    { type: 'user', content: 'Explain enzymes', timestamp: '2026-05-26T20:00:00.000Z' },
                    { type: 'bot', content: 'Enzymes are catalysts.', timestamp: '2026-05-26T20:00:04.000Z' },
                ],
                sessionInfo: { sessionId: 'inst-super-history-keep', duration: '4s' },
            },
        },
        {
            sessionId: 'inst-super-history-delete',
            title: 'Super Course - Deleted',
            messageCount: 1,
            duration: '0s',
            savedAt: '2026-05-26T20:05:00.000Z',
            chatData: {
                metadata: { instructorId: 'inst', courseId: 'SUPER_COURSE', totalMessages: 1 },
                messages: [{ type: 'user', content: 'Delete me', timestamp: '2026-05-26T20:05:00.000Z' }],
                sessionInfo: { sessionId: 'inst-super-history-delete', duration: '0s' },
            },
        },
    ];

    for (const session of sessions) {
        const save = await postJson('/api/instructor/chat/save', session);
        expect(save.ok()).toBeTruthy();
    }

    const beforeDelete = await /** @type {any} */ (api).get('/api/instructor/chat/sessions', { failOnStatusCode: false });
    expect(beforeDelete.ok()).toBeTruthy();
    expect((await beforeDelete.json()).data.sessions.map(session => session.sessionId)).toEqual([
        'inst-super-history-keep',
        'inst-super-history-delete',
    ]);

    const deleted = await /** @type {any} */ (api).delete('/api/instructor/chat/sessions/inst-super-history-delete', { failOnStatusCode: false });
    expect(deleted.ok()).toBeTruthy();

    const afterDelete = await /** @type {any} */ (api).get('/api/instructor/chat/sessions', { failOnStatusCode: false });
    expect(afterDelete.ok()).toBeTruthy();
    const body = await afterDelete.json();
    expect(body.data.sessions.map(session => session.sessionId)).toEqual(['inst-super-history-keep']);
    expect(body.data.sessions[0]).toMatchObject({
        title: 'Super Course - Enzymes',
        messageCount: 2,
        chatData: {
            messages: [
                { type: 'user', content: 'Explain enzymes' },
                { type: 'bot', content: 'Enzymes are catalysts.' },
            ],
        },
    });
});

test('User model SAML and no-match update branches are covered without real IdP auth', async () => {
    let res = await postJson('/__user-model/get-by-puid');
    expect(await res.json()).toMatchObject({ missing: null, found: { userId: 'saml-existing', puid: 'puid-1' } });

    res = await postJson('/__user-model/saml-missing-identifier');
    expect(await res.json()).toMatchObject({ success: false });

    res = await postJson('/__user-model/saml-create-defaults');
    expect(await res.json()).toMatchObject({ success: true, user: { role: 'student', authProvider: 'saml' } });

    res = await postJson('/__user-model/saml-existing-update');
    expect(await res.json()).toMatchObject({ success: true, user: { role: 'instructor', email: 'updated@example.test' } });

    res = await postJson('/__user-model/saml-preserve-ta');
    expect(await res.json()).toMatchObject({ success: true, user: { role: 'ta' } });

    res = await postJson('/__user-model/update-and-deactivate-failures');
    expect(await res.json()).toMatchObject({
        preferences: { success: false },
        deactivateMissing: { success: false },
        deactivateFound: { success: true },
    });
});

test('auth middleware API-only and unmounted helper branches are covered', async () => {
    let res = await /** @type {any} */ (api).get('/api/middleware/require-auth', { failOnStatusCode: false });
    expect(res.status()).toBe(401);

    await configure('middleware-missing-user');
    res = await /** @type {any} */ (api).get('/api/middleware/require-auth', { failOnStatusCode: false });
    expect(res.status()).toBe(401);

    await configure('middleware-throw-user');
    res = await /** @type {any} */ (api).get('/api/middleware/require-auth', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('middleware-wrong-role');
    res = await /** @type {any} */ (api).get('/api/middleware/require-instructor', { failOnStatusCode: false });
    expect(res.status()).toBe(403);

    res = await /** @type {any} */ (api).get('/api/middleware/require-instructor-or-ta', { failOnStatusCode: false });
    expect(res.status()).toBe(403);

    await configure('middleware-admin-denied');
    res = await /** @type {any} */ (api).get('/api/middleware/require-system-admin', { failOnStatusCode: false });
    expect(res.status()).toBe(403);

    await configure('middleware-admin-ok');
    res = await /** @type {any} */ (api).get('/api/middleware/require-system-admin', { failOnStatusCode: false });
    expect(res.ok()).toBeTruthy();

    await configure('middleware-ta-no-course');
    res = await /** @type {any} */ (api).get('/api/middleware/ta-permission', { failOnStatusCode: false });
    expect(res.status()).toBe(400);

    await configure('middleware-ta-throws');
    res = await /** @type {any} */ (api).get('/api/middleware/ta-permission?courseId=BIOC-H', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('middleware-course-instructor-no-context');
    res = await /** @type {any} */ (api).get('/api/middleware/require-course-context', { failOnStatusCode: false, maxRedirects: 0 });
    expect([302, 303]).toContain(res.status());
    expect(res.headers().location).toBe('/instructor/onboarding');
});

test('auth route missing-service, Passport error, and safe CWL logout branches are covered', async () => {
    await configure('auth-no-service');
    let res = await postJson('/api/auth/register', {
        username: 'new-user',
        password: 'pw',
        role: 'student',
    });
    expect(res.status()).toBe(500);

    res = await /** @type {any} */ (api).get('/api/auth/me', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    res = await /** @type {any} */ (api).put('/api/auth/preferences', { data: { preferences: { theme: 'dark' } }, failOnStatusCode: false });
    expect(res.status()).toBe(500);

    res = await postJson('/api/auth/set-course', { courseId: 'BIOC-H' });
    expect(res.status()).toBe(500);

    await configure('auth-login-passport-error');
    res = await postJson('/api/auth/login', { username: 'x', password: 'p' });
    expect(res.status()).toBe(500);

    await configure('auth-login-session-error');
    res = await postJson('/api/auth/login', { username: 'x', password: 'p' });
    expect(res.status()).toBe(500);

    await configure('auth-cwl-helper-success');
    res = await postJson('/api/auth/logout');
    expect(await res.json()).toMatchObject({ success: true, redirect: 'https://idp.example/logout' });

    await configure('auth-cwl-helper-error');
    res = await postJson('/api/auth/logout');
    expect(await res.json()).toMatchObject({ success: true, redirect: '/login' });
});

test('Shibboleth defensive route branches are covered without contacting a real IdP', async () => {
    await configure('shib-login-throws');
    let res = await /** @type {any} */ (api).get('/Shibboleth.sso/Login', { failOnStatusCode: false });
    expect(res.status()).toBe(503);

    for (const role of ['instructor', 'student', 'ta', 'mystery']) {
        await configure(`shib-post-${role}`);
        res = await postJson('/Shibboleth.sso/SAML2/POST');
        expect([302, 303]).toContain(res.status());
        const expected = role === 'instructor' ? '/instructor/home'
            : role === 'student' ? '/student'
                : role === 'ta' ? '/ta'
                    : '/';
        expect(res.headers().location).toBe(expected);
    }
});

test('questions route no-db, no-llm, and dependency-throw branches are covered', async () => {
    await configure('questions-no-db');
    let res = await postJson('/api/questions', {
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
        instructorId: 'inst',
        questionType: 'true-false',
        question: 'Q?',
        correctAnswer: 'true',
    });
    expect(res.status()).toBe(503);

    res = await /** @type {any} */ (api).get('/api/questions/lecture?courseId=BIOC-H&lectureName=Unit%201', { failOnStatusCode: false });
    expect(res.status()).toBe(503);

    await configure('questions-no-llm');
    res = await postJson('/api/questions/auto-link-learning-objectives', {
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
        learningObjectives: ['Objective A'],
        questions: [{ questionId: 'q1', question: 'Q?' }],
    });
    expect(res.status()).toBe(503);

    res = await postJson('/api/questions/check-answer', {
        question: 'Q?',
        studentAnswer: 'A',
        expectedAnswer: 'B',
    });
    expect(res.status()).toBe(503);

    await configure('questions-course-throws');
    res = await postJson('/api/questions', {
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
        instructorId: 'inst',
        questionType: 'true-false',
        question: 'Q?',
        correctAnswer: 'true',
    });
    expect(res.status()).toBe(500);

    res = await /** @type {any} */ (api).get('/api/questions/lecture?courseId=BIOC-H&lectureName=Unit%201', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('questions-llm-throws');
    res = await postJson('/api/questions/check-answer', {
        question: 'Q?',
        studentAnswer: 'A',
        expectedAnswer: 'B',
    });
    expect(res.status()).toBe(500);
});

test('qdrant route failure branches use fake service/db dependencies only', async () => {
    await configure('qdrant-init-throws');
    let res = await /** @type {any} */ (api).get('/api/qdrant/status', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('qdrant-process-fails');
    res = await postJson('/api/qdrant/process-document', {
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
        documentId: 'doc-h',
        content: 'Enough content for route validation.',
        fileName: 'doc.txt',
    });
    expect(res.status()).toBe(500);

    await configure('qdrant-search-throws');
    res = await postJson('/api/qdrant/search', { query: 'cells', courseId: 'BIOC-H' });
    expect(res.status()).toBe(500);

    await configure('qdrant-delete-fails');
    res = await /** @type {any} */ (api).delete('/api/qdrant/document/doc-h', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('middleware-admin-denied');
    res = await /** @type {any} */ (api).delete('/api/qdrant/collection', { failOnStatusCode: false });
    expect(res.status()).toBe(403);

    await configure('qdrant-collection-fails');
    res = await /** @type {any} */ (api).delete('/api/qdrant/collection', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('qdrant-delete-all-qdrant-fails');
    res = await /** @type {any} */ (api).delete('/api/qdrant/delete-all-collections', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('qdrant-delete-all-no-db');
    res = await /** @type {any} */ (api).delete('/api/qdrant/delete-all-collections', { failOnStatusCode: false });
    expect(res.status()).toBe(500);

    await configure('qdrant-cleanup-no-db');
    res = await postJson('/api/qdrant/cleanup-vectors', { courseId: 'BIOC-H' });
    expect(res.status()).toBe(503);

    await configure('qdrant-admin');
    res = await postJson('/api/qdrant/cleanup-vectors', { courseId: 'BIOC-H' });
    expect(res.ok()).toBeTruthy();
    expect(await res.json()).toMatchObject({ success: true, data: { orphanedDocs: 1, deletedChunks: 2 } });
});

// Intentionally still untested: real SAML/CWL IdP exchange, shadowed
// questions.js /stats and /course-material route declarations, and destructive
// qdrant delete-all success against a real DB. Those require production
// routing changes, external IdP state, or unsafe data deletion.
