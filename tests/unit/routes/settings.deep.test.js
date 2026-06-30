/**
 * Deeper in-process route tests for src/routes/settings.js (supertest) — the
 * admin-gated global settings and the course-scoped quiz / anonymize-students
 * settings not covered by settings.test.js. Load-safe (nothing mocked); the real
 * Course model + systemAdmin helpers run over the in-memory Mongo.
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

describe('GET /global — system-admin only', () => {
    test('401 without a user, 403 for a non-admin', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/global')).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: instructor })).get('/global')).status).toBe(403);
    });

    test('defaults allowLocalLogin to true when no settings exist', async () => {
        const res = await request(app({ db: memoryDb({ settings: [] }), user: admin })).get('/global');
        expect(res.status).toBe(200);
        expect(res.body.settings).toMatchObject({ allowLocalLogin: true });
    });

    test('returns the stored global settings', async () => {
        const db = memoryDb({ settings: [{ _id: 'global', allowLocalLogin: false }] });
        const res = await request(app({ db, user: admin })).get('/global');
        expect(res.body.settings).toMatchObject({ allowLocalLogin: false });
    });
});

describe('POST /global — system-admin only', () => {
    test('403 for a non-admin', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).post('/global').send({ allowLocalLogin: false })).status).toBe(403);
    });

    test('upserts the allowLocalLogin flag (coerced to boolean)', async () => {
        const db = memoryDb({ settings: [] });
        const res = await request(app({ db, user: admin })).post('/global').send({ allowLocalLogin: false });
        expect(res.status).toBe(200);
        const saved = await db.collection('settings').findOne({ _id: 'global' });
        expect(saved).toMatchObject({ allowLocalLogin: false, updatedBy: 'admin@x.com' });
    });
});

describe('GET /quiz', () => {
    test('400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/quiz')).status).toBe(400);
    });

    test('returns defaults for a course with no quizSettings', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const res = await request(app({ db })).get('/quiz?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.settings).toMatchObject({ enabled: false, testableUnits: 'all', allowLectureMaterialAccess: true });
    });

    test('returns stored quizSettings', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { enabled: true, testableUnits: 'published' } }] });
        const res = await request(app({ db })).get('/quiz?courseId=C1');
        expect(res.body.settings).toMatchObject({ enabled: true, testableUnits: 'published' });
    });
});

describe('POST /quiz — instructor course-settings gate', () => {
    test('400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).post('/quiz').send({})).status).toBe(400);
    });

    test('403 for a non-instructor', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        expect((await request(app({ db, user: student })).post('/quiz').send({ courseId: 'C1' })).status).toBe(403);
    });

    test('400 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/quiz').send({ courseId: 'C1' });
        expect(res.status).toBe(400);
    });

    test('403 when the instructor does not own the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i2' }] });
        expect((await request(app({ db, user: instructor })).post('/quiz').send({ courseId: 'C1' })).status).toBe(403);
    });

    test('200 saves settings (round-trips through GET /quiz)', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const save = await request(app({ db, user: instructor })).post('/quiz').send({ courseId: 'C1', enabled: true, testableUnits: 'published' });
        expect(save.status).toBe(200);
        const read = await request(app({ db })).get('/quiz?courseId=C1');
        expect(read.body.settings).toMatchObject({ enabled: true, testableUnits: 'published' });
    });
});

describe('anonymize-students', () => {
    test('GET 401 without a user, 400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/anonymize-students')).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: instructor })).get('/anonymize-students')).status).toBe(400);
    });

    test('POST 403 when the instructor does not own the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i2' }] });
        const res = await request(app({ db, user: instructor })).post('/anonymize-students').send({ courseId: 'C1', enabled: true });
        expect(res.status).toBe(403);
    });

    test('POST then GET round-trips the enabled flag for an owning instructor', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const save = await request(app({ db, user: instructor })).post('/anonymize-students').send({ courseId: 'C1', enabled: true });
        expect(save.status).toBe(200);
        const read = await request(app({ db, user: instructor })).get('/anonymize-students?courseId=C1');
        expect(read.body).toMatchObject({ success: true, enabled: true });
    });
});

describe('course tutoring prompt settings', () => {
    const promptBody = {
        courseId: 'C1', base: 'base', protege: 'protege', tutor: 'tutor',
        explain: 'explain', directive: 'directive', quizHelp: 'quiz',
        chatSummary: 'summary', additiveRetrieval: true,
        additionalMaterialSecondarySearch: true, studentIdleTimeout: 300,
    };

    test('GET returns global defaults or stored course prompts', async () => {
        let res = await request(app({ db: memoryDb({}) })).get('/prompts');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, isCourseSpecific: false });
        const db = memoryDb({ courses: [{ courseId: 'C1', prompts: { base: 'custom', studentIdleTimeout: 90 }, isAdditiveRetrieval: true }] });
        res = await request(app({ db })).get('/prompts?courseId=C1');
        expect(res.body.prompts).toMatchObject({ base: 'custom', studentIdleTimeout: 90, additiveRetrieval: true });
    });

    test('POST requires course ownership and valid prompt/timeout formats', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        expect((await request(app({ db, user: instructor })).post('/prompts').send({})).status).toBe(400);
        expect((await request(app({ db })).post('/prompts').send(promptBody)).status).toBe(401);
        expect((await request(app({ db, user: student })).post('/prompts').send(promptBody)).status).toBe(403);
        expect((await request(app({ db, user: instructor })).post('/prompts').send({ ...promptBody, base: 4 })).status).toBe(400);
        expect((await request(app({ db, user: instructor })).post('/prompts').send({ ...promptBody, studentIdleTimeout: 10 })).status).toBe(400);
    });

    test('POST saves prompts and reset removes them', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        let res = await request(app({ db, user: instructor })).post('/prompts').send(promptBody);
        expect(res.status).toBe(200);
        expect(await db.collection('courses').findOne({ courseId: 'C1' })).toMatchObject({
            prompts: { base: 'base', chatSummary: 'summary', studentIdleTimeout: 300 },
            isAdditiveRetrieval: true, additionalMaterialSecondarySearch: true,
        });
        res = await request(app({ db, user: instructor })).post('/prompts/reset').send({ courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(await db.collection('courses').findOne({ courseId: 'C1' })).toMatchObject({ isAdditiveRetrieval: true, additionalMaterialSecondarySearch: false });
    });
});

describe('system-admin question and mental-health prompts', () => {
    test('question prompts require admin and return defaults', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).get('/question-prompts')).status).toBe(403);
        const res = await request(app({ db: memoryDb({}), user: admin })).get('/question-prompts');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, isCourseSpecific: false });
    });

    test('question prompts save, read, and reset', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const body = { courseId: 'C1', systemPrompt: 'system', trueFalse: 'tf', multipleChoice: 'mc', shortAnswer: 'sa' };
        expect((await request(app({ db, user: admin })).post('/question-prompts').send({ ...body, trueFalse: 2 })).status).toBe(400);
        expect((await request(app({ db, user: admin })).post('/question-prompts').send(body)).status).toBe(200);
        const read = await request(app({ db, user: admin })).get('/question-prompts?courseId=C1');
        expect(read.body.prompts).toEqual({ systemPrompt: 'system', trueFalse: 'tf', multipleChoice: 'mc', shortAnswer: 'sa' });
        expect((await request(app({ db, user: admin })).post('/question-prompts/reset').send({ courseId: 'C1' })).status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).questionPrompts).toBeUndefined();
    });

    test('mental-health prompt returns defaults, saves, reads, and resets', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        let res = await request(app({ db, user: admin })).get('/mental-health-prompt');
        expect(res.body).toMatchObject({ success: true, isCourseSpecific: false });
        expect((await request(app({ db, user: admin })).post('/mental-health-prompt').send({ courseId: 'C1', prompt: 3 })).status).toBe(400);
        expect((await request(app({ db, user: admin })).post('/mental-health-prompt').send({ courseId: 'C1', prompt: 'custom safety classifier' })).status).toBe(200);
        res = await request(app({ db, user: admin })).get('/mental-health-prompt?courseId=C1');
        expect(res.body).toMatchObject({ prompt: 'custom safety classifier', isCourseSpecific: true });
        expect((await request(app({ db, user: admin })).post('/mental-health-prompt/reset').send({ courseId: 'C1' })).status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).mentalHealthDetectionPrompt).toBeUndefined();
    });
});

describe('system-admin Super Course chat settings', () => {
    const validSettings = {
        studentTopK: 4, instructorTopK: 6,
        includeInactiveCourses: true, showStudentSuperCourse: true,
        includeNotesInRetrieval: true, noteRetrievalRatio: 0.35, noteMinScore: 0.7,
        instructorPrompt: 'Instructor prompt', studentPrompt: 'Student prompt',
        studentLevelModifiers: { intro: 'Simple' },
        instructorLevelModifiers: { concise: 'Concise' },
    };

    test('GET requires admin and resolves defaults', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).get('/super-course-chat')).status).toBe(403);
        const res = await request(app({ db: memoryDb({ settings: [] }), user: admin })).get('/super-course-chat');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, settings: expect.any(Object), defaults: expect.any(Object) });
    });

    test('PUT validates Top-K values and required prompts', async () => {
        let res = await request(app({ db: memoryDb({}), user: admin })).put('/super-course-chat').send({ ...validSettings, studentTopK: 99 });
        expect(res.status).toBe(400);
        res = await request(app({ db: memoryDb({}), user: admin })).put('/super-course-chat').send({ ...validSettings, instructorPrompt: ' ' });
        expect(res.status).toBe(400);
    });

    test('PUT normalizes and persists settings', async () => {
        const db = memoryDb({ settings: [] });
        const res = await request(app({ db, user: admin })).put('/super-course-chat').send({ ...validSettings, noteRetrievalRatio: 0.356, noteMinScore: 4 });
        expect(res.status).toBe(200);
        expect(res.body.settings).toMatchObject({ studentTopK: 4, instructorTopK: 6, noteRetrievalRatio: 0.36 });
        const saved = await db.collection('settings').findOne({ _id: 'superCourseChat' });
        expect(saved).toMatchObject({ showStudentSuperCourse: true, includeInactiveCourses: true, updatedBy: 'admin@x.com' });
    });

    test('reset stores and returns default settings', async () => {
        const db = memoryDb({ settings: [{ _id: 'superCourseChat', studentTopK: 9 }] });
        const res = await request(app({ db, user: admin })).post('/super-course-chat/reset');
        expect(res.status).toBe(200);
        expect(res.body.message).toMatch(/reset/i);
        expect((await db.collection('settings').findOne({ _id: 'superCourseChat' })).studentTopK).toBe(res.body.settings.studentTopK);
    });
});

describe('global LLM model settings (configuration only)', () => {
    test('GET uses allowed stored settings and reports reasoning support', async () => {
        const db = memoryDb({ settings: [{ _id: 'llm', model: 'gpt-5-nano', reasoningEffort: 'high' }] });
        const res = await request(app({ db, user: admin })).get('/llm');
        expect(res.status).toBe(200);
        expect(res.body.settings).toMatchObject({ model: 'gpt-5-nano', reasoningEffort: 'high', supportsReasoning: true });
    });

    test('POST rejects unsupported models', async () => {
        const res = await request(app({ db: memoryDb({}), user: admin })).post('/llm').send({ model: 'made-up-model' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid model/);
    });

    test('POST persists settings and clears both runtime caches', async () => {
        const db = memoryDb({ settings: [] });
        const llm = { invalidateModelSettingsCache: jest.fn() };
        const llmRegistry = { clear: jest.fn() };
        const res = await request(app({ db, user: admin, locals: { llm, llmRegistry } })).post('/llm').send({ model: 'gpt-5.4-nano', reasoningEffort: 'medium' });
        expect(res.status).toBe(200);
        expect(res.body.settings).toEqual({ model: 'gpt-5.4-nano', reasoningEffort: 'medium', supportsReasoning: true });
        expect(llm.invalidateModelSettingsCache).toHaveBeenCalled();
        expect(llmRegistry.clear).toHaveBeenCalled();
    });

    test('llm-tag exposes only numeric tags and works without a DB', async () => {
        const res = await request(app({ db: null })).get('/llm-tag');
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, llmIndex: expect.any(Number), reasoningIndex: expect.any(Number) });
    });
});
