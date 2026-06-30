jest.mock('../../../src/services/llmKeyStore', () => ({
    validateApiKey: jest.fn().mockResolvedValue({ ok: true, status: 'valid' }),
    buildKeySubdocument: jest.fn(() => ({ ciphertext: 'cipher', status: 'valid' })),
    decryptApiKey: jest.fn(() => 'key'),
    publicKeySummary: jest.fn(key => ({ configured: !!key, status: key?.status || 'missing' }))
}));

const { makeRouteApp, request } = require('../helpers/route-app');
const { memoryDb } = require('../helpers/memory-db');
const settingsRouter = require('../../../src/routes/settings');

const admin = { userId: 'a1', role: 'instructor', email: 'admin@x.com', permissions: { systemAdmin: true } };
const instructor = { userId: 'i1', role: 'instructor', email: 'i@x.com' };
const student = { userId: 's1', role: 'student' };

function app(db, user = admin, locals = {}) {
    return makeRouteApp(settingsRouter, { db, user, locals });
}

function throwingDb(message = 'database failed') {
    const fail = jest.fn(async () => { throw new Error(message); });
    return {
        collection: jest.fn(() => ({
            findOne: fail,
            updateOne: fail,
            find: jest.fn(() => ({ sort: () => ({ toArray: fail }), toArray: fail }))
        }))
    };
}

const promptBody = {
    courseId: 'C1', base: 'b', protege: 'p', tutor: 't', explain: 'e', directive: 'd',
    quizHelp: 'q', chatSummary: 's', studentIdleTimeout: 240
};

beforeAll(() => jest.spyOn(console, 'error').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('settings route database-unavailable contracts', () => {
    test.each([
        ['get', '/system-admins', undefined],
        ['post', '/system-admins', { email: 'x@x.com' }],
        ['post', '/system-admins/revoke', { email: 'x@x.com' }],
        ['get', '/ai-settings?courseId=C1', undefined],
        ['put', '/ai-settings', { courseId: 'C1', studentTopK: 3 }],
        ['post', '/ai-settings/reset', { courseId: 'C1' }],
        ['get', '/super-course-chat', undefined],
        ['put', '/super-course-chat', {}],
        ['post', '/super-course-chat/reset', {}],
        ['get', '/prompts', undefined],
        ['post', '/prompts', promptBody],
        ['post', '/prompts/reset', { courseId: 'C1' }],
        ['get', '/global', undefined],
        ['post', '/global', {}],
        ['get', '/llm', undefined],
        ['post', '/llm', { model: 'gpt-4.1-mini' }],
        ['get', '/question-prompts', undefined],
        ['post', '/question-prompts', { courseId: 'C1' }],
        ['post', '/question-prompts/reset', { courseId: 'C1' }],
        ['get', '/quiz?courseId=C1', undefined],
        ['post', '/quiz', { courseId: 'C1' }],
        ['get', '/chat-survey?courseId=C1', undefined],
        ['post', '/chat-survey', { courseId: 'C1' }],
        ['get', '/mental-health-prompt', undefined],
        ['post', '/mental-health-prompt', { courseId: 'C1', prompt: 'p' }],
        ['post', '/mental-health-prompt/reset', { courseId: 'C1' }],
        ['get', '/notes-llm-key', undefined],
        ['put', '/notes-llm-key', { apiKey: 'k' }],
        ['post', '/notes-llm-key/test', {}],
        ['get', '/instructor-superchat-llm-key', undefined],
        ['put', '/instructor-superchat-llm-key', { apiKey: 'k' }],
        ['post', '/instructor-superchat-llm-key/test', {}]
    ])('%s %s returns 503 without the required database', async (method, path, body) => {
        let call = request(app(null))[method](path);
        if (body !== undefined) call = call.send(body);
        expect((await call).status).toBe(503);
    });
});

describe('settings route stable exception responses', () => {
    test.each([
        ['get', '/system-admins', undefined, admin],
        ['post', '/system-admins', { email: 'x@x.com' }, admin],
        ['post', '/system-admins/revoke', { email: 'x@x.com' }, admin],
        ['get', '/ai-settings?courseId=C1', undefined, admin],
        ['put', '/ai-settings', { courseId: 'C1', studentTopK: 3 }, admin],
        ['post', '/ai-settings/reset', { courseId: 'C1' }, admin],
        ['get', '/super-course-chat', undefined, admin],
        ['put', '/super-course-chat', {
            studentTopK: 3, instructorTopK: 3, instructorPrompt: 'i', studentPrompt: 's'
        }, admin],
        ['post', '/super-course-chat/reset', {}, admin],
        ['get', '/prompts?courseId=C1', undefined, instructor],
        ['post', '/prompts', promptBody, instructor],
        ['post', '/prompts/reset', { courseId: 'C1' }, instructor],
        ['get', '/global', undefined, admin],
        ['post', '/global', { allowLocalLogin: true }, admin],
        ['get', '/llm-tag', undefined, admin],
        ['get', '/llm', undefined, admin],
        ['post', '/llm', { model: 'gpt-4.1-mini' }, admin],
        ['get', '/question-prompts?courseId=C1', undefined, admin],
        ['post', '/question-prompts', {
            courseId: 'C1', systemPrompt: 's', trueFalse: 't', multipleChoice: 'm', shortAnswer: 'a'
        }, admin],
        ['post', '/question-prompts/reset', { courseId: 'C1' }, admin],
        ['get', '/quiz?courseId=C1', undefined, admin],
        ['post', '/quiz', { courseId: 'C1' }, instructor],
        ['get', '/chat-survey?courseId=C1', undefined, admin],
        ['post', '/chat-survey', { courseId: 'C1' }, admin],
        ['get', '/anonymize-students?courseId=C1', undefined, instructor],
        ['post', '/anonymize-students', { courseId: 'C1', enabled: true }, instructor],
        ['get', '/mental-health-prompt?courseId=C1', undefined, admin],
        ['post', '/mental-health-prompt', { courseId: 'C1', prompt: 'p' }, admin],
        ['post', '/mental-health-prompt/reset', { courseId: 'C1' }, admin]
    ])('%s %s converts dependency failures to 500', async (method, path, body, user) => {
        let call = request(app(throwingDb(), user))[method](path);
        if (body !== undefined) call = call.send(body);
        const res = await call;
        expect(res.status).toBe(500);
        expect(res.body.success).toBe(false);
    });
});

describe('settings validation and edge branches', () => {
    test('system-admin routes distinguish no user from a non-admin', async () => {
        const db = memoryDb({ users: [] });
        expect((await request(app(db, null)).get('/system-admins')).status).toBe(401);
        expect((await request(app(db, student)).get('/system-admins')).status).toBe(403);
    });

    test('can-delete-all preserves its stable 500 contract for malformed user objects', async () => {
        const malformedUser = new Proxy({}, {
            get() { throw new Error('malformed user'); }
        });
        const res = await request(app(memoryDb({}), malformedUser)).get('/can-delete-all');
        expect(res.status).toBe(500);
        expect(res.body).toMatchObject({ success: false, canDeleteAll: false });
    });

    test.each([
        ['put', '/ai-settings', {}],
        ['post', '/ai-settings/reset', {}],
        ['post', '/prompts/reset', {}],
        ['post', '/question-prompts', {}],
        ['post', '/question-prompts/reset', {}],
        ['post', '/quiz', {}],
        ['post', '/chat-survey', {}],
        ['post', '/mental-health-prompt', { prompt: 'p' }],
        ['post', '/mental-health-prompt/reset', {}]
    ])('%s %s rejects its missing course id', async (method, path, body) => {
        expect((await request(app(memoryDb({})))[method](path).send(body)).status).toBe(400);
    });

    test('course settings access accepts additional instructors and rejects deleted/missing courses', async () => {
        const db = memoryDb({ courses: [
            { courseId: 'C1', instructorId: 'owner', instructors: ['i1'] },
            { courseId: 'DELETED', instructorId: 'i1', status: 'deleted' }
        ] });
        expect((await request(app(db, instructor)).get('/ai-settings?courseId=C1')).status).toBe(200);
        expect((await request(app(db, instructor)).get('/ai-settings?courseId=DELETED')).status).toBe(400);
        expect((await request(app(db, instructor)).get('/ai-settings?courseId=MISSING')).status).toBe(400);
    });

    test('global updates only supplied fields and returns both toggles', async () => {
        const db = memoryDb({ settings: [{ _id: 'global', allowLocalLogin: false, academicApiEnabled: false }] });
        let res = await request(app(db)).post('/global').send({ academicApiEnabled: 'yes' });
        expect(res.body.settings).toEqual({ allowLocalLogin: false, academicApiEnabled: true });
        res = await request(app(db)).post('/global').send({ allowLocalLogin: 0 });
        expect(res.body.settings).toEqual({ allowLocalLogin: false, academicApiEnabled: true });
    });

    test('LLM settings normalize environment, stored values, effort, and optional caches', async () => {
        const old = process.env.OPENAI_MODEL;
        process.env.OPENAI_MODEL = 'unsupported';
        const db = memoryDb({ settings: [{ _id: 'llm', model: 'bad', reasoningEffort: 'bad' }] });
        let res = await request(app(db)).get('/llm');
        expect(res.body.settings).toMatchObject({ model: 'gpt-4.1-mini', reasoningEffort: 'minimal', supportsReasoning: false });
        res = await request(app(db)).post('/llm').send({ model: 'gpt-5-nano', reasoningEffort: 'bad' });
        expect(res.body.settings.reasoningEffort).toBe('minimal');
        res = await request(app(db)).post('/llm').send({ model: 'gpt-4.1-mini', reasoningEffort: 'high' });
        expect(res.body.settings).toMatchObject({ reasoningEffort: 'minimal', supportsReasoning: false });
        if (old === undefined) delete process.env.OPENAI_MODEL; else process.env.OPENAI_MODEL = old;
    });

    test('LLM tag handles allowed and invalid stored settings for reasoning/non-reasoning models', async () => {
        let db = memoryDb({ settings: [{ _id: 'llm', model: 'gpt-5-nano', reasoningEffort: 'high' }] });
        expect((await request(app(db)).get('/llm-tag')).body).toMatchObject({ llmIndex: 2, reasoningIndex: 4 });
        db = memoryDb({ settings: [{ _id: 'llm', model: 'gpt-4.1-mini', reasoningEffort: 'wat' }] });
        expect((await request(app(db)).get('/llm-tag')).body).toMatchObject({ llmIndex: 1, reasoningIndex: 0 });
    });

    test('prompt timeout accepts numeric strings and rejects non-numeric values', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        expect((await request(app(db, instructor)).post('/prompts').send({ ...promptBody, studentIdleTimeout: '30' })).status).toBe(200);
        expect((await request(app(db, instructor)).post('/prompts').send({ ...promptBody, studentIdleTimeout: 'wat' })).status).toBe(400);
        expect((await request(app(db, instructor)).post('/prompts').send({ ...promptBody, studentIdleTimeout: 1201 })).status).toBe(400);
    });

    test('prompt save defaults optional fields', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const body = { courseId: 'C1', base: 'b', protege: 'p', tutor: 't', explain: 'e', directive: 'd' };
        expect((await request(app(db, instructor)).post('/prompts').send(body)).status).toBe(200);

    });

    test('covers access denials on every remaining protected settings endpoint', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'other' }] });
        const cases = [
            ['post', '/system-admins/revoke', { email: 'x@x.com' }, student],
            ['put', '/ai-settings', { courseId: 'C1', studentTopK: 3 }, instructor],
            ['post', '/ai-settings/reset', { courseId: 'C1' }, instructor],
            ['put', '/super-course-chat', {}, student],
            ['post', '/super-course-chat/reset', {}, student],
            ['post', '/prompts/reset', { courseId: 'C1' }, instructor],
            ['post', '/chat-survey', { courseId: 'C1' }, instructor],
            ['get', '/llm', undefined, student],
            ['post', '/llm', { model: 'gpt-4.1-mini' }, student],
            ['post', '/question-prompts', {}, student],
            ['post', '/question-prompts/reset', {}, student],
            ['get', '/mental-health-prompt', undefined, student],
            ['post', '/mental-health-prompt', {}, student],
            ['post', '/mental-health-prompt/reset', {}, student],
            ['put', '/notes-llm-key', {}, student],
            ['post', '/notes-llm-key/test', {}, student],
            ['put', '/instructor-superchat-llm-key', {}, student],
            ['post', '/instructor-superchat-llm-key/test', {}, student]
        ];
        for (const [method, path, body, user] of cases) {
            let call = request(app(db, user))[method](path);
            if (body !== undefined) call = call.send(body);
            expect([401, 403]).toContain((await call).status);
        }
    });

    test('GET AI settings distinguishes an admin-visible missing course', async () => {
        expect((await request(app(memoryDb({ courses: [] }))).get('/ai-settings?courseId=NOPE')).status).toBe(404);
    });

    test('AI settings reset reports an update that matched no course', async () => {
        const db = { collection: () => ({ updateOne: jest.fn().mockResolvedValue({ matchedCount: 0 }) }) };
        expect((await request(app(db)).post('/ai-settings/reset').send({ courseId: 'NOPE' })).status).toBe(404);
    });

    test('model-level setting failures are translated to 400 responses', async () => {
        const course = { courseId: 'C1', instructorId: 'i1' };
        let reads = 0;
        const quizDb = {
            collection: () => ({
                findOne: jest.fn(async () => (++reads === 1 ? course : null)),
                updateOne: jest.fn().mockResolvedValue({ matchedCount: 0 })
            })
        };
        expect((await request(app(quizDb, instructor)).post('/quiz').send({ courseId: 'C1' })).status).toBe(400);

        reads = 0;
        const surveyDb = {
            collection: () => ({ findOne: jest.fn(async () => (++reads === 1 ? course : null)) })
        };
        expect((await request(app(surveyDb, instructor)).get('/chat-survey?courseId=C1')).status).toBe(400);

        reads = 0;
        expect((await request(app(quizDb, instructor)).post('/anonymize-students').send({ courseId: 'C1' })).status).toBe(400);
    });

    test('anonymize update validates authentication and course id', async () => {
        expect((await request(app(memoryDb({}), null)).post('/anonymize-students').send({ courseId: 'C1' })).status).toBe(401);
        expect((await request(app(memoryDb({}), instructor)).post('/anonymize-students').send({})).status).toBe(400);
    });
});
