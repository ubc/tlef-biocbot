const mockValidateApiKey = jest.fn();
const mockBuildKeySubdocument = jest.fn();
const mockDecryptApiKey = jest.fn();
const mockPublicKeySummary = jest.fn();

jest.mock('../../../src/services/llmKeyStore', () => ({
    validateApiKey: mockValidateApiKey,
    buildKeySubdocument: mockBuildKeySubdocument,
    decryptApiKey: mockDecryptApiKey,
    publicKeySummary: mockPublicKeySummary
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const settingsRouter = require('../../../src/routes/settings');

const admin = {
    userId: 'admin1',
    role: 'instructor',
    email: ' ADMIN@Example.com ',
    permissions: { systemAdmin: true }
};
const instructor = { userId: 'i1', role: 'instructor' };

function app({ db = memoryDb({ settings: [] }), user = admin, locals = {} } = {}) {
    return makeRouteApp(settingsRouter, { db, user, locals });
}

beforeEach(() => {
    mockValidateApiKey.mockResolvedValue({ ok: true, status: 'valid' });
    mockBuildKeySubdocument.mockImplementation((apiKey, userId) => ({
        ciphertext: `encrypted:${apiKey}`,
        status: 'valid',
        updatedById: userId,
        validatedAt: new Date('2026-01-01T00:00:00Z'),
        updatedAt: new Date('2026-01-01T00:00:00Z')
    }));
    mockDecryptApiKey.mockReturnValue('decrypted-key');
    mockPublicKeySummary.mockImplementation(key => key
        ? { configured: true, status: key.status || 'unknown', validatedAt: key.validatedAt, updatedAt: key.updatedAt }
        : { configured: false, status: 'missing' });
    jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => jest.restoreAllMocks());

describe('GET /academic-api-enabled', () => {
    test('returns the persisted feature gate and fails closed without a database', async () => {
        const db = memoryDb({ settings: [{ _id: 'global', academicApiEnabled: true }] });
        expect((await request(app({ db })).get('/academic-api-enabled')).body)
            .toEqual({ success: true, enabled: true });
        expect((await request(app({ db: null })).get('/academic-api-enabled')).body)
            .toEqual({ success: true, enabled: false });
    });
});

describe.each([
    {
        label: 'notes',
        base: '/notes-llm-key',
        id: 'notesLlm',
        evict: 'evictNotes',
        savedMessage: 'Notes API key saved',
        validMessage: 'Notes API key is valid'
    },
    {
        label: 'instructor Super Course',
        base: '/instructor-superchat-llm-key',
        id: 'superCourseChat',
        evict: 'evictSuperCourseChat',
        savedMessage: 'Instructor Super Course chat API key saved',
        validMessage: 'Instructor Super Course chat API key is valid'
    }
])('$label LLM key endpoints', ({ base, id, evict, savedMessage, validMessage }) => {
    test('GET enforces database and admin access', async () => {
        expect((await request(app({ db: null })).get(base)).status).toBe(503);
        expect((await request(app({ user: null })).get(base)).status).toBe(401);
        expect((await request(app({ user: instructor })).get(base)).status).toBe(403);
    });

    test('GET reports missing and valid saved keys', async () => {
        let res = await request(app()).get(base);
        expect(res.body).toMatchObject({ success: true, aiAvailable: false });

        const db = memoryDb({ settings: [{ _id: id, llmApiKey: { ciphertext: 'cipher', status: 'valid' } }] });
        res = await request(app({ db })).get(base);
        expect(res.body).toMatchObject({
            success: true,
            llmKey: { configured: true, status: 'valid' },
            aiAvailable: true
        });
    });

    test('PUT maps invalid and quota validation failures', async () => {
        mockValidateApiKey.mockResolvedValueOnce({
            ok: false,
            status: 'invalid',
            message: '',
            detail: 'bad key'
        });
        let res = await request(app()).put(base).send({ apiKey: 'bad' });
        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ code: 'LLM_KEY_INVALID', message: 'API key validation failed' });

        mockValidateApiKey.mockResolvedValueOnce({
            ok: false,
            status: 'quota_exhausted',
            message: 'Quota exhausted'
        });
        res = await request(app()).put(base).send({ apiKey: 'spent' });
        expect(res.body).toMatchObject({ code: 'LLM_KEY_QUOTA', message: 'Quota exhausted' });
    });

    test('PUT stores a validated key and evicts the corresponding runtime client', async () => {
        const db = memoryDb({ settings: [] });
        const registry = { [evict]: jest.fn() };
        const res = await request(app({ db, locals: { llmRegistry: registry } }))
            .put(base).send({ apiKey: 'secret' });

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, message: savedMessage, aiAvailable: true });
        expect(mockBuildKeySubdocument).toHaveBeenCalledWith('secret', 'admin1');
        expect(registry[evict]).toHaveBeenCalledTimes(1);
        expect(await db.collection('settings').findOne({ _id: id })).toMatchObject({
            llmApiKey: { ciphertext: 'encrypted:secret', status: 'valid' },
            updatedBy: 'admin@example.com'
        });
    });

    test('PUT succeeds when no registry is installed', async () => {
        expect((await request(app()).put(base).send({ apiKey: 'secret' })).status).toBe(200);
    });

    test('test endpoint rejects each missing-key document shape', async () => {
        for (const doc of [null, { _id: id }, { _id: id, llmApiKey: {} }]) {
            const db = memoryDb({ settings: doc ? [doc] : [] });
            const res = await request(app({ db })).post(`${base}/test`);
            expect(res.status).toBe(400);
            expect(res.body.code).toBe('LLM_KEY_MISSING');
        }
    });

    test('test endpoint decrypts, validates, persists validity, and evicts', async () => {
        const db = memoryDb({ settings: [{
            _id: id,
            llmApiKey: { ciphertext: 'cipher', status: 'unknown', validatedAt: null }
        }] });
        const registry = { [evict]: jest.fn() };
        const res = await request(app({ db, locals: { llmRegistry: registry } }))
            .post(`${base}/test`);

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, message: validMessage, aiAvailable: true });
        expect(mockDecryptApiKey).toHaveBeenCalledWith('cipher');
        expect(mockValidateApiKey).toHaveBeenCalledWith('decrypted-key');
        expect(registry[evict]).toHaveBeenCalledTimes(1);
        expect(await db.collection('settings').findOne({ _id: id })).toMatchObject({
            llmApiKey: { status: 'valid', validatedAt: expect.any(Date), updatedAt: expect.any(Date) }
        });
    });

    test.each([
        ['invalid', 'LLM_KEY_INVALID'],
        ['quota_exhausted', 'LLM_KEY_QUOTA']
    ])('test endpoint persists %s validation failures', async (status, code) => {
        const oldValidatedAt = new Date('2025-01-01T00:00:00Z');
        const db = memoryDb({ settings: [{
            _id: id,
            llmApiKey: { ciphertext: 'cipher', status: 'valid', validatedAt: oldValidatedAt }
        }] });
        mockValidateApiKey.mockResolvedValue({ ok: false, status, message: 'Nope' });

        const res = await request(app({ db })).post(`${base}/test`);

        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ success: false, code, message: 'Nope', aiAvailable: false });
        expect(res.body.llmKey.status).toBe(status);
        expect(new Date(res.body.llmKey.validatedAt)).toEqual(oldValidatedAt);
    });

    test('test endpoint works without a registry', async () => {
        const db = memoryDb({ settings: [{ _id: id, llmApiKey: { ciphertext: 'cipher' } }] });
        expect((await request(app({ db })).post(`${base}/test`)).status).toBe(200);
    });
});

describe('key endpoint exception contracts', () => {
    const throwingDb = {
        collection: () => ({
            findOne: jest.fn().mockRejectedValue(new Error('db failed')),
            updateOne: jest.fn().mockRejectedValue(new Error('db failed'))
        })
    };

    test.each([
        ['get', '/notes-llm-key'],
        ['put', '/notes-llm-key'],
        ['post', '/notes-llm-key/test'],
        ['get', '/instructor-superchat-llm-key'],
        ['put', '/instructor-superchat-llm-key'],
        ['post', '/instructor-superchat-llm-key/test']
    ])('%s %s returns its stable 500 response', async (method, path) => {
        const res = await request(app({ db: throwingDb }))[method](path).send({ apiKey: 'secret' });
        expect(res.status).toBe(500);
        expect(res.body.success).toBe(false);
    });
});
