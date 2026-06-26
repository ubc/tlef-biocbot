/**
 * Unit tests for src/routes/llmKeyMiddleware.js.
 *
 * These are plain helper functions (not a mounted router), so we drive them with a
 * fake req/res and an injected llmRegistry on app.locals. llmKeyStore is left real
 * (its LlmKeyError + structuredKeyError carry the contract under test). Covers the
 * structured key-error translation, the registry-missing 503, the success pass-through,
 * and the "LlmKeyError → handled / other error → rethrown" split.
 */
const {
    sendLlmKeyError,
    resolveCourseAi,
    resolveNotesAi,
    resolveSuperchatAi,
    resolveSuperCourseChatAi,
} = require('../../../src/routes/llmKeyMiddleware');
const { LlmKeyError } = require('../../../src/services/llmKeyStore');

function fakeRes() {
    return {
        statusCode: 200,
        body: null,
        status(code) { this.statusCode = code; return this; },
        json(payload) { this.body = payload; return this; },
    };
}

function fakeReq(llmRegistry) {
    return { app: { locals: { db: { tag: 'db' }, llmRegistry } } };
}

describe('sendLlmKeyError', () => {
    test('returns false and leaves res untouched for an ordinary error', () => {
        const res = fakeRes();
        expect(sendLlmKeyError(res, new Error('boom'))).toBe(false);
        expect(res.body).toBeNull();
    });

    test('translates an LlmKeyError into a structured 403 response', () => {
        const res = fakeRes();
        expect(sendLlmKeyError(res, new LlmKeyError('invalid'))).toBe(true);
        expect(res.statusCode).toBe(403);
        expect(res.body).toMatchObject({ success: false, code: 'LLM_KEY_INVALID' });
    });

    test('also handles a duck-typed error whose code starts with LLM_KEY_', () => {
        const res = fakeRes();
        const handled = sendLlmKeyError(res, { code: 'LLM_KEY_QUOTA', status: 'quota_exhausted' });
        expect(handled).toBe(true);
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });
});

describe('resolveCourseAi', () => {
    test('503 and null when the registry is not initialized', async () => {
        const res = fakeRes();
        const out = await resolveCourseAi(fakeReq(undefined), res, 'C1');
        expect(out).toBeNull();
        expect(res.statusCode).toBe(503);
    });

    test('returns the resolved AI surface for the course', async () => {
        const ai = { chat: true };
        const registry = { forCourse: jest.fn(async () => ai) };
        const res = fakeRes();
        const out = await resolveCourseAi(fakeReq(registry), res, 'C1');
        expect(out).toBe(ai);
        expect(registry.forCourse).toHaveBeenCalledWith({ tag: 'db' }, 'C1');
    });

    test('converts an LlmKeyError from the registry into a key-error response (null)', async () => {
        const registry = { forCourse: jest.fn(async () => { throw new LlmKeyError('quota_exhausted'); }) };
        const res = fakeRes();
        const out = await resolveCourseAi(fakeReq(registry), res, 'C1');
        expect(out).toBeNull();
        expect(res.statusCode).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });

    test('rethrows a non-key error so the caller\'s try/catch can 500', async () => {
        const registry = { forCourse: jest.fn(async () => { throw new Error('db exploded'); }) };
        await expect(resolveCourseAi(fakeReq(registry), fakeRes(), 'C1')).rejects.toThrow('db exploded');
    });
});

describe('the other resolvers delegate to the matching registry method', () => {
    test('resolveNotesAi → forNotes(db)', async () => {
        const registry = { forNotes: jest.fn(async () => ({ notes: true })) };
        const out = await resolveNotesAi(fakeReq(registry), fakeRes());
        expect(out).toEqual({ notes: true });
        expect(registry.forNotes).toHaveBeenCalledWith({ tag: 'db' });
    });

    test('resolveSuperchatAi → forSuperchat(db, superchatId)', async () => {
        const registry = { forSuperchat: jest.fn(async () => ({ sc: true })) };
        const out = await resolveSuperchatAi(fakeReq(registry), fakeRes(), 'sc1');
        expect(out).toEqual({ sc: true });
        expect(registry.forSuperchat).toHaveBeenCalledWith({ tag: 'db' }, 'sc1');
    });

    test('resolveSuperCourseChatAi → forSuperCourseChat(db)', async () => {
        const registry = { forSuperCourseChat: jest.fn(async () => ({ scc: true })) };
        const out = await resolveSuperCourseChatAi(fakeReq(registry), fakeRes());
        expect(out).toEqual({ scc: true });
        expect(registry.forSuperCourseChat).toHaveBeenCalledWith({ tag: 'db' });
    });

    test('each returns 503/null when the registry is missing', async () => {
        expect(await resolveNotesAi(fakeReq(undefined), fakeRes())).toBeNull();
        expect(await resolveSuperchatAi(fakeReq(undefined), fakeRes(), 'sc1')).toBeNull();
        expect(await resolveSuperCourseChatAi(fakeReq(undefined), fakeRes())).toBeNull();
    });
});
