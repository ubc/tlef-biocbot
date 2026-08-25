/**
 * Per-surface provider credentials: isolation between platforms, backward
 * compatibility with legacy OpenAI records, real provider-aware validation, and
 * the guarantee that no ciphertext or decrypted key ever reaches a response.
 */
jest.mock('node-fetch', () => jest.fn());
const fetchMock = require('node-fetch');
const { LLMModule } = require('ubc-genai-toolkit-llm');

const {
    KEY_STATUSES,
    LlmKeyError,
    activateProviderSetFields,
    activeCredential,
    activeProviderOf,
    buildKeySubdocument,
    credentialForProvider,
    credentialSetFields,
    decryptActiveKey,
    decryptApiKey,
    mapProviderErrorToStatus,
    messageForStatus,
    publicProviderKeyState,
    readProviderState,
    scopedKeysRequired,
    stripPrivateKeyFields,
    structuredKeyErrorForProvider,
    updateOwnerKeyStatus,
    validateProviderKey,
} = require('../../../src/services/llmKeyStore');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';
const PROXY = 'ubc-llm-proxy';

const OLD_ENV = process.env;
beforeEach(() => {
    process.env = { ...OLD_ENV };
    delete process.env.BIOCBOT_TEST_LLM_STUB;
    delete process.env.LLM_PROVIDER;
    delete process.env.LLM_ENDPOINT;
    delete process.env.SANDBOX_LLM_ENDPOINT;
    fetchMock.mockReset();
});
afterAll(() => { process.env = OLD_ENV; });

const okResponse = () => ({ ok: true, status: 200, json: async () => ({ ok: true }) });
const errorResponse = (status, error) => ({ ok: false, status, json: async () => ({ error }) });

describe('reading a surface\'s provider state', () => {
    test('a legacy llmApiKey with no provider metadata is an OpenAI credential', () => {
        const course = { courseId: 'C1', llmApiKey: { ciphertext: 'c', status: 'valid', last4: '9999' } };
        const state = readProviderState(course);

        expect(state.activeProvider).toBe(OPENAI);
        expect(state.legacyOnly).toBe(true);
        expect(state.credentials[OPENAI]).toMatchObject({ ciphertext: 'c', last4: '9999' });
        expect(state.credentials[SANDBOX]).toBeUndefined();
    });

    test('both platforms can hold their own credential side by side', () => {
        const course = {
            activeLlmProvider: SANDBOX,
            llmCredentials: {
                [OPENAI]: { ciphertext: 'c-gpt', status: 'valid', last4: '1111' },
                [SANDBOX]: { ciphertext: 'c-sbx', status: 'valid', last4: '2222' },
            },
        };
        const state = readProviderState(course);

        expect(state.activeProvider).toBe(SANDBOX);
        expect(activeCredential(course).last4).toBe('2222');
        expect(credentialForProvider(course, OPENAI).last4).toBe('1111');
        expect(state.legacyOnly).toBe(false);
    });

    test('proxy credentials use the same isolated per-surface storage map', () => {
        const course = {
            activeLlmProvider: PROXY,
            llmCredentials: {
                [OPENAI]: { ciphertext: 'c-gpt', status: 'valid' },
                [SANDBOX]: { ciphertext: 'c-sbx', status: 'valid' },
                [PROXY]: { ciphertext: 'c-proxy', status: 'valid', last4: '3333' },
            },
        };
        expect(readProviderState(course).activeProvider).toBe(PROXY);
        expect(activeCredential(course).last4).toBe('3333');
        expect(publicProviderKeyState(course).llmKeysByProvider[PROXY].status).toBe('valid');
    });

    test('a status-only update never loses the legacy ciphertext', () => {
        // updateOwnerKeyStatus writes llmCredentials.openai.status before the
        // key itself is rewritten; the reader must merge, not replace.
        const course = {
            llmApiKey: { ciphertext: 'legacy-cipher', status: 'valid', last4: '4321' },
            llmCredentials: { [OPENAI]: { status: 'invalid', updatedAt: new Date() } },
        };
        const credential = credentialForProvider(course, OPENAI);

        expect(credential.ciphertext).toBe('legacy-cipher');
        expect(credential.status).toBe('invalid');
        expect(credential.last4).toBe('4321');
    });

    test('an unknown or missing active provider falls back to OpenAI', () => {
        expect(activeProviderOf({ activeLlmProvider: 'gemini' })).toBe(OPENAI);
        expect(activeProviderOf({})).toBe(OPENAI);
        expect(activeProviderOf(null)).toBe(OPENAI);
    });

    test('a pending provider and migration id are surfaced', () => {
        const state = readProviderState({
            activeLlmProvider: OPENAI,
            pendingLlmProvider: SANDBOX,
            providerMigrationId: 'mig_1',
            aiPreparationRequired: true,
        });
        expect(state.pendingProvider).toBe(SANDBOX);
        expect(state.migrationId).toBe('mig_1');
        expect(state.preparationRequired).toBe(true);
    });

    test('a bogus pending provider is ignored', () => {
        expect(readProviderState({ pendingLlmProvider: 'nope' }).pendingProvider).toBeNull();
    });
});

describe('credential writes keep platforms isolated', () => {
    test('saving an OpenAI key activates it and mirrors the legacy field', () => {
        const credential = buildKeySubdocument('sk-live-abcd', 'admin', OPENAI);
        const set = credentialSetFields(OPENAI, credential);

        expect(set['llmCredentials.openai']).toBe(credential);
        expect(set.activeLlmProvider).toBe(OPENAI);
        expect(set.llmApiKey).toBe(credential);
    });

    test('saving a Sandbox key never touches the legacy OpenAI field', () => {
        const credential = buildKeySubdocument('sbx-live-wxyz', 'admin', SANDBOX);
        const set = credentialSetFields(SANDBOX, credential);

        expect(set['llmCredentials.ubc-llm-sandbox']).toBe(credential);
        expect(set.activeLlmProvider).toBe(SANDBOX);
        expect(set.llmApiKey).toBeUndefined();
        expect(credential.provider).toBe(SANDBOX);
        expect(credential.last4).toBe('wxyz');
    });

    test('staging a credential does not activate it', () => {
        const credential = buildKeySubdocument('sbx-live-1234', 'admin', SANDBOX);
        const set = credentialSetFields(SANDBOX, credential, { activate: false });

        expect(set['llmCredentials.ubc-llm-sandbox']).toBe(credential);
        expect(set.activeLlmProvider).toBeUndefined();
        expect(set.llmApiKey).toBeUndefined();
    });

    test('activation clears the pending marker and migration id', () => {
        const set = activateProviderSetFields(SANDBOX);
        expect(set).toEqual({
            activeLlmProvider: SANDBOX,
            pendingLlmProvider: null,
            providerMigrationId: null,
            aiPreparationRequired: false,
        });
    });

    test('decryptActiveKey round-trips the active platform\'s key only', () => {
        const doc = {
            activeLlmProvider: SANDBOX,
            llmCredentials: {
                [OPENAI]: buildKeySubdocument('sk-gpt-key', 'a', OPENAI),
                [SANDBOX]: buildKeySubdocument('sbx-sandbox-key', 'a', SANDBOX),
            },
        };
        expect(decryptActiveKey(doc)).toBe('sbx-sandbox-key');
        expect(decryptApiKey(credentialForProvider(doc, OPENAI).ciphertext)).toBe('sk-gpt-key');
        expect(decryptActiveKey({})).toBeNull();
    });
});

describe('no key material in API responses', () => {
    test('publicProviderKeyState exposes status only, never ciphertext', () => {
        const doc = {
            activeLlmProvider: SANDBOX,
            llmCredentials: {
                [OPENAI]: buildKeySubdocument('sk-super-secret-gpt', 'a', OPENAI),
                [SANDBOX]: buildKeySubdocument('sbx-super-secret-key', 'a', SANDBOX),
            },
        };
        const state = publicProviderKeyState(doc);
        const serialised = JSON.stringify(state);

        expect(serialised).not.toContain('sk-super-secret-gpt');
        expect(serialised).not.toContain('sbx-super-secret-key');
        expect(serialised).not.toContain('ciphertext');
        expect(state).toMatchObject({
            llmProvider: SANDBOX,
            llmProviderLabel: 'UBC On-Premise LLM',
            aiAvailable: true,
        });
        expect(state.llmKeysByProvider[OPENAI].last4).toBe('-gpt');
        expect(state.llmKeysByProvider[SANDBOX].last4).toBe('-key');
    });

    test('help text follows the active platform', () => {
        expect(publicProviderKeyState({ activeLlmProvider: OPENAI }).llmProviderHelpText)
            .toBe('Feel free to use your own OpenAI API key, or contact the support team for assistance.');
        expect(publicProviderKeyState({ activeLlmProvider: SANDBOX }).llmProviderHelpText)
            .toBe('Contact the LTIC team to request a UBC LLM Sandbox API key.');
    });

    test('a valid key stays unavailable while initial material preparation is required', () => {
        const credential = buildKeySubdocument('sbx-course-key', 'a', SANDBOX);
        const state = publicProviderKeyState({
            activeLlmProvider: SANDBOX,
            llmCredentials: { [SANDBOX]: credential },
            pendingLlmProvider: SANDBOX,
            providerMigrationId: 'mig_prepare',
            aiPreparationRequired: true,
        });

        expect(state).toMatchObject({
            llmProvider: SANDBOX,
            aiPreparationRequired: true,
            aiAvailable: false,
        });
    });

    test('stripPrivateKeyFields removes both the legacy field and the credential map', () => {
        const doc = {
            courseId: 'C1',
            llmApiKey: { ciphertext: 'SECRET-LEGACY', status: 'valid' },
            llmCredentials: { [SANDBOX]: { ciphertext: 'SECRET-SANDBOX', status: 'valid' } },
        };
        const result = stripPrivateKeyFields(doc);

        expect(result.llmApiKey).toBeUndefined();
        expect(result.llmCredentials).toBeUndefined();
        expect(JSON.stringify(result)).not.toContain('SECRET');
        expect(result.courseId).toBe('C1');
        // The original document is not mutated.
        expect(doc.llmApiKey.ciphertext).toBe('SECRET-LEGACY');
    });

    test('a missing surface reports aiAvailable false without throwing', () => {
        expect(publicProviderKeyState(null)).toMatchObject({ llmProvider: OPENAI, aiAvailable: false });
    });
});

describe('provider-aware validation', () => {
    test('Proxy constructs the toolkit with key and endpoint and preserves exact /models ids', async () => {
        const models = ['openai/gpt-5.6-luna:2026-08', 'vendor/embed.model-v2'];
        const available = jest.spyOn(LLMModule.prototype, 'getAvailableModels').mockResolvedValue(models);

        const result = await validateProviderKey({
            provider: PROXY,
            apiKey: 'prx-real',
            endpoint: 'https://proxy.example/v1',
        });

        expect(result).toEqual({ ok: true, status: 'valid', provider: PROXY, models });
        expect(available).toHaveBeenCalledTimes(1);
        expect(fetchMock).not.toHaveBeenCalled();
        available.mockRestore();
    });

    test('Proxy discovery requires its configured endpoint and never guesses models', async () => {
        const result = await validateProviderKey({ provider: PROXY, apiKey: 'prx-real' });
        expect(result).toMatchObject({ ok: false, status: KEY_STATUSES.INVALID, provider: PROXY });
        expect(result.message).toMatch(/Proxy endpoint is not configured/);
        expect(fetchMock).not.toHaveBeenCalled();
    });

    test('Proxy discovery stops waiting after its validation deadline', async () => {
        const available = jest.spyOn(LLMModule.prototype, 'getAvailableModels')
            .mockImplementation(() => new Promise(() => {}));

        try {
            const result = await validateProviderKey({
                provider: PROXY,
                apiKey: 'prx-real',
                endpoint: 'https://proxy.example/v1',
                timeoutMs: 5,
            });

            expect(result).toMatchObject({ ok: false, status: KEY_STATUSES.INVALID, provider: PROXY });
            expect(result.detail).toContain('did not return its model list within 5 ms');
        } finally {
            available.mockRestore();
        }
    });

    test('OpenAI probes api.openai.com with the configured chat and embedding models', async () => {
        const models = ['gpt-4.1-mini', 'text-embedding-3-small'];
        fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ data: models.map(id => ({ id })) }) });
        fetchMock.mockResolvedValue(okResponse());
        const result = await validateProviderKey({
            provider: OPENAI, apiKey: 'sk-real', chatModel: 'gpt-4.1-mini', embeddingModel: 'text-embedding-3-small',
        });

        expect(result).toEqual({ ok: true, status: 'valid', provider: OPENAI, models, configurationCompatible: true });
        expect(fetchMock).toHaveBeenCalledTimes(3);
        expect(fetchMock.mock.calls[1][0]).toBe('https://api.openai.com/v1/embeddings');
        expect(JSON.parse(fetchMock.mock.calls[1][1].body).model).toBe('text-embedding-3-small');
        expect(fetchMock.mock.calls[2][0]).toBe('https://api.openai.com/v1/chat/completions');
        expect(JSON.parse(fetchMock.mock.calls[2][1].body).model).toBe('gpt-4.1-mini');
    });

    test('Sandbox probes the configured Sandbox endpoint with Qwen — never OpenAI', async () => {
        const models = ['qwen3.6-35b-a3b', 'qwen3-embedding-0.6b'];
        fetchMock.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ data: models.map(id => ({ id })) }) });
        fetchMock.mockResolvedValue(okResponse());
        const result = await validateProviderKey({
            provider: SANDBOX,
            apiKey: 'sbx-real',
            chatModel: 'qwen3.6-35b-a3b',
            embeddingModel: 'qwen3-embedding-0.6b',
            endpoint: 'https://sandbox.example/v1',
        });

        expect(result).toEqual({ ok: true, status: 'valid', provider: SANDBOX, models, configurationCompatible: true });
        const urls = fetchMock.mock.calls.map(call => call[0]);
        expect(urls).toEqual([
            'https://sandbox.example/v1/models',
            'https://sandbox.example/v1/embeddings',
            'https://sandbox.example/v1/chat/completions',
        ]);
        expect(urls.some(url => url.includes('api.openai.com'))).toBe(false);
        expect(JSON.parse(fetchMock.mock.calls[1][1].body).model).toBe('qwen3-embedding-0.6b');
        expect(JSON.parse(fetchMock.mock.calls[2][1].body).model).toBe('qwen3.6-35b-a3b');
        expect(fetchMock.mock.calls[1][1].headers.Authorization).toBe('Bearer sbx-real');
    });

    test('a trailing slash on the Sandbox endpoint does not double up', async () => {
        fetchMock.mockResolvedValue(okResponse());
        await validateProviderKey({ provider: SANDBOX, apiKey: 'k', endpoint: 'https://sandbox.example/v1/' });
        expect(fetchMock.mock.calls[0][0]).toBe('https://sandbox.example/v1/models');
    });

    test('a non-OpenAI key is NOT assumed valid — a bad Sandbox key is rejected', async () => {
        fetchMock.mockResolvedValue(errorResponse(401, { message: 'invalid token' }));
        const result = await validateProviderKey({
            provider: SANDBOX, apiKey: 'sbx-bad', endpoint: 'https://sandbox.example/v1',
        });

        expect(result.ok).toBe(false);
        expect(result.status).toBe(KEY_STATUSES.INVALID);
        expect(result.provider).toBe(SANDBOX);
        expect(result.message).toBe(messageForStatus(KEY_STATUSES.INVALID, SANDBOX));
        expect(result.message).toContain('UBC On-Premise LLM');
    });

    test('a Sandbox 429 maps to quota exhausted', async () => {
        fetchMock.mockResolvedValue(errorResponse(429, { message: 'too many requests' }));
        const result = await validateProviderKey({
            provider: SANDBOX, apiKey: 'sbx-spent', endpoint: 'https://sandbox.example/v1',
        });
        expect(result.status).toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
        expect(result.message).toContain('out of credits');
    });

    test('a Sandbox key with no configured endpoint fails with a safe diagnostic', async () => {
        const result = await validateProviderKey({ provider: SANDBOX, apiKey: 'sbx-key' });
        expect(result.ok).toBe(false);
        expect(result.status).toBe(KEY_STATUSES.INVALID);
        expect(result.message).toMatch(/Sandbox endpoint is not configured/);
        expect(fetchMock).not.toHaveBeenCalled();
    });

    test('an empty key is missing, before any network call', async () => {
        const result = await validateProviderKey({ provider: SANDBOX, apiKey: '   ' });
        expect(result).toMatchObject({ ok: false, status: KEY_STATUSES.MISSING, provider: SANDBOX });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    test('stub mode classifies both platforms by prefix without any network call', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.BIOCBOT_TEST_PROXY_MODELS = 'proxy-chat,proxy-embed';
        await expect(validateProviderKey({ provider: OPENAI, apiKey: 'sk-test-x' }))
            .resolves.toMatchObject({ ok: true, provider: OPENAI });
        await expect(validateProviderKey({ provider: SANDBOX, apiKey: 'sbx-test-x' }))
            .resolves.toMatchObject({ ok: true, provider: SANDBOX });
        await expect(validateProviderKey({ provider: PROXY, apiKey: 'prx-test-x' }))
            .resolves.toMatchObject({ ok: true, provider: PROXY, models: ['proxy-chat', 'proxy-embed'] });
        await expect(validateProviderKey({ provider: SANDBOX, apiKey: 'sbx-quota-x' }))
            .resolves.toMatchObject({ ok: false, status: KEY_STATUSES.QUOTA_EXHAUSTED });
        await expect(validateProviderKey({ provider: SANDBOX, apiKey: 'garbage' }))
            .resolves.toMatchObject({ ok: false, status: KEY_STATUSES.INVALID });
        expect(fetchMock).not.toHaveBeenCalled();
    });

    test('mapProviderErrorToStatus adds plain-HTTP fallbacks to the OpenAI mapping', () => {
        expect(mapProviderErrorToStatus({ status: 403 })).toBe(KEY_STATUSES.INVALID);
        expect(mapProviderErrorToStatus({ status: 429 })).toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
        expect(mapProviderErrorToStatus({ status: 500 })).toBeNull();
        expect(mapProviderErrorToStatus(null)).toBeNull();
    });
});

describe('key enforcement and diagnostics', () => {
    test('all selectable platforms require a scoped key; only ollama bypasses', () => {
        process.env.LLM_PROVIDER = OPENAI;
        expect(scopedKeysRequired()).toBe(true);
        process.env.LLM_PROVIDER = SANDBOX;
        expect(scopedKeysRequired()).toBe(true);
        process.env.LLM_PROVIDER = PROXY;
        expect(scopedKeysRequired()).toBe(true);
        process.env.LLM_PROVIDER = 'ollama';
        expect(scopedKeysRequired()).toBe(false);
    });

    test('LlmKeyError carries the platform so diagnostics name it', () => {
        const error = new LlmKeyError(KEY_STATUSES.INVALID, { type: 'course', id: 'C1' }, SANDBOX);
        expect(error.provider).toBe(SANDBOX);
        expect(error.message).toContain('UBC On-Premise LLM');
        expect(error.httpStatus).toBe(403);
        expect(error.code).toBe('LLM_KEY_INVALID');
    });

    test('structured errors stay safe and name the platform', () => {
        const body = structuredKeyErrorForProvider(KEY_STATUSES.QUOTA_EXHAUSTED, SANDBOX);
        expect(body).toEqual({
            success: false,
            code: 'LLM_KEY_QUOTA',
            message: messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED, SANDBOX),
            provider: SANDBOX,
        });
    });

    test('updateOwnerKeyStatus writes the provider-scoped status', async () => {
        const calls = [];
        const db = {
            collection: (name) => ({
                updateOne: async (query, update) => { calls.push({ name, query, update }); },
            }),
        };

        await updateOwnerKeyStatus(db, { type: 'course', id: 'C1' }, KEY_STATUSES.INVALID, SANDBOX);
        expect(calls[0].update.$set['llmCredentials.ubc-llm-sandbox.status']).toBe(KEY_STATUSES.INVALID);
        // A Sandbox failure must not mark the OpenAI key invalid.
        expect(calls[0].update.$set['llmApiKey.status']).toBeUndefined();

        await updateOwnerKeyStatus(db, { type: 'course', id: 'C1' }, KEY_STATUSES.INVALID, OPENAI);
        expect(calls[1].update.$set['llmCredentials.openai.status']).toBe(KEY_STATUSES.INVALID);
        expect(calls[1].update.$set['llmApiKey.status']).toBe(KEY_STATUSES.INVALID);
    });
});
