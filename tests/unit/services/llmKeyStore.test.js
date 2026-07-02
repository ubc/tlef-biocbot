const crypto = require('crypto');

const {
    CONTACT_EMAIL,
    ERROR_CODES,
    KEY_STATUSES,
    LlmKeyError,
    buildKeySubdocument,
    decryptApiKey,
    encryptApiKey,
    isKeyValid,
    isOllamaProvider,
    mapOpenAIErrorToStatus,
    messageForStatus,
    publicKeySummary,
    scopedKeysRequired,
    stripPrivateKeyFields,
    structuredKeyError,
    updateOwnerKeyStatus,
    validateApiKey,
} = require('../../../src/services/llmKeyStore');

// Several helpers read process.env at call time (encryption secret, provider,
// validation stub). Give every test a private copy so mutations never leak.
const OLD_ENV = process.env;
beforeEach(() => {
    process.env = { ...OLD_ENV };
});
afterAll(() => {
    process.env = OLD_ENV;
});

// The deterministic key the module derives under NODE_ENV=test (jest sets this).
const TEST_KEY = crypto.createHash('sha256').update('biocbot-test-llm-key-secret').digest();

describe('llmKeyStore.encryptApiKey / decryptApiKey', () => {
    test('round-trips a key through the deterministic test key', () => {
        const cipher = encryptApiKey('sk-test-abc123');
        expect(typeof cipher).toBe('string');
        expect(cipher.startsWith('v1:')).toBe(true);
        expect(decryptApiKey(cipher)).toBe('sk-test-abc123');
    });

    test('produces a fresh ciphertext each call (random IV) that still decrypts', () => {
        const a = encryptApiKey('sk-test-same');
        const b = encryptApiKey('sk-test-same');
        expect(a).not.toBe(b);
        expect(decryptApiKey(a)).toBe('sk-test-same');
        expect(decryptApiKey(b)).toBe('sk-test-same');
    });

    test('coerces a non-string key to its String() form', () => {
        expect(decryptApiKey(encryptApiKey(12345))).toBe('12345');
    });

    test('decryptApiKey rejects missing / non-string ciphertext', () => {
        expect(() => decryptApiKey(null)).toThrow(/Missing encrypted API key/);
        expect(() => decryptApiKey('')).toThrow(/Missing encrypted API key/);
        expect(() => decryptApiKey(42)).toThrow(/Missing encrypted API key/);
    });

    test('decryptApiKey rejects an unknown version or malformed segments', () => {
        expect(() => decryptApiKey('not-a-cipher')).toThrow(/Unsupported encrypted API key format/);
        const real = encryptApiKey('sk-test-x');
        const tampered = real.replace(/^v1:/, 'v2:');
        expect(() => decryptApiKey(tampered)).toThrow(/Unsupported encrypted API key format/);
    });

    test('decryptApiKey throws when the GCM auth tag no longer matches the data', () => {
        const real = encryptApiKey('sk-test-tamper');
        const [version, iv, tag, payload] = real.split(':');
        // Flip the last char of the encrypted payload so authentication fails.
        const flipped = payload.slice(0, -1) + (payload.endsWith('A') ? 'B' : 'A');
        expect(() => decryptApiKey([version, iv, tag, flipped].join(':'))).toThrow();
    });
});

describe('llmKeyStore.getEncryptionKey (exercised via encrypt)', () => {
    // getEncryptionKey is private; we observe it through encrypt/decrypt and the
    // errors it throws for bad BIOCBOT_KEY_ENCRYPTION_SECRET values.
    test('test mode derives a stable 32-byte key with no secret set', () => {
        delete process.env.BIOCBOT_KEY_ENCRYPTION_SECRET;
        // A value encrypted now must decrypt with that same derived key.
        const cipher = encryptApiKey('sk-test-derived');
        const ivB64 = cipher.split(':')[1];
        // Decrypt manually with the expected TEST_KEY to prove which key was used.
        const [, , tagB64, payloadB64] = cipher.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', TEST_KEY, Buffer.from(ivB64, 'base64'));
        decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
        const out = Buffer.concat([decipher.update(Buffer.from(payloadB64, 'base64')), decipher.final()]).toString('utf8');
        expect(out).toBe('sk-test-derived');
    });

    test('accepts a base64-encoded 32-byte secret', () => {
        const secret = crypto.randomBytes(32);
        process.env.BIOCBOT_KEY_ENCRYPTION_SECRET = secret.toString('base64');
        const cipher = encryptApiKey('sk-test-b64');
        const [, ivB64, tagB64, payloadB64] = cipher.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', secret, Buffer.from(ivB64, 'base64'));
        decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
        const out = Buffer.concat([decipher.update(Buffer.from(payloadB64, 'base64')), decipher.final()]).toString('utf8');
        expect(out).toBe('sk-test-b64');
    });

    test('accepts a 64-char hex secret', () => {
        const secret = crypto.randomBytes(32);
        process.env.BIOCBOT_KEY_ENCRYPTION_SECRET = secret.toString('hex');
        const cipher = encryptApiKey('sk-test-hex');
        const [, ivB64, tagB64, payloadB64] = cipher.split(':');
        const decipher = crypto.createDecipheriv('aes-256-gcm', secret, Buffer.from(ivB64, 'base64'));
        decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
        const out = Buffer.concat([decipher.update(Buffer.from(payloadB64, 'base64')), decipher.final()]).toString('utf8');
        expect(out).toBe('sk-test-hex');
    });

    test('rejects a secret that decodes to the wrong length', () => {
        process.env.BIOCBOT_KEY_ENCRYPTION_SECRET = 'too-short-not-32-bytes';
        expect(() => encryptApiKey('x')).toThrow(/32 bytes/);
    });

    test('requires a secret when not in test/stub mode', () => {
        delete process.env.BIOCBOT_KEY_ENCRYPTION_SECRET;
        delete process.env.BIOCBOT_TEST_LLM_STUB;
        delete process.env.NODE_ENV;
        expect(() => encryptApiKey('x')).toThrow(/BIOCBOT_KEY_ENCRYPTION_SECRET is required/);
    });
});

describe('llmKeyStore.publicKeySummary', () => {
    test('returns the missing summary for null / non-object input', () => {
        const missing = { status: KEY_STATUSES.MISSING, last4: null, validatedAt: null, updatedAt: null };
        expect(publicKeySummary(null)).toEqual(missing);
        expect(publicKeySummary(undefined)).toEqual(missing);
        expect(publicKeySummary('nope')).toEqual(missing);
    });

    test('surfaces only the public fields, defaulting status to missing', () => {
        const validatedAt = new Date('2026-01-01');
        expect(publicKeySummary({ status: 'valid', last4: '1234', validatedAt, updatedAt: validatedAt, ciphertext: 'SECRET' }))
            .toEqual({ status: 'valid', last4: '1234', validatedAt, updatedAt: validatedAt });
        expect(publicKeySummary({ last4: '9999' })).toEqual({
            status: KEY_STATUSES.MISSING, last4: '9999', validatedAt: null, updatedAt: null,
        });
    });
});

describe('llmKeyStore.isKeyValid', () => {
    test('true only when the summarized status is valid', () => {
        expect(isKeyValid({ status: 'valid' })).toBe(true);
        expect(isKeyValid({ status: 'invalid' })).toBe(false);
        expect(isKeyValid({ status: 'quota_exhausted' })).toBe(false);
        expect(isKeyValid(null)).toBe(false);
    });
});

describe('llmKeyStore.stripPrivateKeyFields', () => {
    test('passes through null / non-object docs untouched', () => {
        expect(stripPrivateKeyFields(null)).toBeNull();
        expect(stripPrivateKeyFields('doc')).toBe('doc');
    });

    test('replaces llmApiKey with a public summary + aiAvailable flag', () => {
        const doc = {
            courseId: 'BIOC-1',
            llmApiKey: { status: 'valid', last4: '4321', ciphertext: 'SECRET' },
        };
        const result = stripPrivateKeyFields(doc);
        expect(result.courseId).toBe('BIOC-1');
        expect(result.llmApiKey).toBeUndefined();
        expect(result.llmKey).toEqual({ status: 'valid', last4: '4321', validatedAt: null, updatedAt: null });
        expect(result.aiAvailable).toBe(true);
        // Original doc is not mutated.
        expect(doc.llmApiKey.ciphertext).toBe('SECRET');
    });

    test('aiAvailable is false for missing or invalid keys', () => {
        expect(stripPrivateKeyFields({ courseId: 'x' }).aiAvailable).toBe(false);
        expect(stripPrivateKeyFields({ llmApiKey: { status: 'invalid' } }).aiAvailable).toBe(false);
    });
});

describe('llmKeyStore.messageForStatus', () => {
    test('each status produces a contact-bearing message', () => {
        expect(messageForStatus(KEY_STATUSES.INVALID)).toContain('invalid');
        expect(messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED)).toContain('out of credits');
        expect(messageForStatus(KEY_STATUSES.MISSING)).toContain('AI is disabled');
        for (const status of [KEY_STATUSES.INVALID, KEY_STATUSES.QUOTA_EXHAUSTED, KEY_STATUSES.MISSING]) {
            expect(messageForStatus(status)).toContain(CONTACT_EMAIL);
        }
    });

    test('unknown status falls back to the missing message', () => {
        expect(messageForStatus('weird')).toBe(messageForStatus(KEY_STATUSES.MISSING));
    });
});

describe('llmKeyStore.mapOpenAIErrorToStatus', () => {
    test('null/undefined error maps to null', () => {
        expect(mapOpenAIErrorToStatus(null)).toBeNull();
        expect(mapOpenAIErrorToStatus(undefined)).toBeNull();
    });

    test('401, invalid_api_key code, and "incorrect api key" message map to invalid', () => {
        expect(mapOpenAIErrorToStatus({ status: 401 })).toBe(KEY_STATUSES.INVALID);
        expect(mapOpenAIErrorToStatus({ code: 'invalid_api_key' })).toBe(KEY_STATUSES.INVALID);
        expect(mapOpenAIErrorToStatus({ message: 'Incorrect API key provided' })).toBe(KEY_STATUSES.INVALID);
    });

    test('invalid_request_error only maps to invalid when the message also names the api key', () => {
        expect(mapOpenAIErrorToStatus({ type: 'invalid_request_error', message: 'Missing API key' }))
            .toBe(KEY_STATUSES.INVALID);
        expect(mapOpenAIErrorToStatus({ type: 'invalid_request_error', message: 'bad model name' }))
            .toBeNull();
    });

    test('429 plus a quota signal maps to quota_exhausted', () => {
        expect(mapOpenAIErrorToStatus({ status: 429, code: 'insufficient_quota' })).toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
        expect(mapOpenAIErrorToStatus({ status: 429, message: 'You exceeded your current quota' })).toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
        expect(mapOpenAIErrorToStatus({ status: 429, message: 'You are out of credits' })).toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
    });

    test('a 429 with no quota signal (plain rate limit) maps to null', () => {
        expect(mapOpenAIErrorToStatus({ status: 429, code: 'rate_limit_exceeded' })).toBeNull();
    });

    test('reads nested status/code shapes (response / error / response.data)', () => {
        expect(mapOpenAIErrorToStatus({ response: { status: 401 } })).toBe(KEY_STATUSES.INVALID);
        expect(mapOpenAIErrorToStatus({ error: { code: 'invalid_api_key' } })).toBe(KEY_STATUSES.INVALID);
        expect(mapOpenAIErrorToStatus({ status: 429, response: { data: { error: { code: 'insufficient_quota' } } } }))
            .toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
    });

    test('an unrelated server error maps to null', () => {
        expect(mapOpenAIErrorToStatus({ status: 500, message: 'internal error' })).toBeNull();
    });
});

describe('llmKeyStore.structuredKeyError', () => {
    test('maps each status to its error code + message', () => {
        expect(structuredKeyError(KEY_STATUSES.INVALID)).toEqual({
            success: false, code: ERROR_CODES.invalid, message: messageForStatus(KEY_STATUSES.INVALID),
        });
        expect(structuredKeyError(KEY_STATUSES.QUOTA_EXHAUSTED).code).toBe(ERROR_CODES.quota_exhausted);
        expect(structuredKeyError(KEY_STATUSES.MISSING).code).toBe(ERROR_CODES.missing);
    });

    test('unknown status falls back to the missing error code', () => {
        expect(structuredKeyError('bogus').code).toBe(ERROR_CODES.missing);
    });
});

describe('llmKeyStore.LlmKeyError', () => {
    test('carries status/code/httpStatus/scope and an Error message', () => {
        const scope = { type: 'course', id: 'BIOC-1' };
        const err = new LlmKeyError(KEY_STATUSES.INVALID, scope);
        expect(err).toBeInstanceOf(Error);
        expect(err.name).toBe('LlmKeyError');
        expect(err.status).toBe(KEY_STATUSES.INVALID);
        expect(err.code).toBe(ERROR_CODES.invalid);
        expect(err.httpStatus).toBe(403);
        expect(err.scope).toBe(scope);
        expect(err.message).toBe(messageForStatus(KEY_STATUSES.INVALID));
    });

    test('defaults to the missing status when none is given', () => {
        const err = new LlmKeyError();
        expect(err.status).toBe(KEY_STATUSES.MISSING);
        expect(err.code).toBe(ERROR_CODES.missing);
        expect(err.scope).toEqual({});
    });
});

describe('llmKeyStore.buildKeySubdocument', () => {
    test('trims the key, records last4 + valid status, and encrypts recoverably', () => {
        const doc = buildKeySubdocument('  sk-test-wxyz  ', 'admin-1');
        expect(doc.last4).toBe('wxyz');
        expect(doc.status).toBe(KEY_STATUSES.VALID);
        expect(doc.updatedBy).toBe('admin-1');
        expect(doc.validatedAt).toBeInstanceOf(Date);
        expect(doc.updatedAt).toBeInstanceOf(Date);
        expect(decryptApiKey(doc.ciphertext)).toBe('sk-test-wxyz');
    });

    test('defaults updatedBy to null when no updater is given', () => {
        const doc = buildKeySubdocument('sk-test-1234');
        expect(doc.updatedBy).toBeNull();
        expect(doc.last4).toBe('1234');
        expect(decryptApiKey(doc.ciphertext)).toBe('sk-test-1234');
    });

    test('coerces a non-string key to an empty key (which is not round-trippable)', () => {
        const doc = buildKeySubdocument(12345);
        expect(doc.last4).toBe('');
        // encrypt('') yields an empty payload segment, which decryptApiKey treats
        // as malformed — documenting that an empty key cannot be recovered.
        expect(() => decryptApiKey(doc.ciphertext)).toThrow(/Unsupported encrypted API key format/);
    });
});

describe('llmKeyStore.isOllamaProvider / scopedKeysRequired', () => {
    test('isOllamaProvider tracks LLM_PROVIDER (case-insensitive)', () => {
        process.env.LLM_PROVIDER = 'Ollama';
        expect(isOllamaProvider()).toBe(true);
        process.env.LLM_PROVIDER = 'openai';
        expect(isOllamaProvider()).toBe(false);
    });

    test('scopedKeysRequired is true for openai or when the LLM stub is on', () => {
        delete process.env.BIOCBOT_TEST_LLM_STUB;
        process.env.LLM_PROVIDER = 'openai';
        expect(scopedKeysRequired()).toBe(true);

        process.env.LLM_PROVIDER = 'ollama';
        expect(scopedKeysRequired()).toBe(false);

        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        expect(scopedKeysRequired()).toBe(true);
    });
});

describe('llmKeyStore.validateApiKey', () => {
    test('rejects an empty key as missing before any provider work', async () => {
        await expect(validateApiKey('   ')).resolves.toMatchObject({ ok: false, status: KEY_STATUSES.MISSING });
    });

    test('stub mode classifies keys by prefix without hitting the network', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        await expect(validateApiKey('sk-test-good')).resolves.toEqual({ ok: true, status: KEY_STATUSES.VALID });
        await expect(validateApiKey('sk-quota-x')).resolves.toMatchObject({ ok: false, status: KEY_STATUSES.QUOTA_EXHAUSTED });
        await expect(validateApiKey('sk-anything-else')).resolves.toMatchObject({ ok: false, status: KEY_STATUSES.INVALID });
    });

    test('non-openai providers accept any non-empty key without validation', async () => {
        delete process.env.BIOCBOT_TEST_LLM_STUB;
        process.env.LLM_PROVIDER = 'ollama';
        await expect(validateApiKey('whatever')).resolves.toEqual({ ok: true, status: KEY_STATUSES.VALID });
    });
});

describe('llmKeyStore.updateOwnerKeyStatus', () => {
    function recordingDb() {
        const calls = [];
        return {
            calls,
            collection(name) {
                return {
                    updateOne: async (query, update) => {
                        calls.push({ name, query, update });
                        return { modifiedCount: 1 };
                    },
                };
            },
        };
    }

    test('no-ops without db, scope, status, or for the missing status', async () => {
        const db = recordingDb();
        await updateOwnerKeyStatus(null, { type: 'course', id: 'x' }, KEY_STATUSES.VALID);
        await updateOwnerKeyStatus(db, null, KEY_STATUSES.VALID);
        await updateOwnerKeyStatus(db, { type: 'course', id: 'x' }, null);
        await updateOwnerKeyStatus(db, { type: 'course', id: 'x' }, KEY_STATUSES.MISSING);
        expect(db.calls).toHaveLength(0);
    });

    test('routes each scope type to the right collection and query', async () => {
        const db = recordingDb();
        await updateOwnerKeyStatus(db, { type: 'course', id: 'BIOC-1' }, KEY_STATUSES.INVALID);
        await updateOwnerKeyStatus(db, { type: 'superchat', id: 'sc-1' }, KEY_STATUSES.INVALID);
        await updateOwnerKeyStatus(db, { type: 'notes' }, KEY_STATUSES.INVALID);
        await updateOwnerKeyStatus(db, { type: 'superCourseChat' }, KEY_STATUSES.INVALID);

        expect(db.calls.map(c => c.name)).toEqual(['courses', 'superchats', 'settings', 'settings']);
        expect(db.calls[0].query).toEqual({ courseId: 'BIOC-1' });
        expect(db.calls[1].query).toEqual({ superchatId: 'sc-1' });
        expect(db.calls[2].query).toEqual({ _id: 'notesLlm' });
        expect(db.calls[3].query).toEqual({ _id: 'superCourseChat' });
        expect(db.calls[0].update.$set['llmApiKey.status']).toBe(KEY_STATUSES.INVALID);
        expect(db.calls[0].update.$set['llmApiKey.updatedAt']).toBeInstanceOf(Date);
    });

    test('ignores an unrecognized scope type', async () => {
        const db = recordingDb();
        await updateOwnerKeyStatus(db, { type: 'mystery', id: 'x' }, KEY_STATUSES.INVALID);
        expect(db.calls).toHaveLength(0);
    });
});

describe('llmKeyStore.validateApiKey — OpenAI provider with a mocked fetch (no network)', () => {
    const okResponse = () => ({ ok: true, status: 200, json: async () => ({ ok: true }) });
    const errorResponse = (status, error) => ({ ok: false, status, json: async () => ({ error }) });
    const ORIGINAL_FETCH = global.fetch;

    beforeEach(() => {
        process.env.LLM_PROVIDER = 'openai';
        delete process.env.BIOCBOT_TEST_LLM_STUB;
        delete process.env.OPENAI_MODEL;
        global.fetch = jest.fn();
    });
    afterAll(() => { global.fetch = ORIGINAL_FETCH; });

    test('valid key: probes embeddings then chat with the bearer key and returns valid', async () => {
        global.fetch.mockResolvedValue(okResponse());
        const result = await validateApiKey(' sk-real ');
        expect(result).toEqual({ ok: true, status: 'valid' });

        expect(global.fetch).toHaveBeenCalledTimes(2);
        const [embedUrl, embedInit] = global.fetch.mock.calls[0];
        expect(embedUrl).toBe('https://api.openai.com/v1/embeddings');
        expect(embedInit.headers.Authorization).toBe('Bearer sk-real');
        const [chatUrl, chatInit] = global.fetch.mock.calls[1];
        expect(chatUrl).toBe('https://api.openai.com/v1/chat/completions');
        // Default (non gpt-5) model probes with a single-token completion.
        expect(JSON.parse(chatInit.body)).toMatchObject({ model: 'gpt-4.1-mini', max_tokens: 1 });
    });

    test('gpt-5 models use max_completion_tokens with a model-specific reasoning effort', async () => {
        global.fetch.mockResolvedValue(okResponse());
        process.env.OPENAI_MODEL = 'gpt-5.4-nano';
        await validateApiKey('sk-real');
        expect(JSON.parse(global.fetch.mock.calls[1][1].body)).toMatchObject({
            model: 'gpt-5.4-nano', max_completion_tokens: 16, reasoning_effort: 'low',
        });

        global.fetch.mockClear();
        process.env.OPENAI_MODEL = 'gpt-5.2';
        await validateApiKey('sk-real');
        expect(JSON.parse(global.fetch.mock.calls[1][1].body)).toMatchObject({
            model: 'gpt-5.2', reasoning_effort: 'minimal',
        });
    });

    test('a 401 with invalid_api_key maps to the invalid status with the provider detail', async () => {
        global.fetch.mockResolvedValue(errorResponse(401, { message: 'Incorrect API key provided', code: 'invalid_api_key' }));
        const result = await validateApiKey('sk-bad');
        expect(result.ok).toBe(false);
        expect(result.status).toBe(KEY_STATUSES.INVALID);
        expect(result.message).toBe(messageForStatus(KEY_STATUSES.INVALID));
        expect(result.detail).toBe('Incorrect API key provided');
    });

    test('a 429 insufficient_quota maps to quota_exhausted', async () => {
        global.fetch.mockResolvedValue(errorResponse(429, { message: 'You exceeded your current quota', code: 'insufficient_quota' }));
        const result = await validateApiKey('sk-broke');
        expect(result.ok).toBe(false);
        expect(result.status).toBe(KEY_STATUSES.QUOTA_EXHAUSTED);
        expect(result.message).toBe(messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED));
    });

    test('an unparseable error body falls back to an HTTP-status message and invalid', async () => {
        global.fetch.mockResolvedValue({ ok: false, status: 500, json: async () => { throw new Error('bad json'); } });
        const result = await validateApiKey('sk-mystery');
        expect(result.ok).toBe(false);
        expect(result.status).toBe(KEY_STATUSES.INVALID);
        expect(result.detail).toBe('OpenAI validation failed with HTTP 500');
    });

    test('a failure on the chat probe (after embeddings succeeds) still fails validation', async () => {
        global.fetch
            .mockResolvedValueOnce(okResponse())
            .mockResolvedValueOnce(errorResponse(401, { message: 'invalid api key', code: 'invalid_api_key' }));
        const result = await validateApiKey('sk-half');
        expect(result.ok).toBe(false);
        expect(result.status).toBe(KEY_STATUSES.INVALID);
    });
});
