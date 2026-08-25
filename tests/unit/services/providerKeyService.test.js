/**
 * Surface-level key operations: saving a key for a platform, switching
 * platforms (which stages rather than flips), testing a stored key, and working
 * out which content a surface's migration has to cover.
 */
const startedMigrations = [];
jest.mock('../../../src/services/providerMigrationRunner', () => ({
    // The runner is exercised in its own suite; here we only assert that the
    // request does NOT wait for a whole course to be re-indexed.
    startMigration: jest.fn((db, migrationId) => { startedMigrations.push(migrationId); }),
}));
jest.mock('../../../src/services/config', () => ({
    getProviderInfra: jest.fn((provider) => ({
        provider,
        endpoint: provider === 'ubc-llm-sandbox'
            ? 'https://sandbox.example/v1'
            : provider === 'ubc-llm-proxy' ? 'https://proxy.example/v1' : null,
        bootstrapApiKey: undefined,
    })),
}));

const mockValidateProviderKey = jest.fn();
jest.mock('../../../src/services/llmKeyStore', () => {
    const actual = jest.requireActual('../../../src/services/llmKeyStore');
    return { ...actual, validateProviderKey: (...args) => mockValidateProviderKey(...args) };
});

const providerKeys = require('../../../src/services/providerKeyService');
const migrations = require('../../../src/services/providerMigrationService');
const adminModelSettings = require('../../../src/services/adminModelSettings');
const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');
const { providerLabel } = require('../../../src/services/llmProviders');
const { buildEmbeddingProfile } = require('../../../src/services/embeddingConfig');
const { buildIndexRecord, contentHash, INDEX_STATUSES } = require('../../../src/services/embeddingIndexService');
const { memoryDb } = require('../helpers/memory-db');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';
const PROXY = 'ubc-llm-proxy';
const COURSE_SCOPE = { type: 'course', id: 'C1' };
const GPT_PROFILE = buildEmbeddingProfile({ provider: OPENAI, embeddingModel: 'text-embedding-3-small' });

beforeEach(() => {
    startedMigrations.length = 0;
    mockValidateProviderKey.mockReset().mockResolvedValue({ ok: true, status: 'valid', provider: OPENAI });
    adminModelSettings.invalidateCache();
});

function registry() {
    return {
        evictCourse: jest.fn(),
        evictSuperchat: jest.fn(),
        evictNotes: jest.fn(),
        evictSuperCourseChat: jest.fn(),
    };
}

describe('validating against the right platform', () => {
    test('a Sandbox key is probed with the Sandbox models and endpoint', async () => {
        const db = memoryDb({ settings: [] });
        await providerKeys.validateForProvider(db, SANDBOX, 'sbx-key');

        expect(mockValidateProviderKey).toHaveBeenCalledWith({
            provider: SANDBOX,
            apiKey: 'sbx-key',
            chatModel: 'qwen3.6-35b-a3b',
            embeddingModel: 'qwen3-embedding-0.6b',
            endpoint: 'https://sandbox.example/v1',
        });
    });

    test('a GPT key is probed with the GPT models and no endpoint', async () => {
        const db = memoryDb({ settings: [] });
        await providerKeys.validateForProvider(db, OPENAI, 'sk-key');

        expect(mockValidateProviderKey).toHaveBeenCalledWith({
            provider: OPENAI,
            apiKey: 'sk-key',
            chatModel: 'gpt-4.1-mini',
            embeddingModel: 'text-embedding-3-small',
            endpoint: null,
        });
    });

    test('the admin\'s configured models are what get probed', async () => {
        const db = memoryDb({
            settings: [{ _id: 'llm', providers: { [OPENAI]: { chatModel: 'gpt-5-nano', embeddingModel: 'text-embedding-3-large' } } }],
        });
        await providerKeys.validateForProvider(db, OPENAI, 'sk-key');

        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({
            chatModel: 'gpt-5-nano', embeddingModel: 'text-embedding-3-large',
        }));
    });

    test('a proxy key returns exact ids without polluting the default template', async () => {
        const models = ['openai/gpt-5.6-luna:2026', 'vendor/embed.model'];
        mockValidateProviderKey.mockResolvedValue({
            ok: true, status: 'valid', provider: PROXY, models,
        });
        const db = memoryDb({ settings: [] });

        const result = await providerKeys.validateForProvider(db, PROXY, 'prx-key');
        const settings = await adminModelSettings.getProviderSettings(db, PROXY, { force: true });

        expect(result.models).toEqual(models);
        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({
            provider: PROXY,
            apiKey: 'prx-key',
            chatModel: null,
            embeddingModel: null,
            endpoint: 'https://proxy.example/v1',
        }));
        expect(settings.availableModels).toEqual([]);
        expect(settings.configured).toBe(false);
    });

    test('proxy reasoning discovery returns operation-supported values without inspecting the model name', async () => {
        const oldStub = process.env.BIOCBOT_TEST_LLM_STUB;
        const oldEfforts = process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS;
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS = 'none,low,UBERFAST';

        try {
            await expect(providerKeys.discoverProxyReasoningEfforts(
                memoryDb({ settings: [] }),
                'vendor/model.with-an-unrelated-name'
            )).resolves.toEqual(['none', 'low', 'UBERFAST']);
        } finally {
            if (oldStub === undefined) delete process.env.BIOCBOT_TEST_LLM_STUB;
            else process.env.BIOCBOT_TEST_LLM_STUB = oldStub;
            if (oldEfforts === undefined) delete process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS;
            else process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS = oldEfforts;
        }
    });
});

describe('saving a key', () => {
    test('the first key for a surface activates immediately — no migration', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const reg = registry();

        const result = await providerKeys.saveSurfaceKey(db, {
            scope: COURSE_SCOPE, provider: OPENAI, apiKey: 'sk-first-key', updatedBy: 'i1', registry: reg,
        });

        expect(result.httpStatus).toBe(200);
        expect(result.body.migration).toBeNull();
        expect(startedMigrations).toEqual([]);
        expect(reg.evictCourse).toHaveBeenCalledWith('C1');

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(OPENAI);
        expect(course.llmCredentials[OPENAI].ciphertext).toBeTruthy();
    });

    test('replacing the key for the SAME platform activates immediately', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-old-key', 'i1', OPENAI) },
            }],
        });

        const result = await providerKeys.saveSurfaceKey(db, {
            scope: COURSE_SCOPE, provider: OPENAI, apiKey: 'sk-new-key', updatedBy: 'i1',
        });

        expect(result.httpStatus).toBe(200);
        expect(startedMigrations).toEqual([]);
        expect(result.body.llmKey.last4).toBe('-key');
    });

    test('an invalid key is refused and nothing is written', async () => {
        mockValidateProviderKey.mockResolvedValue({
            ok: false, status: 'quota_exhausted', message: 'out of credits', provider: SANDBOX,
        });
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });

        const result = await providerKeys.saveSurfaceKey(db, {
            scope: COURSE_SCOPE, provider: SANDBOX, apiKey: 'sbx-spent',
        });

        expect(result.httpStatus).toBe(400);
        expect(result.body).toMatchObject({ code: 'LLM_KEY_QUOTA', llmProvider: SANDBOX });
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.llmCredentials).toBeUndefined();
    });

    test('saving a key for another platform does not prepare or switch implicitly', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI) },
            }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'course text' }],
        });

        const result = await providerKeys.saveSurfaceKey(db, {
            scope: COURSE_SCOPE, provider: SANDBOX, apiKey: 'sbx-new-key', updatedBy: 'i1',
        });

        expect(result.httpStatus).toBe(200);
        expect(result.body.message).toBe(`${providerLabel(SANDBOX)} API key saved`);
        expect(startedMigrations).toHaveLength(0);

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(OPENAI);           // still serving on GPT
        expect(course.pendingLlmProvider).toBeUndefined();
        expect(course.providerMigrationId).toBeUndefined();
        expect(course.llmCredentials[SANDBOX].ciphertext).toBeTruthy();
    });

    test('no key material appears in the response', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const result = await providerKeys.saveSurfaceKey(db, {
            scope: COURSE_SCOPE, provider: OPENAI, apiKey: 'sk-super-secret-value',
        });

        const serialised = JSON.stringify(result.body);
        expect(serialised).not.toContain('sk-super-secret-value');
        expect(serialised).not.toContain('ciphertext');
    });
});

describe('switching back to a stored platform', () => {
    function dualKeyCourse() {
        return {
            courseId: 'C1',
            activeLlmProvider: SANDBOX,
            llmCredentials: {
                [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI),
                [SANDBOX]: buildKeySubdocument('sbx-key', 'i1', SANDBOX),
            },
        };
    }

    test('an unprepared provider is refused with a clear next action', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse()],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });

        const result = await providerKeys.switchToStoredProvider(db, {
            scope: COURSE_SCOPE, provider: OPENAI, requestedBy: 'i1', registry: registry(),
        });

        expect(result.httpStatus).toBe(409);
        expect(result.body).toMatchObject({ code: 'LLM_PROVIDER_NOT_PREPARED', unpreparedCount: 1 });
        expect(startedMigrations).toHaveLength(0);
        expect(mockValidateProviderKey).not.toHaveBeenCalled();

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(SANDBOX);   // unchanged until migration completes
        expect(course.pendingLlmProvider).toBeUndefined();
    });

    test('explicit preparation starts a background job without changing the active provider', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse()],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });

        const result = await providerKeys.prepareStoredProvider(db, {
            scope: COURSE_SCOPE, provider: OPENAI, requestedBy: 'i1',
        });

        expect(result.httpStatus).toBe(202);
        expect(result.body.migration.kind).toBe('prepare');
        expect(startedMigrations).toHaveLength(1);
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(SANDBOX);
        expect(course.pendingLlmProvider).toBe(OPENAI);
    });

    test('initial preparation can keep a new surface unavailable until its job completes', async () => {
        const course = dualKeyCourse();
        course.activeLlmProvider = OPENAI;
        const db = memoryDb({
            courses: [course],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });

        const result = await providerKeys.prepareStoredProvider(db, {
            scope: COURSE_SCOPE,
            provider: OPENAI,
            requestedBy: 'i1',
            disableUntilReady: true,
        });

        expect(result.httpStatus).toBe(202);
        expect(result.body).toMatchObject({ aiAvailable: false, aiPreparationRequired: true });
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved).toMatchObject({
            aiPreparationRequired: true,
            pendingLlmProvider: OPENAI,
            providerMigrationId: result.body.migration.migrationId,
        });
        expect(startedMigrations).toEqual([result.body.migration.migrationId]);
    });

    test('preparation with no missing work becomes ready synchronously', async () => {
        const text = 'text';
        const db = memoryDb({
            courses: [dualKeyCourse()],
            documents: [{
                documentId: 'd1', courseId: 'C1', content: text,
                embeddingIndexes: {
                    [GPT_PROFILE.storageKey]: buildIndexRecord({
                        profile: GPT_PROFILE,
                        hash: contentHash(text),
                        status: INDEX_STATUSES.READY,
                        indexedAt: new Date(),
                    }),
                },
            }],
        });

        const result = await providerKeys.prepareStoredProvider(db, {
            scope: COURSE_SCOPE,
            provider: OPENAI,
            requestedBy: 'i1',
            disableUntilReady: true,
        });

        expect(result.httpStatus).toBe(200);
        expect(result.body).toMatchObject({ aiAvailable: true, aiPreparationRequired: false });
        expect(result.body.migration.status).toBe('completed');
        expect(startedMigrations).toEqual([]);
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved).toMatchObject({ activeLlmProvider: OPENAI, aiPreparationRequired: false });
        expect(saved.pendingLlmProvider).toBeNull();
        expect(saved.providerMigrationId).toBeNull();
    });

    test('a prepared stored provider switches immediately without key re-entry', async () => {
        const text = 'text';
        const db = memoryDb({
            courses: [dualKeyCourse()],
            documents: [{
                documentId: 'd1', courseId: 'C1', content: text,
                embeddingIndexes: {
                    [GPT_PROFILE.storageKey]: buildIndexRecord({
                        profile: GPT_PROFILE,
                        hash: contentHash(text),
                        status: INDEX_STATUSES.READY,
                        indexedAt: new Date(),
                    }),
                },
            }],
        });

        const result = await providerKeys.switchToStoredProvider(db, {
            scope: COURSE_SCOPE, provider: OPENAI, requestedBy: 'i1', registry: registry(),
        });

        expect(result.httpStatus).toBe(200);
        expect(result.body.message).toBe(`Now using ${providerLabel(OPENAI)}.`);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider).toBe(OPENAI);
        expect(startedMigrations).toEqual([]);
        expect(mockValidateProviderKey).not.toHaveBeenCalled();
    });

    test('switching to a platform with no stored key asks for one', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI) },
            }],
        });

        const result = await providerKeys.switchToStoredProvider(db, { scope: COURSE_SCOPE, provider: SANDBOX });

        expect(result.httpStatus).toBe(400);
        expect(result.body.code).toBe('LLM_KEY_MISSING');
        expect(result.body.message).toContain(`No ${providerLabel(SANDBOX)} API key is saved`);
        expect(startedMigrations).toEqual([]);
    });

    test('switching to the platform already in use is a no-op', async () => {
        const db = memoryDb({ courses: [dualKeyCourse()] });
        const result = await providerKeys.switchToStoredProvider(db, { scope: COURSE_SCOPE, provider: SANDBOX });

        expect(result.httpStatus).toBe(200);
        expect(result.body.message).toContain(`Already using ${providerLabel(SANDBOX)}`);
        expect(startedMigrations).toEqual([]);
    });
});

describe('testing a stored key', () => {
    test('a passing test records validity for that platform only', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: SANDBOX,
                llmCredentials: {
                    [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI),
                    [SANDBOX]: buildKeySubdocument('sbx-key', 'i1', SANDBOX),
                },
            }],
        });
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });

        const result = await providerKeys.testSurfaceKey(db, { scope: COURSE_SCOPE, registry: registry() });

        expect(result.httpStatus).toBe(200);
        expect(result.body.llmProvider).toBe(SANDBOX);
        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({
            provider: SANDBOX, apiKey: 'sbx-key',
        }));
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.llmCredentials[SANDBOX].validatedAt).toBeInstanceOf(Date);
    });

    test('a failing test records the status without deleting the key', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI) },
            }],
        });
        mockValidateProviderKey.mockResolvedValue({ ok: false, status: 'invalid', message: 'bad key', provider: OPENAI });

        const result = await providerKeys.testSurfaceKey(db, { scope: COURSE_SCOPE });

        expect(result.httpStatus).toBe(400);
        expect(result.body).toMatchObject({ code: 'LLM_KEY_INVALID', aiAvailable: false });
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.llmCredentials[OPENAI].status).toBe('invalid');
        expect(course.llmCredentials[OPENAI].ciphertext).toBeTruthy();
    });

    test('testing a platform with no stored key reports LLM_KEY_MISSING', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const result = await providerKeys.testSurfaceKey(db, { scope: COURSE_SCOPE, provider: SANDBOX });
        expect(result.body.code).toBe('LLM_KEY_MISSING');
    });

    test('a legacy key still tests, and the legacy field stays in sync', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', llmApiKey: buildKeySubdocument('sk-legacy-key', 'i1') }],
        });
        mockValidateProviderKey.mockResolvedValue({ ok: false, status: 'invalid', message: 'bad', provider: OPENAI });

        await providerKeys.testSurfaceKey(db, { scope: COURSE_SCOPE });

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.llmApiKey.status).toBe('invalid');
        expect(course.llmCredentials[OPENAI].status).toBe('invalid');
    });
});

describe('what a surface migration has to cover', () => {
    test('a course covers only its own documents', async () => {
        const db = memoryDb({});
        expect(await providerKeys.migrationScopeContent(db, COURSE_SCOPE))
            .toEqual({ courseIds: ['C1'], includeNotes: false });
    });

    test('Notes cover the shared notes only', async () => {
        const db = memoryDb({});
        expect(await providerKeys.migrationScopeContent(db, { type: 'notes', id: 'notesLlm' }))
            .toEqual({ courseIds: [], includeNotes: true });
    });

    test('a bucket covers every member course, whatever platform those courses use', async () => {
        // Membership is course-side (`course.superchatIds`) — a bucket document
        // has no course list of its own.
        const db = memoryDb({
            superchats: [{ superchatId: 'S1' }],
            courses: [
                { courseId: 'C1', superchatIds: ['S1'] },
                { courseId: 'C2', superchatIds: ['S1', 'S2'] },
                { courseId: 'C3', superchatIds: ['S2'] },
                { courseId: 'C4' },
            ],
        });

        expect(await providerKeys.migrationScopeContent(db, { type: 'superchat', id: 'S1' }))
            .toEqual({ courseIds: ['C1', 'C2'], includeNotes: true });
    });

    test('a bucket that excludes Notes from retrieval does not prepare them', async () => {
        const db = memoryDb({
            superchats: [{ superchatId: 'S1', includeNotesInRetrieval: false }],
            courses: [{ courseId: 'C1', superchatIds: ['S1'] }],
        });

        expect(await providerKeys.migrationScopeContent(db, { type: 'superchat', id: 'S1' }))
            .toEqual({ courseIds: ['C1'], includeNotes: false });
    });

    test('the instructor Super Course chat pools every bucketed course, plus Notes by default', async () => {
        const db = memoryDb({
            courses: [
                { courseId: 'C1', superchatIds: ['S1'] },
                { courseId: 'C2', superchatIds: ['S2'] },
                // Not in any bucket, so the Super Course chat cannot retrieve it.
                { courseId: 'C3' },
                { courseId: 'C4', superchatIds: ['S1'], status: 'deleted' },
            ],
            settings: [{ _id: 'superCourseChat' }],
        });

        expect(await providerKeys.migrationScopeContent(db, { type: 'superCourseChat', id: 'superCourseChat' }))
            .toEqual({ courseIds: ['C1', 'C2'], includeNotes: true });
    });

    test('the instructor Super Course chat can exclude Notes', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', superchatIds: ['S1'] }],
            settings: [{ _id: 'superCourseChat', includeNotesInRetrieval: false }],
        });

        expect(await providerKeys.migrationScopeContent(db, { type: 'superCourseChat', id: 'superCourseChat' }))
            .toMatchObject({ includeNotes: false });
    });

    test('an unknown scope covers nothing', async () => {
        expect(await providerKeys.migrationScopeContent(memoryDb({}), { type: 'mystery' }))
            .toEqual({ courseIds: [], includeNotes: false });
    });
});

describe('surface state for the UI', () => {
    test('reports the platform, per-platform key status and any live migration', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                pendingLlmProvider: SANDBOX,
                llmCredentials: {
                    [OPENAI]: buildKeySubdocument('sk-gpt-1111', 'i1', OPENAI),
                    [SANDBOX]: buildKeySubdocument('sbx-key-2222', 'i1', SANDBOX),
                },
            }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        const profile = await providerKeys.embeddingProfileFor(db, SANDBOX);
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, toProvider: SANDBOX, profile, courseIds: ['C1'],
        });
        await db.collection('courses').updateOne({ courseId: 'C1' }, { $set: { providerMigrationId: job.migrationId } });

        const state = await providerKeys.surfaceKeyState(db, COURSE_SCOPE);

        expect(state).toMatchObject({
            llmProvider: OPENAI,
            pendingLlmProvider: SANDBOX,
            aiAvailable: true,
        });
        expect(state.llmKeysByProvider[SANDBOX].last4).toBe('2222');
        expect(state.migration).toMatchObject({ toProvider: SANDBOX, total: 1 });
        expect(JSON.stringify(state)).not.toContain('ciphertext');
    });

    test('a surface with no migration reports null', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const state = await providerKeys.surfaceKeyState(db, COURSE_SCOPE);
        expect(state.migration).toBeNull();
        expect(state.aiAvailable).toBe(false);
    });
});
