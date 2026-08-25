/**
 * Admin "Platforms and models" API: settings grouped by platform, immediate
 * chat-model changes, and staged embedding-model changes with an impact preview
 * and rollback.
 */
const startedMigrations = [];
const cancelledMigrations = [];
jest.mock('../../../src/services/providerMigrationRunner', () => ({
    startMigration: jest.fn((db, migrationId) => { startedMigrations.push(migrationId); }),
    cancelAndCleanup: jest.fn(async (db, migrationId, cancelledBy) => {
        cancelledMigrations.push(migrationId);
        const actual = jest.requireActual('../../../src/services/providerMigrationService');
        const job = await actual.cancelMigration(db, migrationId, cancelledBy);
        return { job, cleanup: { migrationId, deletedVectors: 3, clearedIndexRecords: 3 } };
    }),
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

const adminModelSettings = require('../../../src/services/adminModelSettings');
const scopeModelSettings = require('../../../src/services/scopeModelSettings');
const migrations = require('../../../src/services/providerMigrationService');
const { buildEmbeddingProfile } = require('../../../src/services/embeddingConfig');
const { buildIndexRecord, contentHash, INDEX_STATUSES } = require('../../../src/services/embeddingIndexService');
const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');
const { providerLabel } = require('../../../src/services/llmProviders');
const settingsRouter = require('../../../src/routes/settings');
const { makeRouteApp, request } = require('../helpers/route-app');
const { memoryDb } = require('../helpers/memory-db');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';
const PROXY = 'ubc-llm-proxy';

const admin = { userId: 'a1', role: 'instructor', email: 'admin@x.com', permissions: { systemAdmin: true } };
const instructor = { userId: 'i1', role: 'instructor', email: 'i@x.com' };
const COURSE_SCOPE = { scopeType: 'course', scopeId: 'C1' };

const app = ({ db = memoryDb({ settings: [] }), user = admin, locals = {} } = {}) =>
    makeRouteApp(settingsRouter, { db, user, locals });

const OLD_ENV = process.env;
beforeAll(() => jest.spyOn(console, 'error').mockImplementation(() => {}));
afterAll(() => { process.env = OLD_ENV; jest.restoreAllMocks(); });
beforeEach(() => {
    process.env = { ...OLD_ENV };
    delete process.env.LLM_PROVIDER;
    delete process.env.LLM_EMBEDDING_MODEL;
    startedMigrations.length = 0;
    cancelledMigrations.length = 0;
    adminModelSettings.invalidateCache();
});

describe('GET /llm — grouped by platform', () => {
    test('both platforms are returned with their own models and collections', async () => {
        const res = await request(app()).get('/llm');

        expect(res.status).toBe(200);
        expect(res.body.platforms.map(platform => platform.provider)).toEqual([OPENAI, SANDBOX, PROXY]);

        const [gpt, sandbox, proxy] = res.body.platforms;
        expect(gpt).toMatchObject({
            label: providerLabel(OPENAI),
            chatModel: 'gpt-5.6-luna',
            backendChatModel: 'gpt-5.6-luna',
            backendInheritsFrontend: true,
            embeddingModel: 'text-embedding-3-small',
            collection: 'biocbot_documents',
            vectorSize: 1536,
        });
        expect(sandbox).toMatchObject({
            label: providerLabel(SANDBOX),
            chatModel: 'qwen3.6-35b-a3b',
            embeddingModel: 'qwen3-embedding-0.6b',
            collection: 'biocbot_documents_qwen3_embedding_0_6b',
            vectorSize: 1024,
        });
        expect(proxy).toMatchObject({
            provider: PROXY,
            label: providerLabel(PROXY),
            chatModel: null,
            embeddingModel: null,
            allowedModels: [],
            allowedEmbeddingModels: [],
            configured: false,
            modelsDiscovered: false,
        });
    });

    test('each platform only offers its own models', async () => {
        const res = await request(app()).get('/llm');
        const [gpt, sandbox] = res.body.platforms;

        expect(gpt.allowedModels).toEqual(expect.arrayContaining(['gpt-4.1-mini', 'gpt-5-nano']));
        expect(gpt.allowedModels).not.toContain('qwen3.6-35b-a3b');
        expect(gpt.allowedEmbeddingModels).toEqual(expect.arrayContaining(['text-embedding-3-small']));
        expect(gpt.allowedEmbeddingModels).not.toContain('qwen3-embedding-0.6b');

        expect(sandbox.allowedModels).toEqual(expect.arrayContaining(['qwen3.6-35b-a3b', 'gpt-oss-120b']));
        expect(sandbox.allowedEmbeddingModels).toEqual(['qwen3-embedding-0.6b']);
    });

    test('stored per-platform settings are reflected', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: {
                    [OPENAI]: { chatModel: 'gpt-5-nano', embeddingModel: 'text-embedding-3-large', reasoningEffort: 'high' },
                    [SANDBOX]: { chatModel: 'gpt-oss-120b', reasoningEffort: 'medium' },
                },
            }],
        });

        const res = await request(app({ db })).get('/llm');
        const byProvider = Object.fromEntries(res.body.platforms.map(p => [p.provider, p]));

        expect(byProvider[OPENAI]).toMatchObject({
            chatModel: 'gpt-5-nano', embeddingModel: 'text-embedding-3-large',
            collection: 'biocbot_documents_text_embedding_3_large', vectorSize: 3072,
        });
        expect(byProvider[SANDBOX].chatModel).toBe('gpt-oss-120b');
    });

    test('proxy selectors expose exact discovered ids without choosing defaults', async () => {
        const discovered = ['openai/gpt-5.6-luna:2026', 'vendor/embed.model-v2'];
        const db = memoryDb({
            settings: [{ _id: 'llm', providers: { [PROXY]: { availableModels: discovered } } }],
        });

        const res = await request(app({ db })).get('/llm');
        const proxy = res.body.platforms.find(platform => platform.provider === PROXY);

        expect(proxy.allowedModels).toEqual(discovered);
        expect(proxy.allowedEmbeddingModels).toEqual(discovered);
        expect(proxy.chatModel).toBeNull();
        expect(proxy.embeddingModel).toBeNull();
    });

    test('a staged embedding change is surfaced', async () => {
        const db = memoryDb({ settings: [] });
        await adminModelSettings.stagePendingEmbedding(db, OPENAI, {
            embeddingModel: 'text-embedding-3-large', migrationId: 'mig_1',
        });

        const res = await request(app({ db })).get('/llm');
        const gpt = res.body.platforms.find(platform => platform.provider === OPENAI);

        expect(gpt.embeddingModel).toBe('text-embedding-3-small');   // still active
        expect(gpt.pendingEmbedding).toMatchObject({ embeddingModel: 'text-embedding-3-large', migrationId: 'mig_1' });
    });

    test('only system admins may read model settings', async () => {
        expect((await request(app({ user: instructor })).get('/llm')).status).toBe(403);
        expect((await request(app({ user: null })).get('/llm')).status).toBe(401);
    });
});

describe('scope-owned model settings', () => {
    test('a course-scoped chat change does not alter another course or the defaults', async () => {
        const credential = { ciphertext: 'encrypted', status: 'valid' };
        const db = memoryDb({
            settings: [],
            courses: [
                { courseId: 'A', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: credential } },
                { courseId: 'B', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: credential } }
            ]
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'A' });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'B' });

        const res = await request(app({ db })).post('/llm').send({
            scopeType: 'course',
            scopeId: 'A',
            provider: OPENAI,
            chatModel: 'gpt-5.6-luna',
            reasoningEffort: 'low',
            backendInheritsFrontend: true
        });

        expect(res.status).toBe(200);
        expect((await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'A' }, OPENAI)).chatModel)
            .toBe('gpt-5.6-luna');
        expect((await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'B' }, OPENAI)).chatModel)
            .toBe('gpt-5.6-luna');
        expect((await adminModelSettings.getProviderSettings(db, OPENAI, { force: true })).chatModel)
            .toBe('gpt-5.6-luna');
    });

    test('the scoped catalog exposes only providers with a key on that scope', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{
                courseId: 'A',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: { ciphertext: 'encrypted', status: 'valid' } }
            }]
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'A' });

        const res = await request(app({ db }))
            .get('/llm?scopeType=course&scopeId=A');

        expect(res.status).toBe(200);
        expect(res.body.scope).toEqual({ type: 'course', id: 'A' });
        expect(res.body.platforms.map(item => item.provider)).toEqual([OPENAI]);
    });
});

describe('POST /llm — chat model changes are immediate', () => {
    test('discovers supported proxy reasoning efforts through provider operations', async () => {
        const oldStub = process.env.BIOCBOT_TEST_LLM_STUB;
        const oldEfforts = process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS;
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS = 'none,low,medium,high,xhigh,max';
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: { [PROXY]: { availableModels: ['gpt-5.6-luna'] } },
            }],
        });

        try {
            const res = await request(app({ db })).post('/llm/reasoning-efforts').send({
                provider: PROXY,
                model: 'gpt-5.6-luna',
            });

            expect(res.status).toBe(200);
            expect(res.body.reasoningEfforts).toEqual(['none', 'low', 'medium', 'high', 'xhigh', 'max']);
            expect(res.body.reasoningEfforts).not.toContain('minimal');
            expect(res.body.defaultReasoningEffort).toBe('low');
        } finally {
            if (oldStub === undefined) delete process.env.BIOCBOT_TEST_LLM_STUB;
            else process.env.BIOCBOT_TEST_LLM_STUB = oldStub;
            if (oldEfforts === undefined) delete process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS;
            else process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS = oldEfforts;
        }
    });

    test('proxy chat selections are operation-validated before being saved', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.BIOCBOT_TEST_PROXY_MODELS = 'proxy-chat,proxy-embed';
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: { [PROXY]: { availableModels: ['proxy-chat', 'proxy-embed'] } },
            }],
            courses: [{
                courseId: 'C1',
                llmCredentials: { [PROXY]: buildKeySubdocument('prx-test-key', 'a', PROXY) },
            }],
        });

        const res = await request(app({ db })).post('/llm').send({
            provider: PROXY,
            chatModel: 'proxy-chat',
            reasoningEffort: 'low',
            backendInheritsFrontend: true,
        });

        expect(res.status).toBe(200);
        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored.providers[PROXY]).toMatchObject({
            chatModel: 'proxy-chat', reasoningEffort: 'low',
        });
    });

    test('saving GPT does not disturb Sandbox', async () => {
        const db = memoryDb({ settings: [] });
        const llm = { invalidateModelSettingsCache: jest.fn() };
        const llmRegistry = { clear: jest.fn() };

        const res = await request(app({ db, locals: { llm, llmRegistry } }))
            .post('/llm').send({ provider: OPENAI, chatModel: 'gpt-5-nano', reasoningEffort: 'high' });

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ provider: OPENAI, settings: { chatModel: 'gpt-5-nano', reasoningEffort: 'high' } });
        expect(llm.invalidateModelSettingsCache).toHaveBeenCalled();
        expect(llmRegistry.clear).toHaveBeenCalled();
        // No re-indexing: a chat model change touches no vectors.
        expect(startedMigrations).toEqual([]);

        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored.providers[OPENAI].chatModel).toBe('gpt-5-nano');
        expect(stored.providers[SANDBOX]).toBeUndefined();
    });

    test('saving Sandbox stores under its own platform', async () => {
        const db = memoryDb({ settings: [] });
        const res = await request(app({ db }))
            .post('/llm').send({ provider: SANDBOX, chatModel: 'gpt-oss-120b', reasoningEffort: 'medium' });

        expect(res.status).toBe(200);
        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored.providers[SANDBOX].chatModel).toBe('gpt-oss-120b');
    });

    test('saves an independent back-end lane and can restore inheritance', async () => {
        const db = memoryDb({ settings: [] });
        let res = await request(app({ db })).post('/llm').send({
            provider: OPENAI,
            chatModel: 'gpt-4.1-mini',
            backendChatModel: 'gpt-5.4-nano',
            backendReasoningEffort: 'high',
            backendInheritsFrontend: false,
        });
        expect(res.status).toBe(200);

        res = await request(app({ db })).get('/llm');
        let gpt = res.body.platforms.find(platform => platform.provider === OPENAI);
        expect(gpt).toMatchObject({
            backendChatModel: 'gpt-5.4-nano',
            backendReasoningEffort: 'high',
            backendInheritsFrontend: false,
        });

        res = await request(app({ db })).post('/llm').send({
            provider: OPENAI,
            chatModel: 'gpt-5-nano',
            reasoningEffort: 'high',
            backendInheritsFrontend: true,
        });
        expect(res.status).toBe(200);
        res = await request(app({ db })).get('/llm');
        gpt = res.body.platforms.find(platform => platform.provider === OPENAI);
        expect(gpt).toMatchObject({
            backendChatModel: 'gpt-5-nano',
            backendReasoningEffort: 'high',
            backendInheritsFrontend: true,
        });
    });

    test('a model from the wrong platform is rejected', async () => {
        const res = await request(app()).post('/llm').send({ provider: OPENAI, chatModel: 'qwen3.6-35b-a3b' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/Invalid chat model for openai/);
    });

    test('non-admins cannot change models', async () => {
        expect((await request(app({ user: instructor })).post('/llm').send({ chatModel: 'gpt-5-nano' })).status).toBe(403);
    });
});

describe('POST /llm/embedding/impact — preview before confirming', () => {
    test('reports affected surfaces and how much has to be re-indexed', async () => {
        const db = memoryDb({
            settings: [],
            courses: [
                { courseId: 'C1', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) } },
                { courseId: 'C2', activeLlmProvider: SANDBOX, llmCredentials: { [SANDBOX]: buildKeySubdocument('sbx-b', 'a', SANDBOX) } },
            ],
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'gpt course text' },
                { documentId: 'd2', courseId: 'C2', content: 'sandbox course text' },
            ],
        });

        const res = await request(app({ db }))
            .post('/llm/embedding/impact').send({ ...COURSE_SCOPE, provider: OPENAI, embeddingModel: 'text-embedding-3-large' });

        expect(res.status).toBe(200);
        expect(res.body.profile).toMatchObject({
            collection: 'biocbot_documents_text_embedding_3_large', vectorSize: 3072,
        });
        // Only the GPT course is affected; the Sandbox course is untouched.
        expect(res.body.impact.courses).toBe(1);
        expect(res.body.impact.itemsToReindex).toBe(1);
        expect(res.body.impact.surfaces).toEqual([{ type: 'course', id: 'C1' }]);
    });

    test('nothing is written by a dry run', async () => {
        const db = memoryDb({ settings: [], courses: [], documents: [] });
        await request(app({ db })).post('/llm/embedding/impact').send({ provider: OPENAI, embeddingModel: 'text-embedding-3-large' });

        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored).toBeNull();
        expect(startedMigrations).toEqual([]);
    });

    test('an embedding model from the wrong platform is rejected', async () => {
        const res = await request(app())
            .post('/llm/embedding/impact').send({ provider: OPENAI, embeddingModel: 'qwen3-embedding-0.6b' });
        expect(res.status).toBe(400);
        expect(res.body.error).toContain(`Invalid embedding model for ${providerLabel(OPENAI)}`);
    });
});

describe('POST /llm/embedding — staged, never destructive', () => {
    test('saving an embedding choice does not start re-indexing until explicitly requested', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) }
            }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });

        const staged = await request(app({ db })).post('/llm/embedding/stage').send({
            ...COURSE_SCOPE,
            provider: OPENAI,
            embeddingModel: 'text-embedding-3-large'
        });

        expect(staged.status).toBe(200);
        expect(startedMigrations).toEqual([]);
        let settings = await scopeModelSettings.getAll(db, { type: 'course', id: 'C1' });
        expect(settings.pendingEmbedding[OPENAI]).toMatchObject({
            embeddingModel: 'text-embedding-3-large',
            migrationId: null
        });
        expect(settings.providers[OPENAI].embeddingModel).toBe('text-embedding-3-small');

        const started = await request(app({ db })).post('/llm/embedding').send({
            ...COURSE_SCOPE,
            provider: OPENAI
        });

        expect(started.status).toBe(202);
        expect(startedMigrations).toHaveLength(1);
        settings = await scopeModelSettings.getAll(db, { type: 'course', id: 'C1' });
        expect(settings.pendingEmbedding[OPENAI].migrationId).toBe(startedMigrations[0]);
    });

    test('proxy embedding validation records the returned dimension in the staged profile', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.BIOCBOT_TEST_PROXY_MODELS = 'proxy-chat,proxy-embed';
        process.env.BIOCBOT_TEST_PROXY_VECTOR_SIZE = '19';
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: { [PROXY]: { availableModels: ['proxy-chat', 'proxy-embed'] } },
            }],
            courses: [{
                courseId: 'C1',
                llmCredentials: { [PROXY]: buildKeySubdocument('prx-test-key', 'a', PROXY) },
            }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });

        const res = await request(app({ db })).post('/llm/embedding').send({
            ...COURSE_SCOPE,
            provider: PROXY,
            embeddingModel: 'proxy-embed',
        });

        expect(res.status).toBe(202);
        const { pendingEmbedding } = await scopeModelSettings.getAll(db, { type: 'course', id: 'C1' });
        expect(pendingEmbedding[PROXY]).toMatchObject({
            embeddingModel: 'proxy-embed', vectorSize: 19,
        });
        const job = await migrations.getMigration(db, startedMigrations[0]);
        expect(job.targetProfile.vectorSize).toBe(19);
    });

    test('the previous model stays active while a migration runs', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{ courseId: 'C1', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) } }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });

        const res = await request(app({ db }))
            .post('/llm/embedding').send({ ...COURSE_SCOPE, provider: OPENAI, embeddingModel: 'text-embedding-3-large' });

        expect(res.status).toBe(202);
        expect(res.body.message).toMatch(/current embedding model stays active/);
        expect(startedMigrations).toHaveLength(1);

        // Active model unchanged; the new one is only staged.
        const { providers, pendingEmbedding } = await scopeModelSettings.getAll(db, { type: 'course', id: 'C1' });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-small');
        expect(pendingEmbedding[OPENAI].embeddingModel).toBe('text-embedding-3-large');

        // The job targets a NEW collection — the old one is untouched.
        const job = await migrations.getMigration(db, startedMigrations[0]);
        expect(job.kind).toBe('embedding-model');
        expect(job.targetProfile.collection).toBe('biocbot_documents_text_embedding_3_large');
    });

    test('a second embedding change is refused while the first is still re-indexing', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{ courseId: 'C1', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) } }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });
        await request(app({ db })).post('/llm/embedding').send({ ...COURSE_SCOPE, provider: OPENAI, embeddingModel: 'text-embedding-3-large' });

        const res = await request(app({ db }))
            .post('/llm/embedding').send({ ...COURSE_SCOPE, provider: OPENAI, embeddingModel: 'text-embedding-ada-002' });

        // Two jobs would fight over the single staged setting, and whichever
        // finished first would activate the other's not-yet-indexed model.
        expect(res.status).toBe(409);
        expect(res.body.code).toBe('EMBEDDING_MIGRATION_ACTIVE');
        expect(startedMigrations).toHaveLength(1);
        const { pendingEmbedding } = await scopeModelSettings.getAll(db, { type: 'course', id: 'C1' });
        expect(pendingEmbedding[OPENAI].embeddingModel).toBe('text-embedding-3-large');
    });

    test('starting the same embedding migration twice returns the existing job', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{
                courseId: 'C1',
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) }
            }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });
        await request(app({ db })).post('/llm/embedding').send({
            ...COURSE_SCOPE,
            provider: OPENAI,
            embeddingModel: 'text-embedding-3-large'
        });

        const duplicate = await request(app({ db })).post('/llm/embedding').send({
            ...COURSE_SCOPE,
            provider: OPENAI,
            embeddingModel: 'text-embedding-3-large'
        });

        expect(duplicate.status).toBe(202);
        expect(duplicate.body.message).toMatch(/already in progress/);
        expect(duplicate.body.migration.migrationId).toBe(startedMigrations[0]);
        expect(startedMigrations).toHaveLength(1);
    });

    test('selecting the model already in use is a no-op', async () => {
        const db = memoryDb({ settings: [] });
        const res = await request(app({ db }))
            .post('/llm/embedding').send({ provider: OPENAI, embeddingModel: 'text-embedding-3-small' });

        expect(res.status).toBe(200);
        expect(res.body.migration).toBeNull();
        expect(startedMigrations).toEqual([]);
    });

    test('the current Proxy model is rebuilt when its record points at the old shared OpenAI collection', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.BIOCBOT_TEST_PROXY_MODELS = 'gpt-5.6-luna,text-embedding-3-small';
        process.env.BIOCBOT_TEST_PROXY_VECTOR_SIZE = '1536';
        const profile = buildEmbeddingProfile({
            provider: PROXY,
            embeddingModel: 'text-embedding-3-small',
            vectorSize: 1536,
        });
        const hash = contentHash('migrated content');
        const oldSharedRecord = buildIndexRecord({
            profile,
            hash,
            status: INDEX_STATUSES.READY,
            indexedAt: new Date(),
            collection: 'biocbot_documents',
        });
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: {
                    [PROXY]: {
                        availableModels: ['gpt-5.6-luna', 'text-embedding-3-small'],
                        chatModel: 'gpt-5.6-luna',
                        reasoningEffort: 'low',
                        embeddingModel: 'text-embedding-3-small',
                        embeddingRevision: 'v1',
                        vectorSize: 1536,
                    },
                },
            }],
            courses: [{
                courseId: 'C1',
                activeLlmProvider: PROXY,
                llmCredentials: { [PROXY]: buildKeySubdocument('prx-test-key', 'a', PROXY) },
            }],
            documents: [{
                documentId: 'd1',
                courseId: 'C1',
                content: 'migrated content',
                embeddingIndexes: { [profile.storageKey]: oldSharedRecord },
            }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });

        const res = await request(app({ db })).post('/llm/embedding').send({
            ...COURSE_SCOPE,
            provider: PROXY,
            embeddingModel: 'text-embedding-3-small',
        });

        expect(res.status).toBe(202);
        expect(startedMigrations).toHaveLength(1);
        const job = await migrations.getMigration(db, startedMigrations[0]);
        expect(job.items).toHaveLength(1);
        expect(job.items[0].reason).toBe('collection-changed');
        expect(job.targetProfile.collection)
            .toBe('biocbot_documents_stub_ubc_llm_proxy_text_embedding_3_small');
    });

    test('rollback drops the staged change and keeps the active model', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{ courseId: 'C1', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) } }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });
        await request(app({ db })).post('/llm/embedding').send({ ...COURSE_SCOPE, provider: OPENAI, embeddingModel: 'text-embedding-3-large' });

        const res = await request(app({ db })).post('/llm/embedding/rollback').send({ ...COURSE_SCOPE, provider: OPENAI });

        expect(res.status).toBe(200);
        expect(res.body.message).toMatch(/vectors were not touched/i);
        const { providers, pendingEmbedding } = await scopeModelSettings.getAll(db, { type: 'course', id: 'C1' });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-small');
        expect(pendingEmbedding[OPENAI]).toBeUndefined();
    });

    test('rollback also stops the re-indexing job it staged', async () => {
        const db = memoryDb({
            settings: [],
            courses: [{ courseId: 'C1', activeLlmProvider: OPENAI, llmCredentials: { [OPENAI]: buildKeySubdocument('sk-a', 'a', OPENAI) } }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, { type: 'course', id: 'C1' });
        await request(app({ db })).post('/llm/embedding').send({ ...COURSE_SCOPE, provider: OPENAI, embeddingModel: 'text-embedding-3-large' });
        const migrationId = startedMigrations[0];

        const res = await request(app({ db })).post('/llm/embedding/rollback').send({ ...COURSE_SCOPE, provider: OPENAI });

        // Cancelling the job stops it burning provider calls on a profile that
        // is never going to be activated, and drops its partial vectors.
        expect(cancelledMigrations).toEqual([migrationId]);
        expect(res.body.cleanup).toMatchObject({ deletedVectors: 3 });
        expect((await migrations.getMigration(db, migrationId)).status).toBe('cancelled');
    });

    test('rollback with nothing staged is a no-op', async () => {
        const db = memoryDb({ settings: [] });
        const res = await request(app({ db })).post('/llm/embedding/rollback').send({ provider: OPENAI });

        expect(res.status).toBe(200);
        expect(cancelledMigrations).toEqual([]);
        expect(res.body.cleanup).toBeNull();
    });

    test('non-admins cannot stage or roll back an embedding change', async () => {
        expect((await request(app({ user: instructor })).post('/llm/embedding').send({ embeddingModel: 'text-embedding-3-large' })).status).toBe(403);
        expect((await request(app({ user: instructor })).post('/llm/embedding/rollback').send({})).status).toBe(403);
    });
});

describe('instructors never see exact models', () => {
    test('the instructor-facing key endpoints expose platform labels only', async () => {
        const db = memoryDb({ settings: [{ _id: 'notesLlm', activeLlmProvider: SANDBOX }] });
        const res = await request(app({ db })).get('/notes-llm-key');

        expect(res.status).toBe(200);
        expect(res.body.providers.map(provider => provider.label)).toEqual([
            providerLabel(OPENAI), providerLabel(SANDBOX), providerLabel(PROXY)
        ]);

        const serialised = JSON.stringify(res.body);
        for (const modelName of ['gpt-4.1-mini', 'gpt-5-nano', 'qwen3.6-35b-a3b', 'text-embedding-3-small', 'qwen3-embedding-0.6b']) {
            expect(serialised).not.toContain(modelName);
        }
    });
});
