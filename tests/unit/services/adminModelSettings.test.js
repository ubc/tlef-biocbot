/**
 * Per-platform admin model settings: MongoDB is authoritative after
 * initialization, env only supplies bootstrap defaults, and an embedding-model
 * change is staged rather than applied.
 */
const adminModelSettings = require('../../../src/services/adminModelSettings');
const { memoryDb } = require('../helpers/memory-db');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';
const PROXY = 'ubc-llm-proxy';

const OLD_ENV = process.env;
const TOUCHED = [
    'LLM_PROVIDER', 'OPENAI_MODEL', 'LLM_DEFAULT_MODEL', 'LLM_EMBEDDING_MODEL',
    'OPENAI_EMBEDDING_MODEL', 'SANDBOX_EMBEDDING_MODEL',
];
beforeEach(() => {
    process.env = { ...OLD_ENV };
    for (const key of TOUCHED) delete process.env[key];
    adminModelSettings.invalidateCache();
});
afterAll(() => { process.env = OLD_ENV; });

describe('bootstrap defaults', () => {
    test('the expected initial defaults for each platform', () => {
        expect(adminModelSettings.bootstrapDefaults(OPENAI)).toMatchObject({
            chatModel: 'gpt-5.6-luna',
            embeddingModel: 'text-embedding-3-small',
            embeddingRevision: 'v1',
        });
        expect(adminModelSettings.bootstrapDefaults(SANDBOX)).toMatchObject({
            chatModel: 'qwen3.6-35b-a3b',
            embeddingModel: 'qwen3-embedding-0.6b',
            embeddingRevision: 'v1',
        });
        expect(adminModelSettings.bootstrapDefaults(PROXY)).toMatchObject({
            chatModel: null,
            embeddingModel: null,
            reasoningEffort: null,
        });
    });

    test('a sandbox-shaped LLM_EMBEDDING_MODEL never leaks into the GPT platform', () => {
        // A deployment configured for the sandbox must not hand Qwen to OpenAI.
        process.env.LLM_PROVIDER = SANDBOX;
        process.env.LLM_EMBEDDING_MODEL = 'qwen3-embedding-0.6b';

        expect(adminModelSettings.bootstrapDefaults(OPENAI).embeddingModel).toBe('text-embedding-3-small');
        expect(adminModelSettings.bootstrapDefaults(SANDBOX).embeddingModel).toBe('qwen3-embedding-0.6b');
    });

    test('dedicated per-platform env overrides are honoured', () => {
        process.env.OPENAI_EMBEDDING_MODEL = 'text-embedding-3-large';
        expect(adminModelSettings.bootstrapDefaults(OPENAI).embeddingModel).toBe('text-embedding-3-large');
    });

    test('env chat-model overrides apply per platform', () => {
        process.env.OPENAI_MODEL = 'gpt-5-nano';
        process.env.LLM_DEFAULT_MODEL = 'gpt-oss-120b';
        expect(adminModelSettings.bootstrapDefaults(OPENAI).chatModel).toBe('gpt-5-nano');
        expect(adminModelSettings.bootstrapDefaults(SANDBOX).chatModel).toBe('gpt-oss-120b');
    });
});

describe('reading settings', () => {
    test('an empty database yields defaults for both platforms', async () => {
        const db = memoryDb({ settings: [] });
        const { providers } = await adminModelSettings.getAllProviderSettings(db, { force: true });

        expect(providers[OPENAI]).toMatchObject({ chatModel: 'gpt-5.6-luna', reasoningEffort: 'low' });
        expect(providers[SANDBOX].embeddingModel).toBe('qwen3-embedding-0.6b');
        expect(providers[PROXY]).toMatchObject({
            chatModel: null,
            embeddingModel: null,
            configured: false,
            availableModels: [],
        });
    });

    test('records exact proxy model ids without creating model settings', async () => {
        const db = memoryDb({ settings: [] });
        const first = ['openai/gpt-5.6-luna:latest', 'text-embedding/vendor.v2'];
        await adminModelSettings.recordDiscoveredModels(db, PROXY, first);
        await adminModelSettings.recordDiscoveredModels(db, PROXY, ['second/key-model', first[0]]);

        const settings = await adminModelSettings.getProviderSettings(db, PROXY, { force: true });
        expect(settings.availableModels).toEqual([...first, 'second/key-model']);
        expect(settings.chatModel).toBeNull();
        expect(settings.embeddingModel).toBeNull();
        expect(settings.configured).toBe(false);
    });

    test('proxy chat and embedding fields become configured only after explicit saves', async () => {
        const db = memoryDb({ settings: [] });
        const models = ['proxy-chat', 'proxy-embed'];
        await adminModelSettings.recordDiscoveredModels(db, PROXY, models);
        await adminModelSettings.saveChatSettings(db, PROXY, {
            chatModel: 'proxy-chat',
            reasoningEffort: 'low',
            backendInheritsFrontend: true,
        });
        await adminModelSettings.stagePendingEmbedding(db, PROXY, {
            embeddingModel: 'proxy-embed',
            vectorSize: 1536,
        });
        await adminModelSettings.activatePendingEmbedding(db, PROXY);

        const settings = await adminModelSettings.getProviderSettings(db, PROXY, { force: true });
        expect(settings).toMatchObject({
            chatModel: 'proxy-chat',
            reasoningEffort: 'low',
            embeddingModel: 'proxy-embed',
            vectorSize: 1536,
            configured: true,
        });
    });

    test('MongoDB is authoritative once settings exist', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: {
                    [OPENAI]: { chatModel: 'gpt-5.4-nano', embeddingModel: 'text-embedding-3-large', reasoningEffort: 'medium' },
                    [SANDBOX]: { chatModel: 'gpt-oss-120b', embeddingModel: 'qwen3-embedding-0.6b', reasoningEffort: 'high' },
                },
            }],
        });

        const { providers } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI]).toMatchObject({
            chatModel: 'gpt-5.4-nano', embeddingModel: 'text-embedding-3-large', reasoningEffort: 'medium',
        });
        expect(providers[SANDBOX]).toMatchObject({ chatModel: 'gpt-oss-120b', reasoningEffort: 'high' });
    });

    test('an absent back-end lane mirrors the complete front-end model and effort', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: { [OPENAI]: { chatModel: 'gpt-5-nano', reasoningEffort: 'high' } },
            }],
        });

        const settings = await adminModelSettings.getProviderSettings(db, OPENAI, { force: true });
        expect(settings.backendInheritsFrontend).toBe(true);
        expect(settings.lanes.backend).toEqual(settings.lanes.frontend);
        expect(adminModelSettings.chatSettingsForLane(settings, 'backend')).toEqual({
            chatModel: 'gpt-5-nano', reasoningEffort: 'high',
        });
    });

    test('a valid back-end override resolves independently and an invalid one falls back', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: {
                    [OPENAI]: {
                        chatModel: 'gpt-4.1-mini',
                        backend: { chatModel: 'gpt-5.4-nano', reasoningEffort: 'xhigh' },
                    },
                    [SANDBOX]: {
                        chatModel: 'gpt-oss-120b',
                        reasoningEffort: 'high',
                        backend: { chatModel: 'gpt-5-nano', reasoningEffort: 'low' },
                    },
                },
            }],
        });

        const { providers } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI].backendInheritsFrontend).toBe(false);
        expect(providers[OPENAI].lanes.backend).toEqual({ chatModel: 'gpt-5.4-nano', reasoningEffort: 'xhigh' });
        expect(providers[SANDBOX].backendInheritsFrontend).toBe(true);
        expect(providers[SANDBOX].lanes.backend).toEqual(providers[SANDBOX].lanes.frontend);
    });

    test('a legacy flat document is read as the env platform\'s settings', async () => {
        process.env.LLM_PROVIDER = SANDBOX;
        const db = memoryDb({ settings: [{ _id: 'llm', model: 'gpt-oss-120b', reasoningEffort: 'medium' }] });

        const { providers } = await adminModelSettings.getAllProviderSettings(db, { force: true });

        expect(providers[SANDBOX]).toMatchObject({ chatModel: 'gpt-oss-120b', reasoningEffort: 'medium' });
        // The other platform still gets its own defaults.
        expect(providers[OPENAI].chatModel).toBe('gpt-5.6-luna');
    });

    test('a stored model that is not allowed for its platform falls back to the default', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: {
                    // A Qwen chat model is not valid for the GPT platform.
                    [OPENAI]: { chatModel: 'qwen3.6-35b-a3b', embeddingModel: 'qwen3-embedding-0.6b' },
                },
            }],
        });

        const settings = await adminModelSettings.getProviderSettings(db, OPENAI, { force: true });
        expect(settings.chatModel).toBe('gpt-5.6-luna');
        expect(settings.embeddingModel).toBe('text-embedding-3-small');
    });

    test('a DB failure falls back to defaults for runtime callers but throws for the admin screen', async () => {
        const failing = { collection: () => ({ findOne: async () => { throw new Error('mongo down'); } }) };
        jest.spyOn(console, 'warn').mockImplementation(() => {});

        await expect(adminModelSettings.getAllProviderSettings(failing, { force: true }))
            .resolves.toMatchObject({ providers: { [OPENAI]: { chatModel: 'gpt-5.6-luna', reasoningEffort: 'low' } } });

        adminModelSettings.invalidateCache();
        await expect(adminModelSettings.getAllProviderSettings(failing, { force: true, throwOnError: true }))
            .rejects.toThrow('mongo down');
        console.warn.mockRestore();
    });

    test('the embedding profile for a platform reflects stored settings', async () => {
        const db = memoryDb({
            settings: [{ _id: 'llm', providers: { [SANDBOX]: { embeddingModel: 'qwen3-embedding-0.6b' } } }],
        });

        const profile = await adminModelSettings.getEmbeddingProfile(db, SANDBOX, {
            apiKey: 'sbx-secret', endpoint: 'https://sandbox.example/v1', force: true,
        });

        expect(profile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(profile.vectorSize).toBe(1024);
        expect(profile.apiKey).toBe('sbx-secret');
    });
});

describe('saving chat settings (immediate)', () => {
    test('each platform is stored independently', async () => {
        const db = memoryDb({ settings: [] });

        await adminModelSettings.saveChatSettings(db, OPENAI, { chatModel: 'gpt-5-nano', reasoningEffort: 'high' }, 'admin@x');
        await adminModelSettings.saveChatSettings(db, SANDBOX, { chatModel: 'gpt-oss-120b', reasoningEffort: 'medium' }, 'admin@x');

        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored.providers[OPENAI]).toMatchObject({ chatModel: 'gpt-5-nano', reasoningEffort: 'high' });
        expect(stored.providers[SANDBOX]).toMatchObject({ chatModel: 'gpt-oss-120b', reasoningEffort: 'medium' });
        expect(stored.updatedBy).toBe('admin@x');
    });

    test('an unsupported reasoning effort is coerced to one the model accepts', async () => {
        const db = memoryDb({ settings: [] });
        const saved = await adminModelSettings.saveChatSettings(db, OPENAI, {
            chatModel: 'gpt-5.6-luna', reasoningEffort: 'minimal',
        });
        expect(saved.reasoningEffort).toBe('low');
        expect(saved.supportsReasoning).toBe(true);
    });

    test('a model belonging to the other platform is rejected', async () => {
        const db = memoryDb({ settings: [] });
        await expect(adminModelSettings.saveChatSettings(db, OPENAI, { chatModel: 'qwen3.6-35b-a3b' }))
            .rejects.toMatchObject({ code: 'INVALID_CHAT_MODEL' });
    });

    test('saving invalidates the cache so the next read sees the change', async () => {
        const db = memoryDb({ settings: [] });
        await adminModelSettings.getAllProviderSettings(db);
        await adminModelSettings.saveChatSettings(db, OPENAI, { chatModel: 'gpt-5-nano' });

        const settings = await adminModelSettings.getProviderSettings(db, OPENAI);
        expect(settings.chatModel).toBe('gpt-5-nano');
    });

    test('older front-end-only saves preserve an existing back-end override', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'llm',
                providers: { [OPENAI]: { backend: { chatModel: 'gpt-5.4-nano', reasoningEffort: 'high' } } },
            }],
        });

        await adminModelSettings.saveChatSettings(db, OPENAI, {
            chatModel: 'gpt-5-nano', reasoningEffort: 'low',
        });

        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored.providers[OPENAI].backend).toEqual({ chatModel: 'gpt-5.4-nano', reasoningEffort: 'high' });
    });

    test('a back-end override can be saved and restored to front-end inheritance', async () => {
        const db = memoryDb({ settings: [] });
        await adminModelSettings.saveChatSettings(db, OPENAI, {
            chatModel: 'gpt-5-nano',
            reasoningEffort: 'low',
            backendChatModel: 'gpt-5.4-nano',
            backendReasoningEffort: 'xhigh',
            backendInheritsFrontend: false,
        });
        let settings = await adminModelSettings.getProviderSettings(db, OPENAI, { force: true });
        expect(settings.backendInheritsFrontend).toBe(false);
        expect(settings.lanes.backend).toEqual({ chatModel: 'gpt-5.4-nano', reasoningEffort: 'xhigh' });

        await adminModelSettings.saveChatSettings(db, OPENAI, {
            chatModel: 'gpt-5-nano',
            reasoningEffort: 'high',
            backendInheritsFrontend: true,
        });
        settings = await adminModelSettings.getProviderSettings(db, OPENAI, { force: true });
        expect(settings.backendInheritsFrontend).toBe(true);
        expect(settings.lanes.backend).toEqual({ chatModel: 'gpt-5-nano', reasoningEffort: 'high' });
        const stored = await db.collection('settings').findOne({ _id: 'llm' });
        expect(stored.providers[OPENAI].backend).toBeUndefined();
    });
});

describe('staging an embedding-model change', () => {
    test('staging leaves the active model untouched until activation', async () => {
        const db = memoryDb({ settings: [] });

        await adminModelSettings.stagePendingEmbedding(db, OPENAI, {
            embeddingModel: 'text-embedding-3-large', migrationId: 'mig_1',
        });

        const { providers, pendingEmbedding } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-small');
        expect(pendingEmbedding[OPENAI]).toMatchObject({
            embeddingModel: 'text-embedding-3-large', embeddingRevision: 'v1', migrationId: 'mig_1',
        });
    });

    test('activation promotes the staged model and clears the marker', async () => {
        const db = memoryDb({ settings: [] });
        await adminModelSettings.stagePendingEmbedding(db, OPENAI, { embeddingModel: 'text-embedding-3-large' });

        const activated = await adminModelSettings.activatePendingEmbedding(db, OPENAI);

        expect(activated.embeddingModel).toBe('text-embedding-3-large');
        const { providers, pendingEmbedding } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-large');
        expect(pendingEmbedding[OPENAI]).toBeUndefined();
    });

    test('rollback drops the staged change and keeps the previous model', async () => {
        const db = memoryDb({ settings: [] });
        await adminModelSettings.stagePendingEmbedding(db, OPENAI, { embeddingModel: 'text-embedding-3-large' });

        await adminModelSettings.clearPendingEmbedding(db, OPENAI);

        const { providers, pendingEmbedding } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-small');
        expect(pendingEmbedding[OPENAI]).toBeUndefined();
    });

    test('activating with nothing staged is a no-op', async () => {
        const db = memoryDb({ settings: [] });
        expect(await adminModelSettings.activatePendingEmbedding(db, OPENAI)).toBeNull();
    });

    test('a finished migration never activates a model it did not index', async () => {
        const db = memoryDb({ settings: [] });
        // Model A was staged, then replaced by model B while A was still running.
        await adminModelSettings.stagePendingEmbedding(db, OPENAI, { embeddingModel: 'text-embedding-ada-002' });

        const activated = await adminModelSettings.activatePendingEmbedding(db, OPENAI, {
            embeddingModel: 'text-embedding-3-large',
            embeddingRevision: 'v1',
        });

        // A finishing must not promote B — B has no vectors yet.
        expect(activated).toBeNull();
        const { providers, pendingEmbedding } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-small');
        expect(pendingEmbedding[OPENAI].embeddingModel).toBe('text-embedding-ada-002');
    });

    test('a matching migration activates as usual', async () => {
        const db = memoryDb({ settings: [] });
        await adminModelSettings.stagePendingEmbedding(db, OPENAI, { embeddingModel: 'text-embedding-3-large' });

        const activated = await adminModelSettings.activatePendingEmbedding(db, OPENAI, {
            embeddingModel: 'text-embedding-3-large',
        });

        expect(activated.embeddingModel).toBe('text-embedding-3-large');
        const { providers } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(providers[OPENAI].embeddingModel).toBe('text-embedding-3-large');
    });

    test('an embedding model from the other platform is rejected', async () => {
        const db = memoryDb({ settings: [] });
        await expect(adminModelSettings.stagePendingEmbedding(db, OPENAI, { embeddingModel: 'qwen3-embedding-0.6b' }))
            .rejects.toMatchObject({ code: 'INVALID_EMBEDDING_MODEL' });
    });

    test('a staged entry with no model is ignored when read back', async () => {
        const db = memoryDb({ settings: [{ _id: 'llm', pendingEmbedding: { [OPENAI]: { migrationId: 'x' } } }] });
        const { pendingEmbedding } = await adminModelSettings.getAllProviderSettings(db, { force: true });
        expect(pendingEmbedding[OPENAI]).toBeUndefined();
    });
});
