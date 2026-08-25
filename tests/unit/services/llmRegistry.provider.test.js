/**
 * Per-scope provider resolution: no server-wide LLM_PROVIDER, correct collection
 * routing per surface, independent Super Course resolution, and a cache key that
 * tracks provider, models and credential rotation.
 */
jest.mock('../../../src/services/config', () => ({
    getLLMConfig: jest.fn(() => ({ provider: 'openai' })),
    getProviderInfra: jest.fn((provider) => ({
        provider,
        endpoint: provider === 'ubc-llm-sandbox' ? 'https://sandbox.example/v1' : null,
        bootstrapApiKey: undefined,
    })),
}));
jest.mock('../../../src/services/llm', () => ({
    create: jest.fn(async () => ({ setDbAccessor: jest.fn() })),
}));
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(function FakeQdrant(options) {
    return {
        options,
        embeddingProfile: options.embeddingProfile,
        collectionName: options.embeddingProfile.collection,
        vectorSize: options.embeddingProfile.vectorSize,
        embeddings: { tag: 'embeddings' },
        initialize: jest.fn(async () => {}),
    };
}));

const LlmRegistry = require('../../../src/services/llmRegistry');
const LLMService = require('../../../src/services/llm');
const adminModelSettings = require('../../../src/services/adminModelSettings');
const scopeModelSettings = require('../../../src/services/scopeModelSettings');
const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');
const { memoryDb } = require('../helpers/memory-db');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';

const OLD_ENV = process.env;
beforeEach(() => {
    process.env = { ...OLD_ENV };
    delete process.env.LLM_PROVIDER;
    delete process.env.BIOCBOT_TEST_LLM_STUB;
    delete process.env.LLM_EMBEDDING_MODEL;
    adminModelSettings.invalidateCache();
});
afterAll(() => { process.env = OLD_ENV; });

function keyedSurface(provider, extra = {}) {
    return {
        activeLlmProvider: provider,
        llmCredentials: {
            [OPENAI]: buildKeySubdocument('sk-gpt-key-1111', 'admin', OPENAI),
            [SANDBOX]: buildKeySubdocument('sbx-key-2222', 'admin', SANDBOX),
        },
        ...extra,
    };
}

const lastQdrant = () => {
    const QdrantService = require('../../../src/services/qdrantService');
    return QdrantService.mock.results[QdrantService.mock.results.length - 1].value;
};

describe('a scope resolves its own platform', () => {
    test('a GPT course searches the OpenAI collection with its own key', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }] });

        const services = await registry.forCourse(db, 'C1');

        expect(services.provider).toBe(OPENAI);
        expect(services.embeddingProfile.collection).toBe('biocbot_documents');
        expect(services.embeddingProfile.vectorSize).toBe(1536);
        expect(LLMService.create.mock.calls[0][0].llmConfig).toMatchObject({
            provider: OPENAI, apiKey: 'sk-gpt-key-1111', defaultModel: 'gpt-5.6-luna',
        });
    });

    test('a Sandbox course searches the Qwen collection through the Sandbox endpoint', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(SANDBOX) }] });

        const services = await registry.forCourse(db, 'C1');

        expect(services.provider).toBe(SANDBOX);
        expect(services.embeddingProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(services.embeddingProfile.vectorSize).toBe(1024);
        expect(services.embeddingProfile.embeddingModel).toBe('qwen3-embedding-0.6b');
        expect(LLMService.create.mock.calls[0][0].llmConfig).toMatchObject({
            provider: SANDBOX, apiKey: 'sbx-key-2222', endpoint: 'https://sandbox.example/v1',
        });
        // Sandbox work never uses an OpenAI embedding model.
        expect(services.embeddingProfile.embeddingModel).not.toMatch(/text-embedding/);
    });

    test('two courses on different platforms resolve independently', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({
            courses: [
                { courseId: 'GPT-COURSE', ...keyedSurface(OPENAI) },
                { courseId: 'SBX-COURSE', ...keyedSurface(SANDBOX) },
            ],
        });

        const gpt = await registry.forCourse(db, 'GPT-COURSE');
        const sandbox = await registry.forCourse(db, 'SBX-COURSE');

        expect(gpt.embeddingProfile.collection).toBe('biocbot_documents');
        expect(sandbox.embeddingProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(gpt.qdrant.collectionName).not.toBe(sandbox.qdrant.collectionName);
    });

    test('a legacy course with only llmApiKey resolves as GPT — existing behaviour is preserved', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({
            courses: [{ courseId: 'C1', llmApiKey: buildKeySubdocument('sk-legacy-key', 'admin') }],
        });

        const services = await registry.forCourse(db, 'C1');

        expect(services.provider).toBe(OPENAI);
        expect(services.embeddingProfile.collection).toBe('biocbot_documents');
        expect(LLMService.create.mock.calls[0][0].llmConfig.apiKey).toBe('sk-legacy-key');
    });

    test('a missing key for the active platform is refused with that platform named', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: SANDBOX,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-gpt', 'a', OPENAI) },
            }],
        });

        await expect(registry.forCourse(db, 'C1')).rejects.toMatchObject({
            name: 'LlmKeyError', status: 'missing', provider: SANDBOX,
        });
        expect(LLMService.create).not.toHaveBeenCalled();
    });
});

describe('Super Course surfaces resolve independently of member courses', () => {
    test('a Sandbox bucket keeps its own platform while its courses stay on GPT', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({
            superchats: [{ superchatId: 'S1', ...keyedSurface(SANDBOX) }],
            courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }],
        });

        const bucket = await registry.forSuperchat(db, 'S1');
        const course = await registry.forCourse(db, 'C1');

        expect(bucket.provider).toBe(SANDBOX);
        expect(bucket.embeddingProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(course.provider).toBe(OPENAI);
        expect(course.embeddingProfile.collection).toBe('biocbot_documents');
    });

    test('the instructor Super Course chat has its own platform and key', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({
            settings: [{ _id: 'superCourseChat', ...keyedSurface(SANDBOX) }],
        });

        const services = await registry.forSuperCourseChat(db);

        expect(services.provider).toBe(SANDBOX);
        expect(services.scope).toMatchObject({ type: 'superCourseChat', provider: SANDBOX });
        expect(services.embeddingProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
    });

    test('Notes resolve their own platform too', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ settings: [{ _id: 'notesLlm', ...keyedSurface(SANDBOX) }] });

        const services = await registry.forNotes(db);

        expect(services.provider).toBe(SANDBOX);
        expect(services.embeddingProfile.notesCollection).toBe('superchat_notes_qwen3_embedding_0_6b');
    });

    test('embeddingProfileForScope answers without building any client', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ settings: [] });
        const QdrantService = require('../../../src/services/qdrantService');
        QdrantService.mockClear();

        const profile = await registry.embeddingProfileForScope(db, { type: 'superchat', id: 'S1' }, keyedSurface(SANDBOX));

        expect(profile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(profile.apiKey).toBeNull();
        expect(QdrantService).not.toHaveBeenCalled();
    });
});

describe('admin model settings feed the runtime config', () => {
    test('the configured chat and embedding models for that platform are used', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({
            courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }],
            settings: [{
                _id: 'llm',
                providers: { [OPENAI]: { chatModel: 'gpt-5-nano', embeddingModel: 'text-embedding-3-large' } },
            }],
        });

        const services = await registry.forCourse(db, 'C1');

        expect(services.modelSettings.chatModel).toBe('gpt-5-nano');
        expect(services.embeddingProfile.embeddingModel).toBe('text-embedding-3-large');
        expect(services.embeddingProfile.collection).toBe('biocbot_documents_text_embedding_3_large');
        expect(services.embeddingProfile.vectorSize).toBe(3072);
    });
});

describe('cache identity', () => {
    test('rotating the credential rebuilds the services', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }] });

        await registry.forCourse(db, 'C1');
        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(1);

        await db.collection('courses').updateOne(
            { courseId: 'C1' },
            { $set: { 'llmCredentials.openai.updatedAt': new Date(Date.now() + 60000) } }
        );
        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(2);
    });

    test('switching the surface\'s platform rebuilds the services', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }] });

        const before = await registry.forCourse(db, 'C1');
        expect(before.embeddingProfile.collection).toBe('biocbot_documents');

        await db.collection('courses').updateOne({ courseId: 'C1' }, { $set: { activeLlmProvider: SANDBOX } });
        const after = await registry.forCourse(db, 'C1');

        expect(after.embeddingProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(LLMService.create).toHaveBeenCalledTimes(2);
    });

    test('changing new-scope defaults does not rebuild a materialized course', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }], settings: [] });

        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(1);

        await db.collection('settings').updateOne(
            { _id: 'llm' },
            { $set: { 'providers.openai.chatModel': 'gpt-5-nano' } },
            { upsert: true }
        );
        adminModelSettings.invalidateCache();

        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(1);
    });

    test('changing the default back-end lane does not alter a materialized course', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }], settings: [] });

        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(1);

        await db.collection('settings').updateOne(
            { _id: 'llm' },
            { $set: {
                'providers.openai.backend.chatModel': 'gpt-5.4-nano',
                'providers.openai.backend.reasoningEffort': 'high',
            } },
            { upsert: true }
        );
        adminModelSettings.invalidateCache();

        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(1);
    });

    test('clear() preserves the course snapshot after defaults change', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }], settings: [] });

        await registry.forCourse(db, 'C1');
        await db.collection('settings').updateOne(
            { _id: 'llm' },
            { $set: { 'providers.openai.chatModel': 'gpt-5.4-nano' } },
            { upsert: true }
        );
        registry.clear();

        const services = await registry.forCourse(db, 'C1');
        expect(services.modelSettings.chatModel).toBe('gpt-5.6-luna');
    });

    test('changing the course model snapshot rebuilds only that scope', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(OPENAI) }], settings: [] });
        await registry.forCourse(db, 'C1');
        await scopeModelSettings.saveChatSettings(db, { type: 'course', id: 'C1' }, OPENAI, {
            chatModel: 'gpt-5-nano', reasoningEffort: 'high', backendInheritsFrontend: true
        });

        await registry.forCourse(db, 'C1');
        expect(LLMService.create).toHaveBeenCalledTimes(2);
    });
});

describe('key failure handling is provider-scoped', () => {
    test('a Sandbox failure marks only the Sandbox credential', async () => {
        const registry = new LlmRegistry();
        const db = memoryDb({ courses: [{ courseId: 'C1', ...keyedSurface(SANDBOX) }] });

        await registry.forCourse(db, 'C1');
        const { onProviderKeyFailure } = LLMService.create.mock.calls.at(-1)[0];
        await onProviderKeyFailure('invalid');

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.llmCredentials[SANDBOX].status).toBe('invalid');
        expect(course.llmCredentials[OPENAI].status).toBe('valid');
    });
});
