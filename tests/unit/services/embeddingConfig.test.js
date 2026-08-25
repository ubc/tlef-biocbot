/**
 * Embedding profiles: collection routing, dimensionality, and the identity that
 * keeps GPT and Sandbox vectors from ever mixing.
 */
const {
    DEFAULT_PROFILE_REVISION,
    buildEmbeddingProfile,
    chunkingConfig,
    chunkingSignature,
    collectionNameForEmbedding,
    documentsCollectionBase,
    embeddingProfileKey,
    knownVectorSizeForEmbeddingModel,
    modelCollectionSuffix,
    notesCollectionBase,
    parseEmbeddingProfileKey,
    positiveInteger,
    profileStorageKey,
    publicProfileSummary,
    sameProfile,
    vectorSizeForEmbeddingModel,
} = require('../../../src/services/embeddingConfig');

const OLD_ENV = process.env;
const TOUCHED = [
    'BIOCBOT_TEST_LLM_STUB', 'QDRANT_COLLECTION_NAME', 'QDRANT_NOTES_COLLECTION_NAME',
    'QDRANT_VECTOR_SIZE', 'CHUNK_SIZE', 'CHUNK_OVERLAP', 'CHUNK_MIN', 'CHUNK_STRATEGY',
];
beforeEach(() => {
    process.env = { ...OLD_ENV };
    for (const key of TOUCHED) delete process.env[key];
});
afterAll(() => { process.env = OLD_ENV; });

describe('collection routing per platform', () => {
    test('distinguishes known embedding dimensions from fallback dimensions', () => {
        expect(knownVectorSizeForEmbeddingModel('qwen3-embedding-0.6b')).toBe(1024);
        expect(knownVectorSizeForEmbeddingModel('unlisted-proxy-embedding')).toBeNull();
    });

    test('GPT small keeps the legacy collection; Sandbox Qwen gets its own', () => {
        const gpt = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        const sandbox = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });

        expect(gpt.collection).toBe('biocbot_documents');
        expect(sandbox.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(gpt.notesCollection).toBe('superchat_notes');
        expect(sandbox.notesCollection).toBe('superchat_notes_qwen3_embedding_0_6b');
    });

    test('1536 and 1024 vectors land in different collections', () => {
        const gpt = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        const sandbox = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });

        expect(gpt.vectorSize).toBe(1536);
        expect(sandbox.vectorSize).toBe(1024);
        expect(gpt.collection).not.toBe(sandbox.collection);
    });

    test('Proxy never shares a collection with OpenAI, even for the same model id', () => {
        const openai = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        const proxy = buildEmbeddingProfile({ provider: 'ubc-llm-proxy', embeddingModel: 'text-embedding-3-small' });

        expect(openai.collection).toBe('biocbot_documents');
        expect(proxy.collection).toBe('biocbot_documents_ubc_llm_proxy_text_embedding_3_small');
        expect(proxy.notesCollection).toBe('superchat_notes_ubc_llm_proxy_text_embedding_3_small');
        expect(proxy.collection).not.toBe(openai.collection);
    });

    test('same-dimension models still get separate collections', () => {
        // ada-002 is also 1536, but its vectors are not comparable to 3-small's.
        const small = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        const ada = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-ada-002' });

        expect(small.vectorSize).toBe(ada.vectorSize);
        expect(small.collection).not.toBe(ada.collection);
        expect(ada.collection).toBe('biocbot_documents_text_embedding_ada_002');
    });

    test('a non-v1 revision gets its own collection so re-chunks never mix', () => {
        const v1 = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        const v2 = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small', revision: 'v2' });

        expect(v1.collection).toBe('biocbot_documents');
        expect(v2.collection).toBe('biocbot_documents_text_embedding_3_small_v2');
    });

    test('the stub uses its own collection bases, resolved at call time', () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        expect(documentsCollectionBase()).toBe('biocbot_documents_stub');
        expect(notesCollectionBase()).toBe('superchat_notes_stub');
        const profile = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        expect(profile.collection).toBe('biocbot_documents_stub');
    });

    test('an explicit collection env var replaces the base but keeps model separation', () => {
        process.env.QDRANT_COLLECTION_NAME = 'custom_docs';
        expect(buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' }).collection)
            .toBe('custom_docs');
        expect(buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' }).collection)
            .toBe('custom_docs_qwen3_embedding_0_6b');
    });

    test('modelCollectionSuffix only blanks for the legacy model at v1', () => {
        expect(modelCollectionSuffix('text-embedding-3-small')).toBe('');
        expect(modelCollectionSuffix('text-embedding-3-small', 'v2')).toBe('_text_embedding_3_small_v2');
        expect(modelCollectionSuffix('nomic-embed-text')).toBe('_nomic_embed_text');
        expect(modelCollectionSuffix('text-embedding-3-small', 'v1', 'ubc-llm-proxy'))
            .toBe('_ubc_llm_proxy_text_embedding_3_small');
        expect(modelCollectionSuffix(null)).toBe('');
    });
});

describe('profile identity', () => {
    test('key is provider:model:revision and round-trips', () => {
        const profile = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });
        expect(profile.key).toBe('ubc-llm-sandbox:qwen3-embedding-0.6b:v1');
        // MongoDB reads a dot in an update key as a path separator, so the map
        // key stored on documents replaces dots with underscores.
        expect(profile.storageKey).toBe('ubc-llm-sandbox:qwen3-embedding-0_6b:v1');
        expect(profileStorageKey('openai:text-embedding-3-small:v1'))
            .toBe('openai:text-embedding-3-small:v1');
        expect(parseEmbeddingProfileKey(profile.key)).toEqual({
            provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b', revision: 'v1',
        });
    });

    test('embeddingProfileKey accepts either model field name', () => {
        expect(embeddingProfileKey({ provider: 'openai', embeddingModel: 'm' })).toBe(`openai:m:${DEFAULT_PROFILE_REVISION}`);
        expect(embeddingProfileKey({ provider: 'openai', model: 'm', revision: 'v3' })).toBe('openai:m:v3');
    });

    test('parseEmbeddingProfileKey rejects malformed keys', () => {
        expect(parseEmbeddingProfileKey('nope')).toBeNull();
        expect(parseEmbeddingProfileKey('')).toBeNull();
    });

    test('sameProfile compares keys, not object identity', () => {
        const a = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        const b = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small', apiKey: 'sk-other' });
        const c = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });
        expect(sameProfile(a, b)).toBe(true);
        expect(sameProfile(a, c)).toBe(false);
        expect(sameProfile(a, null)).toBe(false);
    });

    test('building a profile without an embedding model is refused', () => {
        expect(() => buildEmbeddingProfile({ provider: 'openai' }))
            .toThrow(/embedding model is required/i);
    });
});

describe('no key material leaves the profile', () => {
    test('publicProfileSummary drops the API key and endpoint', () => {
        const profile = buildEmbeddingProfile({
            provider: 'ubc-llm-sandbox',
            embeddingModel: 'qwen3-embedding-0.6b',
            endpoint: 'https://sandbox.example/v1',
            apiKey: 'sbx-super-secret',
        });
        const summary = publicProfileSummary(profile);

        expect(summary).toEqual({
            key: 'ubc-llm-sandbox:qwen3-embedding-0.6b:v1',
            storageKey: 'ubc-llm-sandbox:qwen3-embedding-0_6b:v1',
            provider: 'ubc-llm-sandbox',
            embeddingModel: 'qwen3-embedding-0.6b',
            revision: 'v1',
            collection: 'biocbot_documents_qwen3_embedding_0_6b',
            notesCollection: 'superchat_notes_qwen3_embedding_0_6b',
            vectorSize: 1024,
        });
        expect(JSON.stringify(summary)).not.toContain('sbx-super-secret');
        expect(publicProfileSummary(null)).toBeNull();
    });
});

describe('vector sizes and chunking signature', () => {
    test('known models map to their dimensionality', () => {
        expect(vectorSizeForEmbeddingModel('text-embedding-3-small')).toBe(1536);
        expect(vectorSizeForEmbeddingModel('qwen3-embedding-0.6b')).toBe(1024);
        expect(vectorSizeForEmbeddingModel('nomic-embed-text')).toBe(768);
    });

    test('an unknown model falls back to the override, then 768', () => {
        expect(vectorSizeForEmbeddingModel('mystery', '3072')).toBe(3072);
        expect(vectorSizeForEmbeddingModel('mystery', undefined)).toBe(768);
    });

    test('positiveInteger rejects non-positive integers', () => {
        expect(positiveInteger('', 5)).toBe(5);
        expect(positiveInteger(null, 5)).toBe(5);
        expect(() => positiveInteger('0', 5)).toThrow(/positive integer/);
        expect(() => positiveInteger('abc', 5)).toThrow(/positive integer/);
    });

    test('chunking signature changes when chunking configuration changes', () => {
        const before = chunkingSignature(chunkingConfig());
        process.env.CHUNK_SIZE = '4321';
        const after = chunkingSignature(chunkingConfig());
        expect(after).not.toBe(before);
        expect(after).toContain('4321');
    });
});

describe('legacy collectionNameForEmbedding helper', () => {
    test('an explicit name wins, otherwise the model suffix applies', () => {
        expect(collectionNameForEmbedding('base', 'qwen3-embedding-0.6b', 'explicit')).toBe('explicit');
        expect(collectionNameForEmbedding('base', 'qwen3-embedding-0.6b')).toBe('base_qwen3_embedding_0_6b');
        expect(collectionNameForEmbedding('base', 'text-embedding-3-small')).toBe('base');
    });
});
