/**
 * Embedding profiles
 *
 * An *embedding profile* is the complete description of how a piece of content
 * was (or must be) vectorised: which provider produced the vectors, with which
 * embedding model, at which revision, into which Qdrant collection, at which
 * dimensionality.
 *
 * Nothing in the app may pick an embedding model from a single global env var
 * any more — every index/search call carries an explicit profile so a course on
 * GPT and a Super Course bucket on Sandbox can coexist without ever mixing
 * vectors.
 *
 * Collection naming:
 *   openai:text-embedding-3-small:v1  -> biocbot_documents            (legacy name preserved)
 *   ubc-llm-sandbox:qwen3-embedding-0.6b:v1 -> biocbot_documents_qwen3_embedding_0_6b
 *   ubc-llm-proxy:text-embedding-3-small:v1 -> biocbot_documents_ubc_llm_proxy_text_embedding_3_small
 * Proxy collections include the provider because a proxy model id matching an
 * OpenAI id does not guarantee byte-compatible vectors. Existing OpenAI and
 * Sandbox collection names remain unchanged.
 */

const { DEFAULT_PROVIDER } = require('./llmProviders');

const EMBEDDING_VECTOR_SIZES = Object.freeze({
    'text-embedding-3-small': 1536,
    'text-embedding-3-large': 3072,
    'text-embedding-ada-002': 1536,
    'nomic-embed-text': 768,
    'qwen3-embedding-0.6b': 1024
});

// The only model that keeps the historical un-suffixed collection names. Every
// other model — even one with the same dimensionality — gets its own
// collection, because vectors from different models are not comparable.
const LEGACY_COLLECTION_MODEL = 'text-embedding-3-small';

const DEFAULT_PROFILE_REVISION = 'v1';

// Collection bases are resolved at call time, not module load, because the
// embeddings stub flag is toggled per test run.
function documentsCollectionBase() {
    if (process.env.QDRANT_COLLECTION_NAME) return process.env.QDRANT_COLLECTION_NAME;
    return process.env.BIOCBOT_TEST_LLM_STUB === '1' ? 'biocbot_documents_stub' : 'biocbot_documents';
}

function notesCollectionBase() {
    if (process.env.QDRANT_NOTES_COLLECTION_NAME) return process.env.QDRANT_NOTES_COLLECTION_NAME;
    return process.env.BIOCBOT_TEST_LLM_STUB === '1' ? 'superchat_notes_stub' : 'superchat_notes';
}

function positiveInteger(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`QDRANT_VECTOR_SIZE must be a positive integer, received: ${value}`);
    }
    return parsed;
}

function vectorSizeForEmbeddingModel(model, override = process.env.QDRANT_VECTOR_SIZE) {
    return EMBEDDING_VECTOR_SIZES[model] || positiveInteger(override, 768);
}

function knownVectorSizeForEmbeddingModel(model) {
    return EMBEDDING_VECTOR_SIZES[model] || null;
}

function slugify(value) {
    return String(value || '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '');
}

/**
 * Suffix appended to a base collection name for a given model/revision.
 * Empty only for the legacy OpenAI small model at revision v1.
 */
function modelCollectionSuffix(model, revision = DEFAULT_PROFILE_REVISION, provider = DEFAULT_PROVIDER) {
    if (provider === 'ubc-llm-proxy') {
        if (!model) return `_${slugify(provider)}`;
        const parts = [slugify(provider), slugify(model)];
        if (revision && revision !== DEFAULT_PROFILE_REVISION) parts.push(slugify(revision));
        return `_${parts.filter(Boolean).join('_')}`;
    }

    const isLegacy = model === LEGACY_COLLECTION_MODEL && revision === DEFAULT_PROFILE_REVISION;
    if (!model || isLegacy) return '';
    const parts = [slugify(model)];
    if (revision && revision !== DEFAULT_PROFILE_REVISION) parts.push(slugify(revision));
    return `_${parts.filter(Boolean).join('_')}`;
}

/**
 * Legacy helper kept for callers that only know a base name + model.
 * @deprecated Prefer buildEmbeddingProfile() and read `profile.collection`.
 */
function collectionNameForEmbedding(baseName, model, explicitName) {
    if (explicitName) return explicitName;
    return `${baseName}${modelCollectionSuffix(model)}`;
}

/**
 * Stable identity of a profile, used as the `embeddingIndexes` map key and as
 * the migration-job dedupe key.
 */
function embeddingProfileKey({ provider, embeddingModel, model, revision } = {}) {
    const usedModel = embeddingModel || model;
    return `${provider}:${usedModel}:${revision || DEFAULT_PROFILE_REVISION}`;
}

/**
 * MongoDB treats a dot in an update key as a path separator, and embedding
 * model ids contain dots (`qwen3-embedding-0.6b`). Using the raw profile key as
 * an `embeddingIndexes` map key would therefore write a nested object instead
 * of one entry, so the map is keyed by this dot-free form.
 *
 * The readable identity is preserved: each stored record still carries
 * provider / model / revision, and `profile.key` keeps its dots for API
 * responses and job fields (which are values, not field names).
 */
function profileStorageKey(key) {
    return String(key || '').replace(/\./g, '_');
}

function parseEmbeddingProfileKey(key) {
    const parts = String(key || '').split(':');
    if (parts.length < 3) return null;
    const revision = parts[parts.length - 1];
    const provider = parts[0];
    const embeddingModel = parts.slice(1, parts.length - 1).join(':');
    return { provider, embeddingModel, revision };
}

/**
 * Chunking configuration. Anything here changes the resulting chunks, so it
 * feeds the index fingerprint.
 */
function chunkingConfig() {
    return {
        strategy: process.env.CHUNK_STRATEGY || 'recursiveCharacter',
        chunkSize: Number(process.env.CHUNK_SIZE) || 1000,
        chunkOverlap: Number(process.env.CHUNK_OVERLAP) || 200,
        minChunkSize: Number(process.env.CHUNK_MIN) || 100
    };
}

/**
 * Compact signature of the chunking configuration, embedded in every index
 * fingerprint so a chunk-size change marks existing indexes stale.
 */
function chunkingSignature(config = chunkingConfig()) {
    return [
        config.strategy,
        config.chunkSize,
        config.chunkOverlap,
        config.minChunkSize
    ].join('/');
}

/**
 * Build the full embedding profile for a provider + model.
 *
 * @param {Object} options
 * @param {string} options.provider - Provider id ('openai' | 'ubc-llm-sandbox' | 'ubc-llm-proxy')
 * @param {string} options.embeddingModel - Exact embedding model id
 * @param {string} [options.revision] - Profile revision, defaults to 'v1'
 * @param {string} [options.endpoint] - Provider endpoint (infrastructure config)
 * @param {string} [options.apiKey] - Decrypted, surface-scoped API key
 * @param {number} [options.vectorSize] - Override for models not in the table
 * @returns {Object} Frozen-ish profile descriptor
 */
function buildEmbeddingProfile({
    provider,
    embeddingModel,
    revision = DEFAULT_PROFILE_REVISION,
    endpoint = null,
    apiKey = null,
    vectorSize
} = {}) {
    const normalizedProvider = provider || DEFAULT_PROVIDER;
    if (!embeddingModel) {
        throw new Error(`An embedding model is required to build an embedding profile for ${normalizedProvider}`);
    }

    const suffix = modelCollectionSuffix(embeddingModel, revision, normalizedProvider);
    const documentsBase = documentsCollectionBase();
    const notesBase = notesCollectionBase();

    const key = embeddingProfileKey({ provider: normalizedProvider, embeddingModel, revision });

    return {
        key,
        // Mongo-safe map key for `embeddingIndexes` (see profileStorageKey).
        storageKey: profileStorageKey(key),
        provider: normalizedProvider,
        embeddingModel,
        revision,
        endpoint,
        apiKey,
        vectorSize: vectorSize || vectorSizeForEmbeddingModel(embeddingModel),
        collection: `${documentsBase}${suffix}`,
        notesCollection: `${notesBase}${suffix}`,
        chunking: chunkingConfig()
    };
}

/**
 * Public (safe to serialise) view of a profile — never carries the API key.
 */
function publicProfileSummary(profile) {
    if (!profile) return null;
    return {
        key: profile.key,
        storageKey: profile.storageKey,
        provider: profile.provider,
        embeddingModel: profile.embeddingModel,
        revision: profile.revision,
        collection: profile.collection,
        notesCollection: profile.notesCollection,
        vectorSize: profile.vectorSize
    };
}

function sameProfile(a, b) {
    if (!a || !b) return false;
    return a.key === b.key;
}

module.exports = {
    DEFAULT_PROFILE_REVISION,
    EMBEDDING_VECTOR_SIZES,
    LEGACY_COLLECTION_MODEL,
    buildEmbeddingProfile,
    documentsCollectionBase,
    notesCollectionBase,
    chunkingConfig,
    chunkingSignature,
    collectionNameForEmbedding,
    embeddingProfileKey,
    knownVectorSizeForEmbeddingModel,
    modelCollectionSuffix,
    parseEmbeddingProfileKey,
    positiveInteger,
    profileStorageKey,
    publicProfileSummary,
    sameProfile,
    vectorSizeForEmbeddingModel
};
