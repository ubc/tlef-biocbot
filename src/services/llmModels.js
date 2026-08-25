const OPENAI_DEFAULT_MODEL = 'gpt-4.1-mini';
const SANDBOX_DEFAULT_MODEL = 'qwen3.6-35b-a3b';
const PROXY_PROVIDER = 'ubc-llm-proxy';
const PROXY_REASONING_EFFORTS = Object.freeze([
    'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'
]);

const MODEL_PROFILES = Object.freeze({
    'gpt-4.1-mini': { providers: ['openai'], reasoningEfforts: [], defaultReasoningEffort: 'minimal' },
    'gpt-5-nano': { providers: ['openai'], reasoningEfforts: ['minimal', 'low', 'medium', 'high'], defaultReasoningEffort: 'minimal' },
    'gpt-5.4-nano': { providers: ['openai'], reasoningEfforts: ['none', 'low', 'medium', 'high', 'xhigh'], defaultReasoningEffort: 'low' },
    'gpt-5.6-luna': {
        providers: ['openai'],
        reasoningEfforts: ['none', 'low', 'medium', 'high', 'xhigh', 'max'],
        // BiocBot intentionally suggests the lower-cost selection; this is a
        // UI choice, not the model vendor's default.
        defaultReasoningEffort: 'low'
    },
    'qwen3.6-35b-a3b': {
        providers: ['ubc-llm-sandbox'],
        // `none` is important for short/structured calls: b3000 translates it
        // to chat_template_kwargs.enable_thinking=false for Qwen3 models.
        reasoningEfforts: ['none', 'low', 'medium', 'high'],
        defaultReasoningEffort: 'none',
        // The sandbox reports a 32K total context window. Reserving all 32K
        // for output leaves no room for BioCBot's system prompt or RAG context.
        maxOutputTokens: 4096
    },
    'gpt-oss-120b': {
        providers: ['ubc-llm-sandbox'],
        reasoningEfforts: ['low', 'medium', 'high'],
        defaultReasoningEffort: 'low'
    }
});

const PROVIDER_MODELS = Object.freeze({
    openai: ['gpt-4.1-mini', 'gpt-5-nano', 'gpt-5.4-nano', 'gpt-5.6-luna'],
    'ubc-llm-sandbox': ['qwen3.6-35b-a3b', 'gpt-oss-120b']
});

// --- Embedding models -------------------------------------------------------
// Sandbox surfaces must embed on the UBC Sandbox/B300 — never with OpenAI —
// so the allowed embedding models are strictly partitioned by provider.
const OPENAI_DEFAULT_EMBEDDING_MODEL = 'text-embedding-3-small';
const SANDBOX_DEFAULT_EMBEDDING_MODEL = 'qwen3-embedding-0.6b';

const PROVIDER_EMBEDDING_MODELS = Object.freeze({
    openai: ['text-embedding-3-small', 'text-embedding-3-large', 'text-embedding-ada-002'],
    'ubc-llm-sandbox': ['qwen3-embedding-0.6b']
});

function configuredProvider() {
    return process.env.LLM_PROVIDER || 'openai';
}

function allowedEmbeddingModelsForProvider(provider, discoveredModels = []) {
    if (provider === 'ollama') {
        return process.env.LLM_EMBEDDING_MODEL ? [process.env.LLM_EMBEDDING_MODEL] : ['nomic-embed-text'];
    }
    if (provider === PROXY_PROVIDER) return exactDiscoveredModels(discoveredModels);
    const supported = [...(PROVIDER_EMBEDDING_MODELS[provider] || PROVIDER_EMBEDDING_MODELS.openai)];
    const discovered = exactDiscoveredModels(discoveredModels);
    return discovered.length > 0 ? supported.filter(model => discovered.includes(model)) : supported;
}

/**
 * Read a provider-scoped embedding model from the environment.
 *
 * `LLM_EMBEDDING_MODEL` is the historical single-provider variable, so it is
 * only honoured when its value actually belongs to the provider being asked
 * about. Otherwise a deployment configured for the sandbox would silently hand
 * `qwen3-embedding-0.6b` to OpenAI surfaces.
 */
function envEmbeddingModelForProvider(provider) {
    if (provider === PROXY_PROVIDER) return null;
    const explicit = provider === 'ubc-llm-sandbox'
        ? process.env.SANDBOX_EMBEDDING_MODEL
        : process.env.OPENAI_EMBEDDING_MODEL;
    if (explicit && (PROVIDER_EMBEDDING_MODELS[provider] || []).includes(explicit)) return explicit;

    const shared = process.env.LLM_EMBEDDING_MODEL;
    if (!shared) return null;
    const known = PROVIDER_EMBEDDING_MODELS[provider] || [];
    if (known.includes(shared)) return shared;
    if (provider === 'ollama') return shared;
    return null;
}

/**
 * Bootstrap default embedding model for a provider — used only until an admin
 * stores model settings in MongoDB.
 */
function defaultEmbeddingModelForProvider(provider) {
    if (provider === 'ollama') {
        return process.env.LLM_EMBEDDING_MODEL || 'nomic-embed-text';
    }
    if (provider === PROXY_PROVIDER) return null;
    return envEmbeddingModelForProvider(provider)
        || (provider === 'ubc-llm-sandbox'
            ? SANDBOX_DEFAULT_EMBEDDING_MODEL
            : OPENAI_DEFAULT_EMBEDDING_MODEL);
}

function isAllowedEmbeddingModel(provider, model, discoveredModels = []) {
    return allowedEmbeddingModelsForProvider(provider, discoveredModels).includes(model);
}

function configuredDefaultModel(provider = configuredProvider()) {
    if (provider === 'ubc-llm-sandbox') {
        return process.env.LLM_DEFAULT_MODEL || SANDBOX_DEFAULT_MODEL;
    }
    if (provider === 'ollama') {
        return process.env.OLLAMA_MODEL || null;
    }
    if (provider === PROXY_PROVIDER) return null;
    return process.env.OPENAI_MODEL || OPENAI_DEFAULT_MODEL;
}

function exactDiscoveredModels(models) {
    if (!Array.isArray(models)) return [];
    return models.filter(model => typeof model === 'string' && model.length > 0);
}

function allowedModelsForProvider(provider, defaultModel = configuredDefaultModel(provider), discoveredModels = []) {
    if (provider === 'ollama') {
        return defaultModel ? [defaultModel] : [];
    }

    if (provider === PROXY_PROVIDER) {
        return exactDiscoveredModels(discoveredModels);
    }

    const models = [...(PROVIDER_MODELS[provider] || PROVIDER_MODELS.openai)];
    const discovered = exactDiscoveredModels(discoveredModels);
    return discovered.length > 0 ? models.filter(model => discovered.includes(model)) : models;
}

function fallbackModelForProvider(provider, defaultModel = configuredDefaultModel(provider), discoveredModels = []) {
    const allowed = allowedModelsForProvider(provider, defaultModel, discoveredModels);
    if (defaultModel && allowed.includes(defaultModel)) return defaultModel;
    if (provider === PROXY_PROVIDER) return null;
    if (provider === 'ubc-llm-sandbox') return SANDBOX_DEFAULT_MODEL;
    return allowed[0] || OPENAI_DEFAULT_MODEL;
}

function modelProfile(provider, model) {
    const profile = MODEL_PROFILES[model];
    if (profile && profile.providers.includes(provider)) return profile;

    if (provider === PROXY_PROVIDER) {
        // `/models` is a flat entitlement list. It does not describe reasoning
        // support, so let the admin choose and validate that choice with a real
        // chat operation instead of guessing from the model id.
        return {
            providers: [provider],
            reasoningEfforts: [...PROXY_REASONING_EFFORTS],
            defaultReasoningEffort: 'low'
        };
    }

    return { providers: [provider], reasoningEfforts: [], defaultReasoningEffort: 'minimal' };
}

function reasoningEffortsForModel(provider, model) {
    return [...modelProfile(provider, model).reasoningEfforts];
}

function supportsReasoning(provider, model) {
    return reasoningEffortsForModel(provider, model).length > 0;
}

function maxOutputTokensForModel(provider, model) {
    const value = modelProfile(provider, model).maxOutputTokens;
    return Number.isInteger(value) && value > 0 ? value : null;
}

function normalizeReasoningEffort(provider, model, requested) {
    const profile = modelProfile(provider, model);
    if (profile.reasoningEfforts.length === 0) return 'minimal';
    if (profile.reasoningEfforts.includes(requested)) return requested;
    if (requested === 'minimal' && profile.reasoningEfforts.includes('low')) return 'low';
    if (['xhigh', 'max'].includes(requested) && profile.reasoningEfforts.includes('high')) return 'high';
    return profile.defaultReasoningEffort;
}

function catalogForProvider(
    provider = configuredProvider(),
    defaultModel = configuredDefaultModel(provider),
    discoveredModels = []
) {
    const allowedModels = allowedModelsForProvider(provider, defaultModel, discoveredModels);
    return {
        provider,
        defaultModel: fallbackModelForProvider(provider, defaultModel),
        allowedModels,
        reasoningEffortsByModel: Object.fromEntries(
            allowedModels.map(model => [model, reasoningEffortsForModel(provider, model)])
        ),
        defaultReasoningEffortByModel: Object.fromEntries(
            allowedModels.map(model => [model, modelProfile(provider, model).defaultReasoningEffort])
        )
    };
}

/**
 * Full admin-facing catalog for a platform: chat models, embedding models and
 * reasoning efforts. Consumed by the Platforms and Models settings screen.
 */
function adminCatalogForProvider(provider, discoveredModels = []) {
    const chat = catalogForProvider(provider, configuredDefaultModel(provider), discoveredModels);
    return {
        ...chat,
        // The proxy endpoint exposes one flat list. Deliberately offer every
        // exact id in both selectors; save-time provider calls establish which
        // operation(s) each selected id actually supports.
        allowedEmbeddingModels: provider === PROXY_PROVIDER
            ? exactDiscoveredModels(discoveredModels)
            : allowedEmbeddingModelsForProvider(provider),
        defaultEmbeddingModel: defaultEmbeddingModelForProvider(provider)
    };
}

module.exports = {
    OPENAI_DEFAULT_EMBEDDING_MODEL,
    OPENAI_DEFAULT_MODEL,
    PROVIDER_EMBEDDING_MODELS,
    PROXY_PROVIDER,
    PROXY_REASONING_EFFORTS,
    SANDBOX_DEFAULT_EMBEDDING_MODEL,
    SANDBOX_DEFAULT_MODEL,
    adminCatalogForProvider,
    allowedEmbeddingModelsForProvider,
    allowedModelsForProvider,
    catalogForProvider,
    configuredDefaultModel,
    configuredProvider,
    defaultEmbeddingModelForProvider,
    envEmbeddingModelForProvider,
    exactDiscoveredModels,
    fallbackModelForProvider,
    isAllowedEmbeddingModel,
    maxOutputTokensForModel,
    normalizeReasoningEffort,
    reasoningEffortsForModel,
    supportsReasoning
};
