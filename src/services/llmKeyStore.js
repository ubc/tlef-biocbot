const crypto = require('crypto');
const fetch = require('node-fetch');
const { LLMModule } = require('ubc-genai-toolkit-llm');
const {
    PROVIDERS,
    SELECTABLE_PROVIDERS,
    SUPPORT_EMAIL,
    normalizeProvider,
    providerHelpText,
    providerLabel
} = require('./llmProviders');

const KEY_STATUSES = {
    VALID: 'valid',
    INVALID: 'invalid',
    QUOTA_EXHAUSTED: 'quota_exhausted',
    MISSING: 'missing'
};

const ERROR_CODES = {
    missing: 'LLM_KEY_MISSING',
    invalid: 'LLM_KEY_INVALID',
    quota_exhausted: 'LLM_KEY_QUOTA'
};

const CONTACT_EMAIL = SUPPORT_EMAIL;
const CIPHER_VERSION = 'v1';
const OPENAI_CHAT_URL = 'https://api.openai.com/v1/chat/completions';
const OPENAI_EMBEDDINGS_URL = 'https://api.openai.com/v1/embeddings';

// Field names for the per-surface provider state. Each keyed surface (course,
// bucket, notes, instructor Super Course chat) carries its own copy — keys are
// never shared between surfaces.
const CREDENTIALS_FIELD = 'llmCredentials';
const ACTIVE_PROVIDER_FIELD = 'activeLlmProvider';
const PENDING_PROVIDER_FIELD = 'pendingLlmProvider';
const MIGRATION_ID_FIELD = 'providerMigrationId';

class LlmKeyError extends Error {
    constructor(status, scope = {}, provider = null) {
        super(messageForStatus(status, provider));
        this.name = 'LlmKeyError';
        this.status = status || KEY_STATUSES.MISSING;
        this.code = ERROR_CODES[this.status] || ERROR_CODES.missing;
        this.scope = scope;
        this.provider = provider || scope.provider || null;
        this.httpStatus = 403;
    }
}

class LlmPreparationError extends Error {
    constructor(scope = {}, provider = null) {
        const selectedProvider = provider || scope.provider || null;
        super(`AI material for ${providerLabel(selectedProvider)} is still being prepared.`);
        this.name = 'LlmPreparationError';
        this.code = 'LLM_PROVIDER_PREPARING';
        this.scope = scope;
        this.provider = selectedProvider;
        this.httpStatus = 409;
    }
}

/**
 * Safe browser-facing diagnostic for a key problem. Names the platform the
 * instructor picked ("OpenAI Chat GPT" / "UBC On-Premise LLM") rather than
 * leaking model details.
 * @param {string} status
 * @param {string|null} [provider]
 */
function messageForStatus(status, provider = null) {
    const platform = provider ? `${providerLabel(provider)} ` : '';
    switch (status) {
        case KEY_STATUSES.INVALID:
            return `The ${platform}API key for this AI surface is invalid. Contact ${CONTACT_EMAIL} for a replacement key.`;
        case KEY_STATUSES.QUOTA_EXHAUSTED:
            return `The ${platform}API key for this AI surface is out of credits. Contact ${CONTACT_EMAIL} for help.`;
        case KEY_STATUSES.MISSING:
        default:
            // "a valid X" avoids an a/an choice: the platform labels start with
            // both vowels ("OpenAI…") and consonant-sounding letters ("UBC…").
            return `AI is disabled until a valid ${platform}API key is added. Contact ${CONTACT_EMAIL} for a key.`;
    }
}

function publicKeySummary(llmApiKey) {
    if (!llmApiKey || typeof llmApiKey !== 'object') {
        return {
            status: KEY_STATUSES.MISSING,
            last4: null,
            validatedAt: null,
            updatedAt: null
        };
    }

    return {
        status: llmApiKey.status || KEY_STATUSES.MISSING,
        last4: llmApiKey.last4 || null,
        validatedAt: llmApiKey.validatedAt || null,
        updatedAt: llmApiKey.updatedAt || null
    };
}

function isKeyValid(llmApiKey) {
    return publicKeySummary(llmApiKey).status === KEY_STATUSES.VALID;
}

// ---------------------------------------------------------------------------
// Per-surface provider state
//
// Shape stored on each keyed surface:
//   activeLlmProvider: 'openai' | 'ubc-llm-sandbox' | 'ubc-llm-proxy'
//   llmCredentials: { <provider>: <encrypted key subdocument> }
//   pendingLlmProvider: provider being migrated to, or null
//   providerMigrationId: id of the in-flight migration job, or null
//   aiPreparationRequired: true only when a newly copied surface must remain
//                          unavailable until its first preparation succeeds
//
// Backward compatibility: a legacy `llmApiKey` subdocument with no provider
// metadata is an OpenAI credential. It is read transparently and rewritten into
// `llmCredentials.openai` the next time the surface's key is saved or tested.
// ---------------------------------------------------------------------------

/**
 * Read the provider state of a surface document, applying legacy compatibility.
 * @param {Object|null} doc - Course / superchat / settings document
 * @returns {{activeProvider: string, credentials: Object, pendingProvider: (string|null), migrationId: (string|null), preparationRequired: boolean, legacyOnly: boolean}}
 */
function readProviderState(doc) {
    const source = (doc && typeof doc === 'object') ? doc : {};
    const credentials = {};

    const stored = source[CREDENTIALS_FIELD];
    if (stored && typeof stored === 'object') {
        for (const provider of SELECTABLE_PROVIDERS) {
            if (stored[provider] && typeof stored[provider] === 'object') {
                credentials[provider] = stored[provider];
            }
        }
    }

    // Legacy `llmApiKey` records carry no provider metadata: they are OpenAI
    // credentials. A partial `llmCredentials.openai` (e.g. a status-only update
    // written before the key itself was rewritten) is merged over the legacy
    // subdocument so the ciphertext is never lost mid-migration.
    const legacyKey = source.llmApiKey;
    const hasLegacyKey = !!(legacyKey && typeof legacyKey === 'object' && legacyKey.ciphertext);
    const storedOpenai = credentials[PROVIDERS.OPENAI];
    const legacyOnly = hasLegacyKey && !(storedOpenai && storedOpenai.ciphertext);
    if (legacyOnly) {
        credentials[PROVIDERS.OPENAI] = { ...legacyKey, ...(storedOpenai || {}) };
    } else if (!storedOpenai && legacyKey && typeof legacyKey === 'object') {
        credentials[PROVIDERS.OPENAI] = legacyKey;
    }

    return {
        activeProvider: normalizeProvider(source[ACTIVE_PROVIDER_FIELD], PROVIDERS.OPENAI),
        credentials,
        pendingProvider: SELECTABLE_PROVIDERS.includes(source[PENDING_PROVIDER_FIELD])
            ? source[PENDING_PROVIDER_FIELD]
            : null,
        migrationId: source[MIGRATION_ID_FIELD] || null,
        preparationRequired: source.aiPreparationRequired === true,
        legacyOnly
    };
}

/**
 * The encrypted credential subdocument a surface currently runs on.
 */
function activeCredential(doc) {
    const state = readProviderState(doc);
    return state.credentials[state.activeProvider] || null;
}

function credentialForProvider(doc, provider) {
    const state = readProviderState(doc);
    return state.credentials[normalizeProvider(provider)] || null;
}

function activeProviderOf(doc) {
    return readProviderState(doc).activeProvider;
}

/**
 * Decrypt the API key a surface currently runs on.
 * @returns {string|null}
 */
function decryptActiveKey(doc) {
    const credential = activeCredential(doc);
    if (!credential || !credential.ciphertext) return null;
    return decryptApiKey(credential.ciphertext);
}

/**
 * Browser-safe view of a surface's provider + key state. Never carries
 * ciphertext or decrypted keys.
 * @param {Object|null} doc
 * @returns {Object}
 */
function publicProviderKeyState(doc) {
    const state = readProviderState(doc);
    const keys = {};
    for (const provider of SELECTABLE_PROVIDERS) {
        keys[provider] = publicKeySummary(state.credentials[provider]);
    }

    const active = keys[state.activeProvider];
    return {
        llmProvider: state.activeProvider,
        llmProviderLabel: providerLabel(state.activeProvider),
        llmProviderHelpText: providerHelpText(state.activeProvider),
        pendingLlmProvider: state.pendingProvider,
        providerMigrationId: state.migrationId,
        aiPreparationRequired: state.preparationRequired,
        llmKey: active,
        llmKeysByProvider: keys,
        aiAvailable: active.status === KEY_STATUSES.VALID && !state.preparationRequired
    };
}

function stripPrivateKeyFields(doc) {
    if (!doc || typeof doc !== 'object') return doc;
    const clone = { ...doc };
    const state = publicProviderKeyState(doc);
    clone.llmKey = state.llmKey;
    clone.aiAvailable = state.aiAvailable;
    clone.llmProvider = state.llmProvider;
    clone.llmKeysByProvider = state.llmKeysByProvider;
    clone.pendingLlmProvider = state.pendingLlmProvider;
    clone.aiPreparationRequired = state.aiPreparationRequired;
    delete clone.llmApiKey;
    delete clone[CREDENTIALS_FIELD];
    return clone;
}

function getEncryptionKey() {
    const raw = process.env.BIOCBOT_KEY_ENCRYPTION_SECRET;
    if (!raw) {
        if (process.env.BIOCBOT_TEST_LLM_STUB === '1' || process.env.NODE_ENV === 'test') {
            return crypto.createHash('sha256').update('biocbot-test-llm-key-secret').digest();
        }
        throw new Error('BIOCBOT_KEY_ENCRYPTION_SECRET is required to store AI provider API keys. Generate one with: openssl rand -base64 32');
    }

    const trimmed = raw.trim();
    const base64 = Buffer.from(trimmed, 'base64');
    if (base64.length === 32) {
        return base64;
    }

    if (/^[a-f0-9]{64}$/i.test(trimmed)) {
        const hex = Buffer.from(trimmed, 'hex');
        if (hex.length === 32) return hex;
    }

    throw new Error('BIOCBOT_KEY_ENCRYPTION_SECRET must decode to exactly 32 bytes (recommended: openssl rand -base64 32)');
}

function encryptApiKey(apiKey) {
    const key = getEncryptionKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
        cipher.update(String(apiKey), 'utf8'),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    return [
        CIPHER_VERSION,
        iv.toString('base64'),
        tag.toString('base64'),
        encrypted.toString('base64')
    ].join(':');
}

function decryptApiKey(ciphertext) {
    if (!ciphertext || typeof ciphertext !== 'string') {
        throw new Error('Missing encrypted API key');
    }

    const [version, ivB64, tagB64, encryptedB64] = ciphertext.split(':');
    if (version !== CIPHER_VERSION || !ivB64 || !tagB64 || !encryptedB64) {
        throw new Error('Unsupported encrypted API key format');
    }

    const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        getEncryptionKey(),
        Buffer.from(ivB64, 'base64')
    );
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(encryptedB64, 'base64')),
        decipher.final()
    ]);
    return decrypted.toString('utf8');
}

function buildKeySubdocument(apiKey, updatedBy, provider = PROVIDERS.OPENAI) {
    const trimmed = normalizeApiKey(apiKey);
    if (!trimmed) {
        throw new TypeError('Provider API key must be a non-empty string');
    }
    const now = new Date();
    return {
        ciphertext: encryptApiKey(trimmed),
        last4: trimmed.slice(-4),
        status: KEY_STATUSES.VALID,
        provider: normalizeProvider(provider),
        validatedAt: now,
        updatedAt: now,
        updatedBy: updatedBy || null
    };
}

/**
 * Mongo `$set` fragment that stores a credential for one provider on a surface
 * without disturbing the other provider's credential.
 *
 * `activate: false` stages a credential (used while a provider migration runs)
 * so the surface keeps serving traffic on its previous provider.
 *
 * @param {string} provider
 * @param {Object} credential - Output of buildKeySubdocument()
 * @param {Object} [options] - { activate: boolean }
 * @returns {Object} $set fragment
 */
function credentialSetFields(provider, credential, options = {}) {
    const normalized = normalizeProvider(provider);
    const set = {
        [`${CREDENTIALS_FIELD}.${normalized}`]: credential
    };
    if (options.activate !== false) {
        set[ACTIVE_PROVIDER_FIELD] = normalized;
        // Keep the legacy field in sync for OpenAI so any read path that has not
        // been migrated yet still sees a working key.
        if (normalized === PROVIDERS.OPENAI) {
            set.llmApiKey = credential;
        }
    }
    return set;
}

/**
 * Nested fields for a document being **inserted**, as opposed to updated.
 *
 * credentialSetFields() returns dotted `$set` paths, which MongoDB only
 * interprets as paths inside an update operator. Spreading them into a document
 * literal would create a field literally named `llmCredentials.openai`, so
 * inserts must use this shape instead.
 *
 * @param {string} provider
 * @param {Object} credential - Output of buildKeySubdocument()
 * @returns {Object} Nested document fragment
 */
function credentialDocumentFields(provider, credential) {
    const normalized = normalizeProvider(provider);
    const fields = {
        [ACTIVE_PROVIDER_FIELD]: normalized,
        [CREDENTIALS_FIELD]: { [normalized]: credential }
    };
    // Keep the legacy field populated for OpenAI so any read path that has not
    // been migrated yet still finds a working key.
    if (normalized === PROVIDERS.OPENAI) {
        fields.llmApiKey = credential;
    }
    return fields;
}

/**
 * Mongo `$set` fragment that activates an already-stored provider credential.
 */
function activateProviderSetFields(provider, credential = null) {
    const normalized = normalizeProvider(provider);
    const set = {
        [ACTIVE_PROVIDER_FIELD]: normalized,
        [PENDING_PROVIDER_FIELD]: null,
        [MIGRATION_ID_FIELD]: null,
        aiPreparationRequired: false
    };
    if (normalized === PROVIDERS.OPENAI && credential) {
        set.llmApiKey = credential;
    }
    return set;
}

function normalizeApiKey(apiKey) {
    return typeof apiKey === 'string' ? apiKey.trim() : '';
}

function isOpenAIProvider() {
    return (process.env.LLM_PROVIDER || '').toLowerCase() === 'openai';
}

function isOllamaProvider() {
    return (process.env.LLM_PROVIDER || '').toLowerCase() === 'ollama';
}

/**
 * Every selectable platform (GPT and Sandbox) requires a per-surface key.
 * Only the local `ollama` development runtime, which has no key concept,
 * bypasses enforcement.
 */
function scopedKeysRequired() {
    return !isOllamaProvider() || process.env.BIOCBOT_TEST_LLM_STUB === '1';
}

function mapOpenAIErrorToStatus(error) {
    if (!error) return null;
    const statusCode = error.status || error.statusCode || error.response?.status;
    const code = String(error.code || error.error?.code || error.response?.data?.error?.code || '').toLowerCase();
    const type = String(error.type || error.error?.type || error.response?.data?.error?.type || '').toLowerCase();
    const message = String(error.message || error.error?.message || '').toLowerCase();

    if (
        statusCode === 401 ||
        code.includes('invalid_api_key') ||
        type.includes('invalid_request_error') && message.includes('api key') ||
        message.includes('incorrect api key') ||
        message.includes('invalid api key')
    ) {
        return KEY_STATUSES.INVALID;
    }

    if (
        statusCode === 429 &&
        (
            code.includes('insufficient_quota') ||
            type.includes('insufficient_quota') ||
            message.includes('insufficient_quota') ||
            message.includes('exceeded your current quota') ||
            message.includes('out of credits')
        )
    ) {
        return KEY_STATUSES.QUOTA_EXHAUSTED;
    }

    return null;
}

async function parseOpenAIResponseError(response) {
    let body = null;
    try {
        body = await response.json();
    } catch (_) {
        body = null;
    }

    const error = /** @type {Error & { status?: number, error?: unknown }} */ (
        new Error(body?.error?.message || `OpenAI validation failed with HTTP ${response.status}`)
    );
    error.status = response.status;
    error.error = body?.error || null;
    return error;
}

async function openaiPost(url, apiKey, body) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    });

    if (!response.ok) {
        throw await parseOpenAIResponseError(response);
    }

    return response.json();
}

async function openaiModelRoster(baseUrl, apiKey) {
    const response = await fetch(joinUrl(baseUrl, 'models'), {
        headers: { Authorization: `Bearer ${apiKey}` }
    });
    if (!response.ok) throw await parseOpenAIResponseError(response);
    const body = await response.json();
    return Array.isArray(body?.data)
        ? body.data.map(item => item && item.id).filter(id => typeof id === 'string' && id.length > 0)
        : [];
}

function chatValidationBody(model) {
    const usedModel = model || process.env.OPENAI_MODEL || 'gpt-4.1-mini';
    const body = {
        model: usedModel,
        messages: [{ role: 'user', content: 'ping' }]
    };

    if (String(usedModel).startsWith('gpt-5')) {
        body.max_completion_tokens = 16;
        body.reasoning_effort = ['gpt-5.4-nano', 'gpt-5.6-luna'].includes(usedModel) ? 'low' : 'minimal';
    } else {
        body.max_tokens = 1;
    }

    return body;
}

/**
 * Map a non-OpenAI (sandbox gateway) HTTP failure onto a key status. The UBC
 * Sandbox speaks the OpenAI wire format through its gateway, so the OpenAI
 * mapper is tried first; this adds the plain-HTTP fallbacks.
 */
function mapProviderErrorToStatus(error) {
    const openaiStatus = mapOpenAIErrorToStatus(error);
    if (openaiStatus) return openaiStatus;
    if (!error) return null;

    const statusCode = error.status || error.statusCode || error.response?.status
        || (Number.isInteger(Number(error.code)) ? Number(error.code) : null);
    if (statusCode === 401 || statusCode === 403) return KEY_STATUSES.INVALID;
    if (statusCode === 429) return KEY_STATUSES.QUOTA_EXHAUSTED;
    return null;
}

function joinUrl(base, path) {
    return `${String(base || '').replace(/\/+$/, '')}/${String(path).replace(/^\/+/, '')}`;
}

/**
 * Classify a key in stub mode by prefix so E2E runs never touch a provider.
 * Sandbox keys may use either the shared `sk-` prefixes or `sbx-`.
 */
function stubValidation(trimmed) {
    const discoveredModels = (process.env.BIOCBOT_TEST_PROXY_MODELS || '')
        .split(',')
        .filter(Boolean);
    if (/^(sk|sbx|prx)-test-/.test(trimmed)) {
        return { ok: true, status: KEY_STATUSES.VALID, models: discoveredModels };
    }
    if (/^(sk|sbx|prx)-quota-/.test(trimmed)) {
        return { ok: false, status: KEY_STATUSES.QUOTA_EXHAUSTED, message: messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED) };
    }
    return { ok: false, status: KEY_STATUSES.INVALID, message: messageForStatus(KEY_STATUSES.INVALID) };
}

function validationFailure(status, error, provider) {
    return {
        ok: false,
        status,
        provider,
        message: status === KEY_STATUSES.QUOTA_EXHAUSTED
            ? messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED, provider)
            : messageForStatus(KEY_STATUSES.INVALID, provider),
        detail: error && error.message
    };
}

/**
 * Real, provider-aware key validation.
 *
 * OpenAI  — probes api.openai.com with the configured OpenAI chat + embedding
 *           models.
 * Sandbox — probes the configured Sandbox endpoint with the configured Sandbox
 *           chat model and the Qwen embedding model. Sandbox work never touches
 *           OpenAI.
 * Proxy   — constructs the toolkit provider with only the key and endpoint and
 *           calls getAvailableModels(). No model is guessed or hardcoded.
 *
 * A non-OpenAI key is never assumed valid.
 *
 * @param {Object} options
 * @param {string} options.provider
 * @param {string} options.apiKey
 * @param {string} [options.chatModel]
 * @param {string} [options.embeddingModel]
 * @param {string} [options.endpoint] - Required for the sandbox provider
 * @returns {Promise<{ok: boolean, status: string, provider: string, models?: string[], message?: string, detail?: string}>}
 */
async function validateProviderKey({ provider, apiKey, chatModel, embeddingModel, endpoint } = {}) {
    const normalizedProvider = normalizeProvider(provider);
    const trimmed = normalizeApiKey(apiKey);
    if (!trimmed) {
        return {
            ok: false,
            status: KEY_STATUSES.MISSING,
            provider: normalizedProvider,
            message: 'API key is required'
        };
    }

    if (process.env.BIOCBOT_TEST_LLM_STUB === '1') {
        return { ...stubValidation(trimmed), provider: normalizedProvider };
    }

    if (normalizedProvider === PROVIDERS.PROXY) {
        const base = endpoint || process.env.UBC_LLM_PROXY_ENDPOINT;
        if (!base) {
            return {
                ok: false,
                status: KEY_STATUSES.INVALID,
                provider: normalizedProvider,
                message: `The UBC LLM Proxy endpoint is not configured. Contact ${CONTACT_EMAIL}.`,
                detail: 'Missing UBC_LLM_PROXY_ENDPOINT'
            };
        }

        try {
            const llm = new LLMModule({
                provider: PROVIDERS.PROXY,
                apiKey: trimmed,
                endpoint: base
            });
            const models = await llm.getAvailableModels();
            if (!Array.isArray(models) || models.length === 0) {
                throw new Error('The proxy returned no models for this API key');
            }
            return {
                ok: true,
                status: KEY_STATUSES.VALID,
                provider: normalizedProvider,
                // Preserve ids and ordering exactly as the toolkit returned them.
                models
            };
        } catch (error) {
            const status = mapProviderErrorToStatus(error) || KEY_STATUSES.INVALID;
            return validationFailure(status, error, normalizedProvider);
        }
    }

    if (normalizedProvider === PROVIDERS.SANDBOX) {
        const base = endpoint || process.env.SANDBOX_LLM_ENDPOINT || process.env.LLM_ENDPOINT;
        if (!base) {
            return {
                ok: false,
                status: KEY_STATUSES.INVALID,
                provider: normalizedProvider,
                message: `The UBC LLM Sandbox endpoint is not configured. Contact ${CONTACT_EMAIL}.`,
                detail: 'Missing SANDBOX_LLM_ENDPOINT / LLM_ENDPOINT'
            };
        }

        try {
            const models = await openaiModelRoster(base, trimmed);
            if ((chatModel && !models.includes(chatModel)) || (embeddingModel && !models.includes(embeddingModel))) {
                return {
                    ok: true,
                    status: KEY_STATUSES.VALID,
                    provider: normalizedProvider,
                    models,
                    configurationCompatible: false
                };
            }
            await openaiPost(joinUrl(base, 'embeddings'), trimmed, {
                model: embeddingModel || 'qwen3-embedding-0.6b',
                input: 'biocbot validation'
            });
            await openaiPost(joinUrl(base, 'chat/completions'), trimmed, {
                model: chatModel || process.env.LLM_DEFAULT_MODEL || 'qwen3.6-35b-a3b',
                messages: [{ role: 'user', content: 'ping' }],
                max_tokens: 1
            });
            return { ok: true, status: KEY_STATUSES.VALID, provider: normalizedProvider, models, configurationCompatible: true };
        } catch (error) {
            const status = mapProviderErrorToStatus(error) || KEY_STATUSES.INVALID;
            return validationFailure(status, error, normalizedProvider);
        }
    }

    try {
        const models = await openaiModelRoster('https://api.openai.com/v1', trimmed);
        if ((chatModel && !models.includes(chatModel)) || (embeddingModel && !models.includes(embeddingModel))) {
            return {
                ok: true,
                status: KEY_STATUSES.VALID,
                provider: normalizedProvider,
                models,
                configurationCompatible: false
            };
        }
        await openaiPost(OPENAI_EMBEDDINGS_URL, trimmed, {
            model: embeddingModel || process.env.OPENAI_EMBEDDING_MODEL || 'text-embedding-3-small',
            input: 'biocbot validation'
        });
        await openaiPost(OPENAI_CHAT_URL, trimmed, chatValidationBody(chatModel));
        return { ok: true, status: KEY_STATUSES.VALID, provider: normalizedProvider, models, configurationCompatible: true };
    } catch (error) {
        const status = mapOpenAIErrorToStatus(error) || KEY_STATUSES.INVALID;
        return validationFailure(status, error, normalizedProvider);
    }
}

/**
 * Legacy entry point. Kept so existing call sites keep working while routes are
 * migrated to validateProviderKey(). Ollama (a local dev runtime with no key
 * concept) still short-circuits; every real platform is probed.
 *
 * @param {string} apiKey
 * @param {Object} [options] - Same options as validateProviderKey()
 */
async function validateApiKey(apiKey, options = {}) {
    if (!options.provider && isOllamaProvider() && process.env.BIOCBOT_TEST_LLM_STUB !== '1') {
        const trimmed = normalizeApiKey(apiKey);
        if (!trimmed) {
            return { ok: false, status: KEY_STATUSES.MISSING, message: 'API key is required' };
        }
        return { ok: true, status: KEY_STATUSES.VALID };
    }

    const result = await validateProviderKey({
        ...options,
        provider: options.provider || PROVIDERS.OPENAI,
        apiKey
    });

    // Preserve the historical return shape for untouched callers.
    if (result.ok) return { ok: true, status: result.status };
    return result;
}

async function updateOwnerKeyStatus(db, scope, status, provider = null) {
    if (!db || !scope || !status || status === KEY_STATUSES.MISSING) return;
    const now = new Date();
    const target = normalizeProvider(provider || scope.provider, PROVIDERS.OPENAI);
    const set = {
        [`${CREDENTIALS_FIELD}.${target}.status`]: status,
        [`${CREDENTIALS_FIELD}.${target}.updatedAt`]: now
    };
    // Mirror onto the legacy field for OpenAI so a surface that has not been
    // rewritten yet reports the same status. readProviderState() merges the two.
    if (target === PROVIDERS.OPENAI) {
        set['llmApiKey.status'] = status;
        set['llmApiKey.updatedAt'] = now;
    }

    if (scope.type === 'course') {
        await db.collection('courses').updateOne({ courseId: scope.id }, { $set: set });
    } else if (scope.type === 'superchat') {
        await db.collection('superchats').updateOne({ superchatId: scope.id }, { $set: set });
    } else if (scope.type === 'notes') {
        await db.collection('settings').updateOne({ _id: 'notesLlm' }, { $set: set });
    } else if (scope.type === 'superCourseChat') {
        await db.collection('settings').updateOne({ _id: 'superCourseChat' }, { $set: set });
    }
}

function structuredKeyError(status) {
    return {
        success: false,
        code: ERROR_CODES[status] || ERROR_CODES.missing,
        message: messageForStatus(status)
    };
}

function structuredKeyErrorForProvider(status, provider) {
    return {
        success: false,
        code: ERROR_CODES[status] || ERROR_CODES.missing,
        message: messageForStatus(status, provider),
        provider: provider || null
    };
}

module.exports = {
    ACTIVE_PROVIDER_FIELD,
    CONTACT_EMAIL,
    CREDENTIALS_FIELD,
    ERROR_CODES,
    KEY_STATUSES,
    LlmKeyError,
    LlmPreparationError,
    MIGRATION_ID_FIELD,
    PENDING_PROVIDER_FIELD,
    activateProviderSetFields,
    activeCredential,
    activeProviderOf,
    buildKeySubdocument,
    credentialDocumentFields,
    credentialForProvider,
    credentialSetFields,
    decryptActiveKey,
    decryptApiKey,
    encryptApiKey,
    isKeyValid,
    isOllamaProvider,
    mapOpenAIErrorToStatus,
    mapProviderErrorToStatus,
    messageForStatus,
    publicKeySummary,
    publicProviderKeyState,
    readProviderState,
    scopedKeysRequired,
    stripPrivateKeyFields,
    structuredKeyError,
    structuredKeyErrorForProvider,
    updateOwnerKeyStatus,
    validateApiKey,
    validateProviderKey
};
