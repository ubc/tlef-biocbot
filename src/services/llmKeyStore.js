const crypto = require('crypto');
const fetch = require('node-fetch');

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

const CONTACT_EMAIL = 'LT.hub@ubc.ca';
const CIPHER_VERSION = 'v1';
const OPENAI_CHAT_URL = 'https://api.openai.com/v1/chat/completions';
const OPENAI_EMBEDDINGS_URL = 'https://api.openai.com/v1/embeddings';

class LlmKeyError extends Error {
    constructor(status, scope = {}) {
        super(messageForStatus(status));
        this.name = 'LlmKeyError';
        this.status = status || KEY_STATUSES.MISSING;
        this.code = ERROR_CODES[this.status] || ERROR_CODES.missing;
        this.scope = scope;
        this.httpStatus = 403;
    }
}

function messageForStatus(status) {
    switch (status) {
        case KEY_STATUSES.INVALID:
            return `The OpenAI API key for this AI surface is invalid. Contact ${CONTACT_EMAIL} for a replacement key.`;
        case KEY_STATUSES.QUOTA_EXHAUSTED:
            return `The OpenAI API key for this AI surface is out of credits. Contact ${CONTACT_EMAIL} for help.`;
        case KEY_STATUSES.MISSING:
        default:
            return `AI is disabled until an OpenAI API key is added. Contact ${CONTACT_EMAIL} for a key.`;
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

function stripPrivateKeyFields(doc) {
    if (!doc || typeof doc !== 'object') return doc;
    const clone = { ...doc };
    clone.llmKey = publicKeySummary(doc.llmApiKey);
    clone.aiAvailable = isKeyValid(doc.llmApiKey);
    delete clone.llmApiKey;
    return clone;
}

function getEncryptionKey() {
    const raw = process.env.BIOCBOT_KEY_ENCRYPTION_SECRET;
    if (!raw) {
        if (process.env.BIOCBOT_TEST_LLM_STUB === '1' || process.env.NODE_ENV === 'test') {
            return crypto.createHash('sha256').update('biocbot-test-llm-key-secret').digest();
        }
        throw new Error('BIOCBOT_KEY_ENCRYPTION_SECRET is required to store OpenAI API keys. Generate one with: openssl rand -base64 32');
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

function buildKeySubdocument(apiKey, updatedBy) {
    const trimmed = normalizeApiKey(apiKey);
    const now = new Date();
    return {
        ciphertext: encryptApiKey(trimmed),
        last4: trimmed.slice(-4),
        status: KEY_STATUSES.VALID,
        validatedAt: now,
        updatedAt: now,
        updatedBy: updatedBy || null
    };
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

function scopedKeysRequired() {
    return isOpenAIProvider() || process.env.BIOCBOT_TEST_LLM_STUB === '1';
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

function chatValidationBody() {
    const model = process.env.OPENAI_MODEL || 'gpt-4.1-mini';
    const body = {
        model,
        messages: [{ role: 'user', content: 'ping' }]
    };

    if (String(model).startsWith('gpt-5')) {
        body.max_completion_tokens = 16;
        body.reasoning_effort = model === 'gpt-5.4-nano' ? 'low' : 'minimal';
    } else {
        body.max_tokens = 1;
    }

    return body;
}

async function validateApiKey(apiKey) {
    const trimmed = normalizeApiKey(apiKey);
    if (!trimmed) {
        return { ok: false, status: KEY_STATUSES.MISSING, message: 'API key is required' };
    }

    if (process.env.BIOCBOT_TEST_LLM_STUB === '1') {
        if (trimmed.startsWith('sk-test-')) {
            return { ok: true, status: KEY_STATUSES.VALID };
        }
        if (trimmed.startsWith('sk-quota-')) {
            return { ok: false, status: KEY_STATUSES.QUOTA_EXHAUSTED, message: messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED) };
        }
        return { ok: false, status: KEY_STATUSES.INVALID, message: messageForStatus(KEY_STATUSES.INVALID) };
    }

    if (!isOpenAIProvider()) {
        return { ok: true, status: KEY_STATUSES.VALID };
    }

    try {
        await openaiPost(OPENAI_EMBEDDINGS_URL, trimmed, {
            model: process.env.LLM_EMBEDDING_MODEL || 'text-embedding-3-small',
            input: 'biocbot validation'
        });
        await openaiPost(OPENAI_CHAT_URL, trimmed, chatValidationBody());
        return { ok: true, status: KEY_STATUSES.VALID };
    } catch (error) {
        const status = mapOpenAIErrorToStatus(error) || KEY_STATUSES.INVALID;
        return {
            ok: false,
            status,
            message: status === KEY_STATUSES.INVALID
                ? messageForStatus(KEY_STATUSES.INVALID)
                : messageForStatus(KEY_STATUSES.QUOTA_EXHAUSTED),
            detail: error.message
        };
    }
}

async function updateOwnerKeyStatus(db, scope, status) {
    if (!db || !scope || !status || status === KEY_STATUSES.MISSING) return;
    const set = {
        'llmApiKey.status': status,
        'llmApiKey.updatedAt': new Date()
    };

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

module.exports = {
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
    validateApiKey
};
