/**
 * Model configuration owned by one keyed AI surface.
 *
 * The `_id: llm` settings document remains the copy-on-create template. Once
 * materialized, a course/bucket/notes/chat resolves models exclusively from
 * its own `llmModelSettings` snapshot.
 */

const adminModelSettings = require('./adminModelSettings');
const migrations = require('./providerMigrationService');
const {
    DEFAULT_PROFILE_REVISION,
    buildEmbeddingProfile
} = require('./embeddingConfig');
const {
    SELECTABLE_PROVIDERS,
    normalizeProvider
} = require('./llmProviders');
const {
    allowedEmbeddingModelsForProvider,
    allowedModelsForProvider,
    configuredDefaultModel,
    normalizeReasoningEffort,
    supportsReasoning
} = require('./llmModels');
const { LANES } = require('./llmLanes');

const FIELD = 'llmModelSettings';
const READY = 'ready';
const NEEDS_ADMIN = 'needs_admin_configuration';

function targetFor(scope) {
    const target = migrations.scopeTarget(scope);
    if (!target) {
        const error = new Error(`Unknown AI model-settings scope: ${scope?.type || '(missing)'}`);
        error.code = 'INVALID_LLM_SCOPE';
        throw error;
    }
    return target;
}

function storageProvider(settings = {}, overrides = {}) {
    const backend = settings.lanes?.[LANES.BACKEND] || settings.backend || settings;
    const stored = {
        chatModel: settings.chatModel || null,
        reasoningEffort: settings.reasoningEffort || null,
        embeddingModel: settings.embeddingModel || null,
        embeddingRevision: settings.embeddingRevision || DEFAULT_PROFILE_REVISION,
        vectorSize: Number.isInteger(settings.vectorSize) ? settings.vectorSize : null,
        availableModels: Array.isArray(settings.availableModels) ? [...settings.availableModels] : [],
        modelsDiscovered: settings.modelsDiscovered === true,
        configurationStatus: settings.configurationStatus || (settings.configured ? READY : NEEDS_ADMIN)
    };
    if (settings.backendInheritsFrontend === false && backend?.chatModel) {
        stored.backend = {
            chatModel: backend.chatModel,
            reasoningEffort: backend.reasoningEffort
        };
    }
    return { ...stored, ...overrides };
}

function compatibleSelection(provider, stored = {}) {
    const rosterKnown = stored.modelsDiscovered === true;
    const roster = Array.isArray(stored.availableModels) ? stored.availableModels : [];
    const rosterFilter = rosterKnown && roster.length === 0 ? ['__no_models_available__'] : roster;
    const chatAllowed = allowedModelsForProvider(provider, configuredDefaultModel(provider), rosterFilter);
    const embeddingAllowed = allowedEmbeddingModelsForProvider(provider, rosterFilter);
    const backend = stored.backend || stored;
    const complete = !!(stored.chatModel && backend.chatModel && stored.embeddingModel);
    const compatible = !rosterKnown || (
        chatAllowed.includes(stored.chatModel)
        && chatAllowed.includes(backend.chatModel)
        && embeddingAllowed.includes(stored.embeddingModel)
    );
    return complete && compatible;
}

function normalizeScopedProviderSettings(provider, stored) {
    const source = stored && typeof stored === 'object' ? { ...stored } : {};
    const normalized = adminModelSettings.normalizeProviderSettings(provider, source);
    const ready = source.configurationStatus
        ? source.configurationStatus === READY && compatibleSelection(provider, source)
        : compatibleSelection(provider, source);
    return {
        ...normalized,
        availableModels: Array.isArray(source.availableModels) ? [...source.availableModels] : [],
        modelsDiscovered: source.modelsDiscovered === true,
        configurationStatus: ready ? READY : NEEDS_ADMIN,
        configured: ready
    };
}

function normalizeDocument(raw = {}) {
    const providers = {};
    for (const provider of SELECTABLE_PROVIDERS) {
        providers[provider] = normalizeScopedProviderSettings(provider, raw.providers?.[provider]);
    }
    return {
        providers,
        pendingEmbedding: raw.pendingEmbedding && typeof raw.pendingEmbedding === 'object'
            ? { ...raw.pendingEmbedding }
            : {}
    };
}

async function defaultSnapshot(db) {
    const defaults = await adminModelSettings.getAllProviderSettings(db, { force: true });
    return {
        providers: Object.fromEntries(SELECTABLE_PROVIDERS.map(provider => [
            provider,
            storageProvider(defaults.providers[provider], {
                // Existing/default settings are trusted until a concrete key
                // supplies a provider roster for this scope.
                modelsDiscovered: false,
                configurationStatus: defaults.providers[provider].configured ? READY : NEEDS_ADMIN
            })
        ])),
        pendingEmbedding: {},
        createdAt: new Date(),
        source: 'new-scope-defaults'
    };
}

async function materialize(db, scope, { availableModelsByProvider = {}, updatedBy = null } = {}) {
    const target = targetFor(scope);
    const existing = await db.collection(target.collection).findOne(target.filter);
    if (!existing) throw new Error(`AI scope not found: ${scope.type}:${scope.id}`);
    if (existing[FIELD]?.providers) return normalizeDocument(existing[FIELD]);

    const snapshot = await defaultSnapshot(db);
    for (const [rawProvider, models] of Object.entries(availableModelsByProvider || {})) {
        const provider = normalizeProvider(rawProvider);
        const stored = snapshot.providers[provider];
        stored.availableModels = Array.isArray(models) ? [...new Set(models)] : [];
        stored.modelsDiscovered = true;
        stored.configurationStatus = compatibleSelection(provider, stored) ? READY : NEEDS_ADMIN;
    }
    snapshot.updatedAt = new Date();
    snapshot.updatedBy = updatedBy;

    await db.collection(target.collection).updateOne(
        { ...target.filter, [`${FIELD}.providers`]: { $exists: false } },
        { $set: { [FIELD]: snapshot, updatedAt: new Date() } }
    );
    const stored = await db.collection(target.collection).findOne(target.filter);
    return normalizeDocument(stored?.[FIELD] || snapshot);
}

async function getAll(db, scope, options = {}) {
    const target = targetFor(scope);
    const doc = await db.collection(target.collection).findOne(target.filter);
    if (!doc) throw new Error(`AI scope not found: ${scope.type}:${scope.id}`);
    if (!doc[FIELD]?.providers) {
        if (options.materialize === false) return normalizeDocument(await defaultSnapshot(db));
        return materialize(db, scope);
    }
    return normalizeDocument(doc[FIELD]);
}

async function getProviderSettings(db, scope, provider, options = {}) {
    const all = await getAll(db, scope, options);
    return all.providers[normalizeProvider(provider)];
}

async function applyCredentialRoster(db, scope, provider, models, updatedBy = null, defaultConfiguration = null) {
    const normalizedProvider = normalizeProvider(provider);
    await materialize(db, scope);
    const target = targetFor(scope);
    const doc = await db.collection(target.collection).findOne(target.filter);
    const current = doc?.[FIELD]?.providers?.[normalizedProvider] || {};
    const roster = [...new Set((Array.isArray(models) ? models : []).filter(Boolean))];
    const selected = defaultConfiguration && typeof defaultConfiguration === 'object'
        ? {
            ...current,
            chatModel: defaultConfiguration.chatModel,
            reasoningEffort: defaultConfiguration.reasoningEffort,
            embeddingModel: defaultConfiguration.embeddingModel,
            vectorSize: defaultConfiguration.vectorSize || null,
            backend: null
        }
        : current;
    const configurationStatus = compatibleSelection(normalizedProvider, {
        ...selected,
        availableModels: roster,
        modelsDiscovered: true
    }) ? READY : NEEDS_ADMIN;
    const set = {
            [`${FIELD}.providers.${normalizedProvider}.availableModels`]: roster,
            [`${FIELD}.providers.${normalizedProvider}.modelsDiscovered`]: true,
            [`${FIELD}.providers.${normalizedProvider}.configurationStatus`]: configurationStatus,
            [`${FIELD}.updatedAt`]: new Date(),
            [`${FIELD}.updatedBy`]: updatedBy,
            updatedAt: new Date()
    };
    if (defaultConfiguration) {
        set[`${FIELD}.providers.${normalizedProvider}.chatModel`] = selected.chatModel;
        set[`${FIELD}.providers.${normalizedProvider}.reasoningEffort`] = selected.reasoningEffort;
        set[`${FIELD}.providers.${normalizedProvider}.embeddingModel`] = selected.embeddingModel;
        set[`${FIELD}.providers.${normalizedProvider}.vectorSize`] = selected.vectorSize;
    }
    const update = { $set: set };
    if (defaultConfiguration) update.$unset = { [`${FIELD}.providers.${normalizedProvider}.backend`]: '' };
    await db.collection(target.collection).updateOne(target.filter, update);
    return getProviderSettings(db, scope, normalizedProvider);
}

async function saveChatSettings(db, scope, provider, values, updatedBy = null) {
    const normalizedProvider = normalizeProvider(provider);
    const current = await getProviderSettings(db, scope, normalizedProvider);
    const roster = current.modelsDiscovered && current.availableModels.length === 0
        ? ['__no_models_available__']
        : current.availableModels;
    const allowed = allowedModelsForProvider(
        normalizedProvider,
        configuredDefaultModel(normalizedProvider),
        roster
    );
    if (!allowed.includes(values.chatModel)) {
        const error = new Error(`Invalid chat model for this ${normalizedProvider} key`);
        error.code = 'INVALID_CHAT_MODEL';
        throw error;
    }
    const backendInherits = values.backendInheritsFrontend !== false;
    const backendModel = backendInherits ? values.chatModel : values.backendChatModel;
    if (!allowed.includes(backendModel)) {
        const error = new Error(`Invalid back-end chat model for this ${normalizedProvider} key`);
        error.code = 'INVALID_CHAT_MODEL';
        throw error;
    }
    const target = targetFor(scope);
    const prefix = `${FIELD}.providers.${normalizedProvider}`;
    const set = {
        [`${prefix}.chatModel`]: values.chatModel,
        [`${prefix}.reasoningEffort`]: normalizeReasoningEffort(normalizedProvider, values.chatModel, values.reasoningEffort),
        [`${FIELD}.updatedAt`]: new Date(),
        [`${FIELD}.updatedBy`]: updatedBy,
        updatedAt: new Date()
    };
    const update = { $set: set };
    if (backendInherits) {
        update.$unset = { [`${prefix}.backend`]: '' };
    } else {
        set[`${prefix}.backend.chatModel`] = backendModel;
        set[`${prefix}.backend.reasoningEffort`] = normalizeReasoningEffort(
            normalizedProvider,
            backendModel,
            values.backendReasoningEffort
        );
    }
    await db.collection(target.collection).updateOne(target.filter, update);
    await refreshStatus(db, scope, normalizedProvider);
    const saved = await getProviderSettings(db, scope, normalizedProvider);
    return {
        ...saved,
        supportsReasoning: supportsReasoning(normalizedProvider, saved.chatModel),
        backendSupportsReasoning: supportsReasoning(normalizedProvider, saved.lanes.backend.chatModel)
    };
}

async function refreshStatus(db, scope, provider) {
    const normalizedProvider = normalizeProvider(provider);
    const target = targetFor(scope);
    const doc = await db.collection(target.collection).findOne(target.filter);
    const stored = doc?.[FIELD]?.providers?.[normalizedProvider] || {};
    const status = compatibleSelection(normalizedProvider, stored) ? READY : NEEDS_ADMIN;
    await db.collection(target.collection).updateOne(target.filter, {
        $set: { [`${FIELD}.providers.${normalizedProvider}.configurationStatus`]: status }
    });
    return status;
}

async function stagePendingEmbedding(db, scope, provider, pending) {
    const normalizedProvider = normalizeProvider(provider);
    const current = await getProviderSettings(db, scope, normalizedProvider);
    const roster = current.modelsDiscovered && current.availableModels.length === 0
        ? ['__no_models_available__']
        : current.availableModels;
    const allowed = allowedEmbeddingModelsForProvider(normalizedProvider, roster);
    if (!allowed.includes(pending.embeddingModel)) {
        const error = new Error(`Invalid embedding model for this ${normalizedProvider} key`);
        error.code = 'INVALID_EMBEDDING_MODEL';
        throw error;
    }
    const value = {
        embeddingModel: pending.embeddingModel,
        embeddingRevision: pending.embeddingRevision || DEFAULT_PROFILE_REVISION,
        vectorSize: Number.isInteger(pending.vectorSize) ? pending.vectorSize : null,
        migrationId: pending.migrationId || null,
        startedAt: new Date()
    };
    const target = targetFor(scope);
    await db.collection(target.collection).updateOne(target.filter, {
        $set: { [`${FIELD}.pendingEmbedding.${normalizedProvider}`]: value, updatedAt: new Date() }
    });
    return value;
}

async function activatePendingEmbedding(db, scope, provider, expected = null) {
    const normalizedProvider = normalizeProvider(provider);
    const target = targetFor(scope);
    const doc = await db.collection(target.collection).findOne(target.filter);
    const pending = doc?.[FIELD]?.pendingEmbedding?.[normalizedProvider];
    if (!pending) return null;
    if (expected && (
        pending.embeddingModel !== expected.embeddingModel
        || pending.embeddingRevision !== (expected.embeddingRevision || DEFAULT_PROFILE_REVISION)
    )) return null;
    const prefix = `${FIELD}.providers.${normalizedProvider}`;
    await db.collection(target.collection).updateOne(target.filter, {
        $set: {
            [`${prefix}.embeddingModel`]: pending.embeddingModel,
            [`${prefix}.embeddingRevision`]: pending.embeddingRevision,
            ...(pending.vectorSize ? { [`${prefix}.vectorSize`]: pending.vectorSize } : {}),
            updatedAt: new Date()
        },
        $unset: { [`${FIELD}.pendingEmbedding.${normalizedProvider}`]: '' }
    });
    await refreshStatus(db, scope, normalizedProvider);
    return pending;
}

async function clearPendingEmbedding(db, scope, provider) {
    const target = targetFor(scope);
    await db.collection(target.collection).updateOne(target.filter, {
        $unset: { [`${FIELD}.pendingEmbedding.${normalizeProvider(provider)}`]: '' },
        $set: { updatedAt: new Date() }
    });
}

async function getEmbeddingProfile(db, scope, provider, options = {}) {
    const settings = await getProviderSettings(db, scope, provider);
    return buildEmbeddingProfile({
        provider: normalizeProvider(provider),
        embeddingModel: settings.embeddingModel,
        revision: settings.embeddingRevision,
        vectorSize: settings.vectorSize || undefined,
        endpoint: options.endpoint || null,
        apiKey: options.apiKey || null
    });
}

async function backfillExistingScopes(db) {
    const scopes = [];
    const courses = await db.collection('courses').find({ isDeleted: { $ne: true } }).project({ courseId: 1 }).toArray();
    for (const course of courses) scopes.push({ type: 'course', id: course.courseId });
    const buckets = await db.collection('superchats').find({ isDeleted: { $ne: true } }).project({ superchatId: 1 }).toArray();
    for (const bucket of buckets) scopes.push({ type: 'superchat', id: bucket.superchatId });
    for (const scope of [
        { type: 'notes', id: 'notesLlm' },
        { type: 'superCourseChat', id: 'superCourseChat' }
    ]) {
        const target = targetFor(scope);
        const doc = await db.collection(target.collection).findOne(target.filter);
        if (doc) scopes.push(scope);
    }
    for (const scope of scopes) await materialize(db, scope);
    return scopes.length;
}

module.exports = {
    FIELD,
    NEEDS_ADMIN,
    READY,
    activatePendingEmbedding,
    applyCredentialRoster,
    backfillExistingScopes,
    clearPendingEmbedding,
    compatibleSelection,
    defaultSnapshot,
    getAll,
    getEmbeddingProfile,
    getProviderSettings,
    materialize,
    normalizeDocument,
    saveChatSettings,
    stagePendingEmbedding,
    targetFor
};
