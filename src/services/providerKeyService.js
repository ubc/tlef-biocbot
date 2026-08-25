/**
 * Provider key operations, shared by every keyed surface
 *
 * The four surfaces — a course, the instructor Notes, the instructor Super
 * Course chat, and each student-facing Super Course bucket — all need the same
 * behaviour, and each keeps its own isolated credentials:
 *
 *   - save a key for a chosen platform (validated against THAT platform)
 *   - test the stored key for the active platform
 *   - explicitly prepare a stored platform, then activate it automatically
 *     only after all required vectors are ready
 *
 * Keys are never shared between surfaces, and no route ever returns ciphertext
 * or a decrypted key.
 */

const adminModelSettings = require('./adminModelSettings');
const scopeModelSettings = require('./scopeModelSettings');
const { LLMModule } = require('ubc-genai-toolkit-llm');
const config = require('./config');
const migrations = require('./providerMigrationService');
const migrationRunner = require('./providerMigrationRunner');
const superCourse = require('./superCourseService');
const {
    buildEmbeddingProfile,
    knownVectorSizeForEmbeddingModel,
    vectorSizeForEmbeddingModel
} = require('./embeddingConfig');
const { PROVIDERS, normalizeProvider, providerLabel } = require('./llmProviders');
const {
    PROXY_REASONING_EFFORTS,
    allowedEmbeddingModelsForProvider,
    allowedModelsForProvider,
    configuredDefaultModel,
    knownReasoningEffortsForModel
} = require('./llmModels');
const {
    KEY_STATUSES,
    buildKeySubdocument,
    credentialForProvider,
    credentialSetFields,
    decryptApiKey,
    publicKeySummary,
    publicProviderKeyState,
    readProviderState,
    validateProviderKey
} = require('./llmKeyStore');

const PROXY_DEFAULT_CONFIGURATIONS = Object.freeze([
    {
        chatModel: 'gpt-5.6-luna',
        reasoningEffort: 'low',
        embeddingModel: 'text-embedding-3-small'
    },
    {
        chatModel: 'qwen3.6-35b-a3b',
        reasoningEffort: 'none',
        embeddingModel: 'qwen3-embedding-0.6b'
    }
]);
const PROXY_VALIDATION_TIMEOUT_MS = 10_000;

function proxyDefaultConfiguration(models) {
    const roster = Array.isArray(models) ? models : [];
    return PROXY_DEFAULT_CONFIGURATIONS.find(configuration => (
        roster.includes(configuration.chatModel)
        && roster.includes(configuration.embeddingModel)
    )) || null;
}

function errorCodeForStatus(status) {
    if (status === KEY_STATUSES.QUOTA_EXHAUSTED) return 'LLM_KEY_QUOTA';
    if (status === KEY_STATUSES.MISSING) return 'LLM_KEY_MISSING';
    return 'LLM_KEY_INVALID';
}

/**
 * Validate a key against the models the admin configured for that platform.
 */
async function validateForProvider(db, provider, apiKey, options = {}) {
    const normalizedProvider = normalizeProvider(provider);
    const settings = options.settings
        || (options.scope
            ? await scopeModelSettings.getProviderSettings(db, options.scope, normalizedProvider)
            : await adminModelSettings.getProviderSettings(db, normalizedProvider));
    let endpoint = null;
    try {
        endpoint = config.getProviderInfra(normalizedProvider).endpoint;
    } catch (_) {
        endpoint = null;
    }

    const validation = await validateProviderKey({
        provider: normalizedProvider,
        apiKey,
        chatModel: settings.chatModel,
        embeddingModel: settings.embeddingModel,
        endpoint,
        timeoutMs: options.timeoutMs
    });

    if (!validation.ok) {
        return validation;
    }

    // Test stubs pre-date roster discovery. Give non-Proxy tests the same
    // supported roster a real /models response would be filtered against.
    if ((!Array.isArray(validation.models) || validation.models.length === 0)
        && normalizedProvider !== PROVIDERS.PROXY
        && process.env.BIOCBOT_TEST_LLM_STUB === '1') {
        validation.models = [
            ...allowedModelsForProvider(normalizedProvider, configuredDefaultModel(normalizedProvider)),
            ...allowedEmbeddingModelsForProvider(normalizedProvider)
        ];
    }

    if (normalizedProvider !== PROVIDERS.PROXY || options.validateConfiguration === false) return validation;

    const current = settings;
    const discoveredDefault = proxyDefaultConfiguration(validation.models);
    if (current.chatModel || current.embeddingModel) {
        try {
            const listed = validation.models || [];
            for (const selected of [
                current.chatModel,
                current.lanes?.backend?.chatModel,
                current.embeddingModel
            ].filter(Boolean)) {
                if (!listed.includes(selected)) {
                    return { ...validation, configurationCompatible: false };
                }
            }
            await validateProxyOperations({
                apiKey,
                endpoint,
                chatSelections: proxyChatSelectionsFromSettings(current),
                embeddingModel: current.embeddingModel
            });
        } catch (error) {
            validation.configurationCompatible = false;
            if (!discoveredDefault) {
                return { ...validation, configurationCompatible: false, detail: error.cause?.message || error.message };
            }
        }
    }

    if (discoveredDefault && (!current.configured || validation.configurationCompatible === false)) {
        try {
            const operation = await validateProxyOperations({
                apiKey,
                endpoint,
                chatSelections: [{
                    model: discoveredDefault.chatModel,
                    reasoningEffort: discoveredDefault.reasoningEffort
                }],
                embeddingModel: discoveredDefault.embeddingModel
            });
            validation.defaultConfiguration = {
                ...discoveredDefault,
                vectorSize: operation.vectorSize
            };
            validation.configurationCompatible = true;
        } catch (error) {
            validation.configurationCompatible = false;
            validation.detail = error.cause?.message || error.message;
        }
    }

    return validation;
}

function incompatibleModelError(model, detail, operation = null) {
    const action = operation ? ` for ${operation}` : '';
    const error = new Error(`${model} cannot be used${action} with the saved UBC LLM Proxy key. ${detail}`);
    error.code = 'MODEL_OPERATION_INCOMPATIBLE';
    return error;
}

function proxyChatSelectionsFromSettings(settings) {
    const selections = [];
    const frontend = settings?.lanes?.frontend || settings;
    const backend = settings?.lanes?.backend || frontend;
    for (const lane of [frontend, backend]) {
        if (!lane?.chatModel) continue;
        if (!selections.some(item => item.model === lane.chatModel && item.reasoningEffort === lane.reasoningEffort)) {
            selections.push({ model: lane.chatModel, reasoningEffort: lane.reasoningEffort });
        }
    }
    return selections;
}

async function validateProxyOperations({ apiKey, endpoint, chatSelections = [], embeddingModel = null }) {
    if (process.env.BIOCBOT_TEST_LLM_STUB === '1') {
        return {
            vectorSize: embeddingModel
                ? vectorSizeForEmbeddingModel(
                    embeddingModel,
                    Number(process.env.BIOCBOT_TEST_PROXY_VECTOR_SIZE) || 8
                )
                : null
        };
    }

    const llm = new LLMModule({
        provider: PROVIDERS.PROXY,
        apiKey,
        endpoint,
        ...(embeddingModel ? { embeddingModel } : {})
    });

    let vectorSize = null;
    const operations = chatSelections.map(async selection => {
        try {
            await withTimeout(
                llm.sendMessage('BiocBot model validation', {
                    model: selection.model,
                    reasoningEffort: selection.reasoningEffort,
                    maxTokens: 16
                }),
                PROXY_VALIDATION_TIMEOUT_MS,
                `${selection.model} did not answer the chat validation within ${PROXY_VALIDATION_TIMEOUT_MS} ms.`
            );
        } catch (cause) {
            const error = incompatibleModelError(
                selection.model,
                cause.message || 'The proxy rejected the chat request.',
                'chat'
            );
            error.cause = cause;
            throw error;
        }
    });

    if (embeddingModel) {
        operations.push((async () => {
            try {
                const response = await withTimeout(
                    llm.embed(['BiocBot embedding validation'], { model: embeddingModel }),
                    PROXY_VALIDATION_TIMEOUT_MS,
                    `${embeddingModel} did not answer the embedding validation within ${PROXY_VALIDATION_TIMEOUT_MS} ms.`
                );
                const vector = response?.embeddings?.[0];
                if (!Array.isArray(vector) || vector.length === 0) {
                    throw new Error('The proxy returned an empty or invalid embedding vector.');
                }
                vectorSize = vector.length;
            } catch (cause) {
                const error = incompatibleModelError(
                    embeddingModel,
                    cause.message || 'The proxy rejected the embedding request.',
                    'embeddings'
                );
                error.cause = cause;
                throw error;
            }
        })());
    }

    await Promise.all(operations);
    return { vectorSize };
}

async function proxyValidationCredential(db, scope = null) {
    const provider = PROVIDERS.PROXY;
    if (scope) {
        const { doc } = await loadSurface(db, scope);
        const credential = doc && credentialForProvider(doc, provider);
        if (!credential?.ciphertext || credential.status !== KEY_STATUSES.VALID) {
            const error = new Error('Save and validate a UBC LLM Proxy key for this AI surface before selecting proxy models.');
            error.code = 'PROXY_KEY_REQUIRED';
            throw error;
        }
        return decryptApiKey(credential.ciphertext);
    }
    const candidates = [
        await db.collection('settings').findOne({ _id: 'notesLlm', [`llmCredentials.${provider}.status`]: KEY_STATUSES.VALID }),
        await db.collection('settings').findOne({ _id: 'superCourseChat', [`llmCredentials.${provider}.status`]: KEY_STATUSES.VALID }),
        await db.collection('courses').findOne({ [`llmCredentials.${provider}.status`]: KEY_STATUSES.VALID }),
        await db.collection('superchats').findOne({
            [`llmCredentials.${provider}.status`]: KEY_STATUSES.VALID,
            isDeleted: { $ne: true }
        })
    ];
    const doc = candidates.find(Boolean);
    const credential = doc && credentialForProvider(doc, provider);
    if (!credential?.ciphertext) {
        const error = new Error(
            'Save and validate a UBC LLM Proxy key on a course, Super Course, notes, or instructor chat before selecting proxy models.'
        );
        error.code = 'PROXY_KEY_REQUIRED';
        throw error;
    }
    return decryptApiKey(credential.ciphertext);
}

async function validateProxyChatSettings(db, selections, scope = null) {
    const apiKey = await proxyValidationCredential(db, scope);
    const endpoint = config.getProviderInfra(PROVIDERS.PROXY).endpoint;
    if (!endpoint) {
        const error = new Error('UBC_LLM_PROXY_ENDPOINT is not configured.');
        error.code = 'PROXY_ENDPOINT_MISSING';
        throw error;
    }
    const unknownSelections = [];
    for (const selection of selections) {
        const knownEfforts = knownReasoningEffortsForModel(selection.model);
        if (!knownEfforts) {
            unknownSelections.push(selection);
            continue;
        }
        if (knownEfforts.length > 0 && !knownEfforts.includes(selection.reasoningEffort)) {
            throw incompatibleModelError(
                selection.model,
                `Reasoning effort "${selection.reasoningEffort}" is not supported.`,
                'chat'
            );
        }
    }
    if (unknownSelections.length === 0) return { vectorSize: null };
    return validateProxyOperations({ apiKey, endpoint, chatSelections: unknownSelections });
}

function withTimeout(promise, timeoutMs, message) {
    let timeout;
    const deadline = new Promise((_, reject) => {
        timeout = setTimeout(() => {
            const error = new Error(message);
            error.code = 'PROXY_OPERATION_TIMEOUT';
            reject(error);
        }, timeoutMs);
    });

    return Promise.race([promise, deadline]).finally(() => clearTimeout(timeout));
}

/**
 * Probe every effort concurrently so discovery has one bounded wall-clock
 * cost. Running these calls serially can exceed an upstream HTTP timeout even
 * when each individual completion succeeds.
 */
async function probeProxyReasoningEfforts(llm, model, options = {}) {
    const reasoningEfforts = options.reasoningEfforts || PROXY_REASONING_EFFORTS;
    const timeoutMs = options.timeoutMs || PROXY_VALIDATION_TIMEOUT_MS;
    const results = await Promise.all(reasoningEfforts.map(async reasoningEffort => {
        try {
            await withTimeout(
                llm.sendMessage('Reply with OK.', {
                    model,
                    reasoningEffort,
                    maxTokens: 32
                }),
                timeoutMs,
                `${model} did not answer the ${reasoningEffort} reasoning probe within ${timeoutMs} ms.`
            );
            return { reasoningEffort, supported: true };
        } catch (error) {
            return { reasoningEffort, supported: false, error };
        }
    }));

    const supported = results
        .filter(result => result.supported)
        .map(result => result.reasoningEffort);

    if (supported.length === 0) {
        const firstFailure = results.find(result => result.error)?.error;
        const error = incompatibleModelError(
            model,
            firstFailure?.message || 'No supported reasoning efforts were detected.',
            'reasoning discovery'
        );
        error.cause = firstFailure;
        throw error;
    }

    return supported;
}

/**
 * Discover the normalized reasoning efforts accepted by one proxy model.
 *
 * `/models` deliberately returns no capability metadata. Exact models already
 * in BiocBot reuse their tested local profile; unknown ids use bounded provider
 * operations and return only the values those operations accept.
 */
async function discoverProxyReasoningEfforts(db, model, scope = null) {
    if (!model || typeof model !== 'string') {
        const error = new Error('Select a proxy model before checking reasoning support.');
        error.code = 'PROXY_MODEL_REQUIRED';
        throw error;
    }

    if (process.env.BIOCBOT_TEST_LLM_STUB === '1') {
        const configured = process.env.BIOCBOT_TEST_PROXY_REASONING_EFFORTS;
        return configured
            ? configured.split(',').map(value => value.trim()).filter(Boolean)
            : [...PROXY_REASONING_EFFORTS];
    }

    const apiKey = await proxyValidationCredential(db, scope);
    const endpoint = config.getProviderInfra(PROVIDERS.PROXY).endpoint;
    if (!endpoint) {
        const error = new Error('UBC_LLM_PROXY_ENDPOINT is not configured.');
        error.code = 'PROXY_ENDPOINT_MISSING';
        throw error;
    }

    // Exact models already supported directly by BiocBot have a tested local
    // capability profile. Avoid a slow/cold generation merely to rediscover
    // those values through the Proxy. Saving still validates the selected
    // model/effort with a real chat operation.
    const knownEfforts = knownReasoningEffortsForModel(model);
    if (knownEfforts) return knownEfforts;

    const llm = new LLMModule({ provider: PROVIDERS.PROXY, apiKey, endpoint });
    return probeProxyReasoningEfforts(llm, model);
}

async function validateProxyEmbeddingModel(db, embeddingModel, scope = null) {
    const apiKey = await proxyValidationCredential(db, scope);
    const endpoint = config.getProviderInfra(PROVIDERS.PROXY).endpoint;
    if (!endpoint) {
        const error = new Error('UBC_LLM_PROXY_ENDPOINT is not configured.');
        error.code = 'PROXY_ENDPOINT_MISSING';
        throw error;
    }
    const knownVectorSize = knownVectorSizeForEmbeddingModel(embeddingModel);
    if (knownVectorSize) return { vectorSize: knownVectorSize };
    return validateProxyOperations({ apiKey, endpoint, embeddingModel });
}

/**
 * The embedding profile a provider would use for this surface, including the
 * decrypted key when one is supplied.
 */
async function embeddingProfileFor(db, scope, provider, apiKey = null) {
    // Backward-compatible service call: embeddingProfileFor(db, provider, key)
    // reads the new-scope template. Runtime paths always pass an explicit scope.
    if (typeof scope === 'string') {
        apiKey = provider || null;
        provider = scope;
        scope = null;
    }
    const normalizedProvider = normalizeProvider(provider);
    const settings = scope
        ? await scopeModelSettings.getProviderSettings(db, scope, normalizedProvider)
        : await adminModelSettings.getProviderSettings(db, normalizedProvider);
    if (!settings.embeddingModel || !settings.configured) {
        const error = new Error(
            `${providerLabel(normalizedProvider)} is not fully configured. A system admin must select and save its chat and embedding models first.`
        );
        error.code = 'LLM_CONFIGURATION_REQUIRED';
        throw error;
    }
    let endpoint = null;
    try {
        endpoint = config.getProviderInfra(normalizedProvider).endpoint;
    } catch (_) {
        endpoint = null;
    }
    return buildEmbeddingProfile({
        provider: normalizedProvider,
        embeddingModel: settings.embeddingModel,
        revision: settings.embeddingRevision,
        vectorSize: settings.vectorSize || undefined,
        endpoint,
        apiKey
    });
}

function evictScope(registry, scope) {
    if (!registry) return;
    if (scope.type === 'course') registry.evictCourse(scope.id);
    else if (scope.type === 'superchat') registry.evictSuperchat(scope.id);
    else if (scope.type === 'notes') registry.evictNotes();
    else if (scope.type === 'superCourseChat') registry.evictSuperCourseChat();
}

/**
 * Which courses' content a scope can retrieve. Determines what must be indexed
 * for the scope's embedding profile before the scope can serve answers.
 *
 * @returns {Promise<{courseIds: Array<string>, includeNotes: boolean}>}
 */
async function migrationScopeContent(db, scope) {
    if (scope.type === 'course') {
        return { courseIds: [scope.id], includeNotes: false };
    }

    if (scope.type === 'notes') {
        return { courseIds: [], includeNotes: true };
    }

    if (scope.type === 'superchat') {
        // A bucket searches its member courses' content with ITS OWN profile,
        // so every member course needs an index in that profile — even courses
        // that themselves run on a different platform. Membership is course-side
        // (`course.superchatIds`), so it comes from the retrieval pool.
        const bucket = await db.collection('superchats').findOne({ superchatId: scope.id });
        return superCourse.superCourseContentScope(db, {
            superchatId: scope.id,
            settingsDoc: bucket
        });
    }

    if (scope.type === 'superCourseChat') {
        // The instructor Super Course chat pools every bucketed course, plus
        // Notes when the chat is configured to include them.
        const settings = await db.collection('settings').findOne({ _id: 'superCourseChat' });
        return superCourse.superCourseContentScope(db, { settingsDoc: settings });
    }

    return { courseIds: [], includeNotes: false };
}

async function loadSurface(db, scope) {
    const target = migrations.scopeTarget(scope);
    if (!target) throw new Error(`Unknown keyed surface: ${scope && scope.type}`);
    const doc = await db.collection(target.collection).findOne(target.filter);
    return { target, doc };
}

/**
 * Save a key for a surface.
 *
 * Saving/replacing a key never implicitly starts a migration. The only special
 * case is first-time setup: when the surface has no usable active credential,
 * the first valid key becomes active immediately.
 *
 * @returns {Promise<Object>} Route-ready result (never contains key material)
 */
async function saveSurfaceKey(db, {
    scope,
    provider,
    apiKey,
    updatedBy = null,
    registry = null
}) {
    const requestedProvider = normalizeProvider(provider);
    const { target, doc } = await loadSurface(db, scope);
    const state = readProviderState(doc);
    const currentProvider = state.activeProvider;
    const hasExistingCredential = !!(state.credentials[currentProvider] && state.credentials[currentProvider].ciphertext);

    const validationSettings = doc
        ? await scopeModelSettings.getProviderSettings(db, scope, requestedProvider)
        : await adminModelSettings.getProviderSettings(db, requestedProvider);
    const validation = await validateForProvider(db, requestedProvider, apiKey, { settings: validationSettings });
    if (!validation.ok) {
        return {
            ok: false,
            httpStatus: 400,
            body: {
                success: false,
                code: errorCodeForStatus(validation.status),
                message: validation.message || 'API key validation failed',
                detail: validation.detail,
                llmProvider: requestedProvider
            }
        };
    }

    const credential = buildKeySubdocument(apiKey, updatedBy, requestedProvider);
    const activate = !hasExistingCredential || requestedProvider === currentProvider;
    await db.collection(target.collection).updateOne(
        target.filter,
        {
            $set: {
                ...credentialSetFields(requestedProvider, credential, { activate }),
                updatedAt: new Date()
            }
        },
        { upsert: target.collection === 'settings' }
    );
    const scopedSettings = Array.isArray(validation.models)
        ? await scopeModelSettings.applyCredentialRoster(
            db, scope, requestedProvider, validation.models, updatedBy, validation.defaultConfiguration
        )
        : await scopeModelSettings.getProviderSettings(db, scope, requestedProvider);
    evictScope(registry, scope);

    const updated = await db.collection(target.collection).findOne(target.filter);
    return {
        ok: true,
        httpStatus: 200,
        body: {
            success: true,
            message: `${providerLabel(requestedProvider)} API key saved`,
            ...publicProviderKeyState(updated),
            llmConfigurationStatus: scopedSettings.configurationStatus,
            aiAvailable: scopedSettings.configurationStatus === scopeModelSettings.READY,
            migration: null
        }
    };
}

/**
 * Prepare all content visible to a surface for a stored provider. The current
 * provider remains active while work runs; the runner switches atomically only
 * after every item is ready. A newly copied surface can opt into being disabled
 * until this first preparation succeeds.
 */
async function prepareStoredProvider(db, {
    scope,
    provider,
    requestedBy = null,
    disableUntilReady = false
}) {
    const requestedProvider = normalizeProvider(provider);
    const { target, doc } = await loadSurface(db, scope);
    const state = readProviderState(doc);
    const credential = state.credentials[requestedProvider];

    if (!credential || !credential.ciphertext) {
        return {
            ok: false,
            httpStatus: 400,
            body: {
                success: false,
                code: 'LLM_KEY_MISSING',
                message: `Save a ${providerLabel(requestedProvider)} API key before preparing material.`
            }
        };
    }
    if (credential.status !== KEY_STATUSES.VALID) {
        return {
            ok: false,
            httpStatus: 400,
            body: {
                success: false,
                code: errorCodeForStatus(credential.status),
                message: `The saved ${providerLabel(requestedProvider)} key must be valid before preparing material.`
            }
        };
    }

    const active = await migrations.findActiveMigration(db, scope);
    if (active) {
        return {
            ok: false,
            httpStatus: 409,
            body: {
                success: false,
                code: 'LLM_MIGRATION_ACTIVE',
                message: 'Course material is already being prepared.',
                migration: migrations.publicMigrationView(active)
            }
        };
    }

    let profile;
    try {
        profile = await embeddingProfileFor(db, scope, requestedProvider);
    } catch (error) {
        if (error.code !== 'LLM_CONFIGURATION_REQUIRED') throw error;
        return {
            ok: false,
            httpStatus: 409,
            body: { success: false, code: error.code, message: error.message }
        };
    }
    const { courseIds, includeNotes } = await migrationScopeContent(db, scope);
    const { job } = await migrations.createMigration(db, {
        scope,
        kind: 'prepare',
        fromProvider: state.activeProvider,
        toProvider: requestedProvider,
        profile,
        courseIds,
        includeNotes,
        requestedBy
    });

    // Nothing needs rebuilding: activate synchronously so a copied course that
    // reused current target-profile vectors never flashes a preparing state.
    if ((job.totals?.total || 0) === 0) {
        await migrations.activateProvider(db, scope, requestedProvider);
        await migrations.finishMigration(
            db,
            job.migrationId,
            migrations.MIGRATION_STATUSES.COMPLETED
        );
        const completedJob = await migrations.getMigration(db, job.migrationId);
        const updated = await db.collection(target.collection).findOne(target.filter);
        return {
            ok: true,
            httpStatus: 200,
            body: {
                success: true,
                message: `${providerLabel(requestedProvider)} material is ready.`,
                ...publicProviderKeyState(updated),
                migration: migrations.publicMigrationView(completedJob)
            }
        };
    }

    await db.collection(target.collection).updateOne(
        target.filter,
        {
            $set: {
                pendingLlmProvider: requestedProvider,
                providerMigrationId: job.migrationId,
                ...(disableUntilReady ? { aiPreparationRequired: true } : {}),
                updatedAt: new Date()
            }
        }
    );
    migrationRunner.startMigration(db, job.migrationId);

    const updated = await db.collection(target.collection).findOne(target.filter);
    return {
        ok: true,
        httpStatus: 202,
        body: {
            success: true,
            message: `Preparing course material for ${providerLabel(requestedProvider)}. `
                + `It will switch automatically when preparation finishes.`,
            ...publicProviderKeyState(updated),
            migration: migrations.publicMigrationView(job)
        }
    };
}

/**
 * Re-validate the stored key for a surface's chosen platform and persist the
 * resulting status.
 */
async function testSurfaceKey(db, { scope, provider = null, registry = null }) {
    const { target, doc } = await loadSurface(db, scope);
    const state = readProviderState(doc);
    const targetProvider = provider ? normalizeProvider(provider) : state.activeProvider;
    const credential = credentialForProvider(doc, targetProvider);

    if (!credential || !credential.ciphertext) {
        return {
            ok: false,
            httpStatus: 400,
            body: {
                success: false,
                code: 'LLM_KEY_MISSING',
                message: `No ${providerLabel(targetProvider)} API key is saved for this surface.`,
                llmProvider: targetProvider
            }
        };
    }

    const validation = await validateForProvider(
        db,
        targetProvider,
        decryptApiKey(credential.ciphertext),
        { scope, validateConfiguration: false }
    );
    const now = new Date();
    const status = validation.ok ? KEY_STATUSES.VALID : validation.status;

    const set = {
        [`llmCredentials.${targetProvider}.status`]: status,
        [`llmCredentials.${targetProvider}.updatedAt`]: now,
        updatedAt: now
    };
    if (validation.ok) set[`llmCredentials.${targetProvider}.validatedAt`] = now;
    if (targetProvider === 'openai' && doc && doc.llmApiKey) {
        set['llmApiKey.status'] = status;
        set['llmApiKey.updatedAt'] = now;
        if (validation.ok) set['llmApiKey.validatedAt'] = now;
    }

    await db.collection(target.collection).updateOne(target.filter, { $set: set });
    let scopedSettings = null;
    if (validation.ok && Array.isArray(validation.models)) {
        scopedSettings = await scopeModelSettings.applyCredentialRoster(
            db,
            scope,
            targetProvider,
            validation.models,
            credential.updatedBy || null,
            validation.defaultConfiguration
        );
    }
    if (validation.ok && !scopedSettings) {
        scopedSettings = await scopeModelSettings.getProviderSettings(db, scope, targetProvider);
    }
    evictScope(registry, scope);

    return {
        ok: validation.ok,
        httpStatus: validation.ok ? 200 : 400,
        body: {
            success: validation.ok,
            code: validation.ok ? undefined : errorCodeForStatus(status),
            message: validation.ok
                ? `${providerLabel(targetProvider)} API key is valid`
                : validation.message,
            llmProvider: targetProvider,
            llmKey: {
                ...publicKeySummary(credential),
                status,
                validatedAt: validation.ok ? now : credential.validatedAt,
                updatedAt: now
            },
            llmConfigurationStatus: scopedSettings?.configurationStatus || null,
            aiAvailable: validation.ok && scopedSettings?.configurationStatus === scopeModelSettings.READY
        }
    };
}

/**
 * Activate a stored provider only when all currently-visible content is already
 * prepared for it. Preparation is an explicit action, separate from switching.
 */
async function switchToStoredProvider(db, { scope, provider, requestedBy = null, registry = null }) {
    const requestedProvider = normalizeProvider(provider);
    const { target, doc } = await loadSurface(db, scope);
    const state = readProviderState(doc);
    const credential = state.credentials[requestedProvider];

    if (!credential || !credential.ciphertext) {
        return {
            ok: false,
            httpStatus: 400,
            body: {
                success: false,
                code: 'LLM_KEY_MISSING',
                message: `No ${providerLabel(requestedProvider)} API key is saved for this surface. Enter one to switch.`,
                llmProvider: state.activeProvider
            }
        };
    }

    if (requestedProvider === state.activeProvider) {
        return {
            ok: true,
            httpStatus: 200,
            body: {
                success: true,
                message: `Already using ${providerLabel(requestedProvider)}`,
                ...publicProviderKeyState(doc),
                migration: null
            }
        };
    }

    let profile;
    try {
        profile = await embeddingProfileFor(db, scope, requestedProvider);
    } catch (error) {
        if (error.code !== 'LLM_CONFIGURATION_REQUIRED') throw error;
        return {
            ok: false,
            httpStatus: 409,
            body: { success: false, code: error.code, message: error.message }
        };
    }
    const { courseIds, includeNotes } = await migrationScopeContent(db, scope);
    const { items } = await migrations.calculateWork({ db, profile, courseIds, includeNotes });
    if (items.length > 0) {
        return {
            ok: false,
            httpStatus: 409,
            body: {
                success: false,
                code: 'LLM_PROVIDER_NOT_PREPARED',
                message: `${items.length} item(s) still need to be prepared for ${providerLabel(requestedProvider)}. `
                    + `Choose “Prepare material for ${providerLabel(requestedProvider)}” first.`,
                llmProvider: state.activeProvider,
                needsPreparation: true,
                unpreparedCount: items.length
            }
        };
    }

    await migrations.activateProvider(db, scope, requestedProvider);
    await migrations.abandonPendingProvider(db, scope);
    evictScope(registry, scope);

    const updated = await db.collection(target.collection).findOne(target.filter);
    return {
        ok: true,
        httpStatus: 200,
        body: {
            success: true,
            message: `Now using ${providerLabel(requestedProvider)}.`,
            ...publicProviderKeyState(updated),
            migration: null
        }
    };
}

/**
 * Current provider + key status + in-flight migration for a surface.
 */
async function surfaceKeyState(db, scope) {
    const { doc } = await loadSurface(db, scope);
    const state = publicProviderKeyState(doc);
    const settings = doc
        ? await scopeModelSettings.getProviderSettings(db, scope, state.llmProvider)
        : { configurationStatus: scopeModelSettings.NEEDS_ADMIN };
    const job = state.providerMigrationId
        ? await migrations.getMigration(db, state.providerMigrationId)
        : await migrations.findActiveMigration(db, scope);

    return {
        ...state,
        llmConfigurationStatus: settings.configurationStatus,
        aiAvailable: state.llmKey?.status === KEY_STATUSES.VALID
            && settings.configurationStatus === scopeModelSettings.READY,
        migration: migrations.publicMigrationView(job)
    };
}

module.exports = {
    embeddingProfileFor,
    errorCodeForStatus,
    evictScope,
    migrationScopeContent,
    prepareStoredProvider,
    saveSurfaceKey,
    surfaceKeyState,
    switchToStoredProvider,
    testSurfaceKey,
    validateForProvider,
    validateProxyChatSettings,
    validateProxyEmbeddingModel,
    discoverProxyReasoningEfforts,
    probeProxyReasoningEfforts
};
