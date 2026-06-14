const LLMService = require('./llm');
const QdrantService = require('./qdrantService');
const config = require('./config');
const {
    KEY_STATUSES,
    LlmKeyError,
    decryptApiKey,
    isOllamaProvider,
    publicKeySummary,
    scopedKeysRequired,
    updateOwnerKeyStatus
} = require('./llmKeyStore');

const CACHE_TTL_MS = 10 * 60 * 1000;

function cacheKey(scope) {
    return `${scope.type}:${scope.id || 'global'}`;
}

class LlmRegistry {
    constructor() {
        this.cache = new Map();
    }

    evict(scope) {
        this.cache.delete(cacheKey(scope));
    }

    evictCourse(courseId) {
        this.evict({ type: 'course', id: courseId });
    }

    evictSuperchat(superchatId) {
        this.evict({ type: 'superchat', id: superchatId });
    }

    evictNotes() {
        this.evict({ type: 'notes', id: 'notesLlm' });
    }

    clear() {
        this.cache.clear();
    }

    async forCourse(db, courseId) {
        if (!courseId) throw new LlmKeyError(KEY_STATUSES.MISSING, { type: 'course', id: courseId });
        const course = await db.collection('courses').findOne(
            { courseId },
            { projection: { llmApiKey: 1 } }
        );
        return this._resolve(db, { type: 'course', id: courseId }, course && course.llmApiKey);
    }

    async forSuperchat(db, superchatId) {
        if (!superchatId) throw new LlmKeyError(KEY_STATUSES.MISSING, { type: 'superchat', id: superchatId });
        const superchat = await db.collection('superchats').findOne(
            { superchatId, isDeleted: { $ne: true } },
            { projection: { llmApiKey: 1 } }
        );
        return this._resolve(db, { type: 'superchat', id: superchatId }, superchat && superchat.llmApiKey);
    }

    async forNotes(db) {
        const settings = await db.collection('settings').findOne(
            { _id: 'notesLlm' },
            { projection: { llmApiKey: 1 } }
        );
        return this._resolve(db, { type: 'notes', id: 'notesLlm' }, settings && settings.llmApiKey);
    }

    async _resolve(db, scope, llmApiKey) {
        if (!scopedKeysRequired() || isOllamaProvider()) {
            return this._getOrCreate(db, scope, null);
        }

        const summary = publicKeySummary(llmApiKey);
        if (summary.status !== KEY_STATUSES.VALID || !llmApiKey || !llmApiKey.ciphertext) {
            throw new LlmKeyError(summary.status || KEY_STATUSES.MISSING, scope);
        }

        return this._getOrCreate(db, scope, llmApiKey);
    }

    async _getOrCreate(db, scope, llmApiKey) {
        const key = cacheKey(scope);
        const cached = this.cache.get(key);
        const updatedAt = llmApiKey && llmApiKey.updatedAt
            ? new Date(llmApiKey.updatedAt).getTime()
            : 0;
        if (
            cached &&
            Date.now() - cached.createdAt < CACHE_TTL_MS &&
            cached.keyUpdatedAt === updatedAt
        ) {
            return cached.services;
        }

        const llmConfig = config.getLLMConfig();
        if (llmApiKey && llmApiKey.ciphertext) {
            llmConfig.apiKey = decryptApiKey(llmApiKey.ciphertext);
        }

        const onProviderKeyFailure = async (status) => {
            await updateOwnerKeyStatus(db, scope, status);
            this.evict(scope);
        };

        const llm = await LLMService.create({
            llmConfig,
            scope,
            onProviderKeyFailure
        });
        if (typeof llm.setDbAccessor === 'function') {
            llm.setDbAccessor(() => db);
        }

        const qdrant = new QdrantService({
            llmConfig,
            onProviderKeyFailure
        });
        await qdrant.initialize();

        const services = { llm, qdrant, embeddings: qdrant.embeddings, scope };
        this.cache.set(key, {
            services,
            createdAt: Date.now(),
            keyUpdatedAt: updatedAt
        });
        return services;
    }
}

module.exports = LlmRegistry;
