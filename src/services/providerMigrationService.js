/**
 * Provider / embedding migrations
 *
 * Switching a surface from GPT to Sandbox (or changing an admin embedding
 * model) means every piece of content that surface can retrieve needs vectors
 * in the *target* embedding profile's collection. That is far too much work to
 * do inside an HTTP request, and it must survive a server restart, so it runs
 * as a persistent MongoDB job.
 *
 * Job document (`providerMigrations` collection):
 *   {
 *     migrationId, scope: { type, id }, kind: 'provider' | 'embedding-model',
 *     fromProvider, toProvider, targetProfileKey, targetProfile,
 *     status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled',
 *     items: [{ itemType, itemId, courseId, contentHash, status, attempts, error }],
 *     totals: { total, completed, failed },
 *     currentItem, startedAt, finishedAt, error, heartbeatAt, leaseOwner
 *   }
 *
 * Guarantees:
 *  - Idempotent: an item already current for the target profile is skipped.
 *  - Resumable: progress lives in Mongo; a restarted server resumes queued and
 *    running jobs.
 *  - Deduped: at most one active job per (scope, target profile).
 *  - Non-destructive: the previous provider stays active and keeps its vectors
 *    and encrypted credential until every required index is ready.
 */

const { createId } = require('./id');
const {
    INDEX_STATUSES,
    contentHash,
    indexingReason,
    markDocumentIndexFailed,
    markDocumentIndexReady,
    markNoteIndexFailed,
    markNoteIndexReady,
    needsIndexing
} = require('./embeddingIndexService');
const { publicProfileSummary } = require('./embeddingConfig');
const failureReasons = require('./migrationFailureReasons');
const {
    activateProviderSetFields,
    credentialForProvider
} = require('./llmKeyStore');

const MIGRATIONS_COLLECTION = 'providerMigrations';

const MIGRATION_STATUSES = Object.freeze({
    QUEUED: 'queued',
    RUNNING: 'running',
    COMPLETED: 'completed',
    FAILED: 'failed',
    CANCELLED: 'cancelled'
});

const ITEM_STATUSES = Object.freeze({
    PENDING: 'pending',
    DONE: 'done',
    FAILED: 'failed',
    SKIPPED: 'skipped'
});

const ACTIVE_STATUSES = [MIGRATION_STATUSES.QUEUED, MIGRATION_STATUSES.RUNNING];
const MAX_ATTEMPTS = 3;
// A running job whose worker died is reclaimable after this long.
const LEASE_TIMEOUT_MS = 5 * 60 * 1000;

function scopeKey(scope) {
    return `${scope.type}:${scope.id || 'global'}`;
}

async function ensureIndexes(db) {
    const collection = db.collection(MIGRATIONS_COLLECTION);
    await collection.createIndex({ migrationId: 1 }, { unique: true });
    await collection.createIndex({ scopeKey: 1, targetProfileKey: 1, status: 1 });
    await collection.createIndex({ status: 1, createdAt: 1 });
}

/**
 * The active (queued or running) migration for a scope, if any.
 */
async function findActiveMigration(db, scope, targetProfileKey = null) {
    const query = {
        scopeKey: scopeKey(scope),
        status: { $in: ACTIVE_STATUSES }
    };
    if (targetProfileKey) query.targetProfileKey = targetProfileKey;
    return db.collection(MIGRATIONS_COLLECTION).findOne(query);
}

async function getMigration(db, migrationId) {
    if (!migrationId) return null;
    return db.collection(MIGRATIONS_COLLECTION).findOne({ migrationId });
}

/**
 * Browser-safe migration view: progress, failures and enough context for the
 * retry control. Never exposes keys or ciphertext.
 */
function publicMigrationView(job) {
    if (!job) return null;
    const items = Array.isArray(job.items) ? job.items : [];
    const failures = items
        .filter(item => item.status === ITEM_STATUSES.FAILED)
        .map(item => ({
            itemType: item.itemType,
            itemId: item.itemId,
            title: item.title || null,
            // `error` is the provider's own words, kept for the browser console;
            // `failureReason` is what the panel turns into a readable sentence.
            // (`item.reason` is taken: it says why the item needed indexing.)
            error: item.error || 'Unknown error',
            failureReason: item.failureReason || failureReasons.classifyFailure(item.error),
            attempts: item.attempts || 0
        }));

    return {
        migrationId: job.migrationId,
        kind: job.kind,
        status: job.status,
        scope: job.scope,
        fromProvider: job.fromProvider || null,
        toProvider: job.toProvider || null,
        targetProfile: publicProfileSummary(job.targetProfile),
        total: job.totals ? job.totals.total : items.length,
        completed: job.totals ? job.totals.completed : 0,
        failed: job.totals ? job.totals.failed : failures.length,
        currentItem: job.currentItem || null,
        failures,
        failureSummary: failureReasons.summarizeFailures(job),
        error: job.error || null,
        startedAt: job.startedAt || null,
        finishedAt: job.finishedAt || null,
        updatedAt: job.updatedAt || null
    };
}

/**
 * Work out which documents/notes still need vectors in the target profile.
 *
 * @param {Object} options
 * @param {Object} options.db
 * @param {Object} options.profile - Target embedding profile
 * @param {Array<string>} [options.courseIds] - Courses whose documents are in scope
 * @param {boolean} [options.includeNotes] - Also cover Super Chat notes
 * @returns {Promise<{items: Array<Object>, skipped: number}>}
 */
async function calculateWork({ db, profile, courseIds = [], includeNotes = false }) {
    const items = [];
    let skipped = 0;

    // Repair the one lossy transition from the first provider-aware release:
    // legacy GPT indexes had no per-profile record, and
    // an early GPT -> Sandbox migration could add only the Sandbox map entry.
    // A completed OpenAI -> Sandbox migration item is durable evidence that
    // the item belonged to the OpenAI-backed surface before that switch.
    // Materialize its GPT record when the content is unchanged so
    // installations that already hit the bug can switch back without paying
    // for the same OpenAI embeddings again.
    let legacyEvidence = null;
    if (profile.key === 'openai:text-embedding-3-small:v1') {
        legacyEvidence = new Map();
        const evidenceQuery = {
            status: MIGRATION_STATUSES.COMPLETED,
            fromProvider: 'openai',
            'targetProfile.provider': 'ubc-llm-sandbox'
        };
        if (courseIds.length > 0 && includeNotes) {
            evidenceQuery.$or = [
                { courseIds: { $in: courseIds } },
                { includeNotes: true }
            ];
        } else if (courseIds.length > 0) {
            evidenceQuery.courseIds = { $in: courseIds };
        } else if (includeNotes) {
            evidenceQuery.includeNotes = true;
        }
        const completed = await db.collection(MIGRATIONS_COLLECTION)
            .find(evidenceQuery)
            .toArray();
        for (const migration of completed) {
            for (const item of migration.items || []) {
                if (item.status !== ITEM_STATUSES.DONE || !item.contentHash) continue;
                legacyEvidence.set(`${item.itemType}:${item.itemId}`, item.contentHash);
            }
        }
    }

    if (courseIds.length > 0) {
        const documents = await db.collection('documents')
            .find({ courseId: { $in: courseIds }, isDeleted: { $ne: true } })
            .toArray();

        for (const doc of documents) {
            // Only content with extracted text can be embedded at all.
            if (!doc.content || !String(doc.content).trim()) continue;
            const hash = contentHash(doc.content);
            const legacyHash = legacyEvidence && legacyEvidence.get(`document:${doc.documentId}`);
            if (legacyHash === hash && needsIndexing(doc, profile, hash)) {
                const record = await markDocumentIndexReady(db, doc.documentId, profile, hash);
                doc.embeddingIndexes = { ...(doc.embeddingIndexes || {}), [profile.storageKey]: record };
            }
            if (!needsIndexing(doc, profile, hash)) {
                skipped += 1;
                continue;
            }
            items.push({
                itemType: 'document',
                itemId: doc.documentId,
                courseId: doc.courseId,
                lectureName: doc.lectureName || null,
                title: doc.filename || doc.originalName || doc.documentId,
                contentHash: hash,
                reason: indexingReason(doc, profile, hash),
                status: ITEM_STATUSES.PENDING,
                attempts: 0,
                error: null
            });
        }
    }

    if (includeNotes) {
        const notes = await db.collection('superchat_notes')
            .find({ isDeleted: { $ne: true } })
            .toArray();

        for (const note of notes) {
            if (!note.content || !String(note.content).trim()) continue;
            const hash = contentHash(note.content);
            const legacyHash = legacyEvidence && legacyEvidence.get(`note:${note.noteId}`);
            if (legacyHash === hash && needsIndexing(note, profile, hash)) {
                const record = await markNoteIndexReady(db, note.noteId, profile, hash);
                note.embeddingIndexes = { ...(note.embeddingIndexes || {}), [profile.storageKey]: record };
            }
            if (!needsIndexing(note, profile, hash)) {
                skipped += 1;
                continue;
            }
            items.push({
                itemType: 'note',
                itemId: note.noteId,
                courseId: null,
                title: note.title || note.noteId,
                contentHash: hash,
                reason: indexingReason(note, profile, hash),
                status: ITEM_STATUSES.PENDING,
                attempts: 0,
                error: null
            });
        }
    }

    return { items, skipped };
}

/**
 * Create (or return the existing) migration job for a scope + target profile.
 * Duplicate migrations for the same scope/profile are prevented.
 *
 * @returns {Promise<{job: Object, created: boolean}>}
 */
async function createMigration(db, {
    scope,
    kind = 'provider',
    fromProvider = null,
    toProvider = null,
    profile,
    courseIds = [],
    includeNotes = false,
    requestedBy = null
}) {
    const existing = await findActiveMigration(db, scope, profile.key);
    if (existing) {
        return { job: existing, created: false };
    }

    const { items, skipped } = await calculateWork({ db, profile, courseIds, includeNotes });
    const now = new Date();
    const job = {
        migrationId: createId('mig'),
        scope,
        scopeKey: scopeKey(scope),
        kind,
        fromProvider,
        toProvider,
        targetProfileKey: profile.key,
        // Store the profile WITHOUT its API key — jobs are read by the browser.
        targetProfile: publicProfileSummary(profile),
        courseIds,
        includeNotes,
        status: MIGRATION_STATUSES.QUEUED,
        items,
        totals: { total: items.length, completed: 0, failed: 0, skipped },
        currentItem: null,
        requestedBy,
        createdAt: now,
        updatedAt: now,
        startedAt: null,
        finishedAt: null,
        heartbeatAt: null,
        leaseOwner: null,
        error: null
    };

    try {
        await db.collection(MIGRATIONS_COLLECTION).insertOne(job);
    } catch (error) {
        // Unique index collision: another request created the job first.
        const raced = await findActiveMigration(db, scope, profile.key);
        if (raced) return { job: raced, created: false };
        throw error;
    }

    return { job, created: true };
}

/**
 * Claim a job for this worker. Returns false when another live worker owns it.
 */
async function claimMigration(db, migrationId, leaseOwner) {
    const now = new Date();
    const staleBefore = new Date(now.getTime() - LEASE_TIMEOUT_MS);
    const result = await db.collection(MIGRATIONS_COLLECTION).findOneAndUpdate(
        {
            migrationId,
            $or: [
                { status: MIGRATION_STATUSES.QUEUED },
                // Reclaim a running job whose worker stopped heart-beating
                // (e.g. the server restarted mid-migration).
                { status: MIGRATION_STATUSES.RUNNING, heartbeatAt: { $lt: staleBefore } },
                { status: MIGRATION_STATUSES.RUNNING, heartbeatAt: null }
            ]
        },
        {
            $set: {
                status: MIGRATION_STATUSES.RUNNING,
                leaseOwner,
                heartbeatAt: now,
                startedAt: now,
                updatedAt: now
            }
        },
        { returnDocument: 'after' }
    );

    return result && (result.value || result);
}

async function heartbeat(db, migrationId, currentItem, leaseOwner = null) {
    const filter = { migrationId, status: { $in: ACTIVE_STATUSES } };
    // Once another worker has reclaimed an expired lease, an old worker must
    // not make the new lease look alive with a late heartbeat.
    if (leaseOwner) filter.leaseOwner = leaseOwner;

    await db.collection(MIGRATIONS_COLLECTION).updateOne(
        filter,
        { $set: { heartbeatAt: new Date(), updatedAt: new Date(), currentItem: currentItem || null } }
    );
}

async function recordItemResult(db, migrationId, itemId, itemType, patch) {
    const job = await getMigration(db, migrationId);
    if (!job || !ACTIVE_STATUSES.includes(job.status)) return null;

    const items = (job.items || []).map(item => (
        item.itemId === itemId && item.itemType === itemType ? { ...item, ...patch } : item
    ));
    const completed = items.filter(item => item.status === ITEM_STATUSES.DONE || item.status === ITEM_STATUSES.SKIPPED).length;
    const failed = items.filter(item => item.status === ITEM_STATUSES.FAILED).length;

    await db.collection(MIGRATIONS_COLLECTION).updateOne(
        { migrationId, status: { $in: ACTIVE_STATUSES } },
        {
            $set: {
                items,
                'totals.completed': completed,
                'totals.failed': failed,
                updatedAt: new Date()
            }
        }
    );

    return { items, completed, failed };
}

async function finishMigration(db, migrationId, status, error = null) {
    await db.collection(MIGRATIONS_COLLECTION).updateOne(
        { migrationId, status: { $ne: MIGRATION_STATUSES.CANCELLED } },
        {
            $set: {
                status,
                error: error ? String(error.message || error).slice(0, 500) : null,
                finishedAt: new Date(),
                updatedAt: new Date(),
                currentItem: null,
                leaseOwner: null
            }
        }
    );
}

/**
 * Cooperatively stop an unfinished migration. Vector cleanup is performed by
 * the runner because it knows the target collections and item types.
 */
async function cancelMigration(db, migrationId, cancelledBy = null) {
    const now = new Date();
    await db.collection(MIGRATIONS_COLLECTION).updateOne(
        { migrationId, status: { $in: ACTIVE_STATUSES } },
        {
            $set: {
                status: MIGRATION_STATUSES.CANCELLED,
                error: 'Cancelled by user',
                cancelledBy,
                cancelledAt: now,
                finishedAt: now,
                updatedAt: now,
                currentItem: null,
                heartbeatAt: null,
                leaseOwner: null
            }
        }
    );
    return getMigration(db, migrationId);
}

/**
 * Reset failed items so a retry re-attempts only what actually failed.
 */
async function retryMigration(db, migrationId) {
    const job = await getMigration(db, migrationId);
    if (!job) return null;

    const items = (job.items || []).map(item => (
        item.status === ITEM_STATUSES.FAILED
            ? { ...item, status: ITEM_STATUSES.PENDING, attempts: 0, error: null }
            : item
    ));
    const completed = items.filter(item => item.status === ITEM_STATUSES.DONE || item.status === ITEM_STATUSES.SKIPPED).length;

    await db.collection(MIGRATIONS_COLLECTION).updateOne(
        { migrationId },
        {
            $set: {
                items,
                status: MIGRATION_STATUSES.QUEUED,
                error: null,
                finishedAt: null,
                leaseOwner: null,
                heartbeatAt: null,
                'totals.completed': completed,
                'totals.failed': 0,
                updatedAt: new Date()
            }
        }
    );

    return getMigration(db, migrationId);
}

/**
 * Where a scope's provider credential lives, so activation can be atomic.
 */
function scopeTarget(scope) {
    switch (scope.type) {
        case 'course':
            return { collection: 'courses', filter: { courseId: scope.id } };
        case 'superchat':
            return { collection: 'superchats', filter: { superchatId: scope.id } };
        case 'notes':
            return { collection: 'settings', filter: { _id: 'notesLlm' } };
        case 'superCourseChat':
            return { collection: 'settings', filter: { _id: 'superCourseChat' } };
        default:
            return null;
    }
}

/**
 * Final consistency pass: content uploaded or edited *while* the migration ran
 * would otherwise be missed. Re-runs the calculation and returns any newly
 * stale items.
 */
async function findRemainingWork(db, job, profile) {
    const { items } = await calculateWork({
        db,
        profile,
        courseIds: job.courseIds || [],
        includeNotes: !!job.includeNotes
    });
    return items;
}

/**
 * Atomically activate the target provider for a scope. Only called once every
 * required index is current. The previous provider's encrypted credential and
 * vectors are preserved, so switching back is cheap.
 */
async function activateProvider(db, scope, provider) {
    const target = scopeTarget(scope);
    if (!target) return false;

    const doc = await db.collection(target.collection).findOne(target.filter);
    const credential = credentialForProvider(doc, provider);
    if (!credential || !credential.ciphertext) {
        throw new Error(`Cannot activate ${provider} for ${scopeKey(scope)}: no stored credential`);
    }

    await db.collection(target.collection).updateOne(
        target.filter,
        { $set: { ...activateProviderSetFields(provider, credential), updatedAt: new Date() } }
    );
    return true;
}

/**
 * Roll a scope back to its previous provider after a failed migration: clear
 * the pending marker and leave the active provider untouched.
 *
 * @param {Object} options
 * @param {boolean} [options.keepMigrationId] - Keep the surface pointing at the
 *   job. A failed migration must stay reachable: the surface's stored id is how
 *   the UI finds the job again after a reload, and dropping it would hide both
 *   the failure and its retry control.
 */
async function abandonPendingProvider(db, scope, { keepMigrationId = false } = {}) {
    const target = scopeTarget(scope);
    if (!target) return;

    const set = { pendingLlmProvider: null, updatedAt: new Date() };
    if (!keepMigrationId) set.providerMigrationId = null;

    await db.collection(target.collection).updateOne(target.filter, { $set: set });
}

/**
 * Persist an item's success against its content, marking the embedding index
 * ready for the target profile.
 */
async function markItemIndexed(db, item, profile) {
    if (item.itemType === 'note') {
        return markNoteIndexReady(db, item.itemId, profile, item.contentHash);
    }
    return markDocumentIndexReady(db, item.itemId, profile, item.contentHash);
}

async function markItemFailed(db, item, profile, error) {
    if (item.itemType === 'note') {
        return markNoteIndexFailed(db, item.itemId, profile, item.contentHash, error);
    }
    return markDocumentIndexFailed(db, item.itemId, profile, item.contentHash, error);
}

module.exports = {
    ACTIVE_STATUSES,
    ITEM_STATUSES,
    LEASE_TIMEOUT_MS,
    MAX_ATTEMPTS,
    MIGRATIONS_COLLECTION,
    MIGRATION_STATUSES,
    abandonPendingProvider,
    activateProvider,
    calculateWork,
    cancelMigration,
    claimMigration,
    createMigration,
    ensureIndexes,
    findActiveMigration,
    findRemainingWork,
    finishMigration,
    getMigration,
    heartbeat,
    markItemFailed,
    markItemIndexed,
    publicMigrationView,
    recordItemResult,
    retryMigration,
    scopeKey,
    scopeTarget
};
