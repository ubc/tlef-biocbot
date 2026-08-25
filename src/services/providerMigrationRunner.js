/**
 * Provider migration runner
 *
 * Executes the persistent jobs created by providerMigrationService: re-embeds
 * only the documents/notes that are missing or stale for the target embedding
 * profile, reports progress, runs a final consistency pass to pick up content
 * that changed while the migration ran, and only then activates the new
 * provider.
 *
 * The runner never runs inside an HTTP request. Routes create a job and return
 * immediately; this worker drains it in the background and is restarted at boot
 * so an interrupted migration resumes where it stopped.
 */

const { randomUUID } = require('crypto');

const QdrantService = require('./qdrantService');
const NotesQdrantService = require('./notesQdrantService');
const scopeModelSettings = require('./scopeModelSettings');
const adminModelSettings = require('./adminModelSettings');
const config = require('./config');
const { buildEmbeddingProfile } = require('./embeddingConfig');
const { clearIndexRecord } = require('./embeddingIndexService');
const { activeProviderOf, credentialForProvider, decryptApiKey } = require('./llmKeyStore');
const { getCourseSuperchatIds } = require('../models/Course');
const { resolveSuperCourseChatSettings } = require('./superCourseService');
const migrations = require('./providerMigrationService');
const failureReasons = require('./migrationFailureReasons');

const { ITEM_STATUSES, MIGRATION_STATUSES, MAX_ATTEMPTS } = migrations;

const WORKER_ID = `worker_${randomUUID()}`;
const ITEM_HEARTBEAT_MS = Math.max(1000, Math.floor(migrations.LEASE_TIMEOUT_MS / 3));
const LEASE_RETRY_BUFFER_MS = 250;
const migrationRetryTimers = new Map();

function leaseRetryDelay(job, now = Date.now()) {
    const heartbeatAt = job && job.heartbeatAt ? new Date(job.heartbeatAt).getTime() : 0;
    if (!Number.isFinite(heartbeatAt) || heartbeatAt <= 0) return LEASE_RETRY_BUFFER_MS;
    return Math.max(
        LEASE_RETRY_BUFFER_MS,
        heartbeatAt + migrations.LEASE_TIMEOUT_MS - now + LEASE_RETRY_BUFFER_MS
    );
}

function scheduleLeaseRetry(db, migrationId, job, options = {}) {
    if (migrationRetryTimers.has(migrationId)) return;
    const delay = leaseRetryDelay(job);
    console.log(`⏳ Migration ${migrationId} is leased by another worker; retrying in ${Math.ceil(delay / 1000)}s`);
    const timer = setTimeout(() => {
        migrationRetryTimers.delete(migrationId);
        startMigration(db, migrationId, options);
    }, delay);
    // A lease retry should not keep a shutting-down Node process alive.
    if (typeof timer.unref === 'function') timer.unref();
    migrationRetryTimers.set(migrationId, timer);
}

/**
 * Surfaces whose stored credential could pay for embedding one item, in
 * preference order: the item's own owner first, then any surface that pulls the
 * item into its own index.
 *
 * A Sandbox bucket indexes its member courses with the bucket's own key even
 * when those courses run on GPT, so the bucket has to be a candidate for their
 * documents — otherwise a GPT course that a Sandbox bucket includes has no
 * Sandbox key of its own and its items can never be embedded.
 */
async function credentialCandidatesForItem(db, item) {
    const isNote = !!(item && item.itemType === 'note');
    const courseId = item && item.courseId;
    const candidates = [];

    if (isNote) {
        candidates.push({ type: 'notes', id: 'notesLlm' });
    } else if (courseId) {
        candidates.push({ type: 'course', id: courseId });
    }

    if (isNote) {
        // Any bucket whose chat pulls Notes into retrieval can pay for a note.
        const buckets = await db.collection('superchats')
            .find({ isDeleted: { $ne: true } })
            .toArray();
        for (const bucket of buckets) {
            if (resolveSuperCourseChatSettings(bucket).includeNotesInRetrieval) {
                candidates.push({ type: 'superchat', id: bucket.superchatId });
            }
        }
    } else if (courseId) {
        // Bucket membership lives on the course, not on the bucket.
        const course = await db.collection('courses').findOne({ courseId });
        for (const superchatId of getCourseSuperchatIds(course || {})) {
            candidates.push({ type: 'superchat', id: superchatId });
        }
    }

    // The instructor Super Course chat pools every bucketed course, and Notes
    // unless it is configured to exclude them.
    const superCourseChat = await db.collection('settings').findOne({ _id: 'superCourseChat' });
    if (superCourseChat
        && (!isNote || resolveSuperCourseChatSettings(superCourseChat).includeNotesInRetrieval)) {
        candidates.push({ type: 'superCourseChat', id: 'superCourseChat' });
    }

    return candidates;
}

/**
 * Which surface's encrypted credential pays for embedding a given item.
 *
 * - A provider switch embeds everything the switching surface can retrieve,
 *   using THAT surface's key.
 * - An admin embedding-model change re-indexes content across many surfaces at
 *   once, so each item is paid for by a surface that actually runs on the target
 *   platform and covers that item — which is not always the item's own owner.
 */
async function resolveCredentialScope(db, job, item) {
    if (job.kind !== 'embedding-model') return job.scope;

    const provider = job.targetProfile.provider || job.toProvider;
    const candidates = await credentialCandidatesForItem(db, item);

    let storedOnly = null;
    for (const scope of candidates) {
        const target = migrations.scopeTarget(scope);
        if (!target) continue;
        const doc = await db.collection(target.collection).findOne(target.filter);
        const credential = credentialForProvider(doc, provider);
        if (!credential || !credential.ciphertext) continue;
        // A surface running on the target platform today is the one whose key
        // pays for the content it retrieves.
        if (activeProviderOf(doc) === provider) return scope;
        // Otherwise remember it: a stored-but-inactive key still beats failing.
        if (!storedOnly) storedOnly = scope;
    }

    // Nothing has a usable key: fall back to the item's own owner so the
    // resulting error names the surface an admin needs to fix.
    return storedOnly || candidates[0] || job.scope;
}

/**
 * Rebuild the target embedding profile *with* a scoped API key. Jobs persist
 * only the key-free summary, so the key is re-read from the owning surface each
 * time the job is picked up.
 */
async function resolveTargetProfile(db, job, scope = job.scope) {
    const target = migrations.scopeTarget(scope);
    if (!target) throw new Error(`Unknown migration scope type: ${scope && scope.type}`);

    const doc = await db.collection(target.collection).findOne(target.filter);
    const provider = job.targetProfile.provider || job.toProvider;
    const credential = credentialForProvider(doc, provider);
    if (!credential || !credential.ciphertext) {
        throw new Error(`No stored ${provider} credential for ${migrations.scopeKey(scope)}`);
    }

    const infra = config.getProviderInfra(provider);
    return buildEmbeddingProfile({
        provider,
        embeddingModel: job.targetProfile.embeddingModel,
        revision: job.targetProfile.revision,
        vectorSize: job.targetProfile.vectorSize,
        endpoint: infra.endpoint,
        apiKey: decryptApiKey(credential.ciphertext)
    });
}

/**
 * Vector services bound to one embedding profile. Documents and notes share the
 * base service so the embeddings client is created once per key.
 */
async function createVectorServices(profile, { needNotes, shouldCancel = null }) {
    const qdrant = new QdrantService({
        embeddingProfile: profile,
        shouldCancel,
        // The job's own items are the real test of the provider; a warm-up
        // embedding here only adds a call that can hang before item 1.
        skipEmbeddingProbe: true
    });
    await qdrant.initialize();

    let notesQdrant = null;
    if (needNotes) {
        notesQdrant = new NotesQdrantService({ embeddingProfile: profile });
        await notesQdrant.initialize(qdrant);
    }

    return { qdrant, notesQdrant };
}

/**
 * Lazily builds and caches the vector services for each credential owner in a
 * job. All of them write into the SAME target collection — only the key that
 * pays for the embeddings differs.
 */
function createServiceResolver(db, job) {
    const cache = new Map();
    // Resolving a paying surface costs a few reads, so do it once per owner
    // rather than once per item.
    const scopeCache = new Map();
    const shouldCancel = async () => {
        const current = await migrations.getMigration(db, job.migrationId);
        return !current || current.status === MIGRATION_STATUSES.CANCELLED;
    };

    return async function servicesFor(item) {
        const ownerKey = item && item.itemType === 'note'
            ? 'note'
            : `course:${(item && item.courseId) || ''}`;
        if (!scopeCache.has(ownerKey)) {
            scopeCache.set(ownerKey, await resolveCredentialScope(db, job, item));
        }
        const scope = scopeCache.get(ownerKey);
        const key = migrations.scopeKey(scope);
        if (cache.has(key)) {
            const cached = cache.get(key);
            if (cached.error) throw cached.error;
            return cached;
        }

        try {
            const profile = await resolveTargetProfile(db, job, scope);
            const services = await createVectorServices(profile, {
                needNotes: !!job.includeNotes || (item && item.itemType === 'note'),
                shouldCancel
            });
            const entry = { ...services, profile };
            cache.set(key, entry);
            return entry;
        } catch (error) {
            // Cache the failure so one broken surface does not re-probe the
            // provider once per item.
            cache.set(key, { error });
            throw error;
        }
    };
}

/**
 * Delete only the partial vectors and index records belonging to a cancelled
 * job's target profile. Other providers' collections and encrypted keys are
 * deliberately untouched. Safe to run repeatedly (the route and worker both
 * call it to close races with an in-flight Qdrant write).
 */
async function cleanupMigrationTarget(db, migrationIdOrJob) {
    const job = typeof migrationIdOrJob === 'string'
        ? await migrations.getMigration(db, migrationIdOrJob)
        : migrationIdOrJob;
    if (!job || job.status !== MIGRATION_STATUSES.CANCELLED) return null;

    const profile = buildEmbeddingProfile({
        provider: job.targetProfile.provider,
        embeddingModel: job.targetProfile.embeddingModel,
        revision: job.targetProfile.revision,
        vectorSize: job.targetProfile.vectorSize
    });
    const qdrant = new QdrantService({
        embeddingProfile: profile,
        skipEmbeddings: true,
        createCollectionIfMissing: false
    });
    await qdrant.initialize();

    let deletedVectors = 0;
    let clearedIndexRecords = 0;
    let notesCollectionExists = null;
    const uniqueItems = new Map((job.items || []).map(item => [`${item.itemType}:${item.itemId}`, item]));

    for (const item of uniqueItems.values()) {
        if (item.itemType === 'note') {
            if (notesCollectionExists === null && qdrant.client) {
                const collections = await qdrant.client.getCollections();
                notesCollectionExists = (collections.collections || [])
                    .some(collection => collection.name === profile.notesCollection);
            }
            if (notesCollectionExists) {
                await qdrant.client.delete(profile.notesCollection, {
                    filter: { must: [{ key: 'noteId', match: { value: item.itemId } }] }
                });
            }
            await clearIndexRecord(db, {
                collectionName: 'superchat_notes',
                filter: { noteId: item.itemId },
                profileKey: profile.storageKey
            });
            clearedIndexRecords += 1;
            continue;
        }

        const result = await qdrant.deleteDocumentChunks(item.itemId, item.courseId || null);
        if (result && result.success) deletedVectors += result.deletedCount || 0;
        await clearIndexRecord(db, {
            collectionName: 'documents',
            filter: { documentId: item.itemId },
            profileKey: profile.storageKey
        });
        clearedIndexRecords += 1;
    }

    await migrations.abandonPendingProvider(db, job.scope);
    return {
        migrationId: job.migrationId,
        status: job.status,
        targetCollection: profile.collection,
        documents: [...uniqueItems.values()].filter(item => item.itemType === 'document').length,
        notes: [...uniqueItems.values()].filter(item => item.itemType === 'note').length,
        deletedVectors,
        clearedIndexRecords
    };
}

async function cancelAndCleanup(db, migrationId, cancelledBy = null) {
    const job = await migrations.cancelMigration(db, migrationId, cancelledBy);
    if (!job) return null;
    const cleanup = await cleanupMigrationTarget(db, job);
    return { job: await migrations.getMigration(db, migrationId), cleanup };
}

/**
 * Re-embed one document into the target profile's collection.
 *
 * Existing chunks for this document in THAT collection are removed first, so a
 * retry after a partial failure cannot leave duplicate chunks behind. Other
 * profiles' collections are untouched.
 */
async function migrateDocument(db, item, { qdrant, profile }) {
    const doc = await db.collection('documents').findOne({ documentId: item.itemId });
    if (!doc || doc.isDeleted) {
        return { skipped: true, reason: 'deleted' };
    }
    if (!doc.content || !String(doc.content).trim()) {
        return { skipped: true, reason: 'no-content' };
    }

    await qdrant.deleteDocumentChunks(item.itemId, doc.courseId);

    const result = await qdrant.processAndStoreDocument({
        courseId: doc.courseId,
        lectureName: doc.lectureName,
        documentId: doc.documentId,
        content: doc.content,
        fileName: doc.filename || doc.originalName,
        mimeType: doc.mimeType,
        documentType: doc.documentType,
        type: doc.type
    });

    if (!result || result.success !== true) {
        throw new Error((result && result.error) || 'Document indexing failed');
    }

    await migrations.markItemIndexed(db, item, profile);
    return { skipped: false };
}

async function migrateNote(db, item, { notesQdrant, profile }) {
    const note = await db.collection('superchat_notes').findOne({ noteId: item.itemId });
    if (!note || note.isDeleted) {
        return { skipped: true, reason: 'deleted' };
    }
    if (!note.content || !String(note.content).trim()) {
        return { skipped: true, reason: 'no-content' };
    }

    // updateNote deletes this note's points in the target collection first, so
    // re-running after a failure is safe.
    await notesQdrant.updateNote(note.noteId, note.content, {
        authorId: note.authorId,
        authorName: note.authorName,
        title: note.title,
        tags: note.tags,
        createdAt: note.createdAt ? new Date(note.createdAt).toISOString() : undefined
    });

    await migrations.markItemIndexed(db, item, profile);
    return { skipped: false };
}

async function processItem(db, item, context) {
    if (item.itemType === 'note') {
        return migrateNote(db, item, context);
    }
    return migrateDocument(db, item, context);
}

/**
 * Drain one migration job to completion.
 *
 * @param {Object} db
 * @param {string} migrationId
 * @param {Object} [options] - { onProgress }
 * @returns {Promise<Object|null>} The finished job document
 */
async function runMigration(db, migrationId, options = {}) {
    const claimed = await migrations.claimMigration(db, migrationId, WORKER_ID);
    if (!claimed) {
        // Another worker holds a live lease on this job.
        return migrations.getMigration(db, migrationId);
    }

    let job = await migrations.getMigration(db, migrationId);

    // Key-free profile used for planning (what is stale, which collection).
    // The keyed profile per item comes from servicesFor().
    const profile = buildEmbeddingProfile({
        provider: job.targetProfile.provider,
        embeddingModel: job.targetProfile.embeddingModel,
        revision: job.targetProfile.revision,
        vectorSize: job.targetProfile.vectorSize
    });
    const servicesFor = createServiceResolver(db, job);

    // Two passes: the queued work, then a consistency pass that catches uploads
    // and edits that landed while the first pass was running.
    for (let pass = 0; pass < 2; pass += 1) {
        job = await migrations.getMigration(db, migrationId);
        if (!job || job.status === MIGRATION_STATUSES.CANCELLED) break;

        let queue = (job.items || []).filter(item => item.status === ITEM_STATUSES.PENDING);

        if (pass === 1) {
            const remaining = await migrations.findRemainingWork(db, job, profile);
            if (remaining.length === 0) break;

            // Merge the newly-discovered work into the persisted job so progress
            // totals stay honest and a restart still sees it.
            const known = new Set((job.items || []).map(item => `${item.itemType}:${item.itemId}`));
            const additions = remaining.filter(item => !known.has(`${item.itemType}:${item.itemId}`));
            const refreshed = remaining.filter(item => known.has(`${item.itemType}:${item.itemId}`));

            const mergedItems = (job.items || []).map((item) => {
                const match = refreshed.find(r => r.itemType === item.itemType && r.itemId === item.itemId);
                if (!match) return item;
                // Content changed since the first pass: re-queue with the new
                // hash and a fresh attempt budget.
                if (match.contentHash !== item.contentHash) {
                    return {
                        ...item,
                        contentHash: match.contentHash,
                        status: ITEM_STATUSES.PENDING,
                        attempts: 0,
                        error: null
                    };
                }
                // Same content: the consistency pass exists to catch uploads and
                // edits, not to hand an exhausted item extra attempts. Retrying
                // a genuine failure is an explicit user action.
                return item;
            }).concat(additions);

            await db.collection(migrations.MIGRATIONS_COLLECTION).updateOne(
                { migrationId },
                {
                    $set: {
                        items: mergedItems,
                        'totals.total': mergedItems.length,
                        'totals.completed': mergedItems.filter(i => i.status === ITEM_STATUSES.DONE || i.status === ITEM_STATUSES.SKIPPED).length,
                        updatedAt: new Date()
                    }
                }
            );
            queue = mergedItems.filter(item => item.status === ITEM_STATUSES.PENDING);
        }

        for (const item of queue) {
            const beforeItem = await migrations.getMigration(db, migrationId);
            if (!beforeItem || beforeItem.status === MIGRATION_STATUSES.CANCELLED) break;

            const currentItem = {
                itemType: item.itemType,
                itemId: item.itemId,
                title: item.title || null
            };
            await migrations.heartbeat(db, migrationId, currentItem, WORKER_ID);

            let heartbeatInFlight = false;
            const heartbeatTimer = setInterval(() => {
                if (heartbeatInFlight) return;
                heartbeatInFlight = true;
                migrations.heartbeat(db, migrationId, currentItem, WORKER_ID)
                    .catch(error => console.error(`⚠️ Migration ${migrationId} heartbeat failed:`, error.message))
                    .finally(() => { heartbeatInFlight = false; });
            }, ITEM_HEARTBEAT_MS);
            if (typeof heartbeatTimer.unref === 'function') heartbeatTimer.unref();

            try {
                const services = await servicesFor(item);
                const outcome = await processItem(db, item, { ...services, profile });
                await migrations.recordItemResult(db, migrationId, item.itemId, item.itemType, {
                    status: outcome.skipped ? ITEM_STATUSES.SKIPPED : ITEM_STATUSES.DONE,
                    attempts: (item.attempts || 0) + 1,
                    error: null,
                    skipReason: outcome.reason || null
                });
            } catch (error) {
                const currentJob = await migrations.getMigration(db, migrationId);
                if (error.code === 'MIGRATION_CANCELLED'
                    || (currentJob && currentJob.status === MIGRATION_STATUSES.CANCELLED)) {
                    break;
                }
                const attempts = (item.attempts || 0) + 1;
                await migrations.markItemFailed(db, item, profile, error);
                await migrations.recordItemResult(db, migrationId, item.itemId, item.itemType, {
                    status: attempts >= MAX_ATTEMPTS ? ITEM_STATUSES.FAILED : ITEM_STATUSES.PENDING,
                    attempts,
                    error: String(error.message || error).slice(0, 500),
                    // Classified here, where the Error object still carries its
                    // code and HTTP status, rather than re-guessed from a string.
                    failureReason: failureReasons.classifyFailure(error)
                });
                console.error(`❌ Migration ${migrationId}: ${item.itemType} ${item.itemId} failed (attempt ${attempts}):`, error.message);

                // A retryable item stays pending; give it its remaining attempts
                // inside this same pass rather than waiting for a manual retry.
                if (attempts < MAX_ATTEMPTS) {
                    queue.push({ ...item, attempts });
                }
            } finally {
                clearInterval(heartbeatTimer);
            }

            if (typeof options.onProgress === 'function') {
                try {
                    options.onProgress(await migrations.getMigration(db, migrationId));
                } catch (_) {
                    // A progress listener must never break a migration.
                }
            }
        }
    }

    job = await migrations.getMigration(db, migrationId);
    if (!job || job.status === MIGRATION_STATUSES.CANCELLED) {
        if (job) await cleanupMigrationTarget(db, job);
        return migrations.getMigration(db, migrationId);
    }
    const failed = (job.items || []).filter(item => item.status === ITEM_STATUSES.FAILED);

    if (failed.length > 0) {
        // `job.error` stays technical on purpose: it names the provider's own
        // words and, for a credential failure, the surface that is missing a
        // key — detail no readable sentence can carry. What a person sees is
        // built separately in publicMigrationView's `failureSummary`.
        const distinctErrors = [...new Set(failed.map(item => item.error).filter(Boolean))];
        const summary = distinctErrors.length === 1
            ? distinctErrors[0]
            : `${failed.length} item(s) could not be indexed`;

        await migrations.finishMigration(db, migrationId, MIGRATION_STATUSES.FAILED, new Error(summary));
        // The previous provider stays active; its vectors and credential are
        // untouched, so the surface keeps working. The migration id stays on the
        // surface so the failure and its retry control survive a page reload.
        await migrations.abandonPendingProvider(db, job.scope, { keepMigrationId: true });
        return migrations.getMigration(db, migrationId);
    }

    if ((job.kind === 'provider' || job.kind === 'prepare') && job.toProvider) {
        try {
            await migrations.activateProvider(db, job.scope, job.toProvider);
        } catch (error) {
            await migrations.finishMigration(db, migrationId, MIGRATION_STATUSES.FAILED, error);
            await migrations.abandonPendingProvider(db, job.scope, { keepMigrationId: true });
            return migrations.getMigration(db, migrationId);
        }
    }

    // Only promote the model THIS job indexed — a newer staged change has its
    // own migration and its own vectors to wait for. A prepare/switch job
    // qualifies too: it is what applies an embedding choice saved in the model
    // settings panel, which never starts a job of its own.
    if (job.kind === 'embedding-model' || job.kind === 'provider' || job.kind === 'prepare') {
        const expected = {
            embeddingModel: job.targetProfile.embeddingModel,
            embeddingRevision: job.targetProfile.revision
        };
        if (job.scope?.type === 'adminEmbedding') {
            // Finish jobs created by the previous global-settings release so a
            // deploy never strands an in-flight migration.
            await adminModelSettings.activatePendingEmbedding(db, job.targetProfile.provider, expected);
        } else {
            await scopeModelSettings.activatePendingEmbedding(db, job.scope, job.targetProfile.provider, expected);
        }
    }

    await migrations.finishMigration(db, migrationId, MIGRATION_STATUSES.COMPLETED);
    return migrations.getMigration(db, migrationId);
}

/**
 * Fire-and-forget wrapper so an HTTP handler never waits for a whole course to
 * be re-indexed.
 */
function startMigration(db, migrationId, options = {}) {
    setImmediate(() => {
        runMigration(db, migrationId, options)
            .then((job) => {
                // Startup can race the previous process's still-fresh lease.
                // Retry when it expires instead of leaving a job permanently
                // displayed as `running` with no worker behind it.
                if (job && migrations.ACTIVE_STATUSES.includes(job.status) && job.leaseOwner !== WORKER_ID) {
                    scheduleLeaseRetry(db, migrationId, job, options);
                }
            })
            .catch((error) => {
                console.error(`❌ Migration ${migrationId} crashed:`, error.message);
                migrations.finishMigration(db, migrationId, MIGRATION_STATUSES.FAILED, error).catch(() => {});
            });
    });
}

/**
 * Resume every unfinished migration at boot. Jobs survive restarts precisely
 * because their state lives in MongoDB rather than in process memory.
 */
async function resumePendingMigrations(db) {
    if (!db) return [];
    const pending = await db.collection(migrations.MIGRATIONS_COLLECTION)
        .find({ status: { $in: migrations.ACTIVE_STATUSES } })
        .toArray();

    for (const job of pending) {
        console.log(`♻️ Resuming migration ${job.migrationId} (${job.scopeKey} -> ${job.targetProfileKey})`);
        startMigration(db, job.migrationId);
    }
    return pending.map(job => job.migrationId);
}

module.exports = {
    WORKER_ID,
    cancelAndCleanup,
    cleanupMigrationTarget,
    createVectorServices,
    credentialCandidatesForItem,
    leaseRetryDelay,
    migrateDocument,
    migrateNote,
    resolveCredentialScope,
    resolveTargetProfile,
    resumePendingMigrations,
    runMigration,
    startMigration
};
