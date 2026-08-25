/**
 * Persistent migration jobs: what work they calculate, how duplicates are
 * prevented, how a dead worker's job is reclaimed, and how retry re-queues only
 * the items that actually failed.
 */
const { buildEmbeddingProfile } = require('../../../src/services/embeddingConfig');
const {
    INDEX_STATUSES,
    buildIndexRecord,
    contentHash,
} = require('../../../src/services/embeddingIndexService');
const {
    ITEM_STATUSES,
    LEASE_TIMEOUT_MS,
    MIGRATIONS_COLLECTION,
    MIGRATION_STATUSES,
    abandonPendingProvider,
    activateProvider,
    calculateWork,
    cancelMigration,
    claimMigration,
    createMigration,
    findActiveMigration,
    finishMigration,
    getMigration,
    heartbeat,
    publicMigrationView,
    recordItemResult,
    retryMigration,
    scopeKey,
    scopeTarget,
} = require('../../../src/services/providerMigrationService');
const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');
const { memoryDb } = require('../helpers/memory-db');

const GPT = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
const SANDBOX = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });
const COURSE_SCOPE = { type: 'course', id: 'C1' };

function readyFor(profile, content, collection = null) {
    return {
        [profile.storageKey]: buildIndexRecord({
            profile,
            hash: contentHash(content),
            status: INDEX_STATUSES.READY,
            indexedAt: new Date(),
            collection,
        }),
    };
}

describe('calculateWork', () => {
    test('skips documents already current for the target profile', async () => {
        const db = memoryDb({
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'alpha', embeddingIndexes: readyFor(SANDBOX, 'alpha') },
                { documentId: 'd2', courseId: 'C1', content: 'beta' },
            ],
        });

        const { items, skipped } = await calculateWork({ db, profile: SANDBOX, courseIds: ['C1'] });

        expect(skipped).toBe(1);
        expect(items).toHaveLength(1);
        expect(items[0]).toMatchObject({ itemType: 'document', itemId: 'd2', reason: 'missing' });
    });

    test('an edit during the other platform\'s period makes the index stale again', async () => {
        const db = memoryDb({
            documents: [
                // Indexed for GPT against the OLD text, then edited.
                { documentId: 'd1', courseId: 'C1', content: 'edited text', embeddingIndexes: readyFor(GPT, 'original text') },
            ],
        });

        const { items } = await calculateWork({ db, profile: GPT, courseIds: ['C1'] });
        expect(items).toHaveLength(1);
        expect(items[0].reason).toBe('content-changed');
        expect(items[0].contentHash).toBe(contentHash('edited text'));
    });

    test('repairs GPT tracking lost by an earlier legacy-to-Sandbox migration', async () => {
        const text = 'legacy course text';
        const db = memoryDb({
            documents: [{
                // `uploaded` is the real terminal document state; embedding
                // readiness comes from per-profile records and migration proof.
                documentId: 'legacy-d1', courseId: 'C1', content: text, status: 'uploaded',
                embeddingIndexes: readyFor(SANDBOX, text),
            }],
            providerMigrations: [{
                migrationId: 'old-sandbox-migration',
                status: MIGRATION_STATUSES.COMPLETED,
                fromProvider: 'openai',
                targetProfile: { provider: 'ubc-llm-sandbox' },
                courseIds: ['C1'],
                items: [{
                    itemType: 'document', itemId: 'legacy-d1', contentHash: contentHash(text),
                    status: ITEM_STATUSES.DONE,
                }],
            }],
        });

        const { items, skipped } = await calculateWork({ db, profile: GPT, courseIds: ['C1'] });

        expect(items).toEqual([]);
        expect(skipped).toBe(1);
        const repaired = await db.collection('documents').findOne({ documentId: 'legacy-d1' });
        expect(repaired.embeddingIndexes[GPT.storageKey]).toMatchObject({
            provider: 'openai', status: 'ready',
        });
        expect(repaired.embeddingIndexes[SANDBOX.storageKey]).toMatchObject({ status: 'ready' });
    });

    test('documents with no extractable text are never queued', async () => {
        const db = memoryDb({
            documents: [
                { documentId: 'd1', courseId: 'C1', content: '' },
                { documentId: 'd2', courseId: 'C1', content: '   ' },
                { documentId: 'd3', courseId: 'C1' },
            ],
        });
        const { items } = await calculateWork({ db, profile: SANDBOX, courseIds: ['C1'] });
        expect(items).toEqual([]);
    });

    test('deleted documents are excluded', async () => {
        const db = memoryDb({
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text', isDeleted: true }],
        });
        const { items } = await calculateWork({ db, profile: SANDBOX, courseIds: ['C1'] });
        expect(items).toEqual([]);
    });

    test('notes are covered when the surface includes them', async () => {
        const db = memoryDb({
            superchat_notes: [
                { noteId: 'n1', content: 'note one', title: 'Note one' },
                {
                    noteId: 'n2',
                    content: 'note two',
                    embeddingIndexes: readyFor(SANDBOX, 'note two', SANDBOX.notesCollection),
                },
            ],
        });

        const withNotes = await calculateWork({ db, profile: SANDBOX, includeNotes: true });
        expect(withNotes.items.map(item => item.itemId)).toEqual(['n1']);
        expect(withNotes.items[0]).toMatchObject({ itemType: 'note', title: 'Note one' });
        expect(withNotes.skipped).toBe(1);

        const withoutNotes = await calculateWork({ db, profile: SANDBOX, includeNotes: false });
        expect(withoutNotes.items).toEqual([]);
    });

    test('only the named courses are considered', async () => {
        const db = memoryDb({
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'a' },
                { documentId: 'd2', courseId: 'C2', content: 'b' },
            ],
        });
        const { items } = await calculateWork({ db, profile: SANDBOX, courseIds: ['C2'] });
        expect(items.map(item => item.itemId)).toEqual(['d2']);
    });
});

describe('creating jobs', () => {
    test('a job persists its queue, totals and key-free target profile', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const keyed = buildEmbeddingProfile({
            provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b', apiKey: 'sbx-secret',
        });

        const { job, created } = await createMigration(db, {
            scope: COURSE_SCOPE, fromProvider: 'openai', toProvider: 'ubc-llm-sandbox',
            profile: keyed, courseIds: ['C1'],
        });

        expect(created).toBe(true);
        expect(job.status).toBe(MIGRATION_STATUSES.QUEUED);
        expect(job.totals).toMatchObject({ total: 1, completed: 0, failed: 0 });
        expect(job.targetProfileKey).toBe('ubc-llm-sandbox:qwen3-embedding-0.6b:v1');
        // The stored job must never carry key material.
        expect(JSON.stringify(job)).not.toContain('sbx-secret');
        expect(job.targetProfile.apiKey).toBeUndefined();

        const stored = await db.collection(MIGRATIONS_COLLECTION).findOne({ migrationId: job.migrationId });
        expect(stored.scopeKey).toBe('course:C1');
    });

    test('a duplicate migration for the same scope and profile is not created twice', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const args = { scope: COURSE_SCOPE, toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'] };

        const first = await createMigration(db, args);
        const second = await createMigration(db, args);

        expect(first.created).toBe(true);
        expect(second.created).toBe(false);
        expect(second.job.migrationId).toBe(first.job.migrationId);
        expect(await db.collection(MIGRATIONS_COLLECTION).countDocuments({})).toBe(1);
    });

    test('a different target profile for the same scope is allowed', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const a = await createMigration(db, { scope: COURSE_SCOPE, profile: SANDBOX, courseIds: ['C1'] });
        const b = await createMigration(db, { scope: COURSE_SCOPE, profile: GPT, courseIds: ['C1'] });
        expect(b.created).toBe(true);
        expect(b.job.migrationId).not.toBe(a.job.migrationId);
    });

    test('findActiveMigration ignores finished jobs', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const { job } = await createMigration(db, { scope: COURSE_SCOPE, profile: SANDBOX, courseIds: ['C1'] });

        expect(await findActiveMigration(db, COURSE_SCOPE)).toMatchObject({ migrationId: job.migrationId });
        await finishMigration(db, job.migrationId, MIGRATION_STATUSES.COMPLETED);
        expect(await findActiveMigration(db, COURSE_SCOPE)).toBeNull();
    });
});

describe('leases and restart resumability', () => {
    async function queuedJob(db) {
        const { job } = await createMigration(db, {
            scope: COURSE_SCOPE, toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });
        return job;
    }

    test('claiming a queued job marks it running and records the owner', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const job = await queuedJob(db);

        const claimed = await claimMigration(db, job.migrationId, 'worker-1');
        expect(claimed).toMatchObject({ status: MIGRATION_STATUSES.RUNNING, leaseOwner: 'worker-1' });
    });

    test('a live lease blocks a second worker', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const job = await queuedJob(db);

        await claimMigration(db, job.migrationId, 'worker-1');
        await heartbeat(db, job.migrationId, { itemId: 'd1' });

        expect(await claimMigration(db, job.migrationId, 'worker-2')).toBeFalsy();
    });

    test('a job whose worker died is reclaimed after the lease times out — a restart resumes it', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const job = await queuedJob(db);
        await claimMigration(db, job.migrationId, 'worker-1');

        // Simulate the server dying mid-migration: the heartbeat goes stale.
        await db.collection(MIGRATIONS_COLLECTION).updateOne(
            { migrationId: job.migrationId },
            { $set: { heartbeatAt: new Date(Date.now() - LEASE_TIMEOUT_MS - 1000) } }
        );

        const reclaimed = await claimMigration(db, job.migrationId, 'worker-2');
        expect(reclaimed).toMatchObject({ status: MIGRATION_STATUSES.RUNNING, leaseOwner: 'worker-2' });
    });

    test('heartbeat records the item currently being processed', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const job = await queuedJob(db);
        await heartbeat(db, job.migrationId, { itemType: 'document', itemId: 'd1', title: 'Lecture 1' });

        const stored = await getMigration(db, job.migrationId);
        expect(stored.currentItem).toMatchObject({ itemId: 'd1', title: 'Lecture 1' });
    });

    test('a late heartbeat cannot overwrite a lease owned by another worker', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }] });
        const job = await queuedJob(db);
        await claimMigration(db, job.migrationId, 'worker-1');

        await heartbeat(db, job.migrationId, { itemId: 'wrong' }, 'worker-2');
        expect((await getMigration(db, job.migrationId)).currentItem).toBeNull();

        await heartbeat(db, job.migrationId, { itemId: 'right' }, 'worker-1');
        expect((await getMigration(db, job.migrationId)).currentItem).toMatchObject({ itemId: 'right' });
    });
});

describe('progress and retry', () => {
    async function jobWithItems(db) {
        const { job } = await createMigration(db, {
            scope: COURSE_SCOPE, toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });
        return job;
    }

    test('recordItemResult keeps totals honest', async () => {
        const db = memoryDb({
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'one' },
                { documentId: 'd2', courseId: 'C1', content: 'two' },
            ],
        });
        const job = await jobWithItems(db);

        await recordItemResult(db, job.migrationId, 'd1', 'document', { status: ITEM_STATUSES.DONE });
        await recordItemResult(db, job.migrationId, 'd2', 'document', { status: ITEM_STATUSES.FAILED, error: 'boom' });

        const stored = await getMigration(db, job.migrationId);
        expect(stored.totals).toMatchObject({ total: 2, completed: 1, failed: 1 });
    });

    test('retry re-queues only the failed items and leaves completed work alone', async () => {
        const db = memoryDb({
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'one' },
                { documentId: 'd2', courseId: 'C1', content: 'two' },
            ],
        });
        const job = await jobWithItems(db);
        await recordItemResult(db, job.migrationId, 'd1', 'document', { status: ITEM_STATUSES.DONE });
        await recordItemResult(db, job.migrationId, 'd2', 'document', { status: ITEM_STATUSES.FAILED, attempts: 3, error: 'boom' });
        await finishMigration(db, job.migrationId, MIGRATION_STATUSES.FAILED, new Error('1 item failed'));

        const requeued = await retryMigration(db, job.migrationId);

        expect(requeued.status).toBe(MIGRATION_STATUSES.QUEUED);
        expect(requeued.error).toBeNull();
        expect(requeued.totals).toMatchObject({ completed: 1, failed: 0 });
        const byId = Object.fromEntries(requeued.items.map(item => [item.itemId, item]));
        expect(byId.d1.status).toBe(ITEM_STATUSES.DONE);
        expect(byId.d2).toMatchObject({ status: ITEM_STATUSES.PENDING, attempts: 0, error: null });
    });

    test('retrying a missing migration returns null', async () => {
        expect(await retryMigration(memoryDb({}), 'nope')).toBeNull();
        expect(await getMigration(memoryDb({}), null)).toBeNull();
    });

    test('cancelling freezes progress and clears the worker lease', async () => {
        const db = memoryDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'one' }] });
        const job = await jobWithItems(db);
        await claimMigration(db, job.migrationId, 'worker-1');

        const cancelled = await cancelMigration(db, job.migrationId, 'i1');
        expect(cancelled).toMatchObject({
            status: MIGRATION_STATUSES.CANCELLED,
            cancelledBy: 'i1',
            leaseOwner: null,
            currentItem: null,
        });

        await recordItemResult(db, job.migrationId, 'd1', 'document', { status: ITEM_STATUSES.DONE });
        await finishMigration(db, job.migrationId, MIGRATION_STATUSES.COMPLETED);
        expect((await getMigration(db, job.migrationId)).status).toBe(MIGRATION_STATUSES.CANCELLED);
    });

    test('publicMigrationView reports totals, failures and never key material', async () => {
        const db = memoryDb({
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'one', filename: 'One.pdf' },
                { documentId: 'd2', courseId: 'C1', content: 'two', filename: 'Two.pdf' },
            ],
        });
        const job = await jobWithItems(db);
        await recordItemResult(db, job.migrationId, 'd1', 'document', { status: ITEM_STATUSES.DONE });
        await recordItemResult(db, job.migrationId, 'd2', 'document', { status: ITEM_STATUSES.FAILED, attempts: 3, error: 'quota' });

        const view = publicMigrationView(await getMigration(db, job.migrationId));

        expect(view).toMatchObject({ total: 2, completed: 1, failed: 1, toProvider: 'ubc-llm-sandbox' });
        expect(view.failures).toEqual([
            {
                itemType: 'document', itemId: 'd2', title: 'Two.pdf',
                error: 'quota', attempts: 3, failureReason: 'rate_limited',
            },
        ]);
        // A person reads the summary; the raw 'quota' string stays for the console.
        expect(view.failureSummary).toMatchObject({
            reason: 'rate_limited',
            headline: expect.stringContaining('refusing further requests'),
            affected: [{ title: 'Two.pdf', cause: null }],
        });
        expect(view.failureSummary.headline).not.toContain('quota');
        expect(view.targetProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
        expect(JSON.stringify(view)).not.toContain('ciphertext');
        expect(publicMigrationView(null)).toBeNull();
    });
});

describe('activation and rollback', () => {
    test('activateProvider promotes the stored credential atomically', async () => {
        const sandboxKey = buildKeySubdocument('sbx-key-1234', 'admin', 'ubc-llm-sandbox');
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: 'openai',
                pendingLlmProvider: 'ubc-llm-sandbox',
                providerMigrationId: 'mig_1',
                llmCredentials: {
                    openai: buildKeySubdocument('sk-key-9999', 'admin', 'openai'),
                    'ubc-llm-sandbox': sandboxKey,
                },
            }],
        });

        expect(await activateProvider(db, COURSE_SCOPE, 'ubc-llm-sandbox')).toBe(true);

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe('ubc-llm-sandbox');
        expect(course.pendingLlmProvider).toBeNull();
        expect(course.providerMigrationId).toBeNull();
        // The previous platform's credential is preserved for switching back.
        expect(course.llmCredentials.openai.ciphertext).toBeTruthy();
    });

    test('activation refuses when the target credential is missing', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', activeLlmProvider: 'openai' }] });
        await expect(activateProvider(db, COURSE_SCOPE, 'ubc-llm-sandbox'))
            .rejects.toThrow(/no stored credential/i);
    });

    test('abandoning a migration keeps the previous provider active', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: 'openai',
                pendingLlmProvider: 'ubc-llm-sandbox',
                providerMigrationId: 'mig_1',
                llmCredentials: { openai: { ciphertext: 'c', status: 'valid' } },
            }],
        });

        await abandonPendingProvider(db, COURSE_SCOPE);

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe('openai');
        expect(course.pendingLlmProvider).toBeNull();
        expect(course.providerMigrationId).toBeNull();
    });

    test('an unknown scope type is a no-op rather than a crash', async () => {
        const db = memoryDb({ courses: [] });
        expect(scopeTarget({ type: 'mystery' })).toBeNull();
        expect(await activateProvider(db, { type: 'mystery', id: 'x' }, 'openai')).toBe(false);
        await expect(abandonPendingProvider(db, { type: 'mystery', id: 'x' })).resolves.toBeUndefined();
    });

    test('every keyed surface maps to its storage location', () => {
        expect(scopeTarget({ type: 'course', id: 'C1' })).toEqual({ collection: 'courses', filter: { courseId: 'C1' } });
        expect(scopeTarget({ type: 'superchat', id: 'S1' })).toEqual({ collection: 'superchats', filter: { superchatId: 'S1' } });
        expect(scopeTarget({ type: 'notes' })).toEqual({ collection: 'settings', filter: { _id: 'notesLlm' } });
        expect(scopeTarget({ type: 'superCourseChat' })).toEqual({ collection: 'settings', filter: { _id: 'superCourseChat' } });
        expect(scopeKey({ type: 'notes' })).toBe('notes:global');
    });
});
