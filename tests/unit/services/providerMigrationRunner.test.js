/**
 * The migration runner end to end, against fake vector services.
 *
 * Covers the scenario the product spec calls out: a course moves GPT -> Sandbox
 * -> GPT, existing indexes are reused, only genuinely new or edited content is
 * re-embedded, uploads landing mid-migration are caught, individual failures are
 * retryable, and the previous platform stays active when a migration fails.
 */
const qdrantInstances = [];
const notesInstances = [];

jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(function FakeQdrant(options) {
    const instance = {
        options,
        profile: options.embeddingProfile,
        stored: [],
        deleted: [],
        failFor: new Set(),
        initialize: jest.fn(async () => {}),
        deleteDocumentChunks: jest.fn(async (documentId, courseId) => {
            instance.deleted.push({ documentId, courseId, collection: options.embeddingProfile.collection });
            return { success: true, deletedCount: 1 };
        }),
        processAndStoreDocument: jest.fn(async (payload) => {
            if (instance.failFor.has(payload.documentId)) {
                throw new Error(`provider rejected ${payload.documentId}`);
            }
            instance.stored.push({ ...payload, collection: options.embeddingProfile.collection });
            return { success: true, chunksStored: 2 };
        }),
    };
    qdrantInstances.push(instance);
    return instance;
}));

jest.mock('../../../src/services/notesQdrantService', () => jest.fn().mockImplementation(function FakeNotes(options) {
    const instance = {
        options,
        profile: options.embeddingProfile,
        stored: [],
        initialize: jest.fn(async () => {}),
        updateNote: jest.fn(async (noteId, content) => {
            instance.stored.push({ noteId, content, collection: options.embeddingProfile.notesCollection });
            return ['p1'];
        }),
    };
    notesInstances.push(instance);
    return instance;
}));

jest.mock('../../../src/services/config', () => ({
    getProviderInfra: jest.fn((provider) => ({
        provider,
        endpoint: provider === 'ubc-llm-sandbox' ? 'https://sandbox.example/v1' : null,
        bootstrapApiKey: undefined,
    })),
    getLLMConfig: jest.fn(() => ({ provider: 'openai' })),
    getVectorDBConfig: jest.fn(() => ({ host: 'localhost', port: 6333 })),
}));

const { buildEmbeddingProfile } = require('../../../src/services/embeddingConfig');
const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');
const {
    INDEX_STATUSES,
    buildIndexRecord,
    contentHash,
    needsIndexing,
} = require('../../../src/services/embeddingIndexService');
const migrations = require('../../../src/services/providerMigrationService');
const runner = require('../../../src/services/providerMigrationRunner');
const scopeModelSettings = require('../../../src/services/scopeModelSettings');
const { memoryDb } = require('../helpers/memory-db');

const GPT = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
const SANDBOX = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });
const COURSE_SCOPE = { type: 'course', id: 'C1' };

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());
beforeEach(() => {
    qdrantInstances.length = 0;
    notesInstances.length = 0;
});

function readyFor(profile, content) {
    return {
        [profile.storageKey]: buildIndexRecord({
            profile, hash: contentHash(content), status: INDEX_STATUSES.READY, indexedAt: new Date(),
        }),
    };
}

/** A course with both platform credentials stored, currently on `active`. */
function dualKeyCourse(active = 'openai', extra = {}) {
    return {
        courseId: 'C1',
        activeLlmProvider: active,
        llmCredentials: {
            openai: buildKeySubdocument('sk-gpt-key', 'admin', 'openai'),
            'ubc-llm-sandbox': buildKeySubdocument('sbx-key', 'admin', 'ubc-llm-sandbox'),
        },
        ...extra,
    };
}

async function runProviderMigration(db, { profile, toProvider, courseIds = ['C1'], includeNotes = false }) {
    const { job } = await migrations.createMigration(db, {
        scope: COURSE_SCOPE,
        kind: 'provider',
        fromProvider: toProvider === 'openai' ? 'ubc-llm-sandbox' : 'openai',
        toProvider,
        profile,
        courseIds,
        includeNotes,
    });
    await db.collection('courses').updateOne(
        { courseId: 'C1' },
        { $set: { pendingLlmProvider: toProvider, providerMigrationId: job.migrationId } }
    );
    return runner.runMigration(db, job.migrationId);
}

describe('the switching scenario from the product spec', () => {
    test('GPT -> Sandbox -> GPT reuses existing indexes and only embeds what is new or edited', async () => {
        // 1-2. Course on GPT; document A already embedded with text-embedding-3-small.
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{
                documentId: 'A', courseId: 'C1', lectureName: 'Unit 1', filename: 'A.pdf',
                content: 'document A text', status: 'parsed', embeddingIndexes: readyFor(GPT, 'document A text'),
            }],
        });

        // 3-4. Switch to Sandbox: A gains a Qwen index, its OpenAI index remains.
        let finished = await runProviderMigration(db, { profile: SANDBOX, toProvider: 'ubc-llm-sandbox' });
        expect(finished.status).toBe('completed');

        let docA = await db.collection('documents').findOne({ documentId: 'A' });
        expect(docA.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
        expect(docA.embeddingIndexes[GPT.storageKey].status).toBe('ready');
        expect(qdrantInstances[0].stored.map(entry => entry.collection))
            .toEqual(['biocbot_documents_qwen3_embedding_0_6b']);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider)
            .toBe('ubc-llm-sandbox');

        // 5. Document B is uploaded while Sandbox is active, with a Qwen index only.
        await db.collection('documents').insertOne({
            documentId: 'B', courseId: 'C1', lectureName: 'Unit 1', filename: 'B.pdf',
            content: 'document B text', status: 'parsed',
            embeddingIndexes: readyFor(SANDBOX, 'document B text'),
        });

        // 6. Switch back to GPT.
        qdrantInstances.length = 0;
        finished = await runProviderMigration(db, { profile: GPT, toProvider: 'openai' });
        expect(finished.status).toBe('completed');

        // 7-8. A's OpenAI index is reused; only B is embedded for OpenAI.
        expect(qdrantInstances[0].stored.map(entry => entry.documentId)).toEqual(['B']);
        expect(finished.totals.total).toBe(1);

        docA = await db.collection('documents').findOne({ documentId: 'A' });
        const docB = await db.collection('documents').findOne({ documentId: 'B' });
        expect(docA.embeddingIndexes[GPT.storageKey].status).toBe('ready');
        expect(docB.embeddingIndexes[GPT.storageKey].status).toBe('ready');
        // Sandbox vectors are preserved on both documents.
        expect(docA.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
        expect(docB.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
    });

    test('9. a document edited during the Sandbox period is re-embedded for GPT too', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('ubc-llm-sandbox')],
            documents: [
                // A was indexed for GPT against the OLD text, then edited.
                {
                    documentId: 'A', courseId: 'C1', filename: 'A.pdf', content: 'edited during sandbox',
                    embeddingIndexes: {
                        ...readyFor(GPT, 'original text'),
                        ...readyFor(SANDBOX, 'edited during sandbox'),
                    },
                },
                // C was never touched, so its GPT index is still current.
                {
                    documentId: 'C', courseId: 'C1', filename: 'C.pdf', content: 'untouched',
                    embeddingIndexes: { ...readyFor(GPT, 'untouched'), ...readyFor(SANDBOX, 'untouched') },
                },
            ],
        });

        const finished = await runProviderMigration(db, { profile: GPT, toProvider: 'openai' });

        expect(finished.status).toBe('completed');
        expect(qdrantInstances[0].stored.map(entry => entry.documentId)).toEqual(['A']);
        const docA = await db.collection('documents').findOne({ documentId: 'A' });
        expect(docA.embeddingIndexes[GPT.storageKey].contentHash).toBe(contentHash('edited during sandbox'));
    });

    test('an already-current course needs no work at all', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{
                documentId: 'A', courseId: 'C1', content: 'text',
                embeddingIndexes: { ...readyFor(GPT, 'text'), ...readyFor(SANDBOX, 'text') },
            }],
        });

        const finished = await runProviderMigration(db, { profile: SANDBOX, toProvider: 'ubc-llm-sandbox' });

        expect(finished.totals.total).toBe(0);
        expect(finished.status).toBe('completed');
        // Nothing to embed means no provider connection is opened at all.
        expect(qdrantInstances).toHaveLength(0);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider)
            .toBe('ubc-llm-sandbox');
    });
});

describe('re-indexing is idempotent and non-destructive', () => {
    test('existing chunks in the TARGET collection are cleared first, other collections untouched', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'text' }],
        });

        await runProviderMigration(db, { profile: SANDBOX, toProvider: 'ubc-llm-sandbox' });

        expect(qdrantInstances[0].deleted).toEqual([
            { documentId: 'A', courseId: 'C1', collection: 'biocbot_documents_qwen3_embedding_0_6b' },
        ]);
        // Only one vector service was built — the OpenAI collection is never opened.
        expect(qdrantInstances).toHaveLength(1);
    });

    test('a deleted or empty document is skipped, not failed', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [
                { documentId: 'A', courseId: 'C1', content: 'text' },
                { documentId: 'B', courseId: 'C1', content: 'text' },
            ],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });
        // A disappears between planning and execution.
        await db.collection('documents').updateOne({ documentId: 'A' }, { $set: { isDeleted: true } });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('completed');
        expect(finished.totals.failed).toBe(0);
        const items = Object.fromEntries(finished.items.map(item => [item.itemId, item]));
        expect(items.A).toMatchObject({ status: 'skipped', skipReason: 'deleted' });
        expect(items.B.status).toBe('done');
    });
});

describe('content that changes while a migration runs', () => {
    test('a document uploaded mid-migration is caught by the consistency pass', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'first' }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });
        expect(job.totals.total).toBe(1);

        // Simulate an upload landing while pass 1 is processing document A.
        const claimed = await migrations.claimMigration(db, job.migrationId, 'test');
        expect(claimed).toBeTruthy();
        await db.collection(migrations.MIGRATIONS_COLLECTION).updateOne(
            { migrationId: job.migrationId },
            { $set: { status: 'queued', leaseOwner: null, heartbeatAt: null } }
        );
        await db.collection('documents').insertOne({
            documentId: 'LATE', courseId: 'C1', content: 'uploaded during migration',
        });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('completed');
        expect(finished.items.map(item => item.itemId).sort()).toEqual(['A', 'LATE']);
        const late = await db.collection('documents').findOne({ documentId: 'LATE' });
        expect(late.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
    });

    test('a document edited mid-migration is re-queued with its new hash', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'before' }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });

        // The stored content changes after the queue was planned.
        await db.collection('documents').updateOne({ documentId: 'A' }, { $set: { content: 'after' } });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('completed');
        const docA = await db.collection('documents').findOne({ documentId: 'A' });
        expect(docA.embeddingIndexes[SANDBOX.storageKey].contentHash).toBe(contentHash('after'));
        expect(needsIndexing(docA, SANDBOX, contentHash('after'))).toBe(false);
    });
});

describe('failure handling', () => {
    test('an item that keeps failing exhausts its attempts, fails the job, and rolls back', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [
                { documentId: 'GOOD', courseId: 'C1', content: 'fine' },
                { documentId: 'BAD', courseId: 'C1', content: 'breaks' },
            ],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', fromProvider: 'openai', toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX, courseIds: ['C1'],
        });
        await db.collection('courses').updateOne(
            { courseId: 'C1' },
            { $set: { pendingLlmProvider: 'ubc-llm-sandbox', providerMigrationId: job.migrationId } }
        );

        // Arm the failure as soon as the runner builds its vector service.
        const QdrantService = require('../../../src/services/qdrantService');
        QdrantService.mockImplementationOnce(function FailingQdrant(options) {
            const instance = {
                options,
                stored: [],
                initialize: jest.fn(async () => {}),
                deleteDocumentChunks: jest.fn(async () => ({ success: true, deletedCount: 0 })),
                processAndStoreDocument: jest.fn(async (payload) => {
                    if (payload.documentId === 'BAD') throw new Error('provider rejected BAD');
                    instance.stored.push(payload);
                    return { success: true };
                }),
            };
            qdrantInstances.push(instance);
            return instance;
        });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('failed');
        expect(finished.totals.failed).toBe(1);
        const bad = finished.items.find(item => item.itemId === 'BAD');
        expect(bad.attempts).toBe(migrations.MAX_ATTEMPTS);
        expect(bad.error).toMatch(/provider rejected BAD/);

        // The previous platform stays active and its vectors/credential remain.
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe('openai');
        expect(course.pendingLlmProvider).toBeNull();
        expect(course.llmCredentials['ubc-llm-sandbox'].ciphertext).toBeTruthy();
        // The surface keeps pointing at the failed job, so a reload still finds
        // the failure and its retry control.
        expect(course.providerMigrationId).toBe(job.migrationId);

        // The failure is recorded against the document for that profile only.
        const badDoc = await db.collection('documents').findOne({ documentId: 'BAD' });
        expect(badDoc.embeddingIndexes[SANDBOX.storageKey].status).toBe('failed');

        // Retrying re-queues only BAD, and succeeds once the provider recovers.
        await migrations.retryMigration(db, job.migrationId);
        const retried = await runner.runMigration(db, job.migrationId);

        expect(retried.status).toBe('completed');
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider)
            .toBe('ubc-llm-sandbox');
        const lastService = qdrantInstances[qdrantInstances.length - 1];
        expect(lastService.stored.map(entry => entry.documentId)).toEqual(['BAD']);
    });

    test('a surface with no credential for the target platform fails cleanly', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: 'openai',
                llmCredentials: { openai: buildKeySubdocument('sk-key', 'a', 'openai') },
            }],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'text' }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('failed');
        expect(finished.error).toMatch(/no stored ubc-llm-sandbox credential/i);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider).toBe('openai');
    });
});

describe('notes and mixed-provider surfaces', () => {
    test('a Sandbox notes migration writes into the Qwen notes collection', async () => {
        const db = memoryDb({
            settings: [{
                _id: 'notesLlm',
                activeLlmProvider: 'openai',
                llmCredentials: {
                    openai: buildKeySubdocument('sk-notes', 'a', 'openai'),
                    'ubc-llm-sandbox': buildKeySubdocument('sbx-notes', 'a', 'ubc-llm-sandbox'),
                },
            }],
            superchat_notes: [{ noteId: 'n1', content: 'a shared note', title: 'Shared' }],
        });
        const scope = { type: 'notes', id: 'notesLlm' };
        const { job } = await migrations.createMigration(db, {
            scope, kind: 'provider', fromProvider: 'openai', toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX, includeNotes: true,
        });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('completed');
        expect(notesInstances[0].stored).toEqual([
            { noteId: 'n1', content: 'a shared note', collection: 'superchat_notes_qwen3_embedding_0_6b' },
        ]);
        const note = await db.collection('superchat_notes').findOne({ noteId: 'n1' });
        expect(note.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
        expect((await db.collection('settings').findOne({ _id: 'notesLlm' })).activeLlmProvider)
            .toBe('ubc-llm-sandbox');
    });

    test('a Sandbox bucket indexes member courses that themselves run on GPT', async () => {
        const db = memoryDb({
            superchats: [{
                superchatId: 'S1',
                courseIds: ['C1', 'C2'],
                activeLlmProvider: 'openai',
                llmCredentials: {
                    openai: buildKeySubdocument('sk-bucket', 'a', 'openai'),
                    'ubc-llm-sandbox': buildKeySubdocument('sbx-bucket', 'a', 'ubc-llm-sandbox'),
                },
            }],
            // Both member courses run on GPT and are already indexed for it.
            courses: [
                { courseId: 'C1', activeLlmProvider: 'openai' },
                { courseId: 'C2', activeLlmProvider: 'openai' },
            ],
            documents: [
                { documentId: 'd1', courseId: 'C1', content: 'c1 text', embeddingIndexes: readyFor(GPT, 'c1 text') },
                { documentId: 'd2', courseId: 'C2', content: 'c2 text', embeddingIndexes: readyFor(GPT, 'c2 text') },
            ],
        });
        const scope = { type: 'superchat', id: 'S1' };
        const { job } = await migrations.createMigration(db, {
            scope, kind: 'provider', fromProvider: 'openai', toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX, courseIds: ['C1', 'C2'],
        });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('completed');
        // Every member course gained a Qwen index, embedded with the BUCKET's key.
        for (const documentId of ['d1', 'd2']) {
            const doc = await db.collection('documents').findOne({ documentId });
            expect(doc.embeddingIndexes[SANDBOX.storageKey].collection)
                .toBe('biocbot_documents_qwen3_embedding_0_6b');
            expect(doc.embeddingIndexes[GPT.storageKey].status).toBe('ready');
        }
        // The member courses' own platform is untouched.
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider).toBe('openai');
    });
});

describe('admin embedding-model changes', () => {
    const ADMIN_SCOPE = { type: 'adminEmbedding', id: 'ubc-llm-sandbox' };

    /** A bucket on Sandbox whose member courses run on GPT. */
    function sandboxBucketOverGptCourses(extra = {}) {
        return {
            superchats: [{
                superchatId: 'S1',
                activeLlmProvider: 'ubc-llm-sandbox',
                llmCredentials: {
                    'ubc-llm-sandbox': buildKeySubdocument('sbx-bucket', 'a', 'ubc-llm-sandbox'),
                },
                ...(extra.bucket || {}),
            }],
            courses: [{
                courseId: 'C1',
                // Membership lives on the course, not on the bucket.
                superchatIds: ['S1'],
                activeLlmProvider: 'openai',
                llmCredentials: { openai: buildKeySubdocument('sk-course', 'a', 'openai') },
                ...(extra.course || {}),
            }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'c1 text' }],
        };
    }

    async function runAdminEmbeddingMigration(db, { courseIds = ['C1'], includeNotes = false } = {}) {
        const { job } = await migrations.createMigration(db, {
            scope: ADMIN_SCOPE,
            kind: 'embedding-model',
            fromProvider: 'ubc-llm-sandbox',
            toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX,
            courseIds,
            includeNotes,
        });
        return runner.runMigration(db, job.migrationId);
    }

    test("a GPT course's documents are embedded with the Sandbox bucket that includes them", async () => {
        const db = memoryDb(sandboxBucketOverGptCourses());

        const finished = await runAdminEmbeddingMigration(db);

        expect(finished.status).toBe('completed');
        // The course has no Sandbox key of its own; the bucket that retrieves
        // its material pays for the embeddings.
        expect(qdrantInstances[0].profile.apiKey).toBe('sbx-bucket');
        const doc = await db.collection('documents').findOne({ documentId: 'd1' });
        expect(doc.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
    });

    test("a course running on the target platform pays with its own key", async () => {
        const db = memoryDb(sandboxBucketOverGptCourses({
            course: {
                activeLlmProvider: 'ubc-llm-sandbox',
                llmCredentials: {
                    openai: buildKeySubdocument('sk-course', 'a', 'openai'),
                    'ubc-llm-sandbox': buildKeySubdocument('sbx-course', 'a', 'ubc-llm-sandbox'),
                },
            },
        }));

        const finished = await runAdminEmbeddingMigration(db);

        expect(finished.status).toBe('completed');
        expect(qdrantInstances[0].profile.apiKey).toBe('sbx-course');
    });

    test('notes are embedded with the Notes surface key', async () => {
        const db = memoryDb({
            ...sandboxBucketOverGptCourses(),
            settings: [{
                _id: 'notesLlm',
                activeLlmProvider: 'ubc-llm-sandbox',
                llmCredentials: {
                    'ubc-llm-sandbox': buildKeySubdocument('sbx-notes', 'a', 'ubc-llm-sandbox'),
                },
            }],
            superchat_notes: [{ noteId: 'n1', content: 'a shared note' }],
        });

        const finished = await runAdminEmbeddingMigration(db, { courseIds: [], includeNotes: true });

        expect(finished.status).toBe('completed');
        expect(qdrantInstances[0].profile.apiKey).toBe('sbx-notes');
        expect(notesInstances[0].stored).toEqual([
            { noteId: 'n1', content: 'a shared note', collection: 'superchat_notes_qwen3_embedding_0_6b' },
        ]);
    });

    test('an item no surface can pay for fails naming its own owner', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                activeLlmProvider: 'openai',
                llmCredentials: { openai: buildKeySubdocument('sk-course', 'a', 'openai') },
            }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'c1 text' }],
        });

        const finished = await runAdminEmbeddingMigration(db);

        expect(finished.status).toBe('failed');
        expect(finished.error).toMatch(/no stored ubc-llm-sandbox credential for course:C1/i);
    });
});

describe('restart resumability', () => {
    test('lease retry waits until just after the previous heartbeat expires', () => {
        const now = Date.now();
        const heartbeatAt = new Date(now - 30_000);
        expect(runner.leaseRetryDelay({ heartbeatAt }, now)).toBe(
            migrations.LEASE_TIMEOUT_MS - 30_000 + 250
        );
        expect(runner.leaseRetryDelay({ heartbeatAt: null }, now)).toBe(250);
    });

    test('resumePendingMigrations picks up queued and running jobs', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'text' }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });
        await migrations.finishMigration(db, job.migrationId, migrations.MIGRATION_STATUSES.COMPLETED);

        const { job: pending } = await migrations.createMigration(db, {
            scope: { type: 'course', id: 'C2' }, kind: 'provider', toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX, courseIds: ['C2'],
        });

        const resumed = await runner.resumePendingMigrations(db);

        expect(resumed).toEqual([pending.migrationId]);
        expect(await runner.resumePendingMigrations(null)).toEqual([]);
    });

    test('a job already held by a live worker is left alone', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai')],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'text' }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE, kind: 'provider', toProvider: 'ubc-llm-sandbox', profile: SANDBOX, courseIds: ['C1'],
        });
        await migrations.claimMigration(db, job.migrationId, 'other-worker');
        await migrations.heartbeat(db, job.migrationId, null);

        const result = await runner.runMigration(db, job.migrationId);

        expect(result.leaseOwner).toBe('other-worker');
        expect(qdrantInstances).toHaveLength(0);
    });
});

describe('explicit preparation and cancellation', () => {
    test('preparation keeps the old provider active while running, then activates the target', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai', { pendingLlmProvider: 'ubc-llm-sandbox' })],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'text' }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE,
            kind: 'prepare',
            fromProvider: 'openai',
            toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX,
            courseIds: ['C1'],
        });
        await db.collection('courses').updateOne(
            { courseId: 'C1' },
            { $set: { providerMigrationId: job.migrationId } }
        );

        const finished = await runner.runMigration(db, job.migrationId);
        expect(finished.status).toBe('completed');
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe('ubc-llm-sandbox');
        expect(course.pendingLlmProvider).toBeNull();
        expect(course.providerMigrationId).toBeNull();
    });

    test('preparation also promotes the embedding choice it indexed', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai', { pendingLlmProvider: 'ubc-llm-sandbox' })],
            documents: [{ documentId: 'A', courseId: 'C1', content: 'text' }],
        });
        await scopeModelSettings.materialize(db, COURSE_SCOPE);
        // The model settings panel only records the choice; this job is what
        // indexes it, so this job is what promotes it.
        await scopeModelSettings.stagePendingEmbedding(db, COURSE_SCOPE, 'ubc-llm-sandbox', {
            embeddingModel: SANDBOX.embeddingModel,
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE,
            kind: 'prepare',
            fromProvider: 'openai',
            toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX,
            courseIds: ['C1'],
        });

        const finished = await runner.runMigration(db, job.migrationId);

        expect(finished.status).toBe('completed');
        const settings = await scopeModelSettings.getAll(db, COURSE_SCOPE);
        expect(settings.providers['ubc-llm-sandbox'].embeddingModel).toBe(SANDBOX.embeddingModel);
        expect(settings.pendingEmbedding['ubc-llm-sandbox']).toBeUndefined();
    });

    test('cancel deletes only the target profile data and clears the pending marker', async () => {
        const db = memoryDb({
            courses: [dualKeyCourse('openai', { pendingLlmProvider: 'ubc-llm-sandbox' })],
            documents: [{
                documentId: 'A', courseId: 'C1', content: 'text',
                embeddingIndexes: {
                    ...readyFor(GPT, 'text'),
                    ...readyFor(SANDBOX, 'text'),
                },
            }],
        });
        const { job } = await migrations.createMigration(db, {
            scope: COURSE_SCOPE,
            kind: 'prepare',
            toProvider: 'ubc-llm-sandbox',
            profile: SANDBOX,
            courseIds: ['C1'],
        });
        // calculateWork skips a ready item, but cleanup operates on job items;
        // simulate the record written by a partially completed preparation.
        await db.collection(migrations.MIGRATIONS_COLLECTION).updateOne(
            { migrationId: job.migrationId },
            { $set: { items: [{ itemType: 'document', itemId: 'A', courseId: 'C1' }] } }
        );
        await db.collection('courses').updateOne(
            { courseId: 'C1' },
            { $set: { providerMigrationId: job.migrationId } }
        );

        const result = await runner.cancelAndCleanup(db, job.migrationId, 'i1');
        expect(result.job.status).toBe('cancelled');
        expect(result.cleanup).toMatchObject({ documents: 1, deletedVectors: 1, clearedIndexRecords: 1 });
        const document = await db.collection('documents').findOne({ documentId: 'A' });
        expect(document.embeddingIndexes[GPT.storageKey].status).toBe('ready');
        expect(document.embeddingIndexes[SANDBOX.storageKey]).toBeUndefined();
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).providerMigrationId).toBeNull();
    });
});
