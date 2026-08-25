/**
 * Migration API: progress polling, access control, and retry.
 */
const startedMigrations = [];
jest.mock('../../../src/services/providerMigrationRunner', () => ({
    startMigration: jest.fn((db, migrationId) => { startedMigrations.push(migrationId); }),
    cancelAndCleanup: jest.fn(async (db, migrationId, cancelledBy) => {
        const migrations = jest.requireActual('../../../src/services/providerMigrationService');
        const job = await migrations.cancelMigration(db, migrationId, cancelledBy);
        await migrations.abandonPendingProvider(db, job.scope);
        return { job, cleanup: { deletedVectors: 2, clearedIndexRecords: 2 } };
    }),
}));

const { buildEmbeddingProfile } = require('../../../src/services/embeddingConfig');
const migrations = require('../../../src/services/providerMigrationService');
const router = require('../../../src/routes/providerMigrations');
const { makeRouteApp, request } = require('../helpers/route-app');
const { memoryDb } = require('../helpers/memory-db');

const SANDBOX_PROFILE = buildEmbeddingProfile({
    provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b', apiKey: 'sbx-secret',
});

const admin = { userId: 'a1', role: 'instructor', email: 'admin@x.com', permissions: { systemAdmin: true } };
const instructor = { userId: 'i1', role: 'instructor' };
const otherInstructor = { userId: 'i2', role: 'instructor' };
const student = { userId: 's1', role: 'student' };

const app = (opts) => makeRouteApp(router, opts);

beforeAll(() => jest.spyOn(console, 'error').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());
beforeEach(() => { startedMigrations.length = 0; });

async function seed({ courseId = 'C1', instructorId = 'i1' } = {}) {
    const db = memoryDb({
        courses: [{ courseId, instructorId, instructors: [instructorId] }],
        documents: [
            { documentId: 'd1', courseId, content: 'one', filename: 'One.pdf' },
            { documentId: 'd2', courseId, content: 'two', filename: 'Two.pdf' },
        ],
    });
    const { job } = await migrations.createMigration(db, {
        scope: { type: 'course', id: courseId },
        kind: 'provider',
        fromProvider: 'openai',
        toProvider: 'ubc-llm-sandbox',
        profile: SANDBOX_PROFILE,
        courseIds: [courseId],
    });
    return { db, job };
}

/** A Super Course bucket migration, started by an instructor rather than an admin. */
async function seedBucket() {
    const db = memoryDb({
        superchats: [{ superchatId: 'S1', name: 'Bucket', courseIds: ['C1'] }],
        courses: [{ courseId: 'C1', instructorId: 'i9', instructors: ['i9'] }],
        documents: [{ documentId: 'd1', courseId: 'C1', content: 'one', filename: 'One.pdf' }],
    });
    const { job } = await migrations.createMigration(db, {
        scope: { type: 'superchat', id: 'S1' },
        kind: 'prepare',
        fromProvider: 'openai',
        toProvider: 'ubc-llm-sandbox',
        profile: SANDBOX_PROFILE,
        courseIds: ['C1'],
    });
    return { db, job };
}

describe('GET /:migrationId', () => {
    test('the course instructor sees persistent progress', async () => {
        const { db, job } = await seed();
        await migrations.recordItemResult(db, job.migrationId, 'd1', 'document', { status: 'done' });

        const res = await request(app({ db, user: instructor })).get(`/${job.migrationId}`);

        expect(res.status).toBe(200);
        expect(res.body.migration).toMatchObject({
            migrationId: job.migrationId,
            status: 'queued',
            toProvider: 'ubc-llm-sandbox',
            total: 2,
            completed: 1,
            failed: 0,
        });
        expect(res.body.migration.targetProfile.collection).toBe('biocbot_documents_qwen3_embedding_0_6b');
    });

    test('failures are listed with a reason for the retry control', async () => {
        const { db, job } = await seed();
        await migrations.recordItemResult(db, job.migrationId, 'd2', 'document', {
            status: 'failed', attempts: 3, error: 'provider rejected',
        });

        const res = await request(app({ db, user: instructor })).get(`/${job.migrationId}`);

        expect(res.body.migration.failed).toBe(1);
        expect(res.body.migration.failures).toEqual([
            {
                itemType: 'document', itemId: 'd2', title: 'Two.pdf',
                // The provider's own words stay for the console...
                error: 'provider rejected', attempts: 3,
                // ...and the classification the panel renders prose from.
                failureReason: 'unknown',
            },
        ]);
    });

    test('no key material is ever returned', async () => {
        const { db, job } = await seed();
        const res = await request(app({ db, user: instructor })).get(`/${job.migrationId}`);
        const serialised = JSON.stringify(res.body);
        expect(serialised).not.toContain('sbx-secret');
        expect(serialised).not.toContain('ciphertext');
        expect(serialised).not.toContain('apiKey');
    });

    test('a system admin can see any migration', async () => {
        const { db, job } = await seed();
        expect((await request(app({ db, user: admin })).get(`/${job.migrationId}`)).status).toBe(200);
    });

    test('an unrelated instructor is refused', async () => {
        const { db, job } = await seed();
        expect((await request(app({ db, user: otherInstructor })).get(`/${job.migrationId}`)).status).toBe(403);
    });

    test('a student is refused', async () => {
        const { db, job } = await seed();
        expect((await request(app({ db, user: student })).get(`/${job.migrationId}`)).status).toBe(403);
    });

    test('the Notes and Super Course chat surfaces are admin-only', async () => {
        const db = memoryDb({ superchat_notes: [{ noteId: 'n1', content: 'note' }] });
        const { job } = await migrations.createMigration(db, {
            scope: { type: 'notes', id: 'notesLlm' }, profile: SANDBOX_PROFILE, includeNotes: true,
        });

        expect((await request(app({ db, user: instructor })).get(`/${job.migrationId}`)).status).toBe(403);
        expect((await request(app({ db, user: admin })).get(`/${job.migrationId}`)).status).toBe(200);
    });

    test('any instructor can follow a bucket migration, matching who can start one', async () => {
        const { db, job } = await seedBucket();

        // The bucket's own platform endpoints admit any instructor, so the
        // instructor who started this job must be able to poll it too.
        expect((await request(app({ db, user: instructor })).get(`/${job.migrationId}`)).status).toBe(200);
        expect((await request(app({ db, user: otherInstructor })).get(`/${job.migrationId}`)).status).toBe(200);
        expect((await request(app({ db, user: student })).get(`/${job.migrationId}`)).status).toBe(403);
    });

    test('an unknown migration is a 404, and a missing database is a 503', async () => {
        const { db } = await seed();
        expect((await request(app({ db, user: admin })).get('/nope')).status).toBe(404);
        expect((await request(app({ db: null, user: admin })).get('/anything')).status).toBe(503);
    });

    test('a course that no longer exists denies access rather than crashing', async () => {
        const { db, job } = await seed();
        await db.collection('courses').deleteOne({ courseId: 'C1' });
        expect((await request(app({ db, user: instructor })).get(`/${job.migrationId}`)).status).toBe(403);
    });
});

describe('POST /:migrationId/retry', () => {
    test('retry re-queues failed items and restarts the worker', async () => {
        const { db, job } = await seed();
        await migrations.recordItemResult(db, job.migrationId, 'd1', 'document', { status: 'done' });
        await migrations.recordItemResult(db, job.migrationId, 'd2', 'document', {
            status: 'failed', attempts: 3, error: 'boom',
        });
        await migrations.finishMigration(db, job.migrationId, 'failed', new Error('1 item failed'));

        const res = await request(app({ db, user: instructor })).post(`/${job.migrationId}/retry`);

        expect(res.status).toBe(202);
        expect(res.body.migration).toMatchObject({ status: 'queued', failed: 0, completed: 1 });
        expect(startedMigrations).toEqual([job.migrationId]);

        // The surface is marked as migrating again so the UI keeps polling.
        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.pendingLlmProvider).toBe('ubc-llm-sandbox');
        expect(course.providerMigrationId).toBe(job.migrationId);
    });

    test('an unrelated instructor cannot retry someone else\'s migration', async () => {
        const { db, job } = await seed();
        expect((await request(app({ db, user: otherInstructor })).post(`/${job.migrationId}/retry`)).status).toBe(403);
        expect(startedMigrations).toEqual([]);
    });

    test('retrying an unknown migration is a 404', async () => {
        const { db } = await seed();
        expect((await request(app({ db, user: admin })).post('/nope/retry')).status).toBe(404);
    });
});

describe('POST /:migrationId/cancel', () => {
    test('the course instructor can cancel and receives the cleanup result', async () => {
        const { db, job } = await seed();
        const res = await request(app({ db, user: instructor })).post(`/${job.migrationId}/cancel`);

        expect(res.status).toBe(200);
        expect(res.body.migration.status).toBe('cancelled');
        expect(res.body.cleanup).toMatchObject({ deletedVectors: 2, clearedIndexRecords: 2 });
        expect((await migrations.getMigration(db, job.migrationId)).cancelledBy).toBe('i1');
    });

    test('an unrelated instructor cannot cancel it', async () => {
        const { db, job } = await seed();
        expect((await request(app({ db, user: otherInstructor })).post(`/${job.migrationId}/cancel`)).status)
            .toBe(403);
    });

    test('an instructor can retry and cancel a bucket migration', async () => {
        const { db, job } = await seedBucket();
        await migrations.recordItemResult(db, job.migrationId, 'd1', 'document', {
            status: 'failed', attempts: 3, error: 'boom',
        });

        const retry = await request(app({ db, user: instructor })).post(`/${job.migrationId}/retry`);
        expect(retry.status).toBe(202);
        expect(startedMigrations).toEqual([job.migrationId]);
        const bucket = await db.collection('superchats').findOne({ superchatId: 'S1' });
        expect(bucket.providerMigrationId).toBe(job.migrationId);

        const cancel = await request(app({ db, user: instructor })).post(`/${job.migrationId}/cancel`);
        expect(cancel.status).toBe(200);
        expect(cancel.body.migration.status).toBe('cancelled');
    });
});

describe('GET / (admin listing)', () => {
    test('system admins can list migrations, newest first', async () => {
        const { db } = await seed();
        const res = await request(app({ db, user: admin })).get('/');

        expect(res.status).toBe(200);
        expect(res.body.migrations).toHaveLength(1);
        expect(res.body.migrations[0].toProvider).toBe('ubc-llm-sandbox');
    });

    test('the active filter selects queued and running jobs', async () => {
        const { db, job } = await seed();
        expect((await request(app({ db, user: admin })).get('/?active=true')).body.migrations).toHaveLength(1);

        await migrations.finishMigration(db, job.migrationId, 'completed');
        expect((await request(app({ db, user: admin })).get('/?active=true')).body.migrations).toHaveLength(0);
        expect((await request(app({ db, user: admin })).get('/?status=completed')).body.migrations).toHaveLength(1);
    });

    test('non-admins are refused', async () => {
        const { db } = await seed();
        expect((await request(app({ db, user: instructor })).get('/')).status).toBe(403);
    });
});
