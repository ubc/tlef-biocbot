// @ts-check
/**
 * Coverage spec for src/services/qdrantService.js.
 *
 * The service module is normally exercised tangentially by chat / document /
 * quiz routes. The existing rag-documents-coverage-branches spec already
 * drives the "happy" round-trip (process-document → search → delete) plus the
 * empty / too-short input branches. This spec targets the remaining
 * uncovered service methods and branches:
 *
 *   - cloneDocumentChunks(): full success path with real source-document
 *     chunks (the routes-courses-api-branches transfer test only exercises
 *     the "no stored chunks" early-return).
 *   - deleteCollection(): success branch AND the "collection does not exist"
 *     branch (achieved by deleting twice).
 *   - getCollectionStats(): the catch branch, reached by deleting the
 *     collection out from under the route.
 *   - ensureCollectionExists(): the create-new-collection branch
 *     (lines 210-220), reached after the collection has been removed.
 *   - processAndStoreDocument(): the "suspicious repeated characters"
 *     sanitization branch (lines 297-301).
 *
 * Everything runs through the public HTTP API. No source-level mocks. Tests
 * that delete the shared Qdrant collection ALWAYS re-create it before
 * yielding so subsequent specs don't see a missing collection.
 *
 * Branches that are genuinely unreachable from outside the process (the
 * initialize() vector-size selection, the embeddings-shape-recovery arms in
 * searchDocuments, the in-process getStatus() / testLLMConnection()
 * helpers, and the "vector dimension mismatch" recreate path) are
 * documented in FINDINGS.md as deliberately skipped.
 */

const { test, expect } = require('./fixtures/monocart');
const { storageStatePath, TEST_USERS } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
    seedDocumentAndAttach,
} = require('./helpers/courses-test');

const SVC_COURSE_A = 'BIOC-E2E-QDRSVC-A';
const SVC_COURSE_TRANSFER_SRC = 'BIOC-E2E-QDRSVC-XFER-SRC';

let instructorId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
});

test.afterAll(async () => {
    await cleanupCourses([
        SVC_COURSE_A,
        SVC_COURSE_TRANSFER_SRC,
    ]);
    await cleanupCoursesForUser(instructorId);
    await withDb((db) =>
        db.collection('documents').deleteMany({ documentId: /^doc_e2e_qdrsvc_/ })
    );
});

async function serviceReady(api, url) {
    try {
        const res = await api.get(url, { timeout: 20_000 });
        return res.ok();
    } catch {
        return false;
    }
}

async function ensureQdrantUp(api) {
    return serviceReady(api, '/api/qdrant/status');
}

/**
 * Restore the shared Qdrant collection after a destructive test. The cheapest
 * way to force the service to (re)create the collection is to push a single
 * tiny document through the ingest endpoint, which calls
 * `ensureCollectionExists()` before storing chunks.
 */
async function reseedCollection(api, courseId) {
    const ingest = await api.post('/api/qdrant/process-document', {
        data: {
            courseId,
            lectureName: 'Unit 1',
            documentId: `doc_e2e_qdrsvc_reseed_${Date.now()}`,
            content: 'Reseed sentinel document used to recreate the shared Qdrant collection between destructive tests.',
            fileName: 'reseed.txt',
            mimeType: 'text/plain',
        },
        timeout: 90_000,
    });
    // We don't strictly assert success here — if the collection was just
    // deleted, the upsert may succeed or 500 depending on Qdrant timing. We
    // care about restoring the collection itself.
    if (ingest.ok()) {
        const body = await ingest.json();
        if (body && body.data && body.data.documentId) {
            await api.delete(`/api/qdrant/document/${body.data.documentId}`).catch(() => {});
        }
    }
}

// ---------------------------------------------------------------------------
// processAndStoreDocument — "suspicious pattern (repeated characters)" branch
// ---------------------------------------------------------------------------
test.describe('qdrantService.processAndStoreDocument — sanitization branches', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('content with a long run of repeated characters is sanitised and still stored', async ({ request: api }) => {
        test.setTimeout(120_000);
        await seedCourse({ courseId: SVC_COURSE_A, instructorId });

        // 60 consecutive 'a' triggers the /(.)\1{10,}/ collapse branch.
        const repeated = 'a'.repeat(60);
        const documentId = `doc_e2e_qdrsvc_repeated_${Date.now()}`;
        const content = [
            `Sentinel REPEAT-PATTERN-${Date.now()}.`,
            `Long run: ${repeated} end of run.`,
            'Catalase splits hydrogen peroxide into water and oxygen.',
        ].join(' ');

        const res = await api.post('/api/qdrant/process-document', {
            data: {
                courseId: SVC_COURSE_A,
                lectureName: 'Unit 1',
                documentId,
                content,
                fileName: `${documentId}.txt`,
                mimeType: 'text/plain',
            },
            timeout: 90_000,
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.chunksStored).toBeGreaterThan(0);

        // Clean up the chunks we just inserted.
        await api.delete(`/api/qdrant/document/${documentId}`).catch(() => {});
    });

    test('content as a non-string (numeric body) triggers the type-validation branch', async ({ request: api }) => {
        await seedCourse({ courseId: SVC_COURSE_A, instructorId });

        // The route validator only rejects falsy `content`. Passing a number
        // gets past it and reaches the service-level
        // `typeof content !== 'string'` check.
        const res = await api.post('/api/qdrant/process-document', {
            data: {
                courseId: SVC_COURSE_A,
                lectureName: 'Unit 1',
                documentId: `doc_e2e_qdrsvc_nonstring_${Date.now()}`,
                content: 1234567,
                fileName: 'numeric.txt',
                mimeType: 'text/plain',
            },
            timeout: 30_000,
        });
        // The validator at the route layer rejects with 400 because !content
        // is false but the JSON body coerces; either 400 or 500 here lights
        // up a meaningful branch — what matters is that we do NOT 200.
        expect([400, 500]).toContain(res.status());
    });
});

// ---------------------------------------------------------------------------
// cloneDocumentChunks — full success path with real seeded chunks.
// The routes-courses-api-branches transfer test seeds a doc with no Qdrant
// chunks, so it only hits the "No stored chunks" early-return (lines 712-718).
// Here we pre-ingest the source content into Qdrant so the clone has real
// vectors to copy, exercising lines 720-744.
// ---------------------------------------------------------------------------
test.describe('qdrantService.cloneDocumentChunks — full clone with real chunks', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('course transfer clones every stored chunk for the source document', async ({ request: api }) => {
        test.setTimeout(180_000);

        const sourceDocId = `doc_e2e_qdrsvc_xfer_${Date.now()}`;
        const sourceSentinel = `XFER-SOURCE-${Date.now()}`;
        const sourceContent = [
            `Transfer source sentinel ${sourceSentinel}.`,
            'Mitochondria are the powerhouses of the cell and host oxidative phosphorylation.',
            'The electron transport chain couples redox reactions to ATP synthase activity.',
            'This long body ensures the chunker produces multiple chunks for the clone.',
            'Add another paragraph so the recursive splitter produces at least one boundary.',
            'And one more sentence to push the chunker past the minimum chunk size.',
        ].join(' ');

        // Seed the source course with the source doc attached to Unit 1.
        await seedCourse({ courseId: SVC_COURSE_TRANSFER_SRC, instructorId });
        await seedDocumentAndAttach({
            documentId: sourceDocId,
            courseId: SVC_COURSE_TRANSFER_SRC,
            lectureName: 'Unit 1',
            instructorId,
            content: sourceContent,
            contentType: 'text',
            mimeType: 'text/plain',
            status: 'parsed',
        });

        // Ingest the source content into Qdrant so cloneDocumentChunks has
        // real chunks to walk.
        const ingest = await api.post('/api/qdrant/process-document', {
            data: {
                courseId: SVC_COURSE_TRANSFER_SRC,
                lectureName: 'Unit 1',
                documentId: sourceDocId,
                content: sourceContent,
                fileName: `${sourceDocId}.txt`,
                mimeType: 'text/plain',
            },
            timeout: 90_000,
        });
        expect(ingest.ok()).toBeTruthy();
        const ingestBody = await ingest.json();
        expect(ingestBody.data.chunksStored).toBeGreaterThan(0);

        try {
            const transfer = await api.post(`/api/courses/${SVC_COURSE_TRANSFER_SRC}/transfer`, {
                data: {
                    newCourseName: `XFER Target ${Date.now()}`,
                    transferSettings: false,
                    transferTAs: false,
                    deactivateSourceCourse: false,
                    units: [
                        {
                            unitName: 'Unit 1',
                            transferDocuments: true,
                            transferLearningObjectives: false,
                            transferAssessmentQuestions: false,
                        },
                        {
                            unitName: 'Unit 2',
                            transferDocuments: false,
                            transferLearningObjectives: false,
                            transferAssessmentQuestions: false,
                        },
                    ],
                },
                timeout: 120_000,
            });
            expect(transfer.ok()).toBeTruthy();
            const transferBody = await transfer.json();
            const targetCourseId = transferBody.data.courseId;
            expect(targetCourseId).toBeTruthy();
            // We expect documentsCopied >= 1 — the clone reached the success
            // branch (lines 720-744) and the target course got the document.
            expect(transferBody.data.summary.documentsCopied).toBeGreaterThan(0);
            // Warnings should NOT include "No stored chunks were found" for
            // this source — we ingested chunks above.
            const warnings = transferBody.data.warnings || [];
            const noChunkWarning = warnings.find((w) =>
                /No stored chunks were found to transfer/.test(w)
            );
            expect(noChunkWarning).toBeUndefined();

            // The target course now has a new documentId; look it up and
            // confirm the cloned vectors are searchable in Qdrant under the
            // *new* documentId. This proves the upsert in
            // cloneDocumentChunks actually wrote points.
            const targetDoc = await withDb((db) =>
                db.collection('documents').findOne({
                    courseId: targetCourseId,
                    lectureName: 'Unit 1',
                })
            );
            expect(targetDoc).toBeTruthy();

            const search = await api.post('/api/qdrant/search', {
                data: {
                    query: sourceSentinel,
                    courseId: targetCourseId,
                    lectureName: 'Unit 1',
                    limit: 5,
                },
                timeout: 60_000,
            });
            expect(search.ok()).toBeTruthy();
            const searchBody = await search.json();
            // The transferred vectors live under the *target* courseId and
            // documentId now. If the clone worked the search should turn up
            // results in the new course.
            expect(Array.isArray(searchBody.data.results)).toBe(true);
            const matched = searchBody.data.results.find(
                (r) => r.documentId === targetDoc.documentId
            );
            expect(matched).toBeTruthy();

            // Clean up Qdrant points the transfer created so we don't leak.
            if (targetDoc && targetDoc.documentId) {
                await api.delete(`/api/qdrant/document/${targetDoc.documentId}`).catch(() => {});
            }
            await withDb((db) =>
                db.collection('courses').deleteOne({ courseId: targetCourseId })
            );
            await withDb((db) =>
                db.collection('documents').deleteMany({ courseId: targetCourseId })
            );
        } finally {
            await api.delete(`/api/qdrant/document/${sourceDocId}`).catch(() => {});
        }
    });
});

// ---------------------------------------------------------------------------
// deleteCollection + getCollectionStats error + ensureCollectionExists create
//
// These are grouped because they all share the destructive "drop the
// collection" act. Tests are ordered so the collection is restored at the
// end, otherwise later specs that hit /api/qdrant/* could see a missing
// collection.
// ---------------------------------------------------------------------------
test.describe('qdrantService — collection lifecycle (destructive, ordered)', () => {
    test.use({ storageState: storageStatePath('instructor') });
    test.describe.configure({ mode: 'serial' });

    // /api/qdrant/status returns 500 when the collection has been removed by
    // an earlier test in this group — that's the whole point of these tests.
    // Probe Qdrant liveness ONCE before any destructive op so individual
    // tests don't false-positive-skip.
    /** @type {boolean | null} */
    let qdrantUpOnce = null;
    async function probeOnce(api) {
        if (qdrantUpOnce !== null) return qdrantUpOnce;
        qdrantUpOnce = await ensureQdrantUp(api);
        return qdrantUpOnce;
    }

    test('DELETE /api/qdrant/collection succeeds, then second delete hits the "does not exist" branch', async ({ request: api }) => {
        test.skip(!(await probeOnce(api)), 'Qdrant not reachable.');
        test.setTimeout(60_000);

        // First delete — collection currently exists from earlier tests.
        const r1 = await api.delete('/api/qdrant/collection', { timeout: 60_000 });
        expect(r1.ok()).toBeTruthy();
        const b1 = await r1.json();
        expect(b1.success).toBe(true);
        // First delete returns deletedCount 'all' on success.
        expect(b1.data.deletedCount === 'all' || b1.data.deletedCount === 0).toBeTruthy();

        // Second delete — collection should now be missing, hitting the
        // "Collection does not exist" early-return (lines 893-898).
        const r2 = await api.delete('/api/qdrant/collection', { timeout: 60_000 });
        expect(r2.ok()).toBeTruthy();
        const b2 = await r2.json();
        expect(b2.success).toBe(true);
        expect(b2.data.deletedCount).toBe(0);
    });

    test('GET /api/qdrant/collection-stats hits the catch branch when the collection has been removed', async ({ request: api }) => {
        test.skip(!(await probeOnce(api)), 'Qdrant not reachable.');
        test.setTimeout(60_000);
        // The previous test left the collection deleted. Calling
        // getCollectionStats now should throw inside the service and surface
        // as a 500 from the route — covers lines 868-871.
        const res = await api.get('/api/qdrant/collection-stats', { timeout: 30_000 });
        expect(res.status()).toBe(500);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(body.message).toMatch(/collection statistics/i);
    });

    test('process-document after collection removal exercises ensureCollectionExists "create new" branch', async ({ request: api }) => {
        test.skip(!(await probeOnce(api)), 'Qdrant not reachable.');
        test.setTimeout(120_000);
        await seedCourse({ courseId: SVC_COURSE_A, instructorId });

        // The collection is still missing from the earlier delete. Ingesting
        // a new document forces ensureCollectionExists to run the "create
        // new collection" arm (lines 210-220) before storeChunks upserts.
        const documentId = `doc_e2e_qdrsvc_recreate_${Date.now()}`;
        const content = [
            `Recreate sentinel ${documentId}.`,
            'Aerobic respiration combines glucose and oxygen to yield CO2, water, and ATP.',
            'Lipid bilayers organise membrane proteins into functional micro-domains.',
        ].join(' ');

        const res = await api.post('/api/qdrant/process-document', {
            data: {
                courseId: SVC_COURSE_A,
                lectureName: 'Unit 1',
                documentId,
                content,
                fileName: `${documentId}.txt`,
                mimeType: 'text/plain',
            },
            timeout: 90_000,
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.chunksStored).toBeGreaterThan(0);

        // The collection should now exist again — /status must succeed.
        const status = await api.get('/api/qdrant/status', { timeout: 30_000 });
        expect(status.ok()).toBeTruthy();

        // Clean up the sentinel chunks.
        await api.delete(`/api/qdrant/document/${documentId}`).catch(() => {});
    });

    test('safety: ensure the shared collection is back in place for downstream specs', async ({ request: api }) => {
        test.skip(!(await probeOnce(api)), 'Qdrant not reachable.');
        await seedCourse({ courseId: SVC_COURSE_A, instructorId });
        await reseedCollection(api, SVC_COURSE_A);
        const res = await api.get('/api/qdrant/status', { timeout: 30_000 });
        expect(res.ok()).toBeTruthy();
    });
});
