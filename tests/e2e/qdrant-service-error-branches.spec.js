// @ts-check
/**
 * Error/edge branch coverage for src/services/qdrantService.js.
 *
 * Existing qdrant-service-coverage.spec.js exercises live HTTP paths:
 * sanitization, clone success, collection delete/missing, stats failure, and
 * create-new collection. This spec covers the service-only defensive branches
 * that need deterministic Qdrant/embedding/chunker boundary behavior.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { spawn } = require('child_process');
const path = require('path');
const net = require('net');
const { once } = require('events');

/** @type {import('child_process').ChildProcess|null} */
let harnessProc = null;
/** @type {import('@playwright/test').APIRequestContext|null} */
let api = null;

function getFreePort() {
    return /** @type {Promise<number>} */ (new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.unref();
        srv.on('error', reject);
        srv.listen(0, () => {
            const addr = /** @type {any} */ (srv.address());
            srv.close(() => resolve(addr.port));
        });
    }));
}

async function runCase(name) {
    if (!api) throw new Error('Qdrant service harness API not ready');
    const res = await api.post(`/__case/${name}`, { failOnStatusCode: false });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.ok).toBe(true);
    return body.result;
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
    const port = await getFreePort();
    const env = {
        ...process.env,
        QDRANT_SERVICE_HARNESS_PORT: String(port),
        NODE_V8_COVERAGE: path.resolve(__dirname, '../../coverage-reports/.v8-server'),
        BIOCBOT_COVERAGE_RUN_ID: process.env.BIOCBOT_COVERAGE_RUN_ID || String(Date.now()),
    };

    harnessProc = spawn(process.execPath, [
        path.resolve(__dirname, 'helpers/qdrant-service-error-harness.js'),
    ], { env, stdio: ['ignore', 'inherit', 'inherit'] });

    api = await request.newContext({ baseURL: `http://127.0.0.1:${port}` });
    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        try {
            const res = await api.get('/__ping', { failOnStatusCode: false });
            if (res.ok()) return;
        } catch {
            // Harness is still binding.
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error('qdrant service harness did not become ready in time');
});

test.afterAll(async () => {
    if (api) {
        await api.dispose().catch(() => {});
        api = null;
    }
    if (harnessProc && harnessProc.pid && !harnessProc.killed) {
        harnessProc.kill('SIGTERM');
        await once(harnessProc, 'exit');
    }
});

test('initialize covers model selection, embedding-test fallbacks, and construction/config failures', async () => {
    const result = await runCase('initialize-branches');

    expect(result.results).toMatchObject({
        ada: { vectorSize: 1536 },
        nomicFallbackEmbedding: { vectorSize: 768 },
        envFallbackUnexpectedTestEmbedding: { vectorSize: '5' },
    });
    expect(result.errors.clientConstructor).toContain('client constructor failure');
    expect(result.errors.getCollections).toContain('getCollections failure');
    expect(result.errors.vectorConfig).toContain('Vector DB configuration error');
    expect(result.errors.llmConfig).toContain('LLM configuration error');
    expect(result.errors.embeddingCreate).toContain('Embeddings initialization error');
    expect(result.errors.embeddingTest).toBeNull();
});

test('ensureCollectionExists recreates an existing collection with the wrong vector size', async () => {
    const result = await runCase('ensure-mismatch');

    expect(result).toEqual({
        deleted: 1,
        created: 1,
        createSize: 3,
    });
});

test('processAndStoreDocument covers service-internal chunking, embedding, and upsert failures', async () => {
    const result = await runCase('process-branches');

    expect(result.noChunker).toMatchObject({ success: false, error: /Chunking service is not initialized/ });
    expect(result.noChunks).toMatchObject({ success: false, error: /No chunks were created/ });
    expect(result.noEmbeddings).toMatchObject({ success: false, error: /No embeddings were generated/ });
    expect(result.embeddingFailure).toMatchObject({ success: false, error: /Failed to generate embedding/ });
    expect(result.upsertMissingCollection).toMatchObject({ success: false, error: /collection not found during upsert/ });
    expect(result.strategyFallback).toMatchObject({ success: true, chunksProcessed: 1, chunksStored: 1 });
});

test('generateEmbeddings covers invalid input, invalid provider shapes, skipped chunks, and size mismatch', async () => {
    const result = await runCase('embedding-branches');

    expect(result.invalidChunks).toContain('Invalid chunks array');
    expect(result.invalidEmbedding).toContain('Invalid embedding returned');
    expect(result.vectorNotArray).toContain('Embedding vector is not an array');
    expect(result.sizeMismatch).toEqual([[0.1, 0.2]]);
});

test('searchDocuments covers empty hits, filter combinations, embedding wrappers, and collection-missing errors', async () => {
    const result = await runCase('search-branches');

    expect(result.empty).toEqual([]);
    expect(result.withCourseAndLecture).toMatchObject([{
        id: 'pt-1',
        score: 0.8,
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
        documentId: 'doc-1',
    }]);

    expect(result.calls.emptyNoFilters.filter).toBeUndefined();
    expect(result.calls.courseAndLecture.filter.must).toHaveLength(2);
    expect(result.calls.lectureOnly.filter.must).toEqual([
        { key: 'lectureName', match: { value: 'Unit 2' } },
    ]);
    expect(result.calls.lectureNamesOnly.filter.must).toEqual([
        { key: 'lectureName', match: { any: ['Unit 1', 'Unit 3'] } },
    ]);
    expect(result.calls.courseAndLectureNames.filter.must).toHaveLength(2);
    expect(result.calls.courseIdPool.filter.must).toEqual([
        { key: 'courseId', match: { any: ['BIOC-202', 'BIOC-302'] } },
    ]);
    expect(result.calls.emptyLectureNames.filter).toBeUndefined();
    expect(result.calls.createBeforeSearch).toBe(1);
    expect(result.calls.searchMissingCollectionError).toContain('collection not found during search');
    expect(result.calls.invalidShape).toContain('Invalid query embedding shape');
});

test('searchDocumentsByCourse fans out one filtered search per course and embeds once', async () => {
    const result = await runCase('by-course-branches');

    // Empty course list short-circuits with no work done.
    expect(result.noCourses).toEqual({ size: 0, embedCalls: 0, searchCalls: 0 });

    // One search per course, each scoped to a single courseId (value, not any-of),
    // and the query embedded exactly once for the whole fan-out.
    expect(result.multi.keys).toEqual(['BIOC-202', 'BIOC-302']);
    expect(result.multi.resultLengths).toEqual([1, 1]);
    expect(result.multi.embedCalls).toBe(1);
    expect(result.multi.searchCalls).toBe(2);
    expect(result.multi.filterCourseIds).toEqual(['BIOC-202', 'BIOC-302']);
    expect(result.multi.perCourseLimit).toBe(6);
});

test('scroll, clone, delete, status, and LLM helper branches are covered directly', async () => {
    const result = await runCase('scroll-clone-delete-branches');

    expect(result.chunks).toEqual(['first', 'second']);
    expect(result.cloneMissing).toMatchObject({ success: false, error: /Missing required chunk clone parameters/ });
    expect(result.cloneEmpty).toMatchObject({ success: true, clonedCount: 0 });
    expect(result.cloneFallbackPayload).toMatchObject({ success: true, clonedCount: 1 });
    expect(result.clonedPayload).toMatchObject({
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
        documentId: 'target',
        documentType: 'unknown',
        type: 'unknown',
    });
    expect(result.deleteEmpty).toMatchObject({ success: true, deletedCount: 0 });
    expect(result.deleteWithCourse).toMatchObject({ success: true, deletedCount: 3 });
    expect(result.deleteFilter.must).toEqual([
        { key: 'documentId', match: { value: 'doc-1' } },
        { key: 'courseId', match: { value: 'BIOC-H' } },
    ]);
    expect(result.deleteFailure).toMatchObject({ success: false, error: /delete failure/ });
    expect(result.statusWithChunker).toMatchObject({ isInitialized: true, strategy: 'recursiveCharacter' });
    expect(result.statusWithoutChunker).toEqual({ isInitialized: false, strategy: null });
    expect(result.llmTrue).toBe(true);
    expect(result.llmFalse).toBe(false);
});
