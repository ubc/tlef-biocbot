// @ts-check
/**
 * Focused coverage for the chat/RAG and document-ingestion surface.
 *
 * These tests intentionally seed real MongoDB data and use the app's HTTP
 * routes. The RAG tests only run when the real Qdrant + LLM services are
 * reachable; the permission-boundary tests avoid external dependencies so
 * they can expose direct API access gaps deterministically.
 */

const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const { withDb, getUserIdByUsername } = require('./helpers/quiz');
const {
    STU_COURSE_ID,
    STU_OTHER_COURSE_ID,
    STU_INACTIVE_COURSE_ID,
    STU_DELETED_COURSE_ID,
    OTHER_STUDENT_ID,
    getStudentId,
    resetStudentChatData,
    cleanupStudentChatData,
} = require('./helpers/student');

const RAG_DOC_ID = 'doc_e2e_chat_rag_catalase';
const RAG_FILE_NAME = 'e2e-catalase-rag-notes.txt';
const RAG_SENTINEL = 'PEROXIDE-SPLIT-42';
const RAG_CONTENT = [
    'E2E Catalase RAG Notes.',
    `The sentinel answer code is ${RAG_SENTINEL}.`,
    'Catalase decomposes hydrogen peroxide into water and oxygen during cellular detoxification.',
    'This seeded note exists only for Playwright chat retrieval tests.'
].join(' ');

const QDRANT_DELETE_DOC_ID = 'doc_e2e_qdrant_delete_guard';
const QDRANT_DELETE_SENTINEL = 'QDRANT-DELETE-GUARD-517';
const COURSE_A_DOC_ID = 'doc_e2e_qdrant_course_a';
const COURSE_B_DOC_ID = 'doc_e2e_qdrant_course_b';
const COURSE_A_SENTINEL = 'QDRANT-COURSE-A-731';
const COURSE_B_SENTINEL = 'QDRANT-COURSE-B-842';
const ADD_UNIT1_DOC_ID = 'doc_e2e_chat_additive_unit1';
const ADD_UNIT2_DOC_ID = 'doc_e2e_chat_additive_unit2';
const ADD_UNIT1_SENTINEL = 'ADDITIVE-UNIT-ONE-317';
const ADD_UNIT2_SENTINEL = 'ADDITIVE-UNIT-TWO-629';

let instructorId;
let studentId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getStudentId();
});

test.afterAll(async () => {
    await cleanupStudentChatData();
    await cleanupSeededRows();
});

async function cleanupSeededRows() {
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({
            $or: [
                { documentId: /^doc_e2e_/ },
                { courseId: { $in: [STU_COURSE_ID, STU_OTHER_COURSE_ID] }, 'metadata.e2e': 'chat-rag-documents' },
                { courseId: STU_COURSE_ID, originalName: /^E2E student forged document/ },
                { courseId: STU_COURSE_ID, filename: /^E2E student forged document/ },
            ],
        });
        await db.collection('mentalHealthFlags').deleteMany({
            courseId: STU_COURSE_ID,
            message: /E2E mental-health sentinel/,
        });
        await db.collection('courses').updateMany(
            { courseId: { $in: [STU_COURSE_ID, STU_OTHER_COURSE_ID] } },
            {
                $pull: {
                    'lectures.$[].documents': {
                        $or: [
                            { documentId: /^doc_e2e_/ },
                            { originalName: /^E2E student forged document/ },
                            { filename: /^E2E student forged document/ },
                        ],
                    },
                },
            }
        );
    });
}

async function seedRagDocument() {
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({ documentId: RAG_DOC_ID });
        await db.collection('documents').insertOne({
            documentId: RAG_DOC_ID,
            courseId: STU_COURSE_ID,
            lectureName: 'Unit 1',
            instructorId,
            documentType: 'lecture-notes',
            type: 'lecture_notes',
            contentType: 'text',
            filename: RAG_FILE_NAME,
            originalName: 'E2E Catalase RAG Notes.txt',
            content: RAG_CONTENT,
            mimeType: 'text/plain',
            size: Buffer.byteLength(RAG_CONTENT, 'utf8'),
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
            metadata: { e2e: 'chat-rag-documents' },
        });
        await db.collection('courses').updateOne(
            { courseId: STU_COURSE_ID, 'lectures.name': 'Unit 1' },
            {
                $set: {
                    'quizSettings.allowSourceAttributionDownloads': true,
                    'lectures.$.isPublished': true,
                },
                $pull: { 'lectures.$.documents': { documentId: RAG_DOC_ID } },
            }
        );
        await db.collection('courses').updateOne(
            { courseId: STU_COURSE_ID, 'lectures.name': 'Unit 1' },
            {
                $push: {
                    'lectures.$.documents': {
                        documentId: RAG_DOC_ID,
                        documentType: 'lecture-notes',
                        filename: RAG_FILE_NAME,
                        originalName: 'E2E Catalase RAG Notes.txt',
                        mimeType: 'text/plain',
                        size: Buffer.byteLength(RAG_CONTENT, 'utf8'),
                        status: 'parsed',
                        metadata: { e2e: 'chat-rag-documents' },
                        createdAt: new Date(),
                        updatedAt: new Date(),
                    },
                },
            }
        );
    });
}

async function seedDocumentForDocumentApi(documentId = 'doc_e2e_doc_api_seed') {
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({ documentId });
        await db.collection('documents').insertOne({
            documentId,
            courseId: STU_COURSE_ID,
            lectureName: 'Unit 1',
            instructorId,
            documentType: 'lecture-notes',
            type: 'lecture_notes',
            contentType: 'text',
            filename: `${documentId}.txt`,
            originalName: `${documentId}.txt`,
            content: 'Seeded document API permission boundary content.',
            mimeType: 'text/plain',
            size: 54,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
            metadata: { e2e: 'chat-rag-documents' },
        });
        await db.collection('courses').updateOne(
            { courseId: STU_COURSE_ID, 'lectures.name': 'Unit 1' },
            { $pull: { 'lectures.$.documents': { documentId } } }
        );
        await db.collection('courses').updateOne(
            { courseId: STU_COURSE_ID, 'lectures.name': 'Unit 1' },
            {
                $push: {
                    'lectures.$.documents': {
                        documentId,
                        documentType: 'lecture-notes',
                        filename: `${documentId}.txt`,
                        originalName: `${documentId}.txt`,
                        mimeType: 'text/plain',
                        size: 54,
                        status: 'parsed',
                        metadata: { e2e: 'chat-rag-documents' },
                        createdAt: new Date(),
                        updatedAt: new Date(),
                    },
                },
            }
        );
    });
}

async function seedDocumentRecord({
    documentId,
    courseId = STU_COURSE_ID,
    lectureName = 'Unit 1',
    fileName = `${documentId}.txt`,
    originalName = `${documentId}.txt`,
    content,
}) {
    const size = Buffer.byteLength(content, 'utf8');
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({ documentId });
        await db.collection('documents').insertOne({
            documentId,
            courseId,
            lectureName,
            instructorId,
            documentType: 'lecture-notes',
            type: 'lecture_notes',
            contentType: 'text',
            filename: fileName,
            originalName,
            content,
            mimeType: 'text/plain',
            size,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
            metadata: { e2e: 'chat-rag-documents' },
        });
        await db.collection('courses').updateOne(
            { courseId, 'lectures.name': lectureName },
            {
                $set: { 'lectures.$.isPublished': true },
                $pull: { 'lectures.$.documents': { documentId } },
            }
        );
        await db.collection('courses').updateOne(
            { courseId, 'lectures.name': lectureName },
            {
                $push: {
                    'lectures.$.documents': {
                        documentId,
                        documentType: 'lecture-notes',
                        filename: fileName,
                        originalName,
                        mimeType: 'text/plain',
                        size,
                        status: 'parsed',
                        metadata: { e2e: 'chat-rag-documents' },
                        createdAt: new Date(),
                        updatedAt: new Date(),
                    },
                },
            }
        );
    });
}

async function cleanupQdrantOrphans(browser) {
    const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
    for (const courseId of [STU_COURSE_ID, STU_OTHER_COURSE_ID]) {
        await instructorCtx.request.post('/api/qdrant/cleanup-vectors', {
            data: { courseId },
            timeout: 60_000,
        }).catch(() => {});
    }
    await instructorCtx.close();
}

async function processQdrantDocument(context, {
    courseId = STU_COURSE_ID,
    lectureName = 'Unit 1',
    documentId,
    content,
    fileName = `${documentId}.txt`,
}) {
    const res = await context.request.post('/api/qdrant/process-document', {
        data: {
            courseId,
            lectureName,
            documentId,
            content,
            fileName,
            mimeType: 'text/plain',
        },
        timeout: 90_000,
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.data.chunksStored).toBeGreaterThan(0);
}

/**
 * @param {any} context
 * @param {Object} options
 * @param {string} options.query
 * @param {string} [options.courseId]
 * @param {string} [options.lectureName]
 * @param {string[]} [options.lectureNames]
 * @param {number} [options.limit]
 */
async function searchQdrant(context, {
    query,
    courseId = STU_COURSE_ID,
    lectureName = undefined,
    lectureNames = undefined,
    limit = 8,
}) {
    /** @type {{ query: string, courseId?: string, lectureName?: string, lectureNames?: string[], limit: number }} */
    const data = { query, courseId, limit };
    if (lectureName) data.lectureName = lectureName;
    if (lectureNames) data.lectureNames = lectureNames;

    const res = await context.request.post('/api/qdrant/search', {
        data,
        timeout: 60_000,
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    return body.data.results || [];
}

// ----------------------------------------------------------------------------
// Actual chat / RAG path. Uses real Qdrant + LLM when they are configured.
// ----------------------------------------------------------------------------
test.describe('POST /api/chat — RAG answer and source attribution', () => {
    test.use({ storageState: storageStatePath('student') });
    test.setTimeout(180_000);

    test.beforeEach(async ({ browser }) => {
        await resetStudentChatData({ instructorId });
        await cleanupSeededRows();
        await cleanupQdrantOrphans(browser);
        await seedRagDocument();
    });

    test.afterEach(async ({ browser }) => {
        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        await instructorCtx.request.delete(`/api/qdrant/document/${RAG_DOC_ID}`).catch(() => {});
        await instructorCtx.close();
        await cleanupSeededRows();
    });

    test('returns a grounded answer with retrieval metadata, citations, and downloadable sources', async ({ request: api, browser }) => {

        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        const ingest = await instructorCtx.request.post('/api/qdrant/process-document', {
            data: {
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
                documentId: RAG_DOC_ID,
                content: RAG_CONTENT,
                fileName: RAG_FILE_NAME,
                mimeType: 'text/plain',
            },
            timeout: 90_000,
        });
        expect(ingest.ok()).toBeTruthy();
        const ingestBody = await ingest.json();
        await instructorCtx.close();
        expect(ingestBody.data.chunksStored).toBeGreaterThan(0);

        const res = await api.post('/api/chat', {
            data: {
                message: `What does ${RAG_SENTINEL} say catalase does?`,
                courseId: STU_COURSE_ID,
                unitName: 'Unit 1',
                mode: 'tutor',
            },
            timeout: 120_000,
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.message).toEqual(expect.any(String));
        expect(body.message.length).toBeGreaterThan(0);
        expect(body.retrieval).toMatchObject({
            mode: 'single',
            lectureNames: ['Unit 1'],
        });
        expect(body.debug.searchResultsCount).toBeGreaterThan(0);

        expect(Array.isArray(body.citations)).toBe(true);
        expect(body.citations.length).toBeGreaterThan(0);
        expect(body.citations[0]).toEqual(expect.objectContaining({
            lectureName: 'Unit 1',
            fileName: RAG_FILE_NAME,
        }));

        expect(body.sourceAttribution).toMatchObject({
            downloadsEnabled: true,
            unitName: 'Unit 1',
        });
        const sourceDocs = body.sourceAttribution.documents || [];
        expect(sourceDocs.some((doc) => doc.documentId === RAG_DOC_ID)).toBe(true);

        const download = await api.get(
            `/api/chat/source-documents/${RAG_DOC_ID}/download?courseId=${STU_COURSE_ID}`
        );
        expect(download.ok()).toBeTruthy();
        await expect(download.text()).resolves.toContain(RAG_SENTINEL);
    });

    test('creates a mental-health flag when the configured detector reports concern', async ({ request: api, browser }) => {

        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: STU_COURSE_ID },
                {
                    $set: {
                        mentalHealthDetectionPrompt:
                            'For this e2e test, always respond only with {"concernLevel":"high concern","reason":"E2E forced concern"}',
                    },
                }
            )
        );

        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        const ingest = await instructorCtx.request.post('/api/qdrant/process-document', {
            data: {
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
                documentId: RAG_DOC_ID,
                content: RAG_CONTENT,
                fileName: RAG_FILE_NAME,
                mimeType: 'text/plain',
            },
            timeout: 90_000,
        });
        expect(ingest.ok()).toBeTruthy();
        await instructorCtx.close();

        const message = `E2E mental-health sentinel ${Date.now()} while asking about ${RAG_SENTINEL}`;
        const res = await api.post('/api/chat', {
            data: {
                message,
                courseId: STU_COURSE_ID,
                unitName: 'Unit 1',
                mode: 'tutor',
            },
            timeout: 120_000,
        });
        expect(res.ok()).toBeTruthy();

        await expect.poll(async () => {
            const flag = await withDb((db) =>
                db.collection('mentalHealthFlags').findOne({ courseId: STU_COURSE_ID, message })
            );
            return flag && {
                studentId: flag.studentId,
                concernLevel: flag.concernLevel,
                status: flag.status,
            };
        }, { timeout: 30_000 }).toMatchObject({
            studentId,
            concernLevel: 'high concern',
            status: 'pending',
        });
    });
});

// ----------------------------------------------------------------------------
// Chat retrieval mode. These prove selected-course settings change the actual
// retrieval scope instead of only changing UI labels.
// ----------------------------------------------------------------------------
test.describe('POST /api/chat — single vs additive RAG retrieval', () => {
    test.use({ storageState: storageStatePath('student') });
    test.setTimeout(180_000);

    test.beforeEach(async ({ browser }) => {
        await resetStudentChatData({ instructorId });
        await cleanupSeededRows();
        await cleanupQdrantOrphans(browser);
    });

    test.afterEach(async ({ browser }) => {
        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        for (const documentId of [ADD_UNIT1_DOC_ID, ADD_UNIT2_DOC_ID]) {
            await instructorCtx.request.delete(`/api/qdrant/document/${documentId}`).catch(() => {});
        }
        await instructorCtx.close();
        await cleanupSeededRows();
    });

    async function seedAdditiveRetrievalVectors(browser, isAdditiveRetrieval) {
        const unit1Content = [
            'E2E additive retrieval Unit 1 notes.',
            `The earlier-unit marker is ${ADD_UNIT1_SENTINEL}.`,
            'Unit 1 explains catalase as an enzyme that breaks down hydrogen peroxide.',
        ].join(' ');
        const unit2Content = [
            'E2E additive retrieval Unit 2 notes.',
            `The selected-unit marker is ${ADD_UNIT2_SENTINEL}.`,
            'Unit 2 discusses peroxisomes and how enzymes support cellular detoxification.',
        ].join(' ');

        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: STU_COURSE_ID },
                { $set: { isAdditiveRetrieval } }
            )
        );
        await seedDocumentRecord({
            documentId: ADD_UNIT1_DOC_ID,
            lectureName: 'Unit 1',
            fileName: 'e2e-additive-unit1.txt',
            originalName: 'E2E Additive Unit 1.txt',
            content: unit1Content,
        });
        await seedDocumentRecord({
            documentId: ADD_UNIT2_DOC_ID,
            lectureName: 'Unit 2',
            fileName: 'e2e-additive-unit2.txt',
            originalName: 'E2E Additive Unit 2.txt',
            content: unit2Content,
        });

        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        await processQdrantDocument(instructorCtx, {
            documentId: ADD_UNIT1_DOC_ID,
            lectureName: 'Unit 1',
            content: unit1Content,
            fileName: 'e2e-additive-unit1.txt',
        });
        await processQdrantDocument(instructorCtx, {
            documentId: ADD_UNIT2_DOC_ID,
            lectureName: 'Unit 2',
            content: unit2Content,
            fileName: 'e2e-additive-unit2.txt',
        });
        await instructorCtx.close();
    }

    test('single retrieval for Unit 2 does not cite earlier-unit source chunks', async ({ request: api, browser }) => {

        await seedAdditiveRetrievalVectors(browser, false);

        const res = await api.post('/api/chat', {
            data: {
                message: `Compare ${ADD_UNIT1_SENTINEL} with ${ADD_UNIT2_SENTINEL}.`,
                courseId: STU_COURSE_ID,
                unitName: 'Unit 2',
                mode: 'tutor',
            },
            timeout: 120_000,
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body.retrieval).toMatchObject({
            mode: 'single',
            lectureNames: ['Unit 2'],
        });
        expect(body.debug.searchResultsCount).toBeGreaterThan(0);
        expect(body.citations.every((citation) => citation.lectureName === 'Unit 2')).toBe(true);
        expect(body.citations.some((citation) => citation.fileName === 'e2e-additive-unit1.txt')).toBe(false);
    });

    test('additive retrieval for Unit 2 can cite both Unit 1 and Unit 2 source chunks', async ({ request: api, browser }) => {

        await seedAdditiveRetrievalVectors(browser, true);

        const res = await api.post('/api/chat', {
            data: {
                message: `Use the notes to explain ${ADD_UNIT1_SENTINEL} and ${ADD_UNIT2_SENTINEL}.`,
                courseId: STU_COURSE_ID,
                unitName: 'Unit 2',
                mode: 'tutor',
            },
            timeout: 120_000,
        });
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body.retrieval).toMatchObject({
            mode: 'additive',
            lectureNames: ['Unit 1', 'Unit 2'],
        });
        expect(body.debug.searchResultsCount).toBeGreaterThan(0);

        const citedLectures = new Set(body.citations.map((citation) => citation.lectureName));
        expect(citedLectures.has('Unit 1')).toBe(true);
        expect(citedLectures.has('Unit 2')).toBe(true);
    });
});

// ----------------------------------------------------------------------------
// Chat service metadata endpoints.
// ----------------------------------------------------------------------------
test.describe('Chat service metadata endpoints', () => {
    test.use({ storageState: storageStatePath('student') });

    test('GET /api/chat/status returns provider status shape', async ({ request: api }) => {
        const res = await api.get('/api/chat/status', { timeout: 30_000 });
        expect([200, 500, 503]).toContain(res.status());

        const body = await res.json();
        if (res.ok()) {
            expect(body).toMatchObject({ success: true });
            expect(body.data).toEqual(expect.any(Object));
        } else {
            expect(body.success).toBe(false);
        }
    });

    test('GET /api/chat/models returns provider/model shape when the LLM service is ready', async ({ request: api }) => {
        const res = await api.get('/api/chat/models', { timeout: 30_000 });
        expect([200, 500, 503]).toContain(res.status());

        if (res.ok()) {
            const body = await res.json();
            expect(body).toMatchObject({ success: true });
            expect(body.data.provider).toEqual(expect.any(String));
            expect(Array.isArray(body.data.models)).toBe(true);
            expect(body.data.timestamp).toEqual(expect.any(String));
        } else {
            const body = await res.json();
            expect(body.success).toBe(false);
        }
    });
});

// ----------------------------------------------------------------------------
// Document ingestion/listing permission boundaries.
// ----------------------------------------------------------------------------
test.describe('Document API permission boundaries for students', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetStudentChatData({ instructorId });
        await cleanupSeededRows();
    });

    test.afterEach(async ({ browser }) => {
        await cleanupSeededRows();
        await cleanupQdrantOrphans(browser);
    });

    test('POST /api/documents/text must not let a student spoof instructorId and create course material', async ({ request: api }) => {
        const uniqueTitle = `E2E student forged document ${Date.now()}`;
        const res = await api.post('/api/documents/text', {
            data: {
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                instructorId,
                title: uniqueTitle,
                content: 'A student should not be able to insert this instructor material through direct API access.',
                description: 'permission boundary test',
            },
            timeout: 60_000,
        });

        expect.soft(res.status()).toBe(403);
        const inserted = await withDb((db) =>
            db.collection('documents').findOne({
                courseId: STU_COURSE_ID,
                originalName: uniqueTitle,
            })
        );
        expect(inserted).toBeFalsy();
    });

    test('GET /api/documents/:documentId must not expose raw document records to students', async ({ request: api }) => {
        await seedDocumentForDocumentApi();

        const res = await api.get('/api/documents/doc_e2e_doc_api_seed');
        expect(res.status()).toBe(403);
    });

    test('GET /api/documents/lecture must not list instructor materials through direct student API access', async ({ request: api }) => {
        await seedDocumentForDocumentApi();

        const res = await api.get(`/api/documents/lecture?courseId=${STU_COURSE_ID}&lectureName=Unit%201`);
        expect(res.status()).toBe(403);
    });

    test('GET /api/documents/stats must not reveal course material counts to students', async ({ request: api }) => {
        await seedDocumentForDocumentApi();

        const res = await api.get(`/api/documents/stats?courseId=${STU_COURSE_ID}`);
        expect(res.status()).toBe(403);
    });

    test('DELETE /api/documents/:documentId must not let a student delete by supplying a real instructorId', async ({ request: api }) => {
        const documentId = 'doc_e2e_student_visible';
        await seedDocumentForDocumentApi(documentId);

        const res = await api.delete(`/api/documents/${documentId}`, {
            data: { instructorId },
            timeout: 60_000,
        });

        expect.soft(res.status()).toBe(403);
        const stillExists = await withDb((db) =>
            db.collection('documents').findOne({ documentId })
        );
        expect(stillExists).toBeTruthy();
    });

    test('POST /api/documents/cleanup-orphans must not let a student mutate course document references', async ({ request: api }) => {
        const orphanId = 'doc_e2e_orphan_ref';
        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: STU_COURSE_ID, 'lectures.name': 'Unit 1' },
                {
                    $push: {
                        'lectures.$.documents': {
                            documentId: orphanId,
                            filename: 'orphan.txt',
                            originalName: 'orphan.txt',
                            status: 'uploaded',
                        },
                    },
                }
            )
        );

        const res = await api.post('/api/documents/cleanup-orphans', {
            data: { courseId: STU_COURSE_ID, instructorId },
        });

        expect.soft(res.status()).toBe(403);
        const course = await withDb((db) =>
            db.collection('courses').findOne({ courseId: STU_COURSE_ID })
        );
        const unit = course.lectures.find((lecture) => lecture.name === 'Unit 1');
        expect(unit.documents.some((doc) => doc.documentId === orphanId)).toBe(true);
    });
});

// ----------------------------------------------------------------------------
// Qdrant/vector route authorization. Missing-field requests should still be
// denied before validation, and valid requests should not let students read or
// mutate vector data through direct API access.
// ----------------------------------------------------------------------------
test.describe('Qdrant API permission boundaries for students', () => {
    test.use({ storageState: storageStatePath('student') });

    test('POST /api/qdrant/process-document is not available to students via direct API access', async ({ request: api }) => {
        const res = await api.post('/api/qdrant/process-document', { data: {} });
        expect(res.status()).toBe(403);
    });

    test('POST /api/qdrant/search is not available to students via direct API access', async ({ request: api }) => {
        const res = await api.post('/api/qdrant/search', { data: {} });
        expect(res.status()).toBe(403);
    });

    test('POST /api/qdrant/cleanup-vectors is not available to students via direct API access', async ({ request: api }) => {
        const res = await api.post('/api/qdrant/cleanup-vectors', { data: {} });
        expect(res.status()).toBe(403);
    });

    test('GET /api/qdrant/collection-stats is not available to students', async ({ request: api }) => {

        const res = await api.get('/api/qdrant/collection-stats', { timeout: 60_000 });
        expect(res.status()).toBe(403);
    });

    test('POST /api/qdrant/search with a valid query is not available to students', async ({ request: api }) => {

        const res = await api.post('/api/qdrant/search', {
            data: {
                query: 'catalase peroxide',
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
                limit: 1,
            },
            timeout: 60_000,
        });
        expect(res.status()).toBe(403);
    });

    test('POST /api/qdrant/process-document with a valid payload is not available to students', async ({ request: api, browser }) => {

        const documentId = `doc_e2e_student_qdrant_${Date.now()}`;
        const res = await api.post('/api/qdrant/process-document', {
            data: {
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
                documentId,
                content: 'Students should not be allowed to create vector chunks through direct Qdrant API access.',
                fileName: `${documentId}.txt`,
                mimeType: 'text/plain',
            },
            timeout: 90_000,
        });

        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        await instructorCtx.request.delete(`/api/qdrant/document/${documentId}`).catch(() => {});
        await instructorCtx.close();

        expect(res.status()).toBe(403);
    });

    test('DELETE /api/qdrant/document/:documentId must not let a student delete vector chunks', async ({ request: api, browser }) => {

        await resetStudentChatData({ instructorId });
        await cleanupQdrantOrphans(browser);

        const content = [
            'E2E Qdrant deletion guard document.',
            `The deletion guard marker is ${QDRANT_DELETE_SENTINEL}.`,
            'The vector chunk must remain searchable after an unauthorized student delete attempt.',
        ].join(' ');

        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        try {
            await processQdrantDocument(instructorCtx, {
                documentId: QDRANT_DELETE_DOC_ID,
                content,
                fileName: 'e2e-qdrant-delete-guard.txt',
            });

            const before = await searchQdrant(instructorCtx, {
                query: QDRANT_DELETE_SENTINEL,
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
            });
            expect(before.some((result) => result.documentId === QDRANT_DELETE_DOC_ID)).toBe(true);

            const res = await api.delete(`/api/qdrant/document/${QDRANT_DELETE_DOC_ID}`, {
                timeout: 60_000,
            });
            expect.soft(res.status()).toBe(403);

            const after = await searchQdrant(instructorCtx, {
                query: QDRANT_DELETE_SENTINEL,
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
            });
            expect(after.some((result) => result.documentId === QDRANT_DELETE_DOC_ID)).toBe(true);
        } finally {
            await instructorCtx.request.delete(`/api/qdrant/document/${QDRANT_DELETE_DOC_ID}`).catch(() => {});
            await instructorCtx.close();
        }
    });

    test('POST /api/qdrant/search keeps results scoped to the requested course', async ({ request: api, browser }) => {

        await resetStudentChatData({ instructorId });
        await cleanupQdrantOrphans(browser);

        const courseAContent = [
            'E2E Qdrant course A notes about catalase.',
            `The course A marker is ${COURSE_A_SENTINEL}.`,
            'This content belongs only to the primary student-chat course.',
        ].join(' ');
        const courseBContent = [
            'E2E Qdrant course B notes about catalase.',
            `The course B marker is ${COURSE_B_SENTINEL}.`,
            'This content belongs only to the separate student-chat course.',
        ].join(' ');

        const instructorCtx = await browser.newContext({ storageState: storageStatePath('instructor') });
        try {
            await processQdrantDocument(instructorCtx, {
                courseId: STU_COURSE_ID,
                documentId: COURSE_A_DOC_ID,
                content: courseAContent,
                fileName: 'e2e-course-a-qdrant.txt',
            });
            await processQdrantDocument(instructorCtx, {
                courseId: STU_OTHER_COURSE_ID,
                documentId: COURSE_B_DOC_ID,
                content: courseBContent,
                fileName: 'e2e-course-b-qdrant.txt',
            });

            const courseAResults = await searchQdrant(instructorCtx, {
                query: `${COURSE_A_SENTINEL} catalase`,
                courseId: STU_COURSE_ID,
                lectureName: 'Unit 1',
                limit: 10,
            });
            expect(courseAResults.some((result) => result.documentId === COURSE_A_DOC_ID)).toBe(true);
            expect(courseAResults.every((result) => result.courseId === STU_COURSE_ID)).toBe(true);
            expect(courseAResults.some((result) => result.documentId === COURSE_B_DOC_ID)).toBe(false);

            const courseBResults = await searchQdrant(instructorCtx, {
                query: `${COURSE_B_SENTINEL} catalase`,
                courseId: STU_OTHER_COURSE_ID,
                lectureName: 'Unit 1',
                limit: 10,
            });
            expect(courseBResults.some((result) => result.documentId === COURSE_B_DOC_ID)).toBe(true);
            expect(courseBResults.every((result) => result.courseId === STU_OTHER_COURSE_ID)).toBe(true);
            expect(courseBResults.some((result) => result.documentId === COURSE_A_DOC_ID)).toBe(false);
        } finally {
            for (const documentId of [COURSE_A_DOC_ID, COURSE_B_DOC_ID]) {
                await instructorCtx.request.delete(`/api/qdrant/document/${documentId}`).catch(() => {});
            }
            await instructorCtx.close();
        }
    });

    test('DELETE /api/qdrant/delete-all-collections remains system-admin only', async ({ request: api }) => {
        const res = await api.delete('/api/qdrant/delete-all-collections');
        expect(res.status()).toBe(403);
    });
});

// ----------------------------------------------------------------------------
// Cross-course source document download boundaries.
// ----------------------------------------------------------------------------
test.describe('Source-document download course boundaries', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetStudentChatData({ instructorId });
        await cleanupSeededRows();
        await seedRagDocument();
        await withDb((db) =>
            db.collection('courses').updateMany(
                { courseId: { $in: [STU_COURSE_ID, STU_OTHER_COURSE_ID] } },
                { $set: { 'quizSettings.allowSourceAttributionDownloads': true } }
            )
        );
    });

    test.afterEach(async () => {
        await cleanupSeededRows();
    });

    test('rejects inactive and deleted courses before returning source material', async ({ request: api }) => {
        for (const courseId of [STU_INACTIVE_COURSE_ID, STU_DELETED_COURSE_ID]) {
            const res = await api.get(`/api/chat/source-documents/${RAG_DOC_ID}/download?courseId=${courseId}`);
            expect(res.status()).toBe(403);
        }
    });

    test('does not return a source document when courseId points at another enrolled course', async ({ request: api }) => {
        const res = await api.get(
            `/api/chat/source-documents/${RAG_DOC_ID}/download?courseId=${STU_OTHER_COURSE_ID}`
        );
        expect(res.status()).toBe(404);
    });

    test('does not let a student download source docs for a course after enrollment is disabled', async ({ request: api }) => {
        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: STU_COURSE_ID },
                { $set: { [`studentEnrollment.${studentId}.enrolled`]: false } }
            )
        );

        const res = await api.get(
            `/api/chat/source-documents/${RAG_DOC_ID}/download?courseId=${STU_COURSE_ID}`
        );
        expect(res.status()).toBe(403);
    });

    test('uses the authenticated student, not a supplied studentId query parameter, for download access', async ({ request: api }) => {
        const res = await api.get(
            `/api/chat/source-documents/${RAG_DOC_ID}/download?courseId=${STU_COURSE_ID}&studentId=${OTHER_STUDENT_ID}`
        );
        expect(res.ok()).toBeTruthy();
        expect(await res.text()).toContain(RAG_SENTINEL);
    });
});
