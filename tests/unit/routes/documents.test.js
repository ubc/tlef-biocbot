/**
 * In-process route tests for src/routes/documents.js (supertest).
 * Document/Course models are real over memory-db. Parsing, GridFS, tokenization,
 * and course AI resolution are isolated because they are external integrations.
 */
jest.mock('js-tiktoken', () => ({
    encodingForModel: jest.fn(() => ({ encode: (text) => Array.from(String(text)) })),
}));
jest.mock('ubc-genai-toolkit-document-parsing', () => ({ DocumentParsingModule: jest.fn() }));
jest.mock('ubc-genai-toolkit-core', () => ({ ConsoleLogger: jest.fn() }));
jest.mock('../../../src/services/gridfs', () => ({
    deleteFile: jest.fn(async () => undefined),
    openDownloadStream: jest.fn(),
}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveCourseAi: jest.fn(async () => ({
        llm: { sendMessage: jest.fn() },
        qdrant: {
            client: {},
            processAndStoreDocument: jest.fn(async () => ({ success: true, chunksStored: 3 })),
            deleteDocumentChunks: jest.fn(async () => ({ success: true, deletedCount: 2 })),
        },
    })),
    sendLlmKeyError: jest.fn(() => false),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const { resolveCourseAi } = require('../../../src/routes/llmKeyMiddleware');
const gridfs = require('../../../src/services/gridfs');
const documentsRouter = require('../../../src/routes/documents');

const instructor = { userId: 'i1', role: 'instructor' };
const otherInstructor = { userId: 'i2', role: 'instructor' };
const student = { userId: 's1', role: 'student' };
const ta = { userId: 't1', role: 'ta' };
const app = (opts) => makeRouteApp(documentsRouter, opts);

function documentsDb({ documents, course = {} } = {}) {
    return memoryDb({
        courses: [{
            courseId: 'C1', instructorId: 'i1', tas: ['t1'],
            lectures: [{ name: 'Unit 1', documents: [] }],
            ...course,
        }],
        documents: documents || [{
            documentId: 'd1', courseId: 'C1', lectureName: 'Unit 1',
            instructorId: 'i1', documentType: 'lecture-notes', type: 'lecture_notes',
            contentType: 'text', originalName: 'Notes', filename: 'Notes.txt',
            content: 'cell membrane', mimeType: 'text/plain', size: 13, status: 'uploaded',
            fileData: { data: [1, 2, 3] },
        }],
    });
}

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST /text', () => {
    const payload = {
        courseId: 'C1', lectureName: 'Unit 1', documentType: 'lecture-notes',
        instructorId: 'i1', content: 'A membrane surrounds the cell.', title: 'Cell notes',
        tags: 'cells, membranes', learningObjectives: 'Identify cells, Explain membranes',
    };

    test('400 when required fields are missing and 503 without db', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).post('/text').send({})).status).toBe(400);
        expect((await request(app({ db: null, user: instructor })).post('/text').send(payload)).status).toBe(503);
    });

    test('401 without authentication and 403 for a student', async () => {
        expect((await request(app({ db: documentsDb() })).post('/text').send(payload)).status).toBe(401);
        expect((await request(app({ db: documentsDb(), user: student })).post('/text').send(payload)).status).toBe(403);
    });

    test('403 when an instructor submits another instructorId', async () => {
        const res = await request(app({ db: documentsDb(), user: otherInstructor })).post('/text').send(payload);
        expect(res.status).toBe(403);
    });

    test('stores text metadata and reports vector processing', async () => {
        const db = documentsDb({ documents: [] });
        const res = await request(app({ db, user: instructor })).post('/text').send(payload);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({
            title: 'Cell notes', linkedToCourse: true, qdrantProcessed: true, chunksStored: 3,
        });
        const stored = await db.collection('documents').findOne({ documentId: res.body.data.documentId });
        expect(stored).toMatchObject({
            courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1',
            contentType: 'text', type: 'lecture_notes', status: 'uploaded',
            metadata: {
                tags: ['cells', 'membranes'],
                learningObjectives: ['Identify cells', 'Explain membranes'],
            },
        });
    });
});

describe('GET /lecture', () => {
    test('400 when parameters are missing', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).get('/lecture?courseId=C1')).status).toBe(400);
    });

    test('401 without authentication and 403 for a student', async () => {
        const path = '/lecture?courseId=C1&lectureName=Unit%201';
        expect((await request(app({ db: documentsDb() })).get(path)).status).toBe(401);
        expect((await request(app({ db: documentsDb(), user: student })).get(path)).status).toBe(403);
    });

    test('returns lecture documents without binary fileData', async () => {
        const res = await request(app({ db: documentsDb(), user: instructor }))
            .get('/lecture?courseId=C1&lectureName=Unit%201');
        expect(res.status).toBe(200);
        expect(res.body.data.count).toBe(1);
        expect(res.body.data.documents[0]).toMatchObject({ documentId: 'd1', content: 'cell membrane' });
        expect(res.body.data.documents[0]).not.toHaveProperty('fileData');
    });

    test('allows an assigned TA with course permission', async () => {
        const res = await request(app({ db: documentsDb(), user: ta }))
            .get('/lecture?courseId=C1&lectureName=Unit%201');
        expect(res.status).toBe(200);
    });
});

describe('GET /stats', () => {
    test('400 without courseId and 403 for an unrelated instructor', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).get('/stats')).status).toBe(400);
        expect((await request(app({ db: documentsDb(), user: otherInstructor })).get('/stats?courseId=C1')).status).toBe(403);
    });

    test('returns aggregate counts and sizes for an authorized instructor', async () => {
        const db = documentsDb({ documents: [
            { documentId: 'd1', courseId: 'C1', status: 'uploaded', size: 10 },
            { documentId: 'd2', courseId: 'C1', status: 'uploaded', size: 5 },
            { documentId: 'd3', courseId: 'C1', status: 'parsed', size: 20 },
            { documentId: 'other', courseId: 'C2', status: 'parsed', size: 99 },
        ] });
        const res = await request(app({ db, user: instructor })).get('/stats?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.stats).toMatchObject({ totalDocuments: 3, totalSize: 35 });
        expect(res.body.data.stats.statusBreakdown).toEqual(expect.arrayContaining([
            { status: 'uploaded', count: 2 }, { status: 'parsed', count: 1 },
        ]));
    });
});

describe('GET /:documentId and /:documentId/download', () => {
    test('404 for an unknown document', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).get('/missing')).status).toBe(404);
    });

    test('403 when the user cannot manage the owning course', async () => {
        expect((await request(app({ db: documentsDb(), user: otherInstructor })).get('/d1')).status).toBe(403);
    });

    test('returns document metadata to the course instructor', async () => {
        const res = await request(app({ db: documentsDb(), user: instructor })).get('/d1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ documentId: 'd1', courseId: 'C1', originalName: 'Notes' });
    });

    test('download rejects students and unrelated instructors', async () => {
        expect((await request(app({ db: documentsDb(), user: student })).get('/d1/download')).status).toBe(403);
        expect((await request(app({ db: documentsDb(), user: otherInstructor })).get('/d1/download')).status).toBe(403);
    });

    test('downloads text with a safe attachment filename', async () => {
        const db = documentsDb({ documents: [{
            documentId: 'd1', courseId: 'C1', contentType: 'text',
            originalName: '../Notes', content: 'cell membrane', mimeType: 'text/plain',
        }] });
        const res = await request(app({ db, user: instructor })).get('/d1/download');
        expect(res.status).toBe(200);
        expect(res.text).toBe('cell membrane');
        expect(res.headers['content-disposition']).toContain('filename="Notes.txt"');
    });

    test('returns 500 for malformed inline file data', async () => {
        const db = documentsDb({ documents: [{
            documentId: 'd1', courseId: 'C1', contentType: 'file',
            originalName: 'slides.pdf', mimeType: 'application/pdf', fileData: { nope: true },
        }] });
        const res = await request(app({ db, user: instructor })).get('/d1/download');
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Stored file data is invalid');
    });
});

describe('DELETE /:documentId', () => {
    test('400 without instructorId and 404 for a missing document', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).delete('/d1').send({})).status).toBe(400);
        expect((await request(app({ db: documentsDb(), user: instructor })).delete('/missing').send({ instructorId: 'i1' })).status).toBe(404);
    });

    test('deletes the document and reports vector cleanup', async () => {
        const db = documentsDb();
        const res = await request(app({ db, user: instructor })).delete('/d1').send({ instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({
            documentId: 'd1', deletedCount: 1, removedFromCourse: true,
            removedFromQdrant: true, qdrantChunksDeleted: 2,
        });
        expect(await db.collection('documents').findOne({ documentId: 'd1' })).toBeNull();
    });

    test('deletes the GridFS backing file when fileId is present', async () => {
        const db = documentsDb({ documents: [{
            documentId: 'd1', courseId: 'C1', contentType: 'file', fileId: 'grid-1',
        }] });
        const res = await request(app({ db, user: instructor })).delete('/d1').send({ instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(gridfs.deleteFile).toHaveBeenCalledWith(db, 'grid-1');
    });
});

describe('POST /:documentId/extract-questions', () => {
    test('404 for an unknown document and 400 when it has no text', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).post('/missing/extract-questions')).status).toBe(404);

        const db = documentsDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: '' }] });
        const res = await request(app({ db, user: instructor })).post('/d1/extract-questions');
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/No text content/);
        expect(resolveCourseAi).toHaveBeenCalled();
    });

    test('currently allows extraction without an authenticated user', async () => {
        // This handler has no course-access check. The mocked LLM returns no
        // response content, which still proves an anonymous request reaches 200.
        const res = await request(app({ db: documentsDb() })).post('/d1/extract-questions');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ documentId: 'd1', totalFound: 0, wasChunked: false });
    });
});

describe('POST /cleanup-orphans', () => {
    test('validates fields, DB, course, and ownership', async () => {
        expect((await request(app({ db: documentsDb(), user: instructor })).post('/cleanup-orphans').send({})).status).toBe(400);
        expect((await request(app({ db: null, user: instructor })).post('/cleanup-orphans').send({ courseId: 'C1', instructorId: 'i1' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/cleanup-orphans').send({ courseId: 'C1', instructorId: 'i1' })).status).toBe(404);
        expect((await request(app({ db: documentsDb(), user: otherInstructor })).post('/cleanup-orphans').send({ courseId: 'C1', instructorId: 'i1' })).status).toBe(403);
    });

    test('removes missing references while preserving real documents', async () => {
        const db = documentsDb({
            documents: [{ documentId: 'valid', courseId: 'C1' }],
            course: { lectures: [{ name: 'Unit 1', documents: [{ documentId: 'valid' }, { documentId: 'missing' }] }] },
        });
        const res = await request(app({ db, user: instructor })).post('/cleanup-orphans').send({ courseId: 'C1', instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ totalOrphans: 1, cleanedUnits: 1 });
    });
});

describe('question extraction with mocked LLM and vector chunks', () => {
    test('normalizes mocked multiple-choice and true-false responses', async () => {
        const sendMessage = jest.fn(async () => ({ content: `Here is JSON: {"questions":[
            {"questionType":"multiple-choice","question":"ATP?","options":{"one":"ATP","two":"DNA"},"correctAnswer":" b ","explanation":"E"},
            {"questionType":"true-false","question":"Cells?","correctAnswer":"t","explanation":"E"}
        ]}` }));
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage }, qdrant: {} });
        const res = await request(app({ db: documentsDb(), user: instructor })).post('/d1/extract-questions');
        expect(res.status).toBe(200);
        expect(res.body.data.totalFound).toBe(2);
        expect(res.body.data.questions[0]).toMatchObject({ options: { A: 'ATP', B: 'DNA' }, correctAnswer: 'B', hasAnswer: true });
        expect(res.body.data.questions[1].correctAnswer).toBe('True');
    });

    test('uses mocked Qdrant chunks for oversized content and batches LLM calls', async () => {
        const longContent = 'x'.repeat(32001);
        const db = documentsDb({ documents: [{ documentId: 'd1', courseId: 'C1', lectureName: 'Unit 1', content: longContent }] });
        const sendMessage = jest.fn(async () => ({ content: '{"questions":[{"questionType":"short-answer","question":"Q?","correctAnswer":"A"}]}' }));
        const getDocumentChunks = jest.fn(async () => ['chunk one', 'chunk two']);
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage }, qdrant: { getDocumentChunks } });
        const res = await request(app({ db, user: instructor })).post('/d1/extract-questions');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ wasChunked: true, totalFound: 1 });
        expect(getDocumentChunks).toHaveBeenCalledWith('d1');
    });

    test('reports missing or failed chunks for oversized content', async () => {
        const db = documentsDb({ documents: [{ documentId: 'd1', courseId: 'C1', content: 'x'.repeat(32001) }] });
        resolveCourseAi.mockResolvedValueOnce({ llm: {}, qdrant: { getDocumentChunks: jest.fn(async () => []) } });
        expect((await request(app({ db, user: instructor })).post('/d1/extract-questions')).status).toBe(400);
        resolveCourseAi.mockResolvedValueOnce({ llm: {}, qdrant: { getDocumentChunks: jest.fn(async () => { throw new Error('mock vector failure'); }) } });
        expect((await request(app({ db, user: instructor })).post('/d1/extract-questions')).status).toBe(400);
    });
});
