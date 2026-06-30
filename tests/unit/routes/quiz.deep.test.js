/**
 * Deeper in-process route tests for src/routes/quiz.js (supertest) — the
 * student-facing GET /questions and GET /materials readers not covered by
 * quiz.test.js. Same mock set as quiz.test.js (gridfs, llmKeyMiddleware,
 * llmKeyStore); Course + Document models run real over the in-memory Mongo.
 */
jest.mock('../../../src/services/gridfs', () => ({ openDownloadStream: jest.fn() }));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveCourseAi: jest.fn(async () => ({ llm: {} })),
    sendLlmKeyError: jest.fn(() => false),
}));
jest.mock('../../../src/services/llmKeyStore', () => ({
    publicKeySummary: jest.fn((key) => (key ? { status: 'valid' } : { status: 'none' })),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const CourseModel = require('../../../src/models/Course');
const QuizAttempt = require('../../../src/models/QuizAttempt');
const DocumentModel = require('../../../src/models/Document');
const gridfs = require('../../../src/services/gridfs');
const { resolveCourseAi, sendLlmKeyError } = require('../../../src/routes/llmKeyMiddleware');
const quizRouter = require('../../../src/routes/quiz');

const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(quizRouter, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /questions', () => {
    test('400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}), user: student })).get('/questions')).status).toBe(400);
    });

    test('403 when quiz practice is not enabled', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] }); // no quizSettings → default disabled
        const res = await request(app({ db, user: student })).get('/questions?courseId=C1');
        expect(res.status).toBe(403);
    });

    test('200 with empty lists when no lectures are published', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1', quizSettings: { enabled: true, allowLectureMaterialAccess: true },
            lectures: [{ name: 'Unit 1', isPublished: false }],
        }] });
        const res = await request(app({ db, user: student })).get('/questions?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ questions: [], units: [] });
    });

    test('200 returns sanitized questions WITHOUT the correct answer', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1',
            quizSettings: { enabled: true, testableUnits: 'all', allowLectureMaterialAccess: true },
            lectures: [{
                name: 'Unit 1', isPublished: true, displayName: 'Glycolysis',
                assessmentQuestions: [
                    { questionId: 'q1', questionType: 'multiple-choice', question: 'Pick one', options: { A: 'x', B: 'y' }, correctAnswer: 'B', points: 2 },
                    { questionId: 'q2', questionType: 'true-false', question: 'T or F', correctAnswer: 'true', isActive: false }, // soft-deleted → skipped
                ],
            }],
        }] });
        const res = await request(app({ db, user: student })).get('/questions?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.questions).toHaveLength(1);
        expect(res.body.questions[0]).toMatchObject({ questionId: 'q1', lectureName: 'Unit 1', points: 2 });
        expect(res.body.questions[0]).not.toHaveProperty('correctAnswer');
        expect(res.body.units).toEqual([{ name: 'Unit 1', displayName: 'Glycolysis' }]);
    });

    test('filters published units to the configured allowlist and supplies defaults', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1', quizSettings: { enabled: true, testableUnits: ['Unit 2'] },
            lectures: [
                { name: 'Unit 1', isPublished: true, assessmentQuestions: [{ questionId: 'q1' }] },
                { name: 'Unit 2', isPublished: true, assessmentQuestions: [{ questionId: 'q2', question: 'Two?' }] },
            ],
        }] });
        const res = await request(app({ db })).get('/questions?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.units).toEqual([{ name: 'Unit 2', displayName: 'Unit 2' }]);
        expect(res.body.questions).toEqual([expect.objectContaining({
            questionId: 'q2', options: {}, difficulty: 'medium', tags: [], points: 1,
        })]);
    });

    test('503 without a DB and handles both key and ordinary collaborator errors', async () => {
        expect((await request(app({ db: null })).get('/questions?courseId=C1')).status).toBe(503);

        const spy = jest.spyOn(CourseModel, 'getQuizSettings').mockRejectedValue(new Error('boom'));
        sendLlmKeyError.mockImplementationOnce((res) => { res.status(401).json({ success: false }); return true; });
        expect((await request(app({ db: memoryDb({}) })).get('/questions?courseId=C1')).status).toBe(401);
        sendLlmKeyError.mockReturnValueOnce(false);
        expect((await request(app({ db: memoryDb({}) })).get('/questions?courseId=C1')).status).toBe(500);
        spy.mockRestore();
    });
});

describe('GET /materials', () => {
    test('400 without courseId or lectureName', async () => {
        expect((await request(app({ db: memoryDb({}), user: student })).get('/materials?courseId=C1')).status).toBe(400);
    });

    test('403 when lecture material access is disabled', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { enabled: true, allowLectureMaterialAccess: false } }] });
        const res = await request(app({ db, user: student })).get('/materials?courseId=C1&lectureName=Unit 1');
        expect(res.status).toBe(403);
    });

    test('200 lists the lecture\'s documents', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { enabled: true, allowLectureMaterialAccess: true } }],
            documents: [
                { documentId: 'd1', courseId: 'C1', lectureName: 'Unit 1', originalName: 'slides.pdf', mimeType: 'application/pdf', size: 100, documentType: 'lecture' },
                { documentId: 'd2', courseId: 'C1', lectureName: 'Unit 2', originalName: 'other.pdf' }, // different lecture
            ],
        });
        const res = await request(app({ db, user: student })).get('/materials?courseId=C1&lectureName=Unit 1');
        expect(res.status).toBe(200);
        expect(res.body.materials.map(m => m.documentId)).toEqual(['d1']);
        expect(res.body.materials[0]).toMatchObject({ originalName: 'slides.pdf', mimeType: 'application/pdf' });
    });

    test('503 without a DB and converts a missing document list to an empty list', async () => {
        expect((await request(app({ db: null })).get('/materials?courseId=C1&lectureName=Unit')).status).toBe(503);
        const db = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }] });
        const spy = jest.spyOn(DocumentModel, 'getDocumentsForLecture').mockResolvedValue(null);
        expect((await request(app({ db })).get('/materials?courseId=C1&lectureName=Unit')).body.materials).toEqual([]);
        spy.mockRestore();
    });

    test('handles key errors and ordinary document lookup failures', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }] });
        const spy = jest.spyOn(DocumentModel, 'getDocumentsForLecture').mockRejectedValue(new Error('boom'));
        sendLlmKeyError.mockImplementationOnce((res) => { res.status(401).json({ success: false }); return true; });
        expect((await request(app({ db })).get('/materials?courseId=C1&lectureName=Unit')).status).toBe(401);
        sendLlmKeyError.mockReturnValueOnce(false);
        expect((await request(app({ db })).get('/materials?courseId=C1&lectureName=Unit')).status).toBe(500);
        spy.mockRestore();
    });
});

describe('GET /materials/:documentId/download', () => {
    test('validates course, settings, and document ownership', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/materials/d1/download')).status).toBe(400);
        const disabled = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: false } }] });
        expect((await request(app({ db: disabled })).get('/materials/d1/download?courseId=C1')).status).toBe(403);
        const missing = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }], documents: [] });
        expect((await request(app({ db: missing })).get('/materials/d1/download?courseId=C1')).status).toBe(404);
    });

    test('downloads text with a safe inferred extension', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'text', originalName: '../Notes', mimeType: 'text/plain', content: 'ATP content' }],
        });
        const res = await request(app({ db })).get('/materials/d1/download?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.text).toBe('ATP content');
        expect(res.headers['content-disposition']).toContain('filename="Notes.txt"');
    });

    test('downloads legacy inline binary and rejects malformed data', async () => {
        let db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'file', originalName: 'slides.pdf', mimeType: 'application/pdf', fileData: { buffer: [1, 2, 3] } }],
        });
        expect((await request(app({ db })).get('/materials/d1/download?courseId=C1')).status).toBe(200);
        db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'file', originalName: 'bad.pdf', fileData: {} }],
        });
        expect((await request(app({ db })).get('/materials/d1/download?courseId=C1')).status).toBe(500);
    });

    test.each([
        ['application/pdf', '.pdf'], ['text/markdown', '.md'], ['application/msword', '.doc'],
        ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', '.docx'],
        ['application/rtf', '.rtf'], ['application/x-unknown', ''],
    ])('infers a safe filename for %s', async (mimeType, extension) => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'text', mimeType, content: 'x' }],
        });
        const res = await request(app({ db })).get('/materials/d1/download?courseId=C1');
        expect(res.headers['content-disposition']).toContain(`quiz-material-d1${extension}`);
    });

    test('prefers a stored filename extension and sanitizes unicode and quotes', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'text', originalName: '../r\u00e9sum\u00e9"', filename: '../actual.pdf', content: '' }],
        });
        const res = await request(app({ db })).get('/materials/d1/download?courseId=C1');
        expect(res.headers['content-disposition']).toContain('filename="actual.pdf"');
    });

    test('downloads a Buffer with the default binary MIME type', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }] });
        const spy = jest.spyOn(DocumentModel, 'getDocumentById').mockResolvedValue({
            documentId: 'd1', courseId: 'C1', contentType: 'file', filename: 'blob.bin', fileData: Buffer.from('abc'),
        });
        const res = await request(app({ db })).get('/materials/d1/download?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toBe('application/octet-stream');
        spy.mockRestore();
    });

    test('streams GridFS-backed files', async () => {
        const { Readable } = require('stream');
        gridfs.openDownloadStream.mockReturnValueOnce(Readable.from([Buffer.from('grid')]));
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'file', filename: 'grid.bin', fileId: 'f1' }],
        });
        const res = await request(app({ db })).get('/materials/d1/download?courseId=C1');
        expect(res.status).toBe(200);
        expect(gridfs.openDownloadStream).toHaveBeenCalledWith(db, 'f1');
    });

    test('handles an immediate GridFS stream failure', async () => {
        const { Readable } = require('stream');
        gridfs.openDownloadStream.mockReturnValueOnce(new Readable({
            read() { this.destroy(new Error('missing')); },
        }));
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'file', filename: 'grid.bin', fileId: 'f1' }],
        });
        const res = await request(app({ db })).get('/materials/d1/download?courseId=C1');
        expect(res.status).toBe(500);
    });

    test('ends a GridFS response that fails after streaming begins', async () => {
        const { Readable } = require('stream');
        let emitted = false;
        gridfs.openDownloadStream.mockReturnValueOnce(new Readable({
            read() {
                if (emitted) return;
                emitted = true;
                this.push(Buffer.from('partial'));
                setImmediate(() => this.destroy(new Error('late')));
            },
        }));
        const db = memoryDb({
            courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }],
            documents: [{ documentId: 'd1', courseId: 'C1', contentType: 'file', filename: 'grid.bin', fileId: 'f1' }],
        });
        await request(app({ db })).get('/materials/d1/download?courseId=C1').catch(() => {});
    });

    test('503 without a DB and handles key and ordinary download failures', async () => {
        expect((await request(app({ db: null })).get('/materials/d1/download?courseId=C1')).status).toBe(503);
        const db = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { allowLectureMaterialAccess: true } }] });
        const spy = jest.spyOn(DocumentModel, 'getDocumentById').mockRejectedValue(new Error('boom'));
        sendLlmKeyError.mockImplementationOnce((res) => { res.status(401).json({ success: false }); return true; });
        expect((await request(app({ db })).get('/materials/d1/download?courseId=C1')).status).toBe(401);
        sendLlmKeyError.mockReturnValueOnce(false);
        expect((await request(app({ db })).get('/materials/d1/download?courseId=C1')).status).toBe(500);
        spy.mockRestore();
    });
});

describe('POST /chat — mocked quiz-help LLM', () => {
    const chatBody = {
        message: 'Explain why', courseId: 'C1', lectureName: 'Unit 1',
        questionText: 'What is ATP?', questionType: 'short-answer',
        correctAnswer: '[evaluated by AI]', studentAnswer: 'energy',
    };

    test('validates required fields and DB', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/chat').send({})).status).toBe(400);
        expect((await request(app({ db: null })).post('/chat').send(chatBody)).status).toBe(503);
    });

    test('profanity and safety messages bypass the mocked LLM response', async () => {
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage: jest.fn() }, qdrant: {} });
        let res = await request(app({ db: memoryDb({}) })).post('/chat').send({ ...chatBody, message: 'this is shit' });
        expect(res.body).toMatchObject({ success: true, source: 'system' });
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage: jest.fn() }, qdrant: {} });
        res = await request(app({ db: memoryDb({}) })).post('/chat').send({ ...chatBody, message: 'I want to die' });
        expect(res.body.source).toBe('system');
        expect(res.body.message).toContain('Wellness Centre');
    });

    test('looks up the stored answer, retrieves one-unit context, and calls only the mock', async () => {
        const sendMessage = jest.fn(async () => ({ content: 'Mock quiz help' }));
        const searchDocuments = jest.fn(async () => [{ lectureName: 'Unit 1', fileName: 'notes', chunkText: 'ATP stores energy' }]);
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage }, qdrant: { searchDocuments } });
        const db = memoryDb({ courses: [{
            courseId: 'C1', prompts: { base: 'Custom base', quizHelp: 'Custom help' },
            lectures: [{ name: 'Unit 1', assessmentQuestions: [{ question: 'What is ATP?', correctAnswer: 'adenosine triphosphate' }] }],
        }] });
        const res = await request(app({ db })).post('/chat').send({
            ...chatBody,
            conversationHistory: [{ role: 'user', content: 'Earlier' }, { role: 'assistant', content: 'Reply' }],
        });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, message: 'Mock quiz help', source: 'quiz-help' });
        expect(searchDocuments).toHaveBeenCalledWith('Explain why', { courseId: 'C1', lectureNames: ['Unit 1'] }, 6);
        expect(sendMessage.mock.calls[0][0]).toContain('adenosine triphosphate');
        expect(sendMessage.mock.calls[0][1].systemPrompt).toContain('Custom help');
    });

    test('continues with no context when mocked vector retrieval fails', async () => {
        const sendMessage = jest.fn(async () => ({}));
        resolveCourseAi.mockResolvedValueOnce({
            llm: { sendMessage },
            qdrant: { searchDocuments: jest.fn(async () => { throw new Error('mock vector failure'); }) },
        });
        const res = await request(app({ db: memoryDb({ courses: [{ courseId: 'C1' }] }) })).post('/chat').send(chatBody);
        expect(res.status).toBe(200);
        expect(res.body.message).toContain('could not generate');
    });

    test('uses supplied answers and default prompts for objective questions', async () => {
        const sendMessage = jest.fn(async () => ({ content: 'ok' }));
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage }, qdrant: { searchDocuments: jest.fn(async () => []) } });
        const res = await request(app({ db: memoryDb({ courses: [{ courseId: 'C1' }] }) })).post('/chat').send({
            ...chatBody, questionType: 'multiple-choice', correctAnswer: 'B', conversationHistory: [],
        });
        expect(res.status).toBe(200);
        expect(sendMessage.mock.calls[0][0]).toContain('Correct Answer: B');
        expect(sendMessage.mock.calls[0][0]).toContain('No specific course materials retrieved');
    });

    test('continues when short-answer lookup itself fails', async () => {
        const sendMessage = jest.fn(async () => ({ content: 'ok' }));
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage }, qdrant: { searchDocuments: jest.fn(async () => []) } });
        const db = memoryDb({});
        jest.spyOn(db.collection('courses'), 'findOne').mockRejectedValueOnce(new Error('lookup failed'));
        const res = await request(app({ db })).post('/chat').send(chatBody);
        expect(res.status).toBe(200);
        expect(sendMessage.mock.calls[0][0]).toContain('Correct Answer: ');
    });

    test('handles key errors and ordinary LLM failures', async () => {
        resolveCourseAi.mockRejectedValueOnce(new Error('key'));
        sendLlmKeyError.mockImplementationOnce((res) => { res.status(401).json({ success: false }); return true; });
        expect((await request(app({ db: memoryDb({}) })).post('/chat').send(chatBody)).status).toBe(401);
        resolveCourseAi.mockRejectedValueOnce(new Error('llm'));
        sendLlmKeyError.mockReturnValueOnce(false);
        expect((await request(app({ db: memoryDb({}) })).post('/chat').send(chatBody)).status).toBe(500);
    });
});

describe('remaining answer, attempt, history, and status branches', () => {
    function shortAnswerDb() {
        return memoryDb({ courses: [{
            courseId: 'C1', quizSettings: { enabled: true, testableUnits: ['Unit 1'] },
            lectures: [{ name: 'Unit 1', isPublished: true, assessmentQuestions: [{
                questionId: 'short', questionType: 'short-answer', question: 'Explain', correctAnswer: 'Because',
            }] }],
        }] });
    }

    test('evaluates a visible short answer through the mocked LLM', async () => {
        const evaluateStudentAnswer = jest.fn(async () => ({ correct: true, feedback: 'nice' }));
        resolveCourseAi.mockResolvedValueOnce({ llm: { evaluateStudentAnswer } });
        const res = await request(app({ db: shortAnswerDb() })).post('/check-answer').send({
            courseId: 'C1', questionId: 'short', lectureName: 'Unit 1', studentAnswer: 'why', studentName: 'Ada',
        });
        expect(res.body.data).toEqual({ correct: true, feedback: 'nice' });
        expect(evaluateStudentAnswer).toHaveBeenCalledWith('Explain', 'why', 'Because', 'short-answer', 'Ada');
    });

    test('rejects unpublished/non-testable questions and validates missing DBs', async () => {
        const db = shortAnswerDb();
        expect((await request(app({ db })).post('/check-answer').send({ courseId: 'C1', questionId: 'short', lectureName: 'Other', studentAnswer: 'x' })).status).toBe(403);
        expect((await request(app({ db: null })).post('/check-answer').send({ courseId: 'C1', questionId: 'q', lectureName: 'U', studentAnswer: 'x' })).status).toBe(503);
        expect((await request(app({ db: null, user: student })).post('/attempt').send({ courseId: 'C1', questionId: 'q', lectureName: 'U', questionType: 'short-answer', studentAnswer: '', correct: false })).status).toBe(503);
        expect((await request(app({ db: null, user: student })).get('/history?courseId=C1')).status).toBe(503);
    });

    test('records short answers without trusting an objective-answer comparison', async () => {
        resolveCourseAi.mockResolvedValueOnce({ llm: {} });
        const res = await request(app({ db: shortAnswerDb(), user: student })).post('/attempt').send({
            courseId: 'C1', questionId: 'short', lectureName: 'Unit 1', questionType: 'short-answer', studentAnswer: '', correct: false,
        });
        expect(res.status).toBe(200);
    });

    test('covers missing attempt fields and visible-question rejection', async () => {
        expect((await request(app({ db: shortAnswerDb(), user: student })).post('/attempt').send({})).status).toBe(400);
        expect((await request(app({ db: shortAnswerDb(), user: student })).post('/attempt').send({
            courseId: 'C1', questionId: 'short', lectureName: 'Other', questionType: 'short-answer', studentAnswer: 'x', correct: false,
        })).status).toBe(403);
    });

    test('covers ordinary failures in status, check-answer, attempt, and history', async () => {
        let spy = jest.spyOn(CourseModel, 'getQuizSettings').mockRejectedValue(new Error('status'));
        expect((await request(app({ db: memoryDb({}) })).get('/status?courseId=C1')).status).toBe(500);
        spy.mockRestore();

        spy = jest.spyOn(CourseModel, 'getQuizSettings').mockRejectedValue(new Error('answer'));
        sendLlmKeyError.mockReturnValueOnce(false);
        expect((await request(app({ db: memoryDb({}) })).post('/check-answer').send({ courseId: 'C1', questionId: 'q', lectureName: 'U', studentAnswer: 'x' })).status).toBe(500);
        spy.mockRestore();

        spy = jest.spyOn(QuizAttempt, 'saveAttempt').mockRejectedValue(new Error('save'));
        resolveCourseAi.mockResolvedValueOnce({ llm: {} });
        sendLlmKeyError.mockReturnValueOnce(false);
        expect((await request(app({ db: shortAnswerDb(), user: student })).post('/attempt').send({ courseId: 'C1', questionId: 'short', lectureName: 'Unit 1', questionType: 'short-answer', studentAnswer: 'x', correct: true })).status).toBe(500);
        spy.mockRestore();

        spy = jest.spyOn(QuizAttempt, 'getAttemptStats').mockRejectedValue(new Error('stats'));
        expect((await request(app({ db: memoryDb({}), user: student })).get('/history?courseId=C1')).status).toBe(500);
        spy.mockRestore();
    });
});
