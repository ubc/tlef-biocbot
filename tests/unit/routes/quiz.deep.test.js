/**
 * Deeper in-process route tests for src/routes/quiz.js (supertest) — the
 * student-facing GET /questions and GET /materials readers not covered by
 * quiz.test.js. Same mock set as quiz.test.js (gridfs, llmKeyMiddleware,
 * llmKeyStore); Course + Document models run real over the in-memory Mongo.
 */
jest.mock('../../../src/services/gridfs', () => ({}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveCourseAi: jest.fn(async () => ({ llm: {} })),
    sendLlmKeyError: jest.fn(() => false),
}));
jest.mock('../../../src/services/llmKeyStore', () => ({
    publicKeySummary: jest.fn((key) => (key ? { status: 'valid' } : { status: 'none' })),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const { resolveCourseAi } = require('../../../src/routes/llmKeyMiddleware');
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
});
