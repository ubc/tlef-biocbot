/**
 * In-process route tests for src/routes/quiz.js (supertest).
 * Real: Course + QuizAttempt models over memory-db. Mocked: gridfs (download
 * only), llmKeyMiddleware (resolveCourseAi/sendLlmKeyError), llmKeyStore key
 * summary. Covers status, objective check-answer, attempt recording, and history.
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
const quizRouter = require('../../../src/routes/quiz');

const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(quizRouter, opts);

// A course with quiz enabled, one published unit, and one MC question (answer "B").
function quizDb() {
    return memoryDb({ courses: [{
        courseId: 'C1',
        llmApiKey: { enc: 'k' },
        quizSettings: { enabled: true, testableUnits: 'all', allowLectureMaterialAccess: true },
        lectures: [{
            name: 'Unit 1', isPublished: true,
            assessmentQuestions: [{ questionId: 'q1', questionType: 'multiple-choice', question: 'Pick one', correctAnswer: 'B' }],
        }],
    }] });
}

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /status', () => {
    test('400 without courseId, 503 without db', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/status')).status).toBe(400);
        expect((await request(app({ db: null })).get('/status?courseId=C1')).status).toBe(503);
    });

    test('enabled only when quiz is on AND a valid key is present', async () => {
        const on = await request(app({ db: quizDb() })).get('/status?courseId=C1');
        expect(on.body).toMatchObject({ success: true, enabled: true, aiAvailable: true });

        const noKey = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { enabled: true } }] });
        const off = await request(app({ db: noKey })).get('/status?courseId=C1');
        expect(off.body).toMatchObject({ enabled: false, aiAvailable: false });
    });
});

describe('POST /check-answer', () => {
    test('400 when required fields are missing', async () => {
        const res = await request(app({ db: quizDb() })).post('/check-answer').send({ courseId: 'C1' });
        expect(res.status).toBe(400);
    });

    test('grades a correct multiple-choice answer server-side', async () => {
        const res = await request(app({ db: quizDb() })).post('/check-answer')
            .send({ courseId: 'C1', questionId: 'q1', lectureName: 'Unit 1', studentAnswer: 'b' }); // case-insensitive
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ correct: true, feedback: 'Correct! Well done.', correctAnswer: 'B' });
    });

    test('grades an incorrect answer and reveals the correct one in feedback', async () => {
        const res = await request(app({ db: quizDb() })).post('/check-answer')
            .send({ courseId: 'C1', questionId: 'q1', lectureName: 'Unit 1', studentAnswer: 'A' });
        expect(res.body.data).toMatchObject({ correct: false, correctAnswer: 'B' });
        expect(res.body.data.feedback).toMatch(/correct answer is B/);
    });

    test('403 when the quiz is disabled, 404 for an unknown question', async () => {
        const disabled = memoryDb({ courses: [{ courseId: 'C1', quizSettings: { enabled: false } }] });
        expect((await request(app({ db: disabled })).post('/check-answer')
            .send({ courseId: 'C1', questionId: 'q1', lectureName: 'Unit 1', studentAnswer: 'B' })).status).toBe(403);

        expect((await request(app({ db: quizDb() })).post('/check-answer')
            .send({ courseId: 'C1', questionId: 'nope', lectureName: 'Unit 1', studentAnswer: 'B' })).status).toBe(404);
    });
});

describe('POST /attempt', () => {
    test('401 when there is no authenticated student', async () => {
        const res = await request(app({ db: quizDb() })).post('/attempt')
            .send({ courseId: 'C1', questionId: 'q1', lectureName: 'Unit 1', questionType: 'multiple-choice', studentAnswer: 'B', correct: true });
        expect(res.status).toBe(401);
    });

    test('409 when submitted correctness disagrees with the stored answer', async () => {
        const res = await request(app({ db: quizDb(), user: student })).post('/attempt')
            .send({ courseId: 'C1', questionId: 'q1', lectureName: 'Unit 1', questionType: 'multiple-choice', studentAnswer: 'B', correct: false });
        expect(res.status).toBe(409);
    });

    test('records a valid attempt and returns an attemptId', async () => {
        const db = quizDb();
        const res = await request(app({ db, user: student })).post('/attempt')
            .send({ courseId: 'C1', questionId: 'q1', lectureName: 'Unit 1', questionType: 'multiple-choice', studentAnswer: 'B', correct: true });
        expect(res.status).toBe(200);
        expect(res.body.attemptId).toMatch(/^qa_[0-9a-f-]{36}$/i);
        expect(await db.collection('quizAttempts').findOne({ studentId: 's1' })).toBeTruthy();
    });
});

describe('GET /history', () => {
    test('401 without a user, 400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}), user: student })).get('/history')).status).toBe(400);
        expect((await request(app({ db: memoryDb({}) })).get('/history?courseId=C1')).status).toBe(401);
    });

    test('returns aggregated stats for the student', async () => {
        const db = memoryDb({ quizAttempts: [
            { studentId: 's1', courseId: 'C1', lectureName: 'Unit 1', correct: true },
            { studentId: 's1', courseId: 'C1', lectureName: 'Unit 1', correct: false },
        ] });
        const res = await request(app({ db, user: student })).get('/history?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.stats).toMatchObject({ totalAttempts: 2, correctCount: 1, accuracy: 50 });
    });
});
