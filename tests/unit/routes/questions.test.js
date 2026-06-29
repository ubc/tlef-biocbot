/**
 * In-process route tests for src/routes/questions.js (supertest).
 * The Course model is real over memory-db; only the course AI resolver is
 * mocked so loading the router cannot initialize an external LLM/vector store.
 */
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveCourseAi: jest.fn(async () => ({ llm: {} })),
    sendLlmKeyError: jest.fn(() => false),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const questionsRouter = require('../../../src/routes/questions');

const instructor = { userId: 'i1', role: 'instructor' };
const otherInstructor = { userId: 'i2', role: 'instructor' };
const student = { userId: 's1', role: 'student' };
const ta = { userId: 't1', role: 'ta' };
const app = (opts) => makeRouteApp(questionsRouter, opts);

function courseDb(overrides = {}) {
    return memoryDb({ courses: [{
        courseId: 'C1',
        instructorId: 'i1',
        tas: ['t1'],
        studentEnrollment: { s1: { enrolled: true } },
        lectures: [{
            name: 'Unit 1',
            learningObjectives: [],
            assessmentQuestions: [{
                questionId: 'q1',
                questionType: 'multiple-choice',
                question: 'Existing question?',
                correctAnswer: 'A',
                points: 2,
            }],
        }],
        ...overrides,
    }] });
}

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST / — create a question', () => {
    const payload = {
        courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1',
        questionType: 'true-false', question: 'Cells have membranes.', correctAnswer: false,
        learningObjective: '  Describe cell membranes  ',
    };

    test('400 when required fields are missing and 503 when db is unavailable', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).post('/').send({})).status).toBe(400);
        expect((await request(app({ db: null, user: instructor })).post('/').send(payload)).status).toBe(503);
    });

    test('401 without authentication and 403 for a student', async () => {
        expect((await request(app({ db: courseDb() })).post('/').send(payload)).status).toBe(401);
        expect((await request(app({ db: courseDb(), user: student })).post('/').send(payload)).status).toBe(403);
    });

    test('403 when an instructor submits another instructorId', async () => {
        const res = await request(app({ db: courseDb(), user: otherInstructor })).post('/').send(payload);
        expect(res.status).toBe(403);
    });

    test('accepts boolean false as an explicit answer and normalizes the objective', async () => {
        const res = await request(app({ db: courseDb(), user: instructor })).post('/').send(payload);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({
            questionType: 'true-false',
            question: 'Cells have membranes.',
            learningObjective: 'Describe cell membranes',
            created: true,
        });
        expect(res.body.data.questionId).toMatch(/^q_/);
    });
});

describe('GET /lecture — list unit questions', () => {
    test('400 without both query parameters', async () => {
        expect((await request(app({ db: courseDb(), user: student })).get('/lecture?courseId=C1')).status).toBe(400);
    });

    test('returns an empty list for a missing course', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }) })).get('/lecture?courseId=missing&lectureName=Unit%201');
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ courseId: 'missing', lectureName: 'Unit 1', questions: [], count: 0 });
    });

    test('403 for a non-enrolled student', async () => {
        const db = courseDb({ studentEnrollment: {} });
        expect((await request(app({ db, user: student })).get('/lecture?courseId=C1&lectureName=Unit%201')).status).toBe(403);
    });

    test('returns embedded questions to an enrolled student', async () => {
        const res = await request(app({ db: courseDb(), user: student })).get('/lecture?courseId=C1&lectureName=Unit%201');
        expect(res.status).toBe(200);
        expect(res.body.data.count).toBe(1);
        expect(res.body.data.questions[0]).toMatchObject({ questionId: 'q1', correctAnswer: 'A' });
    });

    test('allows an assigned TA with course permission', async () => {
        const res = await request(app({ db: courseDb(), user: ta })).get('/lecture?courseId=C1&lectureName=Unit%201');
        expect(res.status).toBe(200);
    });
});

describe('GET /stats', () => {
    test('400 without courseId', async () => {
        expect((await request(app({ db: courseDb() })).get('/stats')).status).toBe(400);
    });

    test('calculates totals and type breakdown from all lectures', async () => {
        const db = courseDb({ lectures: [
            { name: 'One', assessmentQuestions: [
                { questionType: 'multiple-choice', points: 2 },
                { questionType: 'multiple-choice' },
            ] },
            { name: 'Two', assessmentQuestions: [{ questionType: 'true-false', points: 3 }] },
        ] });
        // Current route behavior: statistics are public; no req.user check runs.
        const res = await request(app({ db })).get('/stats?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.stats).toEqual({
            totalQuestions: 3,
            totalPoints: 6,
            typeBreakdown: [
                { type: 'multiple-choice', count: 2, points: 3 },
                { type: 'true-false', count: 1, points: 3 },
            ],
        });
    });
});

describe('GET /:questionId', () => {
    test('404 for an unknown question', async () => {
        expect((await request(app({ db: courseDb(), user: instructor })).get('/unknown')).status).toBe(404);
    });

    test('403 when the user cannot read the owning course', async () => {
        expect((await request(app({ db: courseDb(), user: otherInstructor })).get('/q1')).status).toBe(403);
    });

    test('returns the exact embedded question to an authorized instructor', async () => {
        const res = await request(app({ db: courseDb(), user: instructor })).get('/q1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ questionId: 'q1', question: 'Existing question?', points: 2 });
    });
});

describe('PUT and DELETE /:questionId', () => {
    test('PUT returns 404 instead of silently creating a missing question', async () => {
        const res = await request(app({ db: courseDb(), user: instructor })).put('/missing').send({
            courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1', question: 'Replacement',
        });
        expect(res.status).toBe(404);
        expect(res.body.message).toMatch(/Question missing not found/);
    });

    test('PUT blocks a student before attempting the update', async () => {
        const res = await request(app({ db: courseDb(), user: student })).put('/q1').send({
            courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1', question: 'Replacement',
        });
        expect(res.status).toBe(403);
    });

    test('DELETE returns a zero count for an absent question on an existing lecture', async () => {
        const res = await request(app({ db: courseDb(), user: instructor })).delete('/missing').send({
            courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1',
        });
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ questionId: 'missing', deletedCount: 0 });
    });
});

describe('POST /bulk', () => {
    test('400 when questions is not an array', async () => {
        const res = await request(app({ db: courseDb(), user: instructor })).post('/bulk').send({
            courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1', questions: {},
        });
        expect(res.status).toBe(400);
    });

    test('creates each supplied question and reports generated IDs', async () => {
        const res = await request(app({ db: courseDb(), user: instructor })).post('/bulk').send({
            courseId: 'C1', lectureName: 'Unit 1', instructorId: 'i1',
            questions: [
                { questionType: 'short-answer', question: 'One?', correctAnswer: 'one' },
                { questionType: 'short-answer', question: 'Two?', correctAnswer: 'two', learningObjective: '  LO  ' },
            ],
        });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ courseId: 'C1', lectureName: 'Unit 1', insertedCount: 2, autoLinkedCount: 0 });
        expect(res.body.data.insertedIds).toHaveLength(2);
        res.body.data.insertedIds.forEach(id => expect(id).toMatch(/^q_/));
    });
});
