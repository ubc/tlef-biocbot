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
