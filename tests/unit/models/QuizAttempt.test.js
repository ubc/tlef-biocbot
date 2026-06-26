/**
 * Unit tests for src/models/QuizAttempt.js against the in-memory Mongo double.
 * getAttemptStats exercises the aggregate() support added to memory-db.js
 * ($match -> $group with $sum, $cond, $push).
 */
const { memoryDb } = require('../helpers/memory-db');
const QuizAttempt = require('../../../src/models/QuizAttempt');

const COLL = 'quizAttempts';

describe('QuizAttempt.saveAttempt', () => {
    test('inserts an attempt with defaults and returns its id', async () => {
        const db = memoryDb({});
        const res = await QuizAttempt.saveAttempt(db, {
            studentId: 's1', courseId: 'c1', questionId: 'q1',
            lectureName: 'Unit 1', questionType: 'TF', studentAnswer: true, correct: true,
        });
        expect(res.success).toBe(true);
        expect(res.attemptId).toMatch(/^qa_\d+_[a-z0-9]+$/);

        const stored = await db.collection(COLL).findOne({ attemptId: res.attemptId });
        expect(stored).toMatchObject({ studentId: 's1', courseId: 'c1', correct: true, feedback: '' });
        expect(stored.attemptedAt).toBeInstanceOf(Date);
    });
});

describe('QuizAttempt.getAttemptsByStudent', () => {
    test('returns only this student/course, newest first', async () => {
        const db = memoryDb({
            [COLL]: [
                { attemptId: 'older', studentId: 's1', courseId: 'c1', attemptedAt: new Date('2026-01-01') },
                { attemptId: 'newer', studentId: 's1', courseId: 'c1', attemptedAt: new Date('2026-03-01') },
                { attemptId: 'other-course', studentId: 's1', courseId: 'c2', attemptedAt: new Date('2026-02-01') },
                { attemptId: 'other-student', studentId: 's2', courseId: 'c1', attemptedAt: new Date('2026-02-01') },
            ],
        });
        const attempts = await QuizAttempt.getAttemptsByStudent(db, 's1', 'c1');
        expect(attempts.map(a => a.attemptId)).toEqual(['newer', 'older']);
    });
});

describe('QuizAttempt.getAttemptStats', () => {
    test('returns zeros and an empty breakdown when there are no attempts', async () => {
        const db = memoryDb({ [COLL]: [] });
        expect(await QuizAttempt.getAttemptStats(db, 's1', 'c1')).toEqual({
            totalAttempts: 0, correctCount: 0, accuracy: 0, unitBreakdown: {},
        });
    });

    test('aggregates totals, accuracy (rounded %), and a per-unit breakdown', async () => {
        const db = memoryDb({
            [COLL]: [
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 1', correct: true },
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 1', correct: false },
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 2', correct: true },
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 2', correct: true },
                // noise that must be excluded by the $match:
                { studentId: 's2', courseId: 'c1', lectureName: 'Unit 1', correct: true },
                { studentId: 's1', courseId: 'c2', lectureName: 'Unit 1', correct: true },
            ],
        });
        expect(await QuizAttempt.getAttemptStats(db, 's1', 'c1')).toEqual({
            totalAttempts: 4,
            correctCount: 3,
            accuracy: 75,
            unitBreakdown: {
                'Unit 1': { total: 2, correct: 1 },
                'Unit 2': { total: 2, correct: 2 },
            },
        });
    });

    test('rounds accuracy to the nearest integer percent', async () => {
        const db = memoryDb({
            [COLL]: [
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 1', correct: true },
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 1', correct: false },
                { studentId: 's1', courseId: 'c1', lectureName: 'Unit 1', correct: false },
            ],
        });
        const stats = await QuizAttempt.getAttemptStats(db, 's1', 'c1');
        expect(stats.accuracy).toBe(33); // round(1/3 * 100)
    });
});
