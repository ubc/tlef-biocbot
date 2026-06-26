/**
 * Unit tests for src/models/Question.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const Question = require('../../../src/models/Question');

const COLL = 'questions';

describe('Question.getQuestionsCollection', () => {
    test('returns the questions collection', () => {
        const db = memoryDb({});
        expect(Question.getQuestionsCollection(db)).toBe(db.collection(COLL));
    });
});

describe('Question.createQuestion', () => {
    test('stores a new active question with timestamps and a generated id', async () => {
        const db = memoryDb({});
        const created = await Question.createQuestion(db, {
            courseId: 'C1',
            lectureName: 'Unit 1',
            instructorId: 'i1',
            questionType: 'multiple-choice',
            question: 'Which molecule stores genetic information?',
            options: { A: 'DNA', B: 'ATP' },
            correctAnswer: 'A',
            explanation: 'DNA stores genetic information.',
            difficulty: 'easy',
            tags: ['DNA', 'genetics'],
            points: 2,
            isActive: false,
            metadata: { source: 'manual' },
        });

        expect(created).toMatchObject({
            courseId: 'C1',
            lectureName: 'Unit 1',
            instructorId: 'i1',
            questionType: 'multiple-choice',
            question: 'Which molecule stores genetic information?',
            isActive: true,
            _id: 'mem-1',
        });
        expect(created.questionId).toMatch(/^q_\d+_[a-z0-9]+$/);
        expect(created.createdAt).toBeInstanceOf(Date);
        expect(created.updatedAt).toBeInstanceOf(Date);

        const stored = await db.collection(COLL).findOne({ questionId: created.questionId });
        expect(stored).toMatchObject({
            questionId: created.questionId,
            isActive: true,
            tags: ['DNA', 'genetics'],
        });
    });
});

describe('Question.getQuestionsForLecture', () => {
    test('returns active questions for the requested course and lecture, oldest first', async () => {
        const db = memoryDb({
            [COLL]: [
                { questionId: 'new', courseId: 'C1', lectureName: 'Unit 1', isActive: true, createdAt: new Date('2026-03-01') },
                { questionId: 'old', courseId: 'C1', lectureName: 'Unit 1', isActive: true, createdAt: new Date('2026-01-01') },
                { questionId: 'inactive', courseId: 'C1', lectureName: 'Unit 1', isActive: false, createdAt: new Date('2026-02-01') },
                { questionId: 'other-course', courseId: 'C2', lectureName: 'Unit 1', isActive: true, createdAt: new Date('2026-01-15') },
                { questionId: 'other-lecture', courseId: 'C1', lectureName: 'Unit 2', isActive: true, createdAt: new Date('2026-01-15') },
            ],
        });

        const questions = await Question.getQuestionsForLecture(db, 'C1', 'Unit 1');
        expect(questions.map(q => q.questionId)).toEqual(['old', 'new']);
    });
});

describe('Question.getQuestionById', () => {
    test('returns the matching question regardless of active status, or null', async () => {
        const db = memoryDb({
            [COLL]: [
                { questionId: 'active', isActive: true, question: 'A?' },
                { questionId: 'inactive', isActive: false, question: 'B?' },
            ],
        });

        expect(await Question.getQuestionById(db, 'active')).toMatchObject({ question: 'A?' });
        expect(await Question.getQuestionById(db, 'inactive')).toMatchObject({ question: 'B?' });
        expect(await Question.getQuestionById(db, 'missing')).toBeNull();
    });
});

describe('Question.updateQuestion', () => {
    test('updates caller-provided fields and stamps updatedAt', async () => {
        const db = memoryDb({
            [COLL]: [{ questionId: 'q1', question: 'Old?', points: 1, tags: ['old'], isActive: true }],
        });

        const result = await Question.updateQuestion(db, 'q1', {
            question: 'New?',
            points: 3,
            tags: ['new'],
        });
        expect(result).toMatchObject({ matchedCount: 1, modifiedCount: 1 });

        const updated = await Question.getQuestionById(db, 'q1');
        expect(updated).toMatchObject({ question: 'New?', points: 3, tags: ['new'] });
        expect(updated.updatedAt).toBeInstanceOf(Date);
    });

    test('returns the raw no-match update result when missing', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Question.updateQuestion(db, 'missing', { points: 2 })).resolves.toEqual({
            matchedCount: 0,
            modifiedCount: 0,
            upsertedCount: 0,
        });
    });
});

describe('Question.deleteQuestion', () => {
    test('soft-deletes by setting isActive false and updatedAt', async () => {
        const db = memoryDb({ [COLL]: [{ questionId: 'q1', isActive: true, lectureName: 'Unit 1', courseId: 'C1' }] });

        const result = await Question.deleteQuestion(db, 'q1');
        expect(result).toMatchObject({ matchedCount: 1, modifiedCount: 1 });

        const deleted = await Question.getQuestionById(db, 'q1');
        expect(deleted.isActive).toBe(false);
        expect(deleted.updatedAt).toBeInstanceOf(Date);
        expect(await Question.getQuestionsForLecture(db, 'C1', 'Unit 1')).toEqual([]);
    });

    test('returns the raw no-match update result when missing', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Question.deleteQuestion(db, 'missing')).resolves.toEqual({
            matchedCount: 0,
            modifiedCount: 0,
            upsertedCount: 0,
        });
    });
});

describe('Question.getQuestionStats', () => {
    test('returns the empty stats shape when a course has no active questions', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', questionType: 'multiple-choice', points: 5, isActive: false },
                { courseId: 'C2', questionType: 'true-false', points: 1, isActive: true },
            ],
        });

        expect(await Question.getQuestionStats(db, 'C1')).toEqual({
            totalQuestions: 0,
            totalPoints: 0,
            typeBreakdown: [],
        });
    });

    test('aggregates active question counts and points by type for one course', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', questionType: 'multiple-choice', points: 2, isActive: true },
                { courseId: 'C1', questionType: 'multiple-choice', points: 3, isActive: true },
                { courseId: 'C1', questionType: 'true-false', points: 1, isActive: true },
                { courseId: 'C1', questionType: 'short-answer', points: undefined, isActive: true },
                { courseId: 'C1', questionType: 'true-false', points: 99, isActive: false },
                { courseId: 'C2', questionType: 'multiple-choice', points: 99, isActive: true },
            ],
        });

        const stats = await Question.getQuestionStats(db, 'C1');
        expect(stats).toMatchObject({
            _id: null,
            totalQuestions: 4,
            totalPoints: 6,
        });
        expect(stats.typeBreakdown).toEqual(expect.arrayContaining([
            { type: 'multiple-choice', count: 2, points: 5 },
            { type: 'true-false', count: 1, points: 1 },
            { type: 'short-answer', count: 1, points: 0 },
        ]));
        expect(stats.typeBreakdown).toHaveLength(3);
    });
});

describe('Question.getQuestionsByTags', () => {
    test('returns active questions for the course with any matching tag, oldest first', async () => {
        const db = memoryDb({
            [COLL]: [
                { questionId: 'late', courseId: 'C1', tags: ['enzyme'], isActive: true, createdAt: new Date('2026-03-01') },
                { questionId: 'early', courseId: 'C1', tags: ['ATP', 'metabolism'], isActive: true, createdAt: new Date('2026-01-01') },
                { questionId: 'inactive', courseId: 'C1', tags: ['ATP'], isActive: false, createdAt: new Date('2026-02-01') },
                { questionId: 'other-course', courseId: 'C2', tags: ['ATP'], isActive: true, createdAt: new Date('2026-01-15') },
                { questionId: 'no-match', courseId: 'C1', tags: ['DNA'], isActive: true, createdAt: new Date('2026-01-15') },
            ],
        });

        const questions = await Question.getQuestionsByTags(db, 'C1', ['ATP', 'enzyme']);
        expect(questions.map(q => q.questionId)).toEqual(['early', 'late']);
    });
});

describe('Question.bulkCreateQuestions', () => {
    test('creates active questions with generated ids and shared timestamps', async () => {
        const db = memoryDb({});

        const result = await Question.bulkCreateQuestions(db, [
            { courseId: 'C1', lectureName: 'Unit 1', questionType: 'true-false', question: 'A?', points: 1 },
            { courseId: 'C1', lectureName: 'Unit 1', questionType: 'short-answer', question: 'B?', points: 2 },
        ]);

        expect(result.insertedCount).toBe(2);

        const stored = await db.collection(COLL).find({ courseId: 'C1' }).sort({ points: 1 }).toArray();
        expect(stored).toHaveLength(2);
        expect(stored[0]).toMatchObject({ question: 'A?', isActive: true });
        expect(stored[1]).toMatchObject({ question: 'B?', isActive: true });
        expect(stored[0].questionId).toMatch(/^q_\d+_[a-z0-9]+$/);
        expect(stored[1].questionId).toMatch(/^q_\d+_[a-z0-9]+$/);
        expect(stored[0].createdAt).toBeInstanceOf(Date);
        expect(stored[0].updatedAt).toBeInstanceOf(Date);
        expect(stored[1].createdAt.getTime()).toBe(stored[0].createdAt.getTime());
    });

    test('returns zero inserts for an empty input list', async () => {
        const db = memoryDb({});

        await expect(Question.bulkCreateQuestions(db, [])).resolves.toMatchObject({
            insertedCount: 0,
        });
        expect(await db.collection(COLL).countDocuments({})).toBe(0);
    });
});
