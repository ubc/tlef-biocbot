const { memoryDb } = require('../helpers/memory-db');
const {
    normalizeAssessmentQuestion,
    migrateQuestionSchema,
} = require('../../../scripts/migrate-question-schema');

describe('question schema migration', () => {
    test('normalizes legacy TF and MCQ values while preserving structured questions', () => {
        expect(normalizeAssessmentQuestion({ questionType: 'true-false', correctAnswer: 'false' }))
            .toMatchObject({ correctAnswer: false });
        expect(normalizeAssessmentQuestion({
            questionType: 'multiple-choice', options: { A: 'One', B: 'Two' }, correctAnswer: 'B',
        })).toMatchObject({ options: ['One', 'Two'], correctAnswer: 1 });
        expect(normalizeAssessmentQuestion({
            questionType: 'multiple-choice', options: ['One'], correctAnswer: 0,
        })).toMatchObject({ options: ['One'], correctAnswer: 0 });
    });

    test('migrates only changed courses and reports counts', async () => {
        const db = memoryDb({ courses: [
            {
                _id: 'legacy', courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: [
                    { questionId: 'tf', questionType: 'true-false', correctAnswer: 'true' },
                    { questionId: 'mc', questionType: 'multiple-choice', options: { A: 'One', B: 'Two' }, correctAnswer: 'A' },
                ] }],
            },
            {
                _id: 'current', courseId: 'C2', lectures: [{ name: 'Unit 1', assessmentQuestions: [
                    { questionId: 'mc2', questionType: 'multiple-choice', options: ['One'], correctAnswer: 0 },
                ] }],
            },
        ] });

        await expect(migrateQuestionSchema(db)).resolves.toEqual({
            scannedCourses: 2, updatedCourses: 1, updatedQuestions: 2, dryRun: false,
        });
        const migrated = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(migrated.lectures[0].assessmentQuestions).toEqual([
            expect.objectContaining({ correctAnswer: true }),
            expect.objectContaining({ options: ['One', 'Two'], correctAnswer: 0 }),
        ]);
    });

    test('dry-run reports changes without writing them', async () => {
        const legacy = {
            _id: 'legacy', courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: [
                { questionType: 'true-false', correctAnswer: 'true' },
            ] }],
        };
        const db = memoryDb({ courses: [legacy] });

        await expect(migrateQuestionSchema(db, { dryRun: true })).resolves.toEqual({
            scannedCourses: 1, updatedCourses: 1, updatedQuestions: 1, dryRun: true,
        });
        await expect(db.collection('courses').findOne({ courseId: 'C1' }))
            .resolves.toMatchObject(legacy);
    });
});
