'use strict';

const scoring = require('../../../public/common/scripts/assessment-scoring');

describe('assessment scoring', () => {
    const arrayOptions = ['Initiation', 'Termination', 'Elongation', 'Recycling'];

    test('preserves numeric zero and boolean false as valid correct answers', () => {
        const mc = scoring.evaluateQuestion({
            type: 'multiple-choice',
            options: arrayOptions,
            correctAnswer: 0
        }, 0);
        const tf = scoring.evaluateQuestion({
            type: 'true-false',
            correctAnswer: false
        }, 1);

        expect(mc).toMatchObject({
            scorable: true,
            isCorrect: true,
            displayExpectedAnswer: 'A) Initiation'
        });
        expect(tf).toMatchObject({
            scorable: true,
            isCorrect: true,
            displayExpectedAnswer: 'False'
        });
    });

    test.each([
        ['A', 0],
        ['B', 1],
        ['C', 2],
        ['D', 3]
    ])('maps legacy MC key %s explicitly to index %i', (letter, index) => {
        expect(scoring.normalizeAnswer({
            type: 'multiple-choice',
            options: { D: 'Four', B: 'Two', A: 'One', C: 'Three' }
        }, letter, 'correct answer')).toMatchObject({ valid: true, value: index });
    });

    test('invalid MC keys are unscorable and never default to option zero', () => {
        const result = scoring.evaluateQuestion({
            type: 'multiple-choice',
            options: arrayOptions,
            correctAnswer: 'Z'
        }, 0);

        expect(result.scorable).toBe(false);
        expect(result.isCorrect).toBe(false);
        expect(result.expectedAnswer).toBe('Z');
        expect(result.reason).toContain('not a recognized MC index');
    });

    test('formats numeric-keyed option objects with A-D labels', () => {
        const question = {
            type: 'multiple-choice',
            options: { 0: 'Bruce Wayne', 1: 'Peter', 2: 'Spiderbite', 3: 'Asdc' },
            correctAnswer: 0
        };

        expect(scoring.evaluateQuestion(question, 0)).toMatchObject({
            isCorrect: true,
            displayStudentAnswer: 'A) Bruce Wayne',
            displayExpectedAnswer: 'A) Bruce Wayne'
        });
    });

    test('authoritative 3/3 mode, HTML, and text summaries agree', () => {
        const questions = [
            { type: 'multiple-choice', question: 'MC?', options: arrayOptions, correctAnswer: 0 },
            { type: 'true-false', question: 'TF?', correctAnswer: false },
            { type: 'multiple-choice', question: 'Legacy?', options: { A: 'One', B: 'Two' }, correctAnswer: 'B' }
        ];
        const score = scoring.evaluateAssessment(questions, [0, 1, 1], 3);
        const html = scoring.buildModeResultHtml(score, questions);
        const text = scoring.buildModeResultText(score, questions);

        expect(score).toMatchObject({
            totalCorrect: 3,
            totalQuestions: 3,
            passed: true,
            mode: 'protege'
        });
        expect(score.results.map(result => result.isCorrect)).toEqual([true, true, true]);
        expect(html).toContain('Score: 3/3');
        expect(text).toContain('Score: 3/3');
        expect(html).toContain('Expected Answer</span><div class="answer-box-content">A) Initiation');
        expect(html).toContain('Expected Answer</span><div class="answer-box-content">False');
        expect(html).not.toContain('N/A');
        expect(text).not.toContain('N/A');
        expect(html).toContain('BiocBot is in protégé mode');
        expect(text).toContain('BiocBot is in protégé mode');
    });
});
