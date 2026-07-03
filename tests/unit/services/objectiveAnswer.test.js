const { evaluateObjectiveAnswer } = require('../../../src/services/objectiveAnswer');

describe('evaluateObjectiveAnswer', () => {
    test.each([
        [{ correctAnswer: true }, ' True ', true],
        [{ correctAnswer: false }, 'false', true],
        [{ correctAnswer: 0 }, '0', true],
        [{ correctAnswer: 2 }, '1', false],
        [{ correctAnswer: 'B' }, ' b ', true],
    ])('compares structured and legacy objective answers', (question, answer, correct) => {
        expect(evaluateObjectiveAnswer(question, answer)).toMatchObject({
            correct,
            correctAnswer: question.correctAnswer,
        });
    });
});
