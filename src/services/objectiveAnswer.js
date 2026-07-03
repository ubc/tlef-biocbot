function normalizeAnswer(value) {
    return String(value).trim().toLowerCase();
}

function evaluateObjectiveAnswer(question, studentAnswer) {
    const correctAnswer = question.correctAnswer;
    const correct = normalizeAnswer(studentAnswer) === normalizeAnswer(correctAnswer);
    const feedback = correct
        ? 'Correct! Well done.'
        : `Incorrect. The correct answer is ${correctAnswer}.`;

    return { correct, feedback, correctAnswer };
}

module.exports = { evaluateObjectiveAnswer };
