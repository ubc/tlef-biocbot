(function assessmentScoringModule(root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.AssessmentScoring = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function createAssessmentScoring() {
    'use strict';

    const LEGACY_MC_INDEX = Object.freeze({ A: 0, B: 1, C: 2, D: 3 });

    function getExpectedAnswer(question) {
        return question?.correctAnswer ?? question?.expectedAnswer ?? question?.answer;
    }

    function getQuestionType(question) {
        const rawType = String(question?.type ?? question?.questionType ?? '').toLowerCase();
        if (['multiple-choice', 'multiple_choice', 'multiplechoice', 'mc', 'mcq'].includes(rawType)) {
            return 'multiple-choice';
        }
        if (['true-false', 'true_false', 'truefalse', 'tf', 'boolean'].includes(rawType)) {
            return 'true-false';
        }
        if (['short-answer', 'short_answer', 'shortanswer', 'sa'].includes(rawType)) {
            return 'short-answer';
        }
        if (Array.isArray(question?.options) || (
            question?.options && typeof question.options === 'object' &&
            Object.keys(question.options).length > 0
        )) return 'multiple-choice';
        if (typeof getExpectedAnswer(question) === 'boolean') return 'true-false';
        return rawType || 'short-answer';
    }

    function getOptionEntries(options) {
        if (Array.isArray(options)) {
            return options.map((value, index) => ({
                index,
                key: String.fromCharCode(65 + index),
                value
            }));
        }
        if (!options || typeof options !== 'object') return [];
        const entries = Object.entries(options);
        const allLetters = entries.every(([key]) =>
            Object.prototype.hasOwnProperty.call(LEGACY_MC_INDEX, String(key).toUpperCase())
        );
        if (allLetters) {
            return entries
                .map(([key, value]) => ({
                    index: LEGACY_MC_INDEX[String(key).toUpperCase()],
                    key: String(key).toUpperCase(),
                    value
                }))
                .sort((a, b) => a.index - b.index);
        }
        return entries.map(([key, value], index) => ({ index, key, value }));
    }

    function invalid(reason, rawValue) {
        return { valid: false, value: null, rawValue, reason };
    }

    function normalizeMultipleChoice(value, options, label) {
        const optionEntries = getOptionEntries(options);
        if (optionEntries.length === 0) {
            return invalid('multiple-choice options are missing', value);
        }
        let index = value;
        if (typeof value === 'string') {
            const letter = value.trim().toUpperCase();
            if (!Object.prototype.hasOwnProperty.call(LEGACY_MC_INDEX, letter)) {
                return invalid(`${label} "${value}" is not a recognized MC index or A-D key`, value);
            }
            index = LEGACY_MC_INDEX[letter];
        }
        if (!Number.isInteger(index) || index < 0 || index > 3) {
            return invalid(`${label} must be an integer from 0 to 3 or a letter from A to D`, value);
        }
        if (!optionEntries.some(entry => entry.index === index)) {
            return invalid(`${label} ${index} does not identify an available option`, value);
        }
        return { valid: true, value: index, rawValue: value, reason: null };
    }

    function normalizeTrueFalse(value, label) {
        if (typeof value === 'boolean') {
            return { valid: true, value, rawValue: value, reason: null };
        }
        if (value === 0 || value === 1) {
            return { valid: true, value: value === 0, rawValue: value, reason: null };
        }
        if (typeof value === 'string') {
            const normalized = value.trim().toLowerCase();
            if (normalized === 'true' || normalized === 'false') {
                return { valid: true, value: normalized === 'true', rawValue: value, reason: null };
            }
        }
        return invalid(`${label} must be true, false, 0, 1, "true", or "false"`, value);
    }

    function normalizeShortAnswer(value, label) {
        if (typeof value !== 'string') return invalid(`${label} must be a string`, value);
        return { valid: true, value: value.trim(), rawValue: value, reason: null };
    }

    function normalizeAnswer(question, value, label = 'answer') {
        const type = getQuestionType(question);
        if (type === 'multiple-choice') return normalizeMultipleChoice(value, question?.options, label);
        if (type === 'true-false') return normalizeTrueFalse(value, label);
        if (type === 'short-answer') return normalizeShortAnswer(value, label);
        return invalid(`question type "${type}" is not supported`, value);
    }

    function formatAnswer(question, value, role = 'student') {
        const type = getQuestionType(question);
        const normalized = normalizeAnswer(question, value, `${role} answer`);
        if (!normalized.valid) {
            return role === 'expected'
                ? 'Invalid or unrecognized answer key'
                : 'No valid answer provided';
        }
        if (type === 'true-false') return normalized.value ? 'True' : 'False';
        if (type === 'multiple-choice') {
            const option = getOptionEntries(question.options)
                .find(entry => entry.index === normalized.value);
            return option ? `${option.key}) ${option.value}` : 'Invalid or unrecognized answer key';
        }
        return normalized.value;
    }

    function evaluateQuestion(question, studentAnswer, evaluation) {
        const type = getQuestionType(question);
        const expectedRaw = getExpectedAnswer(question);
        const expected = normalizeAnswer(question, expectedRaw, 'correct answer');
        const student = normalizeAnswer(question, studentAnswer, 'student answer');
        const base = {
            expectedAnswer: expected.valid ? expected.value : expectedRaw,
            studentAnswer: student.valid ? student.value : studentAnswer,
            displayExpectedAnswer: formatAnswer(question, expectedRaw, 'expected'),
            displayStudentAnswer: formatAnswer(question, studentAnswer, 'student'),
            feedback: evaluation?.feedback ?? ''
        };
        if (!expected.valid) {
            return { ...base, isCorrect: false, scorable: false, reason: expected.reason };
        }
        if (!student.valid) {
            return { ...base, isCorrect: false, scorable: false, reason: student.reason };
        }
        let isCorrect;
        if (type === 'short-answer' && evaluation && typeof evaluation.correct === 'boolean') {
            isCorrect = evaluation.correct;
        } else if (type === 'short-answer') {
            isCorrect = student.value.localeCompare(expected.value, undefined, { sensitivity: 'base' }) === 0;
        } else {
            isCorrect = student.value === expected.value;
        }
        return { ...base, isCorrect, scorable: true, reason: null };
    }

    function evaluateAssessment(questions, answers, passThreshold, evaluations = []) {
        const safeQuestions = Array.isArray(questions) ? questions : [];
        const safeAnswers = Array.isArray(answers) ? answers : [];
        const numericThreshold = Number(passThreshold);
        const threshold = Number.isFinite(numericThreshold)
            ? Math.max(0, Math.min(numericThreshold, safeQuestions.length))
            : 0;
        const results = safeQuestions.map((question, index) =>
            evaluateQuestion(question, safeAnswers[index], evaluations[index])
        );
        const totalCorrect = results.filter(result => result.scorable && result.isCorrect).length;
        const totalQuestions = safeQuestions.length;
        const scorable = results.every(result => result.scorable);
        const passed = scorable && totalCorrect >= threshold;
        return {
            totalCorrect,
            totalQuestions,
            percentage: totalQuestions > 0 ? (totalCorrect / totalQuestions) * 100 : 0,
            passThreshold: threshold,
            results,
            passed,
            mode: passed ? 'protege' : 'tutor',
            scorable,
            invalidResults: results
                .map((result, index) => ({ ...result, index }))
                .filter(result => !result.scorable)
        };
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function getModeCopy(mode) {
        return mode === 'protege'
            ? {
                title: 'BiocBot is in protégé mode',
                body: "Excellent work! You've demonstrated strong understanding of the course material. I'm ready to be your study partner and help you explore advanced topics together. What questions do you have about the course material?"
            }
            : {
                title: 'BiocBot is in tutor mode',
                body: "Thanks for completing the assessment! I'm here to guide your learning and help explain concepts clearly. What questions do you have about the course material?"
            };
    }

    function buildModeResultHtml(score, questions) {
        const copy = getModeCopy(score.mode);
        const cards = (Array.isArray(questions) ? questions : []).map((question, index) => {
            const result = score.results[index];
            const feedback = result?.feedback
                ? `<div class="summary-feedback-section ${result.isCorrect ? 'correct' : 'incorrect'}"><div class="feedback-icon">${result.isCorrect ? '✅' : '❌'}</div><div class="feedback-content"><strong>Feedback:</strong> ${escapeHtml(result.feedback)}</div></div>`
                : '';
            return `<div class="summary-question-card"><div class="summary-question-header"><span class="summary-q-number">#${index + 1}</span><span class="summary-q-text">${escapeHtml(question?.question ?? '')}</span></div><div class="summary-answer-section"><div class="answer-box student"><span class="answer-box-label">Your Answer</span><div class="answer-box-content">${escapeHtml(result?.displayStudentAnswer ?? 'No valid answer provided')}</div></div><div class="answer-box expected"><span class="answer-box-label">Expected Answer</span><div class="answer-box-content">${escapeHtml(result?.displayExpectedAnswer ?? 'Invalid or unrecognized answer key')}</div></div></div>${feedback}</div>`;
        }).join('');
        return `<div class="mode-explanation"><strong>${escapeHtml(copy.title)}</strong><br>${escapeHtml(copy.body)}</div><div class="assessment-summary-container"><div class="assessment-summary-header"><h4 class="assessment-summary-title">Assessment Summary</h4><div class="assessment-summary-score">Score: ${score.totalCorrect}/${score.totalQuestions}</div></div><div class="assessment-questions-list">${cards}</div></div>`;
    }

    function buildModeResultText(score, questions) {
        const copy = getModeCopy(score.mode);
        const lines = [
            copy.title,
            copy.body,
            'Assessment Summary',
            `Score: ${score.totalCorrect}/${score.totalQuestions}`
        ];
        (Array.isArray(questions) ? questions : []).forEach((question, index) => {
            const result = score.results[index];
            lines.push(
                `#${index + 1} ${question?.question ?? ''}`,
                `Your Answer: ${result?.displayStudentAnswer ?? 'No valid answer provided'}`,
                `Expected Answer: ${result?.displayExpectedAnswer ?? 'Invalid or unrecognized answer key'}`
            );
            if (result?.feedback) lines.push(`Feedback: ${result.feedback}`);
        });
        return lines.join('\n');
    }

    return {
        LEGACY_MC_INDEX,
        getQuestionType,
        getExpectedAnswer,
        getOptionEntries,
        normalizeAnswer,
        formatAnswer,
        evaluateQuestion,
        evaluateAssessment,
        buildModeResultHtml,
        buildModeResultText
    };
}));
