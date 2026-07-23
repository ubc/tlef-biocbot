'use strict';

const { repairChatData } = require('../../../scripts/repair-assessment-summaries');

function inconsistentFixture() {
    return {
        metadata: { currentMode: 'tutor' },
        practiceTests: {
            passThreshold: 2,
            questions: [
                {
                    question: 'First?',
                    questionType: 'multiple-choice',
                    options: ['Initiation', 'Termination'],
                    correctAnswer: 0,
                    isCorrect: false
                },
                {
                    question: 'Second?',
                    questionType: 'true-false',
                    correctAnswer: false,
                    isCorrect: false
                }
            ]
        },
        studentAnswers: {
            answers: [
                { questionIndex: 0, answer: 0, isCorrect: false },
                { questionIndex: 1, answer: 1, isCorrect: false }
            ]
        },
        messages: [{
            messageType: 'mode-result',
            content: 'BiocBot is in protégé mode Assessment Summary Score: 0/2 Expected Answer: N/A',
            htmlContent: '<div>Score: 0/2</div><div>Expected Answer: N/A</div>',
            modeData: { determinedMode: 'protege' }
        }]
    };
}

describe('assessment summary historical repair', () => {
    test('dry-run calculation detects and repairs an inconsistent fixture without mutating it', () => {
        const fixture = inconsistentFixture();
        const original = JSON.parse(JSON.stringify(fixture));
        const repair = repairChatData(fixture);

        expect(fixture).toEqual(original);
        expect(repair).toMatchObject({
            changed: true,
            oldScore: '0/2',
            newScore: '2/2',
            skippedReason: null
        });
        expect(repair.changedFields).toEqual(expect.arrayContaining([
            'practiceTests.questions[0].isCorrect',
            'practiceTests.questions[1].isCorrect',
            'studentAnswers.answers[0].isCorrect',
            'studentAnswers.answers[1].isCorrect',
            'messages[0].content',
            'messages[0].htmlContent',
            'metadata.currentMode'
        ]));
        expect(repair.chatData.metadata.currentMode).toBe('protege');
        expect(repair.chatData.practiceTests.questions.map(q => q.isCorrect)).toEqual([true, true]);
        expect(repair.chatData.studentAnswers.answers.map(a => a.isCorrect)).toEqual([true, true]);
        expect(repair.chatData.messages[0].content).toContain('Score: 2/2');
        expect(repair.chatData.messages[0].content).toContain('Expected Answer: A) Initiation');
        expect(repair.chatData.messages[0].content).toContain('Expected Answer: False');
        expect(repair.chatData.messages[0].htmlContent).not.toContain('N/A');
    });

    test('repair is idempotent when applied twice to a fixture', () => {
        const first = repairChatData(inconsistentFixture());
        const second = repairChatData(first.chatData);

        expect(first.changed).toBe(true);
        expect(second.changed).toBe(false);
        expect(second.skippedReason).toBeNull();
        expect(second.changedFields).toEqual([]);
    });

    test('does not overwrite a later manual mode toggle', () => {
        const fixture = inconsistentFixture();
        fixture.messages.push({ messageType: 'mode-toggle-result', content: 'Tutor manually selected' });
        fixture.metadata.currentMode = 'tutor';
        const repair = repairChatData(fixture);

        expect(repair.preservedLaterManualMode).toBe(true);
        expect(repair.chatData.metadata.currentMode).toBe('tutor');
        expect(repair.changedFields).not.toContain('metadata.currentMode');
    });

    test('skips invalid structured answer keys instead of guessing', () => {
        const fixture = inconsistentFixture();
        fixture.practiceTests.questions[0].correctAnswer = 'Z';
        const repair = repairChatData(fixture);

        expect(repair.changed).toBe(false);
        expect(repair.skippedReason).toContain('unscorable structured data');
    });

    test('skips non-exact historical short answers without a trustworthy evaluation', () => {
        const fixture = inconsistentFixture();
        fixture.practiceTests.questions[1] = {
            question: 'Explain it.',
            questionType: 'short-answer',
            correctAnswer: 'A detailed expected response'
        };
        fixture.studentAnswers.answers[1] = {
            questionIndex: 1,
            answer: 'A semantically similar response'
        };
        const repair = repairChatData(fixture);

        expect(repair.changed).toBe(false);
        expect(repair.skippedReason).toContain('short answer without a trustworthy persisted evaluation');
    });
});
