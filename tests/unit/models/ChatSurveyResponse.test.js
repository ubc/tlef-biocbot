const { memoryDb } = require('../helpers/memory-db');
const ChatSurveyResponse = require('../../../src/models/ChatSurveyResponse');

const COLL = ChatSurveyResponse.COLLECTION_NAME;

const settings = {
    enabled: true,
    triggerMessageCount: 10,
    promptText: 'Was this useful?',
    introText: 'Please rate your experience',
    accuracyPrompt: 'Was the content accurate?',
    satisfactionPrompt: 'Are you satisfied?',
    allowFreeText: true
};

describe('ChatSurveyResponse model', () => {
    test('builds stable settings fingerprints from normalized settings', () => {
        const a = ChatSurveyResponse.buildSettingsFingerprint({
            ...settings,
            promptText: 'Was this useful?'
        });
        const b = ChatSurveyResponse.buildSettingsFingerprint({
            ...settings,
            promptText: '  Was   this useful?  '
        });
        const c = ChatSurveyResponse.buildSettingsFingerprint({
            ...settings,
            triggerMessageCount: 12
        });

        expect(a).toBe(b);
        expect(a).not.toBe(c);
    });

    test('records submitted star ratings without requiring a comment', async () => {
        const db = memoryDb();
        const result = await ChatSurveyResponse.upsertChatSurveyEvent(db, {
            courseId: 'C1',
            studentId: 's1',
            studentName: 'Student One',
            conversationId: 'session-1',
            eventType: 'submitted',
            ratingAccuracy: 5,
            ratingSatisfaction: 4,
            comment: '',
            settings,
            messageCountAtPrompt: 10
        });

        expect(result.success).toBe(true);
        expect(result.response).toMatchObject({
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            ratingAccuracy: 5,
            ratingSatisfaction: 4,
            comment: null,
            lastEvent: 'submitted',
            messageCountAtPrompt: 10
        });
        expect(result.response.submittedAt).toBeInstanceOf(Date);
    });

    test('rejects submitted events without a valid accuracy rating', async () => {
        const result = await ChatSurveyResponse.upsertChatSurveyEvent(memoryDb(), {
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            eventType: 'submitted',
            ratingAccuracy: 6,
            ratingSatisfaction: 4,
            settings
        });

        expect(result).toEqual({
            success: false,
            error: 'ratingAccuracy must be an integer from 1 to 5'
        });
    });

    test('rejects submitted events without a valid satisfaction rating', async () => {
        const result = await ChatSurveyResponse.upsertChatSurveyEvent(memoryDb(), {
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            eventType: 'submitted',
            ratingAccuracy: 4,
            settings
        });

        expect(result).toEqual({
            success: false,
            error: 'ratingSatisfaction must be an integer from 1 to 5'
        });
    });

    test('upserts a single response per settings fingerprint and can replace dismissal with submission', async () => {
        const db = memoryDb();
        const base = {
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            settings,
            messageCountAtPrompt: 10
        };

        const shown = await ChatSurveyResponse.upsertChatSurveyEvent(db, {
            ...base,
            eventType: 'shown'
        });
        const dismissed = await ChatSurveyResponse.upsertChatSurveyEvent(db, {
            ...base,
            eventType: 'dismissed'
        });
        const submitted = await ChatSurveyResponse.upsertChatSurveyEvent(db, {
            ...base,
            eventType: 'submitted',
            ratingAccuracy: 4,
            ratingSatisfaction: 3,
            comment: 'Useful later in the chat'
        });

        expect(shown.response.responseId).toBe(dismissed.response.responseId);
        expect(submitted.response.responseId).toBe(shown.response.responseId);
        expect(submitted.response.dismissedAt).toBeUndefined();
        expect(submitted.response.ratingAccuracy).toBe(4);
        expect(submitted.response.ratingSatisfaction).toBe(3);

        const stored = await db.collection(COLL).find({}).toArray();
        expect(stored).toHaveLength(1);
    });

    test('lists responses, computes stats, and exports CSV', async () => {
        const db = memoryDb({
            [COLL]: [
                {
                    responseId: 'r1',
                    courseId: 'C1',
                    studentId: 's1',
                    studentName: 'A, Student',
                    conversationId: 'session-1',
                    ratingAccuracy: 5,
                    ratingSatisfaction: 3,
                    comment: 'Very useful',
                    shownAt: new Date('2026-01-01'),
                    submittedAt: new Date('2026-01-02'),
                    updatedAt: new Date('2026-01-02')
                },
                {
                    responseId: 'r2',
                    courseId: 'C1',
                    studentId: 's2',
                    conversationId: 'session-2',
                    shownAt: new Date('2026-01-03'),
                    dismissedAt: new Date('2026-01-03'),
                    updatedAt: new Date('2026-01-03')
                }
            ]
        });

        const submitted = await ChatSurveyResponse.listSurveyResponsesForCourse(db, 'C1', { status: 'submitted' });
        expect(submitted.map(item => item.responseId)).toEqual(['r1']);

        await expect(ChatSurveyResponse.getSurveyStatsForCourse(db, 'C1')).resolves.toEqual({
            total: 2,
            shown: 2,
            dismissed: 1,
            submitted: 1,
            averageAccuracy: 5,
            averageSatisfaction: 3
        });

        const csv = ChatSurveyResponse.surveyResponsesToCsv(submitted);
        expect(csv).toContain('responseId,courseId,unitName');
        expect(csv).toContain('"A, Student"');
        expect(csv).toContain('Very useful');
    });

    test('ensureIndexes runs against the in-memory Mongo double', async () => {
        await expect(ChatSurveyResponse.ensureIndexes(memoryDb({}))).resolves.toBeUndefined();
    });
});
