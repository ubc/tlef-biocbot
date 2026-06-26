const { memoryDb } = require('../helpers/memory-db');
const ChatSurveyResponse = require('../../../src/models/ChatSurveyResponse');

const COLL = ChatSurveyResponse.COLLECTION_NAME;

const settings = {
    enabled: true,
    triggerMessageCount: 10,
    promptText: 'Was this useful?',
    ratingPrompt: 'Rate the chat',
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

    test('records a submitted star rating without requiring a comment', async () => {
        const db = memoryDb();
        const result = await ChatSurveyResponse.upsertChatSurveyEvent(db, {
            courseId: 'C1',
            studentId: 's1',
            studentName: 'Student One',
            conversationId: 'session-1',
            eventType: 'submitted',
            rating: 5,
            comment: '',
            settings,
            messageCountAtPrompt: 10
        });

        expect(result.success).toBe(true);
        expect(result.response).toMatchObject({
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            rating: 5,
            comment: null,
            lastEvent: 'submitted',
            messageCountAtPrompt: 10
        });
        expect(result.response.submittedAt).toBeInstanceOf(Date);
    });

    test('rejects submitted events without a valid star rating', async () => {
        const result = await ChatSurveyResponse.upsertChatSurveyEvent(memoryDb(), {
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            eventType: 'submitted',
            rating: 6,
            settings
        });

        expect(result).toEqual({
            success: false,
            error: 'rating must be an integer from 1 to 5'
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
            rating: 4,
            comment: 'Useful later in the chat'
        });

        expect(shown.response.responseId).toBe(dismissed.response.responseId);
        expect(submitted.response.responseId).toBe(shown.response.responseId);
        expect(submitted.response.dismissedAt).toBeUndefined();
        expect(submitted.response.rating).toBe(4);

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
                    rating: 5,
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
            averageRating: 5
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
