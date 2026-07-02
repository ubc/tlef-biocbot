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

describe('ChatSurveyResponse validation and filter coverage', () => {
    const base = { courseId: 'C1', studentId: 's1', conversationId: 'conv1', settings };

    test('generateSurveyResponseId falls back to a timestamp id without crypto.randomUUID', () => {
        const crypto = require('crypto');
        const original = crypto.randomUUID;
        // Simulate an older runtime with no crypto.randomUUID.
        crypto.randomUUID = undefined;
        try {
            expect(ChatSurveyResponse.generateSurveyResponseId()).toMatch(/^survey_\d+_[a-z0-9]+$/);
        } finally {
            crypto.randomUUID = original;
        }
    });

    test('upsert rejects missing identifiers, bad event types, and blank fingerprints', async () => {
        const db = memoryDb({});
        expect(await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, courseId: '  ' }))
            .toEqual({ success: false, error: 'courseId is required' });
        expect(await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, eventType: 'poked' }))
            .toEqual({ success: false, error: 'eventType must be "shown", "dismissed", or "submitted"' });
        expect(await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, eventType: 'shown', settingsFingerprint: '   ' }))
            .toEqual({ success: false, error: 'settingsFingerprint is required' });
    });

    test('later non-submit events are ignored once a session has submitted', async () => {
        const db = memoryDb({});
        const submitted = await ChatSurveyResponse.upsertChatSurveyEvent(db, {
            ...base, eventType: 'submitted', ratingAccuracy: 5, ratingSatisfaction: 4,
        });
        expect(submitted.success).toBe(true);

        const shownAgain = await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, eventType: 'shown' });
        expect(shownAgain).toMatchObject({ success: true, ignored: true });
        expect(shownAgain.response.ratingAccuracy).toBe(5);
    });

    test('listSurveyResponsesForCourse filters by student, conversation, and status', async () => {
        const db = memoryDb({});
        await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, eventType: 'shown' });
        await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, studentId: 's2', conversationId: 'conv2', eventType: 'dismissed' });
        await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, studentId: 's3', eventType: 'submitted', ratingAccuracy: 3, ratingSatisfaction: 3 });

        const s2 = await ChatSurveyResponse.listSurveyResponsesForCourse(db, 'C1', { studentId: 's2', conversationId: 'conv2' });
        expect(s2.map(r => r.studentId)).toEqual(['s2']);

        const dismissed = await ChatSurveyResponse.listSurveyResponsesForCourse(db, 'C1', { status: 'dismissed' });
        expect(dismissed.map(r => r.studentId)).toEqual(['s2']);

        const shown = await ChatSurveyResponse.listSurveyResponsesForCourse(db, 'C1', { status: 'shown' });
        expect(shown.length).toBeGreaterThanOrEqual(1);

        const submitted = await ChatSurveyResponse.listSurveyResponsesForCourse(db, 'C1', { status: 'submitted' });
        expect(submitted.map(r => r.studentId)).toEqual(['s3']);
    });
});

describe('ChatSurveyResponse.getSurveyResponseForSession', () => {
    const base = { courseId: 'C1', studentId: 's1', conversationId: 'conv1', settings };

    test('returns null for invalid keys or a blank fingerprint, else the stored response', async () => {
        const db = memoryDb({});
        expect(await ChatSurveyResponse.getSurveyResponseForSession(db, { ...base, courseId: '' })).toBeNull();
        expect(await ChatSurveyResponse.getSurveyResponseForSession(db, { ...base })).toBeNull(); // no fingerprint

        const saved = await ChatSurveyResponse.upsertChatSurveyEvent(db, { ...base, eventType: 'shown' });
        const fingerprint = saved.response.settingsFingerprint;
        const found = await ChatSurveyResponse.getSurveyResponseForSession(db, { ...base, settingsFingerprint: fingerprint });
        expect(found).toMatchObject({ courseId: 'C1', studentId: 's1', settingsFingerprint: fingerprint });
        expect(found).not.toHaveProperty('_id');

        expect(await ChatSurveyResponse.getSurveyResponseForSession(db, { ...base, settingsFingerprint: 'nope' })).toBeNull();
    });
});
