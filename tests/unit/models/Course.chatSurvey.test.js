const { memoryDb } = require('../helpers/memory-db');
const Course = require('../../../src/models/Course');

describe('Course chat survey settings', () => {
    test('returns defaults for an existing course with no survey settings', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const result = await Course.getChatSurveySettings(db, 'C1');

        expect(result).toMatchObject({
            success: true,
            settings: {
                enabled: false,
                triggerMessageCount: 10,
                promptText: 'Was this chat helpful?',
                ratingPrompt: 'How useful was this conversation?',
                allowFreeText: false
            },
            defaults: {
                minTriggerMessageCount: 2,
                maxTriggerMessageCount: 30
            }
        });
    });

    test('normalizes and persists valid settings', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const result = await Course.updateChatSurveySettings(db, 'C1', {
            enabled: true,
            triggerMessageCount: 12,
            promptText: '  Was this time well   spent?  ',
            ratingPrompt: '  Rate this chat  ',
            allowFreeText: false
        }, 'i1');

        expect(result.success).toBe(true);
        expect(result.settings).toMatchObject({
            enabled: true,
            triggerMessageCount: 12,
            promptText: 'Was this time well spent?',
            ratingPrompt: 'Rate this chat',
            allowFreeText: false,
            updatedById: 'i1'
        });
        expect(result.settings.updatedAt).toBeInstanceOf(Date);

        const stored = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(stored.chatSurveySettings.triggerMessageCount).toBe(12);
        expect(stored.lastUpdatedById).toBe('i1');
    });

    test('rejects trigger counts outside the per-session chat range', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });

        await expect(Course.updateChatSurveySettings(db, 'C1', {
            triggerMessageCount: 31
        })).resolves.toMatchObject({
            success: false,
            error: 'Survey trigger must be an integer from 2 to 30'
        });

        await expect(Course.updateChatSurveySettings(db, 'C1', {
            triggerMessageCount: 1
        })).resolves.toMatchObject({
            success: false,
            error: 'Survey trigger must be an integer from 2 to 30'
        });

        const stored = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(stored.chatSurveySettings).toBeUndefined();
    });

    test('reports missing or deleted courses', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'DELETED', status: 'deleted' }]
        });

        await expect(Course.getChatSurveySettings(db, 'NOPE')).resolves.toMatchObject({
            success: false,
            error: 'Course not found'
        });
        await expect(Course.updateChatSurveySettings(db, 'DELETED', {
            triggerMessageCount: 10
        })).resolves.toMatchObject({
            success: false,
            error: 'Course not found'
        });
    });
});
