const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const settingsRouter = require('../../../src/routes/settings');

const instructor = { userId: 'i1', role: 'instructor' };
const otherInstructor = { userId: 'i2', role: 'instructor' };
const admin = { userId: 'admin1', role: 'instructor', permissions: { systemAdmin: true } };

function app(db, user = instructor) {
    return makeRouteApp(settingsRouter, { db, user });
}

beforeAll(() => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('settings chat survey routes', () => {
    test('GET /chat-survey requires courseId and instructor course access', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }]
        });

        expect((await request(app(db)).get('/chat-survey')).status).toBe(400);

        const denied = await request(app(db, otherInstructor)).get('/chat-survey?courseId=C1');
        expect(denied.status).toBe(403);
    });

    test('GET /chat-survey returns defaults for the course owner', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }]
        });

        const res = await request(app(db)).get('/chat-survey?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
            success: true,
            settings: {
                enabled: false,
                triggerMessageCount: 10,
                promptText: 'How useful is this chat so far',
                introText: 'So BIOCBOT would like your help to improve the user and learning experience, if you are able to please rate your recent experience with BIOCBOT',
                accuracyPrompt: 'Has BIOCBOT been presenting accurate and appropriate content?',
                satisfactionPrompt: 'Are you satisfied with your learning experience using BIOCBOT?',
                allowFreeText: false
            },
            defaults: {
                minTriggerMessageCount: 2,
                maxTriggerMessageCount: 30
            }
        });
    });

    test('POST /chat-survey persists normalized settings', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }]
        });

        const res = await request(app(db)).post('/chat-survey').send({
            courseId: 'C1',
            enabled: true,
            triggerMessageCount: 14,
            promptText: '  Did this help your studying? ',
            introText: '  Please   rate your experience  ',
            accuracyPrompt: '  Was it accurate?  ',
            satisfactionPrompt: '  Are you   satisfied?  ',
            allowFreeText: false
        });

        expect(res.status).toBe(200);
        expect(res.body.settings).toMatchObject({
            enabled: true,
            triggerMessageCount: 14,
            promptText: 'Did this help your studying?',
            introText: 'Please rate your experience',
            accuracyPrompt: 'Was it accurate?',
            satisfactionPrompt: 'Are you satisfied?',
            allowFreeText: false
        });

        const stored = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(stored.chatSurveySettings.updatedById).toBe('i1');
    });

    test('POST /chat-survey rejects out-of-range trigger counts', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }]
        });

        const res = await request(app(db)).post('/chat-survey').send({
            courseId: 'C1',
            triggerMessageCount: 40
        });

        expect(res.status).toBe(400);
        expect(res.body.message).toBe('Survey trigger must be an integer from 2 to 30');
    });

    test('a system admin can manage another instructor course', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }]
        });

        const res = await request(app(db, admin)).post('/chat-survey').send({
            courseId: 'C1',
            triggerMessageCount: 10,
            promptText: 'Admin prompt',
            ratingPrompt: 'Admin rating',
            allowFreeText: true
        });

        expect(res.status).toBe(200);
        expect(res.body.settings.promptText).toBe('Admin prompt');
    });
});
