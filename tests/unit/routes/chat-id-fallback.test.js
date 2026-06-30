jest.mock('crypto', () => {
    const actual = jest.requireActual('crypto');
    return new Proxy(actual, {
        get(target, property) {
            return property === 'randomUUID' ? undefined : target[property];
        }
    });
});
jest.mock('../../../src/services/llm', () => jest.fn());
jest.mock('../../../src/services/gridfs', () => ({}));
jest.mock('../../../src/services/tracker', () => jest.fn());
jest.mock('../../../src/models/User', () => ({}));
jest.mock('../../../src/models/MentalHealthFlag', () => ({}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveCourseAi: jest.fn(),
    sendLlmKeyError: jest.fn(() => false)
}));

const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/chat');

test('chat message ids fall back when randomUUID is unavailable', async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    const app = makeRouteApp(router, { db: {} });
    const res = await request(app).post('/').send({
        message: 'this is shit', courseId: 'C1', unitName: 'Unit 1'
    });
    expect(res.status).toBe(200);
    expect(res.body.messageId).toMatch(/^msg_\d+_[a-z0-9]+$/);
    jest.restoreAllMocks();
});
