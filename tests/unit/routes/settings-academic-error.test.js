jest.mock('../../../src/services/academicApi', () => ({
    isAcademicApiEnabled: jest.fn().mockRejectedValue(new Error('gate failed'))
}));

const { makeRouteApp, request } = require('../helpers/route-app');
const settingsRouter = require('../../../src/routes/settings');

test('academic API gate fails closed if its service rejects', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const app = makeRouteApp(settingsRouter, { db: {} });
    const res = await request(app).get('/academic-api-enabled');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, enabled: false });
    jest.restoreAllMocks();
});
