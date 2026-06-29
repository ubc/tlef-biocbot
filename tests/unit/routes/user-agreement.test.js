/**
 * In-process route tests for src/routes/user-agreement.js (supertest).
 *
 * No heavy deps: the router reads the UserAgreement model over the in-memory Mongo
 * double and req.user. Covers the status read (default vs stored), recording an
 * agreement (upsert), the db guard, and the missing-user characterization.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/user-agreement');

const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(router, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /status', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: student })).get('/status');
        expect(res.status).toBe(503);
    });

    test('defaults to hasAgreed:false when no record exists', async () => {
        const res = await request(app({ db: memoryDb({ userAgreements: [] }), user: student })).get('/status');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ hasAgreed: false, agreementVersion: '1.0', agreedAt: null });
    });

    test('returns the stored agreement for the user\'s role', async () => {
        const agreedAt = new Date('2026-05-01T00:00:00Z');
        const db = memoryDb({ userAgreements: [
            { userId: 's1', userType: 'student', hasAgreed: true, agreementVersion: '2.0', agreedAt },
            { userId: 's1', userType: 'instructor', hasAgreed: true, agreementVersion: '9.9' }, // different role
        ] });
        const res = await request(app({ db, user: student })).get('/status');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ hasAgreed: true, agreementVersion: '2.0' });
    });

    test('500 when there is no authenticated user (handler destructures req.user)', async () => {
        // The handler reads `const { userId, role } = req.user` with no guard; in
        // production the mount applies requireAuth. Characterized, not fixed.
        const res = await request(app({ db: memoryDb({}) })).get('/status');
        expect(res.status).toBe(500);
    });
});

describe('POST /agree', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: student })).post('/agree').send({});
        expect(res.status).toBe(503);
    });

    test('records the agreement (upsert) and stamps agreedAt', async () => {
        const db = memoryDb({ userAgreements: [] });
        const res = await request(app({ db, user: student })).post('/agree').send({ agreementVersion: '2.0' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ hasAgreed: true, agreementVersion: '2.0' });
        expect(res.body.data.agreedAt).toBeTruthy();
        const saved = await db.collection('userAgreements').findOne({ userId: 's1', userType: 'student' });
        expect(saved).toMatchObject({ hasAgreed: true, agreementVersion: '2.0' });
    });

    test('defaults the agreement version to 1.0 when none is supplied', async () => {
        const db = memoryDb({ userAgreements: [] });
        const res = await request(app({ db, user: student })).post('/agree').send({});
        expect(res.status).toBe(200);
        expect(res.body.data.agreementVersion).toBe('1.0');
    });
});
