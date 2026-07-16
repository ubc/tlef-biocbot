/**
 * Deepened coverage for src/routes/auth.js: the branches NOT exercised by
 * auth.test.js — catch blocks, db-unavailable (503) guards, missing-authService
 * (500) guards, and authService-failure (400) branches. Passport-driven flows
 * (login success/error, logout, SAML) live in auth.passport.test.js.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/auth');

const instructor = { userId: 'i1', role: 'instructor', displayName: 'Dr. I' };

function makeAuthService(over = {}) {
    return {
        registerUser: jest.fn(async () => ({ success: true, userId: 'u9', user: { userId: 'u9', role: 'student' } })),
        createSessionUser: jest.fn((u) => ({ userId: u.userId, role: u.role, displayName: u.displayName })),
        getUserById: jest.fn(async () => null),
        updateUserPreferences: jest.fn(async () => ({ success: true })),
        setCurrentCourseId: jest.fn(async () => ({ success: true })),
        ...over,
    };
}

// A db stub whose named collection method always rejects, for exercising catch blocks.
function throwingDb(methodsByCollection) {
    return {
        collection: jest.fn((name) => methodsByCollection[name] || {}),
    };
}

const app = (opts) => makeRouteApp(router, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST /register catch block and branches', () => {
    test('500 when authService.registerUser throws', async () => {
        const authService = makeAuthService({ registerUser: jest.fn(async () => { throw new Error('db down'); }) });
        const res = await request(app({ db: memoryDb({}), locals: { authService } }))
            .post('/register').send({ username: 'a', password: 'b', role: 'student' });
        expect(res.status).toBe(500);
        expect(res.body.error).toMatch(/registration failed/i);
    });

    test('fails closed when registration cannot read the admin setting', async () => {
        const authService = makeAuthService();
        const res = await request(app({ db: null, locals: { authService } }))
            .post('/register').send({ username: 'a', password: 'b', role: 'student' });
        expect(res.status).toBe(503);
        expect(res.body.code).toBe('AUTH_SERVICE_UNAVAILABLE');
        expect(authService.registerUser).not.toHaveBeenCalled();
    });
});

describe('GET /me fallback session path and catch block', () => {
    test('200 falls back to session userId + authService.getUserById when no Passport user', async () => {
        const fallbackUser = { userId: 's1', role: 'student', displayName: 'Sess' };
        const authService = makeAuthService({ getUserById: jest.fn(async () => fallbackUser) });
        const res = await request(app({ db: memoryDb({}), session: { userId: 's1' }, locals: { authService } }))
            .get('/me');
        expect(res.status).toBe(200);
        expect(authService.getUserById).toHaveBeenCalledWith('s1');
        expect(res.body.user).toMatchObject({ userId: 's1', role: 'student' });
    });

    test('401 when session userId resolves to no user', async () => {
        const authService = makeAuthService({ getUserById: jest.fn(async () => null) });
        const res = await request(app({ db: memoryDb({}), session: { userId: 'ghost' }, locals: { authService } }))
            .get('/me');
        expect(res.status).toBe(401);
    });

    test('401 when a session userId exists but no authService is registered at all', async () => {
        const res = await request(app({ db: memoryDb({}), session: { userId: 's1' } })).get('/me');
        expect(res.status).toBe(401);
    });

    test('500 when authService.createSessionUser throws', async () => {
        const authService = makeAuthService({ createSessionUser: jest.fn(() => { throw new Error('boom'); }) });
        const res = await request(app({ db: memoryDb({}), user: instructor, locals: { authService } })).get('/me');
        expect(res.status).toBe(500);
        expect(res.body.error).toMatch(/failed to get user/i);
    });
});

describe('PUT /preferences uncovered branches', () => {
    test('500 when the auth service is unavailable', async () => {
        const res = await request(app({ db: memoryDb({}), session: { userId: 'i1' } }))
            .put('/preferences').send({ preferences: { theme: 'dark' } });
        expect(res.status).toBe(500);
    });

    test('400 surfacing the auth service failure', async () => {
        const authService = makeAuthService({ updateUserPreferences: jest.fn(async () => ({ success: false, error: 'Invalid prefs' })) });
        const res = await request(app({ db: memoryDb({}), session: { userId: 'i1' }, locals: { authService } }))
            .put('/preferences').send({ preferences: { theme: 'dark' } });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Invalid prefs');
    });

    test('500 catch block when the auth service throws', async () => {
        const authService = makeAuthService({ updateUserPreferences: jest.fn(async () => { throw new Error('boom'); }) });
        const res = await request(app({ db: memoryDb({}), session: { userId: 'i1' }, locals: { authService } }))
            .put('/preferences').send({ preferences: { theme: 'dark' } });
        expect(res.status).toBe(500);
        expect(res.body.error).toMatch(/failed to update preferences/i);
    });
});

describe('POST /set-course uncovered branches', () => {
    test('500 when the auth service is unavailable', async () => {
        const res = await request(app({ db: memoryDb({}), session: { userId: 'i1' } }))
            .post('/set-course').send({ courseId: 'C1' });
        expect(res.status).toBe(500);
    });

    test('400 surfacing the auth service failure', async () => {
        const authService = makeAuthService({ setCurrentCourseId: jest.fn(async () => ({ success: false, error: 'No such course' })) });
        const res = await request(app({ db: memoryDb({}), session: { userId: 'i1' }, locals: { authService } }))
            .post('/set-course').send({ courseId: 'C-missing' });
        expect(res.status).toBe(400);
        expect(res.body.error).toBe('No such course');
    });

    test('500 catch block when the auth service throws', async () => {
        const authService = makeAuthService({ setCurrentCourseId: jest.fn(async () => { throw new Error('boom'); }) });
        const res = await request(app({ db: memoryDb({}), session: { userId: 'i1' }, locals: { authService } }))
            .post('/set-course').send({ courseId: 'C1' });
        expect(res.status).toBe(500);
        expect(res.body.error).toMatch(/failed to set course context/i);
    });
});

describe('GET /tas catch block', () => {
    test('500 when the users query throws', async () => {
        const fail = jest.fn(() => { throw new Error('query failed'); });
        const db = throwingDb({
            users: { find: jest.fn(() => ({ project: () => ({ sort: () => ({ toArray: fail }) }) })) },
        });
        const res = await request(app({ db, user: instructor })).get('/tas');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/internal server error/i);
    });
});

describe('GET /users/:userId uncovered branches', () => {
    test('401 without an authenticated user', async () => {
        const res = await request(app({ db: memoryDb({}) })).get('/users/x');
        expect(res.status).toBe(401);
    });

    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: instructor })).get('/users/x');
        expect(res.status).toBe(503);
    });

    test('500 when the users query throws', async () => {
        const db = throwingDb({ users: { findOne: jest.fn(async () => { throw new Error('boom'); }) } });
        const res = await request(app({ db, user: instructor })).get('/users/x');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/internal server error/i);
    });
});

describe('DELETE /tas/:taId uncovered branches', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: instructor })).delete('/tas/t1');
        expect(res.status).toBe(503);
    });

    test('500 when the update throws', async () => {
        const db = throwingDb({ users: { updateOne: jest.fn(async () => { throw new Error('boom'); }) } });
        const res = await request(app({ db, user: instructor })).delete('/tas/t1');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/internal server error/i);
    });
});

describe('GET /methods catch block and branches', () => {
    test('503 with safe methods when reading global settings throws', async () => {
        const db = throwingDb({ settings: { findOne: jest.fn(async () => { throw new Error('boom'); }) } });
        const res = await request(app({ db })).get('/methods');
        expect(res.status).toBe(503);
        expect(res.body.error).toMatch(/temporarily unavailable/i);
        expect(res.body.methods).toMatchObject({ local: false, ubcshib: false, allowLocalLogin: false, serviceAvailable: false });
    });

    test('fails closed when there is no database', async () => {
        const res = await request(app({ db: null })).get('/methods');
        expect(res.status).toBe(503);
        expect(res.body.methods).toMatchObject({ local: false, allowLocalLogin: false, serviceAvailable: false });
    });

    test('an explicit allowLocalLogin: true leaves local enabled', async () => {
        const db = memoryDb({ settings: [{ _id: 'global', allowLocalLogin: true }] });
        const res = await request(app({ db })).get('/methods');
        expect(res.body.methods).toMatchObject({ local: true, allowLocalLogin: true });
    });
});

describe('POST /promote-to-ta uncovered branches', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: instructor })).post('/promote-to-ta').send({ userId: 's9' });
        expect(res.status).toBe(503);
    });

    test('500 when the update throws (caught after ownership check passes)', async () => {
        const db = throwingDb({
            courses: { findOne: jest.fn(async () => ({ courseId: 'C1', instructorId: 'i1' })) },
            users: { updateOne: jest.fn(async () => { throw new Error('boom'); }) },
        });
        const res = await request(app({ db, user: instructor })).post('/promote-to-ta').send({ userId: 's9', courseId: 'C1' });
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/internal server error/i);
    });

    test('owns the course via the instructors array even when instructorId differs', async () => {
        const db = memoryDb({
            users: [{ userId: 's9', role: 'student' }],
            courses: [{ courseId: 'C1', instructorId: 'someone-else', instructors: ['i1'], status: 'active' }],
        });
        const res = await request(app({ db, user: instructor })).post('/promote-to-ta').send({ userId: 's9', courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ userId: 's9', invitedToCourse: 'C1' });
    });

    test('promotes a student with no courseId: skips ownership check, invitedToCourse is null', async () => {
        const db = memoryDb({ users: [{ userId: 's9', role: 'student' }] });
        const res = await request(app({ db, user: instructor })).post('/promote-to-ta').send({ userId: 's9' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ userId: 's9', role: 'ta', invitedToCourse: null });
        const saved = await db.collection('users').findOne({ userId: 's9' });
        expect(saved.invitedCourses).toBeUndefined();
    });
});
