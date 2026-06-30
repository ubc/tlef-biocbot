/**
 * Passport-driven coverage for src/routes/auth.js: POST /login's
 * passport.authenticate('local', callback) flow, POST /logout (local +
 * CWL/SAML branches), GET /saml, and POST /saml/callback.
 *
 * The whole `passport` module is mocked (pattern copied from
 * tests/unit/routes/shibboleth.test.js) so these routes can be driven without a
 * real strategy/session store. req.login/req.logout/req.session are injected
 * directly by a small local app builder (not the shared route-app helper,
 * which doesn't model Passport's req.login/req.logout monkey-patches).
 */
// passport.authenticate('saml', {...}) is invoked at route-registration time
// (module load), before any test sets up mockAuthenticate's per-test
// implementation, so fall back to a no-op middleware when nothing is configured.
const mockAuthenticate = jest.fn();
jest.mock('passport', () => ({
    authenticate: (...args) => mockAuthenticate(...args) || ((req, res, next) => next()),
}));

const express = require('express');
const request = require('supertest');
const router = require('../../../src/routes/auth');

function buildApp({ db = null, user = null, session, locals = {}, login, logout, omitSession = false } = {}) {
    const app = express();
    app.use(express.json());
    app.locals.db = db;
    Object.assign(app.locals, locals);
    app.use((req, res, next) => {
        if (user) req.user = user;
        if (!omitSession) req.session = session || {};
        req.login = login || ((u, cb) => cb(null));
        req.logout = logout || ((cb) => cb(null));
        next();
    });
    app.use('/', router);
    return app;
}

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => mockAuthenticate.mockReset());
afterAll(() => jest.restoreAllMocks());

// Helper: make the 'local' strategy mock invoke the route's (err, user, info) callback.
function mockLocalAuth(err, user, info) {
    mockAuthenticate.mockImplementation((strategy, cb) => (req, res, next) => cb(err, user, info));
}

describe('POST /login passport.authenticate flow', () => {
    test('500 when passport reports an error', async () => {
        mockLocalAuth(new Error('strategy exploded'), null, null);
        const res = await request(buildApp({})).post('/login').send({ username: 'a', password: 'b' });
        expect(res.status).toBe(500);
        expect(res.body.error).toMatch(/login failed/i);
    });

    test('401 with the strategy-provided message when no user is returned', async () => {
        mockLocalAuth(null, false, { message: 'Bad credentials' });
        const res = await request(buildApp({})).post('/login').send({ username: 'a', password: 'b' });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Bad credentials');
    });

    test('401 with a default message when info has no message', async () => {
        mockLocalAuth(null, false, null);
        const res = await request(buildApp({})).post('/login').send({ username: 'a', password: 'b' });
        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Invalid username or password');
    });

    test('500 when req.login fails to create a session', async () => {
        const user = { userId: 'u1', role: 'student' };
        mockLocalAuth(null, user, null);
        const login = (u, cb) => cb(new Error('session store down'));
        const res = await request(buildApp({ login })).post('/login').send({ username: 'a', password: 'b' });
        expect(res.status).toBe(500);
        expect(res.body.error).toMatch(/failed to create session/i);
    });

    test('200 success uses authService.createSessionUser and redirects by role', async () => {
        const user = { userId: 'u1', role: 'instructor', displayName: 'Dr. I' };
        mockLocalAuth(null, user, null);
        const authService = { createSessionUser: jest.fn(() => ({ userId: 'u1', shaped: true })) };
        const session = {};
        const res = await request(buildApp({ session, locals: { authService } }))
            .post('/login').send({ username: 'a', password: 'b' });
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, redirect: '/instructor/home', user: { userId: 'u1', shaped: true } });
        expect(authService.createSessionUser).toHaveBeenCalledWith(user);
        expect(session).toMatchObject({ userId: 'u1', userRole: 'instructor', userDisplayName: 'Dr. I' });
    });

    test('200 success falls back to a manually shaped user when authService is absent', async () => {
        const user = {
            userId: 'u2', username: 'bob', email: 'b@x.com', role: 'student',
            displayName: 'Bob', authProvider: 'local', preferences: { theme: 'dark' },
        };
        mockLocalAuth(null, user, null);
        const res = await request(buildApp({ session: {} })).post('/login').send({ username: 'a', password: 'b' });
        expect(res.status).toBe(200);
        expect(res.body.user).toEqual({
            userId: 'u2', username: 'bob', email: 'b@x.com', role: 'student',
            displayName: 'Bob', authProvider: 'local', preferences: { theme: 'dark' },
        });
        expect(res.body.redirect).toBe('/student');
    });

    test.each([
        ['ta', '/ta'],
        ['unknown-role', '/login'],
    ])('redirect for role %s is %s', async (role, redirect) => {
        const user = { userId: 'u3', role };
        mockLocalAuth(null, user, null);
        const res = await request(buildApp({ session: {} })).post('/login').send({ username: 'a', password: 'b' });
        expect(res.body.redirect).toBe(redirect);
    });
});

describe('POST /logout', () => {
    beforeEach(() => mockAuthenticate.mockImplementation((strategy, opts) => (req, res, next) => next()));

    test('local user: success destroys the session and reports localOnly', async () => {
        const session = { userId: 's1', destroy: jest.fn((cb) => cb(null)) };
        const res = await request(buildApp({ session })).post('/logout');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, redirect: '/login' });
        // isCWL is computed as `req.user && ...`; with no req.user that's `undefined`,
        // which JSON.stringify drops entirely (not serialized as `false`).
        expect(res.body.debug).toMatchObject({ userId: 's1', localOnly: true });
        expect(res.body.debug).not.toHaveProperty('isCWL');
        expect(session.destroy).toHaveBeenCalled();
    });

    test('req.logout error is logged but logout still proceeds to destroy the session', async () => {
        const session = { userId: 's1', destroy: jest.fn((cb) => cb(null)) };
        const logout = (cb) => cb(new Error('passport logout broke'));
        const res = await request(buildApp({ session, logout })).post('/logout');
        expect(res.status).toBe(200);
        expect(res.body.debug.logoutError).toMatch(/passport logout broke/);
    });

    test('500 when session.destroy fails', async () => {
        const session = { userId: 's1', destroy: jest.fn((cb) => cb(new Error('disk full'))) };
        const res = await request(buildApp({ session })).post('/logout');
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('Failed to logout');
        expect(res.body.debug.destroyError).toMatch(/disk full/);
    });

    // These three drive the strategy.logout() branch and verify both callback and
    // synchronous failure behavior.
    describe('strategy.logout() branch (schedules a 5s timeout internally)', () => {
        test('strategy.logout succeeds and the SAML logout URL becomes the redirect', async () => {
            const user = { userId: 'cwl1', authProvider: 'saml' };
            const session = { destroy: jest.fn((cb) => cb(null)) };
            const strategy = { logout: jest.fn((req, cb) => cb(null, 'https://idp/logout?req=1')) };
            const passportLocal = { _strategies: { ubcshib: strategy } };
            const res = await request(buildApp({ user, session, locals: { passport: passportLocal } })).post('/logout');
            expect(res.status).toBe(200);
            expect(res.body.redirect).toBe('https://idp/logout?req=1');
            expect(res.body.debug).toMatchObject({ isCWL: true, strategyFound: true, samlLogoutInitiated: true, samlLogoutUrl: 'https://idp/logout?req=1', samlSuccess: true });
            expect(strategy.logout).toHaveBeenCalled();
        });

        test('strategy.logout callback error falls back to local logout', async () => {
            const user = { userId: 'cwl1', authProvider: 'saml' };
            const session = { destroy: jest.fn((cb) => cb(null)) };
            const strategy = { logout: jest.fn((req, cb) => cb(new Error('idp unreachable'))) };
            const passportLocal = { _strategies: { ubcshib: strategy } };
            const res = await request(buildApp({ user, session, locals: { passport: passportLocal } })).post('/logout');
            expect(res.status).toBe(200);
            expect(res.body.redirect).toBe('/login');
            expect(res.body.debug.samlError).toBe(true);
            expect(res.body.debug.error).toMatch(/idp unreachable/);
        });

        test('strategy.logout throwing synchronously falls back to local logout', async () => {
            const user = { userId: 'cwl1', authProvider: 'saml' };
            const session = { destroy: jest.fn((cb) => cb(null)) };
            const strategy = { logout: jest.fn(() => { throw new Error('sync explosion'); }) };
            const passportLocal = { _strategies: { ubcshib: strategy } };
            const res = await request(buildApp({ user, session, locals: { passport: passportLocal } })).post('/logout');
            expect(res.status).toBe(200);
            expect(res.body.redirect).toBe('/login');
            expect(res.body.debug.samlError).toBe(true);
            expect(res.body.debug.error).toMatch(/sync explosion/);
        });
    });

    test('CWL user: no strategy, falls back to passport.ubcShibHelpers.logout success', async () => {
        const user = { userId: 'cwl1', authProvider: 'saml' };
        const session = { destroy: jest.fn((cb) => cb(null)) };
        const passportLocal = { _strategies: {}, ubcShibHelpers: { logout: jest.fn((req, cb) => cb(null, 'https://idp/helper-logout')) } };
        const res = await request(buildApp({ user, session, locals: { passport: passportLocal } })).post('/logout');
        expect(res.status).toBe(200);
        expect(res.body.redirect).toBe('https://idp/helper-logout');
        expect(res.body.debug).toMatchObject({ helperFound: true, samlLogoutUrl: 'https://idp/helper-logout', helperSuccess: true });
    });

    test('CWL user: no strategy, helpers.logout errors falls back to local logout', async () => {
        const user = { userId: 'cwl1', authProvider: 'saml' };
        const session = { destroy: jest.fn((cb) => cb(null)) };
        const passportLocal = { _strategies: {}, ubcShibHelpers: { logout: jest.fn((req, cb) => cb(new Error('helper down'))) } };
        const res = await request(buildApp({ user, session, locals: { passport: passportLocal } })).post('/logout');
        expect(res.status).toBe(200);
        expect(res.body.redirect).toBe('/login');
        expect(res.body.debug.helperError).toBe(true);
    });

    test('CWL user: no strategy and no helpers falls through to standard local logout', async () => {
        const user = { userId: 'cwl1', authProvider: 'saml' };
        const session = { destroy: jest.fn((cb) => cb(null)) };
        const passportLocal = { _strategies: {} };
        const res = await request(buildApp({ user, session, locals: { passport: passportLocal } })).post('/logout');
        expect(res.status).toBe(200);
        expect(res.body.redirect).toBe('/login');
        expect(res.body.debug).toMatchObject({ isCWL: true, strategyFound: false, helperFound: false, localOnly: true });
    });

    test('CWL user: app.locals.passport itself is missing, falls through to standard local logout', async () => {
        const user = { userId: 'cwl1', authProvider: 'saml' };
        const session = { destroy: jest.fn((cb) => cb(null)) };
        const res = await request(buildApp({ user, session })).post('/logout');
        expect(res.status).toBe(200);
        expect(res.body.redirect).toBe('/login');
        expect(res.body.debug).toMatchObject({ isCWL: true, strategyFound: false, helperFound: false, localOnly: true });
    });

    test('500 outer catch when req.session is unavailable', async () => {
        const res = await request(buildApp({ omitSession: true })).post('/logout');
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('Logout failed');
    });
});

describe('GET /saml', () => {
    test('delegates to the saml strategy with a failureRedirect', async () => {
        mockAuthenticate.mockImplementation((strategy, opts) => (req, res, next) => next());
        const res = await request(buildApp({})).get('/saml');
        expect(mockAuthenticate).toHaveBeenCalledWith('saml', { failureRedirect: '/login?error=saml_failed' });
        expect(res.status).toBe(404); // mock calls next(); nothing downstream is mounted
    });
});

describe('POST /saml/callback', () => {
    beforeEach(() => mockAuthenticate.mockImplementation((strategy, opts) => (req, res, next) => next()));

    test.each([
        ['instructor', '/instructor/home'],
        ['student', '/student'],
        ['ta', '/ta'],
        ['unknown', '/login'],
    ])('redirects %s users to %s and stores session details', async (role, destination) => {
        const session = {};
        const user = { userId: 'u1', role, displayName: 'User' };
        const res = await request(buildApp({ user, session })).post('/saml/callback').type('form').send({ SAMLResponse: 'mock' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe(destination);
        expect(session).toEqual({ userId: 'u1', userRole: role, userDisplayName: 'User' });
    });

    test('redirects to /login and skips session writes when passport advances without a user', async () => {
        const session = {};
        const res = await request(buildApp({ session })).post('/saml/callback').type('form').send({ SAMLResponse: 'mock' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('/login');
        expect(session).toEqual({});
    });
});
