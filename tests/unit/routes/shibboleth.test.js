const mockAuthenticate = jest.fn(() => (req, _res, next) => next());
jest.mock('passport', () => ({ authenticate: (...args) => mockAuthenticate(...args) }));

const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/shibboleth');

const app = options => makeRouteApp(router, options);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('Shibboleth routes with mocked Passport', () => {
    test('login invokes the ubcshib strategy', async () => {
        const res = await request(app({})).get('/Shibboleth.sso/Login');
        expect(res.status).toBe(404); // mock calls next; no downstream application route is mounted
        expect(mockAuthenticate).toHaveBeenCalledWith('ubcshib', { failureRedirect: '/login?error=ubcshib_failed' });
    });

    test('login returns 503 when strategy lookup throws synchronously', async () => {
        mockAuthenticate.mockImplementationOnce(() => { throw new Error('strategy missing'); });
        const res = await request(app({})).get('/Shibboleth.sso/Login');
        expect(res.status).toBe(503);
        expect(res.body.error).toMatch(/not available or misconfigured/);
    });

    test.each([
        ['instructor', '/instructor/home'],
        ['student', '/student'],
        ['ta', '/ta'],
        ['unknown', '/'],
    ])('SAML callback stores %s session details and redirects', async (role, destination) => {
        const session = {};
        const user = { userId: 'u1', role, displayName: 'User' };
        const res = await request(app({ user, session })).post('/Shibboleth.sso/SAML2/POST').type('form').send({ SAMLResponse: 'mock' });
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe(destination);
        expect(session).toEqual({ userId: 'u1', userRole: role, userDisplayName: 'User' });
    });

    test('SAML callback currently throws when Passport advances without a user', async () => {
        const res = await request(app({ session: {} })).post('/Shibboleth.sso/SAML2/POST').type('form').send({ SAMLResponse: 'mock' });
        expect(res.status).toBe(500);
    });

    test.each([
        ['get', '/Shibboleth.sso/SLO/Redirect'],
        ['post', '/Shibboleth.sso/SLO/POST'],
        ['post', '/Shibboleth.sso/SLO/Artifact'],
    ])('SLO placeholder %s %s redirects to login', async (method, path) => {
        const res = await request(app({}))[method](path);
        expect(res.status).toBe(302);
        expect(res.headers.location).toBe('/login?logout=slo_success');
    });
});

describe('local SAML alias routes (ENABLE_LOCAL_SAML_ALIASES=true at load)', () => {
    test('registers /auth/saml/callback and /auth/logout aliases', async () => {
        const previous = process.env.ENABLE_LOCAL_SAML_ALIASES;
        process.env.ENABLE_LOCAL_SAML_ALIASES = 'true';
        let aliasRouter;
        jest.isolateModules(() => { aliasRouter = require('../../../src/routes/shibboleth'); });
        if (previous === undefined) delete process.env.ENABLE_LOCAL_SAML_ALIASES;
        else process.env.ENABLE_LOCAL_SAML_ALIASES = previous;

        const session = {};
        const user = { userId: 'u1', role: 'student', displayName: 'User' };
        const cb = await request(makeRouteApp(aliasRouter, { user, session }))
            .post('/auth/saml/callback').type('form').send({ SAMLResponse: 'mock' });
        expect(cb.status).toBe(302);
        expect(cb.headers.location).toBe('/student');

        const logoutGet = await request(makeRouteApp(aliasRouter, {})).get('/auth/logout');
        expect(logoutGet.status).toBe(302);
        expect(logoutGet.headers.location).toBe('/login?logout=slo_success');
        const logoutPost = await request(makeRouteApp(aliasRouter, {})).post('/auth/logout');
        expect(logoutPost.headers.location).toBe('/login?logout=slo_success');
    });
});
