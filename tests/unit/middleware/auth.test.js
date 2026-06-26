/**
 * Unit tests for src/middleware/auth.js (the createAuthMiddleware(db) factory).
 *
 * Strategy: drive each middleware with fake req/res/next and assert the observable
 * outcome — next() vs res.status().json() vs res.redirect(). We populate req.user
 * directly (the Passport path) so we exercise the authz branches without the
 * db/bcrypt session-hydration path. requireTAPermission does hit the Course model,
 * so that group seeds the in-memory db.
 */
const { memoryDb } = require('../helpers/memory-db');
const createAuthMiddleware = require('../../../src/middleware/auth');

function makeRes() {
    return {
        statusCode: undefined,
        body: undefined,
        redirectedTo: undefined,
        status(code) { this.statusCode = code; return this; },
        json(obj) { this.body = obj; return this; },
        redirect(url) { this.redirectedTo = url; return this; },
    };
}

function makeReq(overrides = {}) {
    return { path: '/x', originalUrl: '/x', query: {}, body: {}, params: {}, session: undefined, user: undefined, ...overrides };
}

let mw;
let next;
beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());
beforeEach(() => {
    mw = createAuthMiddleware(memoryDb({}));
    next = jest.fn();
});

describe('requireAuth', () => {
    test('calls next() when req.user is present (Passport path)', async () => {
        const res = makeRes();
        await mw.requireAuth(makeReq({ user: { userId: 'u1' } }), res, next);
        expect(next).toHaveBeenCalledTimes(1);
        expect(res.statusCode).toBeUndefined();
    });

    test('API request with no auth returns 401 JSON', async () => {
        const res = makeRes();
        await mw.requireAuth(makeReq({ originalUrl: '/api/thing' }), res, next);
        expect(next).not.toHaveBeenCalled();
        expect(res.statusCode).toBe(401);
        expect(res.body).toMatchObject({ success: false, error: 'Authentication required', redirect: '/login' });
    });

    test('page request with no auth redirects to /login', async () => {
        const res = makeRes();
        await mw.requireAuth(makeReq({ originalUrl: '/dashboard' }), res, next);
        expect(res.redirectedTo).toBe('/login');
        expect(next).not.toHaveBeenCalled();
    });
});

describe('requireRole', () => {
    test('calls next() when the role matches', async () => {
        const res = makeRes();
        await mw.requireRole('instructor')(makeReq({ user: { role: 'instructor' } }), res, next);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('API request with wrong role returns 403 JSON including the actual role', async () => {
        const res = makeRes();
        await mw.requireRole('instructor')(makeReq({ originalUrl: '/api/x', user: { role: 'student' } }), res, next);
        expect(res.statusCode).toBe(403);
        expect(res.body).toMatchObject({ success: false, error: 'Access denied. instructor role required.', userRole: 'student' });
        expect(next).not.toHaveBeenCalled();
    });

    test('page request with wrong role redirects to the user’s own dashboard', async () => {
        const res = makeRes();
        await mw.requireRole('instructor')(makeReq({ originalUrl: '/page', user: { role: 'student' } }), res, next);
        expect(res.redirectedTo).toBe('/student');
    });

    test('no auth at all on an API request returns 401', async () => {
        const res = makeRes();
        await mw.requireRole('instructor')(makeReq({ originalUrl: '/api/x' }), res, next);
        expect(res.statusCode).toBe(401);
    });
});

describe('requireInstructorOrTA', () => {
    test.each(['instructor', 'ta'])('allows %s through', async (role) => {
        const res = makeRes();
        await mw.requireInstructorOrTA(makeReq({ user: { role } }), res, next);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('denies a student on an API request with 403', async () => {
        const res = makeRes();
        await mw.requireInstructorOrTA(makeReq({ originalUrl: '/api/x', user: { role: 'student' } }), res, next);
        expect(res.statusCode).toBe(403);
        expect(res.body).toMatchObject({ error: 'Access denied. Instructor or TA role required.', userRole: 'student' });
    });

    test('no auth on a page request redirects to /login', async () => {
        const res = makeRes();
        await mw.requireInstructorOrTA(makeReq({ originalUrl: '/page' }), res, next);
        expect(res.redirectedTo).toBe('/login');
    });
});

describe('requireSystemAdmin', () => {
    test('allows a system admin through', async () => {
        const res = makeRes();
        await mw.requireSystemAdmin(makeReq({ user: { permissions: { systemAdmin: true } } }), res, next);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('denies a non-admin API request with 403', async () => {
        const res = makeRes();
        await mw.requireSystemAdmin(makeReq({ originalUrl: '/api/x', user: { permissions: {} } }), res, next);
        expect(res.statusCode).toBe(403);
        expect(res.body).toMatchObject({ error: 'Access denied. System admin access required.' });
    });

    test('redirects a non-admin page request to /instructor/home', async () => {
        const res = makeRes();
        await mw.requireSystemAdmin(makeReq({ originalUrl: '/page', user: { permissions: {} } }), res, next);
        expect(res.redirectedTo).toBe('/instructor/home');
    });

    test('no auth on an API request returns 401', async () => {
        const res = makeRes();
        await mw.requireSystemAdmin(makeReq({ originalUrl: '/api/x' }), res, next);
        expect(res.statusCode).toBe(401);
    });
});

describe('redirectIfAuthenticated', () => {
    test('redirects an authenticated instructor session to /instructor', () => {
        const res = makeRes();
        mw.redirectIfAuthenticated(makeReq({ session: { userId: 'u1', userRole: 'instructor' } }), res, next);
        expect(res.redirectedTo).toBe('/instructor');
        expect(next).not.toHaveBeenCalled();
    });

    test('passes through when there is no session', () => {
        const res = makeRes();
        mw.redirectIfAuthenticated(makeReq({}), res, next);
        expect(next).toHaveBeenCalledTimes(1);
        expect(res.redirectedTo).toBeUndefined();
    });
});

describe('requireCourseContext', () => {
    test('redirects to /login when there is no user', async () => {
        const res = makeRes();
        await mw.requireCourseContext(makeReq({}), res, next);
        expect(res.redirectedTo).toBe('/login');
    });

    test('instructor with a course context continues and gets req.courseId', async () => {
        const res = makeRes();
        const req = makeReq({ user: { role: 'instructor', preferences: { courseId: 'C1' } } });
        await mw.requireCourseContext(req, res, next);
        expect(next).toHaveBeenCalledTimes(1);
        expect(req.courseId).toBe('C1');
    });

    test('instructor with no course context is sent to onboarding', async () => {
        const res = makeRes();
        await mw.requireCourseContext(makeReq({ user: { role: 'instructor', preferences: {} } }), res, next);
        expect(res.redirectedTo).toBe('/instructor/onboarding');
    });

    test('non-instructors pass through untouched', async () => {
        const res = makeRes();
        const req = makeReq({ user: { role: 'student' } });
        await mw.requireCourseContext(req, res, next);
        expect(next).toHaveBeenCalledTimes(1);
        expect(req.courseId).toBeUndefined();
    });
});

describe('requireTAPermission', () => {
    function taMiddleware() {
        const db = memoryDb({
            courses: [{ courseId: 'C1', tas: ['t1'], taPermissions: { t1: { canAccessCourses: true, canAccessFlags: false } } }],
        });
        return createAuthMiddleware(db);
    }

    test('is a no-op for non-TA users', async () => {
        const res = makeRes();
        await taMiddleware().requireTAPermission('courses')(makeReq({ user: { role: 'instructor', userId: 'i1' } }), res, next);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('allows a TA who has the requested permission', async () => {
        const res = makeRes();
        const req = makeReq({ user: { role: 'ta', userId: 't1' }, query: { courseId: 'C1' } });
        await taMiddleware().requireTAPermission('courses')(req, res, next);
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('denies a TA who lacks the requested permission with 403', async () => {
        const res = makeRes();
        const req = makeReq({ user: { role: 'ta', userId: 't1' }, query: { courseId: 'C1' } });
        await taMiddleware().requireTAPermission('flags')(req, res, next);
        expect(res.statusCode).toBe(403);
        expect(res.body.message).toMatch(/do not have permission to access Flagged Content/);
        expect(next).not.toHaveBeenCalled();
    });

    test('API request with no resolvable course returns 400', async () => {
        const res = makeRes();
        // TA belongs to no course, and no courseId in query/body/params/preferences.
        const req = makeReq({ originalUrl: '/api/x', user: { role: 'ta', userId: 'orphan' } });
        await taMiddleware().requireTAPermission('courses')(req, res, next);
        expect(res.statusCode).toBe(400);
        expect(res.body).toMatchObject({ success: false, message: 'Course ID is required to check TA permissions' });
    });
});
