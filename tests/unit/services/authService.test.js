/**
 * Unit tests for the PURE (no-DB, no-bcrypt) helpers of src/services/authService.js.
 * The class wraps src/services/authorization.js for role resolution, so these
 * verify the wiring (system-admin elevation, session-safe shaping) end to end.
 *
 * loginUser/registerUser/getUserById/handleSAMLUser are db+bcrypt and are left to
 * the e2e/integration layer; here we instantiate with a null db and only call the
 * synchronous helpers.
 */
const AuthService = require('../../../src/services/authService');

const svc = new AuthService(null);

describe('authService.isValidEmail', () => {
    test('accepts well-formed addresses', () => {
        expect(svc.isValidEmail('a@b.com')).toBe(true);
        expect(svc.isValidEmail('foo.bar@x.co.uk')).toBe(true);
    });

    test('rejects malformed addresses', () => {
        expect(svc.isValidEmail('bad')).toBe(false);
        expect(svc.isValidEmail('a@b')).toBe(false);       // no TLD dot
        expect(svc.isValidEmail('a @b.com')).toBe(false);  // space
        expect(svc.isValidEmail('@b.com')).toBe(false);    // no local part
        expect(svc.isValidEmail('a@.com')).toBe(false);    // empty domain label
    });
});

describe('authService.hasRole', () => {
    test('false when there is no user', () => {
        expect(svc.hasRole(null, 'student')).toBe(false);
    });

    test('matches the declared role for non-admins', () => {
        expect(svc.hasRole({ role: 'student' }, 'student')).toBe(true);
        expect(svc.hasRole({ role: 'student' }, 'instructor')).toBe(false);
    });

    test('system admins resolve to instructor regardless of base role', () => {
        const admin = { role: 'student', permissions: { systemAdmin: true } };
        expect(svc.hasRole(admin, 'instructor')).toBe(true);
        expect(svc.hasRole(admin, 'student')).toBe(false);
    });
});

describe('authService.isInstructor / isStudent', () => {
    test('track the effective role', () => {
        expect(svc.isInstructor({ role: 'instructor' })).toBe(true);
        expect(svc.isStudent({ role: 'instructor' })).toBe(false);
        expect(svc.isStudent({ role: 'student' })).toBe(true);
    });

    test('a system-admin student counts as instructor, not student', () => {
        const admin = { role: 'student', permissions: { systemAdmin: true } };
        expect(svc.isInstructor(admin)).toBe(true);
        expect(svc.isStudent(admin)).toBe(false);
    });
});

describe('authService.isSystemAdmin', () => {
    test('true only when permissions.systemAdmin is strictly true', () => {
        expect(svc.isSystemAdmin({ permissions: { systemAdmin: true } })).toBe(true);
        expect(svc.isSystemAdmin({ permissions: { systemAdmin: 'true' } })).toBe(false);
        expect(svc.isSystemAdmin({ permissions: {} })).toBe(false);
        expect(svc.isSystemAdmin(null)).toBe(false);
    });
});

describe('authService.getCurrentCourseId', () => {
    test('reads preferences.courseId, defaulting to null', () => {
        expect(svc.getCurrentCourseId({ preferences: { courseId: 'C1' } })).toBe('C1');
        expect(svc.getCurrentCourseId({ preferences: {} })).toBeNull();
        expect(svc.getCurrentCourseId({})).toBeNull();
        expect(svc.getCurrentCourseId(null)).toBeNull();
    });
});

describe('authService.createSessionUser', () => {
    test('returns null when there is no user', () => {
        expect(svc.createSessionUser(null)).toBeNull();
    });

    test('strips sensitive fields and resolves role/email/permissions', () => {
        const session = svc.createSessionUser({
            userId: 'u1',
            username: 'jdoe',
            email: '  JDoe@Example.COM ',
            role: 'student',
            password: 'hunter2',
            hashedPassword: 'abc',
            preferences: { courseId: 'C1' },
            permissions: { systemAdmin: true },
        });

        expect(session).toEqual({
            userId: 'u1',
            username: 'jdoe',
            email: 'jdoe@example.com',     // normalized
            role: 'instructor',            // elevated (systemAdmin)
            baseRole: 'student',
            displayName: undefined,
            authProvider: undefined,
            preferences: { courseId: 'C1' },
            permissions: { systemAdmin: true },
        });
        // No credential material leaks into the session object.
        expect(session).not.toHaveProperty('password');
        expect(session).not.toHaveProperty('hashedPassword');
    });
});
