const {
    normalizeEmail,
    hasSystemAdminAccess,
    getEffectiveRole,
    applyAccessState,
} = require('../../../src/services/authorization');

describe('authorization.normalizeEmail', () => {
    test('trims surrounding whitespace and lowercases', () => {
        expect(normalizeEmail('  Foo@BAR.com ')).toBe('foo@bar.com');
    });

    test('returns null for empty / whitespace-only / falsy input', () => {
        expect(normalizeEmail('')).toBeNull();
        expect(normalizeEmail('   ')).toBeNull();
        expect(normalizeEmail(null)).toBeNull();
        expect(normalizeEmail(undefined)).toBeNull();
    });
});

describe('authorization.hasSystemAdminAccess', () => {
    test('true only when permissions.systemAdmin is strictly true', () => {
        expect(hasSystemAdminAccess({ permissions: { systemAdmin: true } })).toBe(true);
    });

    test('false for non-true, missing permissions, or missing user', () => {
        expect(hasSystemAdminAccess({ permissions: { systemAdmin: false } })).toBe(false);
        expect(hasSystemAdminAccess({ permissions: { systemAdmin: 'true' } })).toBe(false);
        expect(hasSystemAdminAccess({})).toBe(false);
        expect(hasSystemAdminAccess(null)).toBe(false);
    });
});

describe('authorization.getEffectiveRole', () => {
    test('returns null when there is no user', () => {
        expect(getEffectiveRole(null)).toBeNull();
    });

    test('system admins are elevated to instructor regardless of base role', () => {
        const admin = { role: 'student', permissions: { systemAdmin: true } };
        expect(getEffectiveRole(admin)).toBe('instructor');
    });

    test('non-admins keep their declared role, or null when absent', () => {
        expect(getEffectiveRole({ role: 'student' })).toBe('student');
        expect(getEffectiveRole({})).toBeNull();
    });
});

describe('authorization.applyAccessState', () => {
    test('returns null when there is no user', () => {
        expect(applyAccessState(null)).toBeNull();
    });

    test('normalizes email, preserves other fields, and sets effective role for admins', () => {
        const result = applyAccessState({
            _id: 'u1',
            email: '  Admin@Test.COM ',
            role: 'student',
            permissions: { systemAdmin: true, other: 1 },
        });

        expect(result).toMatchObject({
            _id: 'u1',
            email: 'admin@test.com',
            baseRole: 'student',      // falls back to role when baseRole absent
            role: 'instructor',        // elevated because systemAdmin
            permissions: { systemAdmin: true, other: 1 },
        });
    });

    test('keeps an explicit baseRole and coerces systemAdmin to a boolean', () => {
        const result = applyAccessState({
            email: null,
            baseRole: 'ta',
            role: 'ta',
        });

        expect(result.baseRole).toBe('ta');
        expect(result.role).toBe('ta');
        expect(result.email).toBeNull();
        expect(result.permissions.systemAdmin).toBe(false);
    });
});
