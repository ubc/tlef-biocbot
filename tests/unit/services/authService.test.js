/**
 * Unit tests for the PURE (no-DB, no-bcrypt) helpers of src/services/authService.js.
 * The class wraps src/services/authorization.js for role resolution, so these
 * verify the wiring (system-admin elevation, session-safe shaping) end to end.
 *
 * loginUser/registerUser/getUserById/handleSAMLUser are db+bcrypt and are left to
 * the e2e/integration layer; here we instantiate with a null db and only call the
 * synchronous helpers.
 */
jest.mock('../../../src/models/User', () => ({
    createUser: jest.fn(),
    authenticateUser: jest.fn(),
    getUserById: jest.fn(),
    updateUserPreferences: jest.fn(),
    createOrGetSAMLUser: jest.fn(),
    getUsersByRole: jest.fn()
}));

const User = require('../../../src/models/User');
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
            puid: undefined,
            academicStudentId: undefined,
            preferences: { courseId: 'C1' },
            permissions: { systemAdmin: true },
        });
        // No credential material leaks into the session object.
        expect(session).not.toHaveProperty('password');
        expect(session).not.toHaveProperty('hashedPassword');
    });
});

describe('authService database-backed methods', () => {
    let service;
    let errorSpy;

    beforeEach(() => {
        service = new AuthService({ marker: 'db' });
        errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        errorSpy.mockRestore();
    });

    test('ensureDefaultAcademicIds is a no-op without a database', async () => {
        await expect(new AuthService(null).ensureDefaultAcademicIds()).resolves.toBeUndefined();
    });

    test('ensureDefaultAcademicIds backfills only missing instructor and student identifiers', async () => {
        const updateOne = jest.fn().mockResolvedValue({ modifiedCount: 1 });
        const db = { collection: jest.fn(() => ({ updateOne })) };

        await new AuthService(db).ensureDefaultAcademicIds();

        expect(db.collection).toHaveBeenCalledWith('users');
        expect(updateOne).toHaveBeenCalledTimes(2);
        expect(updateOne.mock.calls[0][0]).toEqual({
            username: 'instructor',
            $or: [{ puid: { $exists: false } }, { puid: null }, { puid: '' }]
        });
        expect(updateOne.mock.calls[0][1].$set).toEqual({
            puid: 'PUID-E000001',
            updatedAt: expect.any(Date)
        });
        expect(updateOne.mock.calls[1][0].username).toBe('student');
        expect(updateOne.mock.calls[1][1].$set).toEqual({
            puid: 'PUID-S000001',
            academicStudentId: 'STU-10001',
            updatedAt: expect.any(Date)
        });
    });

    test.each([
        [{ password: 'pw', role: 'student' }, 'Username, password, and role are required'],
        [{ username: 'u', role: 'student' }, 'Username, password, and role are required'],
        [{ username: 'u', password: 'pw' }, 'Username, password, and role are required'],
        [{ username: 'u', password: 'pw', role: 'admin' }, 'Role must be "instructor", "student", or "ta"'],
        [{ username: 'u', password: 'pw', role: 'student', email: 'bad' }, 'Invalid email format']
    ])('registerUser validates input %#', async (input, error) => {
        await expect(service.registerUser(input)).resolves.toEqual({ success: false, error });
        expect(User.createUser).not.toHaveBeenCalled();
    });

    test.each(['instructor', 'student', 'ta'])('registerUser delegates valid %s accounts to User', async role => {
        const input = { username: role, password: 'pw', role, email: `${role}@example.com` };
        User.createUser.mockResolvedValue({ success: true, userId: `${role}-id` });

        await expect(service.registerUser(input)).resolves.toEqual({
            success: true,
            userId: `${role}-id`
        });
        expect(User.createUser).toHaveBeenCalledWith(service.db, input);
    });

    test('registerUser converts model failures into its public error contract', async () => {
        User.createUser.mockRejectedValue(new Error('write failed'));
        await expect(service.registerUser({ username: 'u', password: 'pw', role: 'student' }))
            .resolves.toEqual({ success: false, error: 'Registration failed. Please try again.' });
        expect(errorSpy).toHaveBeenCalledWith('Error in registerUser:', expect.any(Error));
    });

    test('loginUser validates credentials, delegates, and handles failures', async () => {
        await expect(service.loginUser('', 'pw')).resolves.toEqual({
            success: false,
            error: 'Username and password are required'
        });
        User.authenticateUser.mockResolvedValue({ success: true, user: { userId: 'u1' } });
        await expect(service.loginUser('user', 'pw')).resolves.toEqual({
            success: true,
            user: { userId: 'u1' }
        });
        expect(User.authenticateUser).toHaveBeenCalledWith(service.db, 'user', 'pw');

        User.authenticateUser.mockRejectedValue(new Error('hash failed'));
        await expect(service.loginUser('user', 'pw')).resolves.toEqual({
            success: false,
            error: 'Login failed. Please try again.'
        });
    });

    test('getUserById handles empty ids, successful reads, and failures', async () => {
        await expect(service.getUserById()).resolves.toBeNull();
        User.getUserById.mockResolvedValue({ userId: 'u1' });
        await expect(service.getUserById('u1')).resolves.toEqual({ userId: 'u1' });
        expect(User.getUserById).toHaveBeenCalledWith(service.db, 'u1');
        User.getUserById.mockRejectedValue(new Error('read failed'));
        await expect(service.getUserById('u2')).resolves.toBeNull();
    });

    test('updateUserPreferences validates, delegates, and handles failures', async () => {
        await expect(service.updateUserPreferences('', {})).resolves.toEqual({
            success: false,
            error: 'User ID is required'
        });
        User.updateUserPreferences.mockResolvedValue({ success: true });
        await expect(service.updateUserPreferences('u1', { courseId: 'C1' }))
            .resolves.toEqual({ success: true });
        expect(User.updateUserPreferences).toHaveBeenCalledWith(
            service.db,
            'u1',
            { courseId: 'C1' }
        );
        User.updateUserPreferences.mockRejectedValue(new Error('write failed'));
        await expect(service.updateUserPreferences('u1', {})).resolves.toEqual({
            success: false,
            error: 'Failed to update preferences'
        });
    });

    test('handleSAMLUser validates identity fields, delegates, and handles failures', async () => {
        await expect(service.handleSAMLUser({ email: 'u@example.com' })).resolves.toEqual({
            success: false,
            error: 'SAML data is incomplete'
        });
        const samlData = { samlId: 's1', email: 'u@example.com' };
        User.createOrGetSAMLUser.mockResolvedValue({ success: true, userId: 'u1' });
        await expect(service.handleSAMLUser(samlData)).resolves.toEqual({
            success: true,
            userId: 'u1'
        });
        expect(User.createOrGetSAMLUser).toHaveBeenCalledWith(service.db, samlData);
        User.createOrGetSAMLUser.mockRejectedValue(new Error('saml failed'));
        await expect(service.handleSAMLUser(samlData)).resolves.toEqual({
            success: false,
            error: 'SAML authentication failed'
        });
    });

    test('setCurrentCourseId merges existing preferences', async () => {
        jest.spyOn(service, 'getUserById').mockResolvedValue({
            userId: 'u1',
            preferences: { theme: 'dark', courseId: 'old' }
        });
        jest.spyOn(service, 'updateUserPreferences').mockResolvedValue({ success: true });

        await expect(service.setCurrentCourseId('u1', 'C2')).resolves.toEqual({ success: true });
        expect(service.updateUserPreferences).toHaveBeenCalledWith('u1', {
            theme: 'dark',
            courseId: 'C2'
        });
    });

    test('setCurrentCourseId reports missing users and internal failures', async () => {
        jest.spyOn(service, 'getUserById').mockResolvedValue(null);
        await expect(service.setCurrentCourseId('missing', 'C1')).resolves.toEqual({
            success: false,
            error: 'User not found'
        });

        service.getUserById.mockRejectedValue(new Error('read failed'));
        await expect(service.setCurrentCourseId('u1', 'C1')).resolves.toEqual({
            success: false,
            error: 'Failed to update course context'
        });
    });
});

describe('authService.initializeDefaultUsers', () => {
    let service;
    let logSpy;
    let errorSpy;

    beforeEach(() => {
        service = new AuthService({ marker: 'db' });
        logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
        errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        logSpy.mockRestore();
        errorSpy.mockRestore();
    });

    test('keeps existing defaults and backfills their academic ids', async () => {
        User.getUsersByRole.mockResolvedValue([{ userId: 'existing' }]);
        jest.spyOn(service, 'ensureDefaultAcademicIds').mockResolvedValue();
        jest.spyOn(service, 'registerUser');

        await expect(service.initializeDefaultUsers()).resolves.toEqual({
            success: true,
            message: 'Default users already exist'
        });
        expect(User.getUsersByRole).toHaveBeenCalledWith(service.db, 'instructor');
        expect(service.ensureDefaultAcademicIds).toHaveBeenCalledTimes(1);
        expect(service.registerUser).not.toHaveBeenCalled();
    });

    test('creates both default users and returns their ids', async () => {
        User.getUsersByRole.mockResolvedValue([]);
        jest.spyOn(service, 'ensureDefaultAcademicIds').mockResolvedValue();
        jest.spyOn(service, 'registerUser')
            .mockResolvedValueOnce({ success: true, userId: 'instructor-id' })
            .mockResolvedValueOnce({ success: true, userId: 'student-id' });

        await expect(service.initializeDefaultUsers()).resolves.toEqual({
            success: true,
            message: 'Default users created successfully',
            users: { instructor: 'instructor-id', student: 'student-id' }
        });
        expect(service.registerUser).toHaveBeenNthCalledWith(1, expect.objectContaining({
            username: 'instructor',
            role: 'instructor',
            puid: 'PUID-E000001'
        }));
        expect(service.registerUser).toHaveBeenNthCalledWith(2, expect.objectContaining({
            username: 'student',
            role: 'student',
            puid: 'PUID-S000001',
            academicStudentId: 'STU-10001'
        }));
        expect(service.ensureDefaultAcademicIds).toHaveBeenCalledTimes(1);
    });

    test('stops when default instructor creation fails', async () => {
        User.getUsersByRole.mockResolvedValue([]);
        jest.spyOn(service, 'registerUser').mockResolvedValue({ success: false, error: 'duplicate' });

        await expect(service.initializeDefaultUsers()).resolves.toEqual({
            success: false,
            error: 'Failed to create default instructor'
        });
        expect(service.registerUser).toHaveBeenCalledTimes(1);
    });

    test('reports default student creation failure', async () => {
        User.getUsersByRole.mockResolvedValue([]);
        jest.spyOn(service, 'registerUser')
            .mockResolvedValueOnce({ success: true, userId: 'instructor-id' })
            .mockResolvedValueOnce({ success: false, error: 'duplicate' });

        await expect(service.initializeDefaultUsers()).resolves.toEqual({
            success: false,
            error: 'Failed to create default student'
        });
    });

    test('converts unexpected initialization failures to a stable result', async () => {
        User.getUsersByRole.mockRejectedValue(new Error('database unavailable'));
        await expect(service.initializeDefaultUsers()).resolves.toEqual({
            success: false,
            error: 'Failed to initialize default users'
        });
        expect(errorSpy).toHaveBeenCalledWith('Error initializing default users:', expect.any(Error));
    });
});
