const ORIGINAL_ENV = process.env;

function toolkitModule(CourseListSyncModule) {
    jest.doMock(
        '@ubc/ubc-genai-toolkit-course-list-sync',
        () => ({ CourseListSyncModule }),
        { virtual: true }
    );
}

function loadService() {
    return require('../../../src/services/academicApi');
}

describe('academicApi', () => {
    beforeEach(() => {
        jest.resetModules();
        process.env = { ...ORIGINAL_ENV };
        delete process.env.UBC_API_USE_MOCK;
        delete process.env.UBC_API_CLIENT_ID;
        delete process.env.UBC_API_CLIENT_SECRET;
        delete process.env.UBC_API_ENV;
    });

    afterAll(() => {
        process.env = ORIGINAL_ENV;
    });

    test('creates the toolkit client from configured credentials and environment', () => {
        const CourseListSyncModule = jest.fn(function Client(options) {
            this.options = options;
        });
        toolkitModule(CourseListSyncModule);
        process.env.UBC_API_CLIENT_ID = 'client-id';
        process.env.UBC_API_CLIENT_SECRET = 'client-secret';
        process.env.UBC_API_ENV = 'prod';

        const client = loadService().createAcademicApiClient();

        expect(CourseListSyncModule).toHaveBeenCalledWith({
            clientId: 'client-id',
            clientSecret: 'client-secret',
            env: 'prod'
        });
        expect(client.options.env).toBe('prod');
    });

    test('uses safe mock defaults and the dev environment', () => {
        const CourseListSyncModule = jest.fn();
        toolkitModule(CourseListSyncModule);
        process.env.UBC_API_USE_MOCK = 'true';

        loadService().createAcademicApiClient();

        expect(CourseListSyncModule).toHaveBeenCalledWith({
            clientId: 'mock-client',
            clientSecret: 'mock-secret',
            env: 'dev'
        });
    });

    test('does not invent credentials when mock mode is off', () => {
        const CourseListSyncModule = jest.fn();
        toolkitModule(CourseListSyncModule);

        loadService().createAcademicApiClient();

        expect(CourseListSyncModule).toHaveBeenCalledWith({
            clientId: undefined,
            clientSecret: undefined,
            env: 'dev'
        });
    });

    test('reports a stable error when the optional toolkit is unavailable', () => {
        jest.doMock('@ubc/ubc-genai-toolkit-course-list-sync', () => {
            const error = new Error('not installed');
            error.code = 'MODULE_NOT_FOUND';
            throw error;
        }, { virtual: true });

        expect(() => loadService().createAcademicApiClient()).toThrow(
            expect.objectContaining({ code: 'ACADEMIC_API_TOOLKIT_MISSING' })
        );
    });

    test('does not disguise non-resolution errors raised while loading the toolkit', () => {
        jest.doMock('@ubc/ubc-genai-toolkit-course-list-sync', () => {
            const error = new Error('broken package');
            error.code = 'ERR_PACKAGE_PATH_NOT_EXPORTED';
            throw error;
        }, { virtual: true });

        expect(() => loadService().createAcademicApiClient()).toThrow('broken package');
    });

    test('lazily creates and caches one client', () => {
        const instance = { getSections: jest.fn() };
        const CourseListSyncModule = jest.fn(() => instance);
        toolkitModule(CourseListSyncModule);
        const service = loadService();

        expect(service.getAcademicApiClient()).toBe(instance);
        expect(service.getAcademicApiClient()).toBe(instance);
        expect(CourseListSyncModule).toHaveBeenCalledTimes(1);
    });

    test('allows tests to inject and clear the cached client', () => {
        const created = { source: 'created' };
        const CourseListSyncModule = jest.fn(() => created);
        toolkitModule(CourseListSyncModule);
        const service = loadService();
        const injected = { source: 'injected' };

        service.setAcademicApiClientForTests(injected);
        expect(service.getAcademicApiClient()).toBe(injected);
        expect(CourseListSyncModule).not.toHaveBeenCalled();

        service.setAcademicApiClientForTests(null);
        expect(service.getAcademicApiClient()).toBe(created);
    });

    test('feature gate fails closed without a database or global setting', async () => {
        const service = loadService();
        const findOne = jest.fn().mockResolvedValue(null);
        const db = { collection: jest.fn(() => ({ findOne })) };

        await expect(service.isAcademicApiEnabled()).resolves.toBe(false);
        await expect(service.isAcademicApiEnabled(db)).resolves.toBe(false);
        expect(findOne).toHaveBeenCalledWith(
            { _id: 'global' },
            { projection: { academicApiEnabled: 1 } }
        );
    });

    test.each([
        [{ academicApiEnabled: true }, true],
        [{ academicApiEnabled: false }, false],
        [{ academicApiEnabled: 1 }, true],
        [{}, false]
    ])('coerces the stored feature setting %#', async (setting, expected) => {
        const service = loadService();
        const db = {
            collection: jest.fn(() => ({ findOne: jest.fn().mockResolvedValue(setting) }))
        };
        await expect(service.isAcademicApiEnabled(db)).resolves.toBe(expected);
    });

    test('feature gate logs read failures and remains disabled', async () => {
        const service = loadService();
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        const db = {
            collection: jest.fn(() => ({
                findOne: jest.fn().mockRejectedValue(new Error('database unavailable'))
            }))
        };

        await expect(service.isAcademicApiEnabled(db)).resolves.toBe(false);
        expect(errorSpy).toHaveBeenCalledWith(
            'Failed to read academicApiEnabled setting:',
            'database unavailable'
        );
        errorSpy.mockRestore();
    });
});
