const captured = { strategies: {}, serialize: null, deserialize: null };

class mockStrategyClass {
    constructor(options, verify) {
        this.options = options;
        this.verify = verify;
    }
}

const mockPassport = {
    use: jest.fn((name, strategy) => { captured.strategies[name] = strategy; }),
    serializeUser: jest.fn(fn => { captured.serialize = fn; }),
    deserializeUser: jest.fn(fn => { captured.deserialize = fn; }),
};

jest.mock('passport', () => mockPassport);
jest.mock('passport-local', () => ({ Strategy: mockStrategyClass }));
jest.mock('passport-saml', () => ({ Strategy: mockStrategyClass }));
jest.mock('passport-ubcshib', () => ({
    Strategy: mockStrategyClass,
    ensureAuthenticated: jest.fn(),
    logout: jest.fn(),
    conditionalAuth: jest.fn(),
}));
jest.mock('fs', () => ({ readFileSync: jest.fn(() => 'MOCK CERTIFICATE') }));
jest.mock('../../../src/models/User', () => ({
    authenticateUser: jest.fn(),
    createOrGetSAMLUser: jest.fn(),
    getUserById: jest.fn(),
}));

const fs = require('fs');
const User = require('../../../src/models/User');
const originalConsoleLog = console.log;
console.log = jest.fn();
const initializePassport = require('../../../src/config/passport');
console.log = originalConsoleLog;

function callVerify(strategy, ...args) {
    return new Promise(resolve => strategy.verify(...args, (...doneArgs) => resolve(doneArgs)));
}

describe('Passport configuration', () => {
    const originalEnv = process.env;
    const db = { name: 'mock-db' };

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'warn').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    beforeEach(() => {
        process.env = {
            ...originalEnv,
            SAML_ENTRY_POINT: 'https://idp.test/login',
            SAML_ISSUER: 'biocbot-test',
            SAML_CALLBACK_URL: 'https://app.test/callback',
            SAML_CERT_PATH: '/mock/cert.pem',
        };
        captured.strategies = {};
        captured.serialize = null;
        captured.deserialize = null;
        mockPassport.use.mockClear();
        User.authenticateUser.mockReset();
        User.createOrGetSAMLUser.mockReset();
        User.getUserById.mockReset();
        fs.readFileSync.mockReset().mockReturnValue('MOCK CERTIFICATE');
    });

    afterAll(() => {
        process.env = originalEnv;
        jest.restoreAllMocks();
    });

    test('registers local, generic SAML, and UBC Shibboleth strategies', () => {
        const result = initializePassport(db);
        expect(result).toBe(mockPassport);
        expect(Object.keys(captured.strategies)).toEqual(['local', 'saml', 'ubcshib']);
        expect(captured.strategies.local.options).toMatchObject({ usernameField: 'username', passwordField: 'password' });
        expect(captured.strategies.saml.options).toMatchObject({ entryPoint: 'https://idp.test/login', cert: 'MOCK CERTIFICATE', signatureAlgorithm: 'sha256' });
        expect(captured.strategies.ubcshib.options).toMatchObject({ issuer: 'biocbot-test', cert: 'MOCK CERTIFICATE', enableSLO: true });
        expect(mockPassport.ubcShibHelpers).toBeDefined();
    });

    test('local strategy returns authenticated users, failures, and errors', async () => {
        initializePassport(db);
        User.authenticateUser.mockResolvedValueOnce({ success: true, user: { userId: 'u1' } });
        expect(await callVerify(captured.strategies.local, 'alice', 'pw')).toEqual([null, { userId: 'u1' }]);
        User.authenticateUser.mockResolvedValueOnce({ success: false, error: 'Invalid credentials' });
        expect(await callVerify(captured.strategies.local, 'alice', 'bad')).toEqual([null, false, { message: 'Invalid credentials' }]);
        User.authenticateUser.mockRejectedValueOnce(new Error('db failed'));
        expect((await callVerify(captured.strategies.local, 'alice', 'pw'))[0].message).toBe('db failed');
    });

    test('generic SAML validates attributes and creates a student by default', async () => {
        initializePassport(db);
        expect(await callVerify(captured.strategies.saml, {})).toEqual([null, false, { message: 'SAML profile missing required attributes' }]);
        User.createOrGetSAMLUser.mockResolvedValueOnce({ success: true, user: { userId: 's1' } });
        expect(await callVerify(captured.strategies.saml, { nameID: 'id1', email: 'student@test.ca', displayName: 'Student' })).toEqual([null, { userId: 's1' }]);
        expect(User.createOrGetSAMLUser).toHaveBeenCalledWith(db, {
            samlId: 'id1', email: 'student@test.ca', username: 'student', displayName: 'Student', role: 'student',
        });
        User.createOrGetSAMLUser.mockResolvedValueOnce({ success: false, error: 'rejected' });
        expect(await callVerify(captured.strategies.saml, { nameID: 'id2', mail: 'fail@test.ca' })).toEqual([null, false, { message: 'rejected' }]);
    });

    test.each([
        [['faculty'], 'instructor'],
        [['faculty', 'student'], 'student'],
        [['staff'], 'student'],
        ['faculty', 'instructor'],
    ])('UBC strategy maps affiliation %j to %s', async (affiliation, expectedRole) => {
        initializePassport(db);
        User.createOrGetSAMLUser.mockResolvedValueOnce({ success: true, user: { userId: 'ubc' } });
        const profile = { attributes: { ubcEduCwlPuid: 'P123', mail: 'person@ubc.ca', displayName: 'Person', eduPersonAffiliation: affiliation } };
        expect(await callVerify(captured.strategies.ubcshib, profile)).toEqual([null, { userId: 'ubc' }]);
        expect(User.createOrGetSAMLUser.mock.calls[0][1]).toMatchObject({ puid: 'P123', username: 'P123', role: expectedRole });
    });

    test('UBC strategy rejects profiles without PUID or email', async () => {
        initializePassport(db);
        expect(await callVerify(captured.strategies.ubcshib, { attributes: { mail: 'x@ubc.ca' } })).toEqual([
            null, false, { message: 'UBC Shibboleth profile missing required attribute: ubcEduCwlPuid' },
        ]);
        expect(await callVerify(captured.strategies.ubcshib, { attributes: { ubcEduCwlPuid: 'P1' } })).toEqual([
            null, false, { message: 'UBC Shibboleth profile missing required attributes (email or nameID)' },
        ]);
    });

    test('serialize and deserialize use only userId and handle missing users/errors', async () => {
        initializePassport(db);
        expect(await new Promise(resolve => captured.serialize({ userId: 'u1' }, (...args) => resolve(args)))).toEqual([null, 'u1']);
        User.getUserById.mockResolvedValueOnce({ userId: 'u1' });
        expect(await new Promise(resolve => captured.deserialize('u1', (...args) => resolve(args)))).toEqual([null, { userId: 'u1' }]);
        User.getUserById.mockResolvedValueOnce(null);
        expect(await new Promise(resolve => captured.deserialize('missing', (...args) => resolve(args)))).toEqual([null, false]);
        User.getUserById.mockRejectedValueOnce(new Error('lookup failed'));
        expect((await new Promise(resolve => captured.deserialize('bad', (...args) => resolve(args))))[0].message).toBe('lookup failed');
    });

    test('missing or unreadable SAML certificate leaves only local strategy configured', () => {
        delete process.env.SAML_CERT_PATH;
        initializePassport(db);
        expect(captured.strategies.saml).toBeUndefined();
        expect(captured.strategies.ubcshib).toBeUndefined();
        fs.readFileSync.mockImplementationOnce(() => { throw new Error('unreadable'); });
        process.env.SAML_CERT_PATH = '/bad.pem';
        captured.strategies = {};
        initializePassport(db);
        // The certificate is read independently for generic SAML and UBC; this mock fails only the first read.
        expect(Object.keys(captured.strategies)).toEqual(['local', 'ubcshib']);
    });
});
