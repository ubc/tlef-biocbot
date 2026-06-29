// @ts-check
/**
 * Focused server-side coverage for src/config/passport.js.
 *
 * The live app can exercise local login, but the SAML and UBC strategy setup
 * depends on external IdP modules/configuration. This spec drives a small
 * browser-level harness that loads the real passport config with test doubles
 * for those external dependencies, then invokes the captured strategy callbacks.
 */

const { test, expect } = require('./fixtures/monocart');
const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const { once } = require('events');

/** @type {import('child_process').ChildProcess|null} */
let harnessProc = null;
/** @type {string} */
let harnessUrl = '';

function getFreePort() {
    return /** @type {Promise<number>} */ (new Promise((resolve, reject) => {
        const srv = net.createServer();
        srv.unref();
        srv.on('error', reject);
        srv.listen(0, () => {
            const addr = /** @type {any} */ (srv.address());
            srv.close(() => resolve(addr.port));
        });
    }));
}

async function harnessFetch(page, pathName, body) {
    return await page.evaluate(async ({ url, payload }) => {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload || {}),
        });
        return {
            status: response.status,
            body: await response.json(),
        };
    }, { url: `${harnessUrl}${pathName}`, payload: body });
}

async function loadPassport(page, options = {}) {
    const response = await harnessFetch(page, '/__load', options);
    expect(response.status).toBe(200);
    return response.body;
}

const fullSamlEnv = {
    SAML_ENTRY_POINT: 'https://idp.test.local/sso',
    SAML_ISSUER: 'biocbot-test-sp',
    SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
    SAML_CERT_PATH: '__CERT__',
    SAML_PRIVATE_KEY: 'inline-private-key',
    SAML_PRIVATE_KEY_PATH: '/tmp/private-key.pem',
    SAML_SIGNATURE_ALGORITHM: 'sha512',
    SAML_DIGEST_ALGORITHM: 'sha512',
    SAML_CLOCK_SKEW_MS: '4500',
    SAML_VALIDATE_IN_RESPONSE_TO: 'true',
    SAML_DISABLE_REQUEST_ACS_URL: 'true',
    SAML_ENVIRONMENT: 'PRODUCTION',
    SAML_LOGOUT_URL: 'https://idp.test.local/logout',
    ENABLE_SLO: 'false',
};

test.beforeAll(async () => {
    const port = await getFreePort();
    harnessUrl = `http://127.0.0.1:${port}`;
    const env = {
        ...process.env,
        PASSPORT_HARNESS_PORT: String(port),
        NODE_V8_COVERAGE: path.resolve(__dirname, '../../coverage-reports/.v8-server'),
        BIOCBOT_COVERAGE_RUN_ID: process.env.BIOCBOT_COVERAGE_RUN_ID || String(Date.now()),
    };

    harnessProc = spawn(process.execPath, [
        path.resolve(__dirname, 'helpers/passport-coverage-harness.js'),
    ], { env, stdio: ['ignore', 'inherit', 'inherit'] });

    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
        try {
            const response = await fetch(`${harnessUrl}/__ping`);
            if (response.ok) return;
        } catch {
            // Harness is still starting.
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error('Passport coverage harness did not become ready in time');
});

test.afterAll(async () => {
    if (harnessProc && harnessProc.pid && !harnessProc.killed) {
        harnessProc.kill('SIGTERM');
        await once(harnessProc, 'exit');
    }
});

test.describe('passport local strategy and sessions', () => {
    test('local strategy returns success, credential failure, thrown errors, and session outcomes', async ({ page }) => {
        const configured = await loadPassport(page, { ubcStyle: 'missing' });
        expect(configured.strategies).toEqual(['local']);
        expect(configured.localOptions).toMatchObject({
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: false,
        });

        const success = await harnessFetch(page, '/__invoke/local', {
            username: 'alice',
            password: 'correct-password',
        });
        expect(success.body.result.user).toMatchObject({ userId: 'local-user', username: 'alice' });

        const failure = await harnessFetch(page, '/__invoke/local', {
            username: 'alice',
            password: 'wrong-password',
        });
        expect(failure.body.result).toMatchObject({
            err: null,
            user: false,
            info: { message: 'Invalid credentials' },
        });

        const thrown = await harnessFetch(page, '/__invoke/local', {
            username: 'throw-local',
            password: 'correct-password',
        });
        expect(thrown.body.result.err.message).toBe('local auth boom');

        const serialized = await harnessFetch(page, '/__serialize', {
            user: { userId: 'session-user' },
        });
        expect(serialized.body.result.user).toBe('session-user');

        const deserialized = await harnessFetch(page, '/__deserialize', {
            userId: 'session-user',
        });
        expect(deserialized.body.result.user).toMatchObject({ userId: 'session-user' });

        const missing = await harnessFetch(page, '/__deserialize', {
            userId: 'missing-user',
        });
        expect(missing.body.result).toMatchObject({ err: null, user: false });

        const errored = await harnessFetch(page, '/__deserialize', {
            userId: 'throw-deserialize',
        });
        expect(errored.body.result.err.message).toBe('deserialize boom');
    });
});

test.describe('passport SAML strategy', () => {
    test('configures SAML options and handles success, validation failure, model failure, and thrown errors', async ({ page }) => {
        const configured = await loadPassport(page, {
            ubcStyle: 'named',
            env: fullSamlEnv,
        });
        expect(configured.strategies).toEqual(['local', 'saml', 'ubcshib']);
        expect(configured.samlOptions).toMatchObject({
            entryPoint: fullSamlEnv.SAML_ENTRY_POINT,
            issuer: fullSamlEnv.SAML_ISSUER,
            callbackUrl: fullSamlEnv.SAML_CALLBACK_URL,
            privateKey: fullSamlEnv.SAML_PRIVATE_KEY,
            signatureAlgorithm: 'sha512',
            digestAlgorithm: 'sha512',
            acceptedClockSkewMs: 4500,
            validateInResponseTo: true,
            disableRequestAcsUrl: true,
        });

        const success = await harnessFetch(page, '/__invoke/saml', {
            profile: {
                nameID: 'saml-name-id',
                email: 'learner@test.local',
                displayName: 'Learner One',
                role: 'instructor',
            },
        });
        expect(success.body.result.user).toMatchObject({
            samlId: 'saml-name-id',
            email: 'learner@test.local',
            username: 'learner',
            displayName: 'Learner One',
            role: 'instructor',
        });

        const missingAttributes = await harnessFetch(page, '/__invoke/saml', {
            profile: { displayName: 'No ID or Email' },
        });
        expect(missingAttributes.body.result).toMatchObject({
            user: false,
            info: { message: 'SAML profile missing required attributes' },
        });

        const modelFailure = await harnessFetch(page, '/__invoke/saml', {
            profile: { ID: 'id-fail', mail: 'fail@test.local', cn: 'Failure User' },
        });
        expect(modelFailure.body.result).toMatchObject({
            user: false,
            info: { message: 'SAML user rejected' },
        });

        const thrown = await harnessFetch(page, '/__invoke/saml', {
            profile: {
                issuer: 'issuer-throw',
                'urn:oid:0.9.2342.19200300.100.1.3': 'throw@test.local',
            },
        });
        expect(thrown.body.result.err.message).toBe('saml user boom');
    });

    test('covers SAML setup fallbacks, missing env combinations, certificate read failure, and constructor failure', async ({ page }) => {
        const defaults = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_ISSUER: 'biocbot-test-sp',
                SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
                SAML_CERT_PATH: '__CERT__',
                SAML_VALIDATE_IN_RESPONSE_TO: 'false',
                SAML_DISABLE_REQUEST_ACS_URL: 'false',
                SAML_CLOCK_SKEW_MS: 'not-a-number',
                ENABLE_SLO: 'true',
            },
        });
        expect(defaults.samlOptions).toMatchObject({
            privateKey: null,
            signatureAlgorithm: 'sha256',
            digestAlgorithm: 'sha256',
            acceptedClockSkewMs: 0,
            validateInResponseTo: false,
            disableRequestAcsUrl: false,
        });
        expect(defaults.ubcOptions).toMatchObject({
            entryPoint: 'https://idp.test.local/sso',
            enableSLO: true,
            validateInResponseTo: false,
            acceptedClockSkewMs: 0,
            logoutUrl: 'https://idp.test.local/sso',
        });

        const missingEntryPoint = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ISSUER: 'biocbot-test-sp',
                SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
                SAML_CERT_PATH: '__CERT__',
            },
        });
        expect(missingEntryPoint.strategies).toEqual(['local', 'ubcshib']);

        const missingIssuer = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
                SAML_CERT_PATH: '__CERT__',
            },
        });
        expect(missingIssuer.strategies).toEqual(['local']);

        const missingCallback = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_ISSUER: 'biocbot-test-sp',
                SAML_CERT_PATH: '__CERT__',
            },
        });
        expect(missingCallback.strategies).toEqual(['local']);

        const badCert = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_ISSUER: 'biocbot-test-sp',
                SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
                SAML_CERT_PATH: '/definitely/not/a/cert.pem',
            },
        });
        expect(badCert.strategies).toEqual(['local']);

        const constructorFailure = await loadPassport(page, {
            ubcStyle: 'named',
            samlConstructorThrows: true,
            env: fullSamlEnv,
        });
        expect(constructorFailure.strategies).toEqual(['local', 'ubcshib']);
    });
});

test.describe('passport UBC Shibboleth strategy', () => {
    test('supports UBC module export shapes and helper fallbacks', async ({ page }) => {
        const named = await loadPassport(page, { ubcStyle: 'named', env: fullSamlEnv });
        expect(named.helperTypes).toEqual({
            ensureAuthenticated: 'function',
            logout: 'function',
            conditionalAuth: 'function',
        });

        const defaultExport = await loadPassport(page, { ubcStyle: 'default', env: fullSamlEnv });
        expect(defaultExport.strategies).toEqual(['local', 'saml', 'ubcshib']);
        expect(defaultExport.helperTypes).toEqual({
            ensureAuthenticated: 'function',
            logout: 'function',
            conditionalAuth: 'function',
        });

        const noHelpers = await loadPassport(page, { ubcStyle: 'named-no-helpers', env: fullSamlEnv });
        expect(noHelpers.helperTypes).toEqual({
            ensureAuthenticated: 'undefined',
            logout: 'undefined',
            conditionalAuth: 'undefined',
        });

        const direct = await loadPassport(page, { ubcStyle: 'direct', env: fullSamlEnv });
        expect(direct.strategies).toEqual(['local', 'saml', 'ubcshib']);

        const invalid = await loadPassport(page, { ubcStyle: 'invalid', env: fullSamlEnv });
        expect(invalid.strategies).toEqual(['local', 'saml']);
    });

    test('handles UBC callback role assignment, attribute fallbacks, validation failures, and model errors', async ({ page }) => {
        await loadPassport(page, { ubcStyle: 'named', env: fullSamlEnv });

        const faculty = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                attributes: {
                    ubcEduCwlPuid: 'puid-faculty',
                    mail: 'Faculty@Test.Local ',
                    displayName: 'Faculty Member',
                    eduPersonAffiliation: ['faculty'],
                },
            },
        });
        expect(faculty.body.result.user).toMatchObject({
            samlId: 'puid-faculty',
            puid: 'puid-faculty',
            username: 'puid-faculty',
            displayName: 'Faculty Member',
            role: 'instructor',
        });

        const dualAffiliation = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                nameID: 'name-id-student',
                attributes: {
                    ubcEduCwlPuid: 'puid-student',
                    email: 'student@test.local',
                    cn: 'Student Member',
                    eduPersonAffiliation: ['faculty', 'student'],
                },
            },
        });
        expect(dualAffiliation.body.result.user).toMatchObject({
            samlId: 'name-id-student',
            role: 'student',
            displayName: 'Student Member',
        });

        const macePuid = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                'urn:mace:dir:attribute-def:ubcEduCwlPuid': 'puid-mace',
                'urn:oid:0.9.2342.19200300.100.1.3': 'mace@test.local',
                'urn:oid:2.16.840.1.113730.3.1.241': 'Mace User',
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': 'faculty',
            },
        });
        expect(macePuid.body.result.user).toMatchObject({
            puid: 'puid-mace',
            role: 'instructor',
            displayName: 'Mace User',
        });

        const oidPuid = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                'urn:oid:1.3.6.1.4.1.60.6.1.6': 'puid-oid',
                mail: 'mail-fallback@test.local',
            },
        });
        expect(oidPuid.body.result.user).toMatchObject({
            puid: 'puid-oid',
            role: 'student',
            displayName: 'mail-fallback@test.local',
        });

        const profileEmailFallback = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                attributes: { ubcEduCwlPuid: 'puid-email' },
                email: 'profile-email@test.local',
            },
        });
        expect(profileEmailFallback.body.result.user.email).toBe('profile-email@test.local');

        const nameIdEmailFallback = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                nameID: 'nameid-email@test.local',
                attributes: { ubcEduCwlPuid: 'puid-nameid' },
            },
        });
        expect(nameIdEmailFallback.body.result.user.email).toBe('nameid-email@test.local');

        const noAttributes = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {},
        });
        expect(noAttributes.body.result).toMatchObject({
            user: false,
            info: { message: 'UBC Shibboleth profile missing required attribute: ubcEduCwlPuid' },
        });

        const missingPuid = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: { attributes: { mail: 'missing-puid@test.local' } },
        });
        expect(missingPuid.body.result).toMatchObject({
            user: false,
            info: { message: 'UBC Shibboleth profile missing required attribute: ubcEduCwlPuid' },
        });

        const missingEmail = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: { attributes: { ubcEduCwlPuid: 'puid-no-email' } },
        });
        expect(missingEmail.body.result).toMatchObject({
            user: false,
            info: { message: 'UBC Shibboleth profile missing required attributes (email or nameID)' },
        });

        const modelFailure = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                attributes: {
                    ubcEduCwlPuid: 'puid-fail',
                    mail: 'fail@test.local',
                    eduPersonAffiliation: ['student'],
                },
            },
        });
        expect(modelFailure.body.result).toMatchObject({
            user: false,
            info: { message: 'SAML user rejected' },
        });

        const thrown = await harnessFetch(page, '/__invoke/ubcshib', {
            profile: {
                attributes: {
                    ubcEduCwlPuid: 'puid-throw',
                    mail: 'throw@test.local',
                    eduPersonAffiliation: ['student'],
                },
            },
        });
        expect(thrown.body.result.err.message).toBe('saml user boom');
    });

    test('covers UBC setup missing config combinations and constructor failure', async ({ page }) => {
        const missingIssuer = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
                SAML_CERT_PATH: '__CERT__',
            },
        });
        expect(missingIssuer.strategies).toEqual(['local']);

        const missingCallback = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_ISSUER: 'biocbot-test-sp',
                SAML_CERT_PATH: '__CERT__',
            },
        });
        expect(missingCallback.strategies).toEqual(['local']);

        const missingCert = await loadPassport(page, {
            ubcStyle: 'named',
            env: {
                SAML_ENTRY_POINT: 'https://idp.test.local/sso',
                SAML_ISSUER: 'biocbot-test-sp',
                SAML_CALLBACK_URL: 'http://127.0.0.1/callback',
            },
        });
        expect(missingCert.strategies).toEqual(['local']);

        const constructorFailure = await loadPassport(page, {
            ubcStyle: 'named',
            ubcConstructorThrows: true,
            env: fullSamlEnv,
        });
        expect(constructorFailure.strategies).toEqual(['local', 'saml']);
    });
});
