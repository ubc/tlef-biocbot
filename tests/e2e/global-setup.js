// @ts-check
const fs = require('fs');
const crypto = require('crypto');
const { request } = require('@playwright/test');
const {
    TEST_USERS,
    STORAGE_STATE_DIR,
    CREDENTIALS_PATH,
    storageStatePath,
} = require('./helpers/users');

function loadOrGenerateCredentials() {
    if (fs.existsSync(CREDENTIALS_PATH)) {
        const existing = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
        const allRolesPresent = Object.keys(TEST_USERS).every((role) => existing[role]);
        if (allRolesPresent) return existing;
    }

    const generated = {};
    for (const role of Object.keys(TEST_USERS)) {
        generated[role] = `E2e!${crypto.randomBytes(24).toString('hex')}`;
    }

    fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(generated, null, 2), { mode: 0o600 });
    return generated;
}

async function ensureUser(api, user, password) {
    const loginRes = await api.post('/api/auth/login', {
        data: { username: user.username, password },
        failOnStatusCode: false,
    });

    if (loginRes.ok()) return;

    const registerRes = await api.post('/api/auth/register', {
        data: {
            username: user.username,
            password,
            email: user.email,
            role: user.role,
            displayName: user.displayName,
        },
        failOnStatusCode: false,
    });

    if (!registerRes.ok()) {
        const body = await registerRes.text();
        throw new Error(
            `Failed to register test ${user.role} "${user.username}": ` +
            `${registerRes.status()} ${body}. ` +
            `If a user with this username already exists with a different password, ` +
            `delete it from the local DB or remove ${CREDENTIALS_PATH} and recreate.`
        );
    }
}

async function saveStorageState(baseURL, user, password) {
    const api = await request.newContext({ baseURL });
    const loginRes = await api.post('/api/auth/login', {
        data: { username: user.username, password },
        failOnStatusCode: false,
    });

    if (!loginRes.ok()) {
        const body = await loginRes.text();
        throw new Error(
            `Failed to log in as ${user.role} "${user.username}" while saving ` +
            `storage state: ${loginRes.status()} ${body}`
        );
    }

    await api.storageState({ path: storageStatePath(user.role) });
    await api.dispose();
}

module.exports = async function globalSetup(config) {
    const baseURL = config.projects[0].use.baseURL;
    if (!baseURL) {
        throw new Error('global-setup: baseURL is not configured on the chromium project');
    }

    fs.mkdirSync(STORAGE_STATE_DIR, { recursive: true });
    const credentials = loadOrGenerateCredentials();

    const setupApi = await request.newContext({ baseURL });
    try {
        for (const [role, user] of Object.entries(TEST_USERS)) {
            await ensureUser(setupApi, user, credentials[role]);
        }
    } finally {
        await setupApi.dispose();
    }

    for (const [role, user] of Object.entries(TEST_USERS)) {
        await saveStorageState(baseURL, user, credentials[role]);
    }
};
