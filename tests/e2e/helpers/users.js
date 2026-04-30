// @ts-check
const fs = require('fs');
const path = require('path');

const STORAGE_STATE_DIR = path.join(__dirname, '..', '..', '..', 'playwright', '.auth');
const CREDENTIALS_PATH = path.join(STORAGE_STATE_DIR, '.credentials.json');

const TEST_USERS = {
    instructor: {
        username: 'e2e_instructor',
        email: 'e2e-instructor@test.local',
        role: 'instructor',
        displayName: 'E2E Instructor',
        landingPath: '/instructor/home',
    },
    student: {
        username: 'e2e_student',
        email: 'e2e-student@test.local',
        role: 'student',
        displayName: 'E2E Student',
        landingPath: '/student',
    },
    ta: {
        username: 'e2e_ta',
        email: 'e2e-ta@test.local',
        role: 'ta',
        displayName: 'E2E TA',
        landingPath: '/ta',
    },
};

function storageStatePath(role) {
    return path.join(STORAGE_STATE_DIR, `${role}.json`);
}

function loadCredentials() {
    if (!fs.existsSync(CREDENTIALS_PATH)) {
        throw new Error(
            `Test credentials not found at ${CREDENTIALS_PATH}. ` +
            'Run "npx playwright test" once to generate them via global-setup.'
        );
    }
    return JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
}

module.exports = {
    TEST_USERS,
    STORAGE_STATE_DIR,
    CREDENTIALS_PATH,
    storageStatePath,
    loadCredentials,
};
