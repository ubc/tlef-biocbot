// @ts-check
/**
 * Student-facing Super Course tests. Covers the new
 *   /student/super-course page,
 *   /api/student/super-course/status,
 *   /api/student/super-course/pool, and
 *   /api/student/super-course/chat
 * routes. Seeds dedicated courses + a `superCourseChat` settings document so
 * each test is independent and the toggle can be flipped at will.
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');
const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, loadCredentials, storageStatePath } = require('./helpers/users');
const { resetLlmStub, enqueueLlmResponses } = require('./helpers/llm-stub');

const SUPER_OPTED_IN_ID = 'BIOC-E2E-SUPER-OPTED-IN';
const SUPER_OPTED_OUT_ID = 'BIOC-E2E-SUPER-OPTED-OUT';
const SUPER_INACTIVE_ID = 'BIOC-E2E-SUPER-INACTIVE';
const SUPER_TEST_COURSE_IDS = [SUPER_OPTED_IN_ID, SUPER_OPTED_OUT_ID, SUPER_INACTIVE_ID];
const SETTINGS_ID = 'superCourseChat';

let instructorId;
let studentId;
let studentPassword;
let originalSuperCourseSettings = null;

async function withDb(fn) {
    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI not set; cannot run student super course e2e tests.');
    }
    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    try {
        return await fn(client.db());
    } finally {
        await client.close();
    }
}

async function getUserIdByUsername(username) {
    return withDb(async (db) => {
        const user = await db.collection('users').findOne({ username });
        if (!user) throw new Error(`User ${username} not found in DB.`);
        return user.userId;
    });
}

async function readSetting(id) {
    return withDb((db) => db.collection('settings').findOne({ _id: id }));
}

async function restoreSettingDoc(id, originalDoc) {
    await withDb(async (db) => {
        if (originalDoc) {
            await db.collection('settings').replaceOne({ _id: id }, originalDoc, { upsert: true });
        } else {
            await db.collection('settings').deleteOne({ _id: id });
        }
    });
}

async function setSuperCourseSettings({ showStudentSuperCourse, includeInactiveCourses = false }) {
    await withDb(async (db) => {
        await db.collection('settings').updateOne(
                { _id: SETTINGS_ID },
                {
                    $set: {
                        studentTopK: 5,
                        instructorTopK: 5,
                        includeInactiveCourses,
                        showStudentSuperCourse,
                        instructorPrompt: 'E2E instructor super prompt',
                        studentPrompt: 'E2E student super prompt',
                        updatedAt: new Date(),
                    },
                    $setOnInsert: { createdAt: new Date() },
                },
                { upsert: true }
            );
    });
}

function buildCourse({ courseId, courseName, allowInSuperCourse, status = 'active' }) {
    const now = new Date();
    return {
        courseId,
        courseName,
        courseCode: `${courseId}-STU`,
        instructorCourseCode: `${courseId}-INS`,
        instructorId,
        instructors: [instructorId],
        tas: [],
        courseDescription: '',
        assessmentCriteria: '',
        courseMaterials: [],
        approvedStruggleTopics: [],
        courseStructure: { weeks: 1, lecturesPerWeek: 1, totalUnits: 1 },
        isOnboardingComplete: true,
        status,
        allowInSuperCourse,
        lectures: [],
        createdAt: now,
        updatedAt: now,
    };
}

async function resetSuperCourseSeed() {
    await withDb(async (db) => {
        await db.collection('courses').deleteMany({ courseId: { $in: SUPER_TEST_COURSE_IDS } });
        await db.collection('courses').insertMany([
            buildCourse({
                courseId: SUPER_OPTED_IN_ID,
                courseName: 'BIOC E2E Super Opted In',
                allowInSuperCourse: true,
                status: 'active',
            }),
            buildCourse({
                courseId: SUPER_OPTED_OUT_ID,
                courseName: 'BIOC E2E Super Opted Out',
                allowInSuperCourse: false,
                status: 'active',
            }),
            buildCourse({
                courseId: SUPER_INACTIVE_ID,
                courseName: 'BIOC E2E Super Inactive',
                allowInSuperCourse: true,
                status: 'inactive',
            }),
        ]);
    });
}

async function cleanupSuperCourseSeed() {
    await withDb(async (db) => {
        await db.collection('courses').deleteMany({ courseId: { $in: SUPER_TEST_COURSE_IDS } });
    });
}

async function loginAsStudent(page) {
    await page.goto('/');
    await page.locator('#auth-form input#username').fill(TEST_USERS.student.username);
    await page.locator('#auth-form input#password').fill(studentPassword);
    await page.locator('#auth-form button#login-btn').click();
    await page.waitForURL((url) => url.pathname !== '/' && url.pathname !== '/login', {
        timeout: 10_000,
    });
}

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
    studentPassword = loadCredentials().student;
    originalSuperCourseSettings = await readSetting(SETTINGS_ID);
});

test.beforeEach(async () => {
    await resetSuperCourseSeed();
});

test.afterAll(async () => {
    await cleanupSuperCourseSeed();
    await restoreSettingDoc(SETTINGS_ID, originalSuperCourseSettings);
});

test.describe('Super Course nav visibility', () => {
    test.use({ storageState: storageStatePath('student') });

    test('nav item is hidden when the admin toggle is off', async ({ page }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: false });

        await page.goto('/student');
        await expect(page.locator('#super-course-nav-item')).toBeHidden({ timeout: 10_000 });
    });

    test('nav item is visible when the admin toggle is on', async ({ page }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true });

        await page.goto('/student');
        await expect(page.locator('#super-course-nav-item')).toBeVisible({ timeout: 10_000 });
    });
});

test.describe('Super Course page — toggle off', () => {
    test.use({ storageState: storageStatePath('student') });

    test('redirects students back to /student when the toggle is off', async ({ page }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: false });

        await page.goto('/student/super-course');
        await page.waitForURL((url) => url.pathname === '/student', { timeout: 10_000 });
    });
});

test.describe('Super Course page — toggle on', () => {
    test.use({ storageState: storageStatePath('student') });

    test('renders the source pool from opted-in active courses only', async ({ page }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true });

        await page.goto('/student/super-course');
        const poolList = page.locator('#super-course-pool-list');
        await expect(poolList).toContainText('BIOC E2E Super Opted In', { timeout: 10_000 });

        // Opted-out and inactive courses must not appear when the toggle is on
        // and includeInactiveCourses is false.
        await expect(poolList).not.toContainText('BIOC E2E Super Opted Out');
        await expect(poolList).not.toContainText('BIOC E2E Super Inactive');
    });

    test('sends a chat message and renders the bot response', async ({ page, baseURL }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true });

        // The LLM stub helper drives the in-process stub the server uses when
        // BIOCBOT_TEST_LLM_STUB=1; that flag is set in playwright.config.js.
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, ['ATP is the cell\'s energy currency.']);
        } finally {
            await api.dispose();
        }

        await page.goto('/student/super-course');
        await expect(page.locator('#super-course-pool-list')).toContainText('BIOC E2E Super Opted In', {
            timeout: 10_000,
        });

        await page.locator('#chat-input').fill('What is ATP?');
        await page.locator('#send-button').click();

        const messages = page.locator('#chat-messages .bot-message');
        await expect(messages.last()).toContainText("ATP is the cell's energy currency.", {
            timeout: 15_000,
        });
    });
});

test.describe('Super Course API', () => {
    test('/status returns the current toggle value', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            await setSuperCourseSettings({ showStudentSuperCourse: false });
            const offResp = await api.get('/api/student/super-course/status');
            expect(offResp.status()).toBe(200);
            expect(await offResp.json()).toMatchObject({ success: true, enabled: false });

            await setSuperCourseSettings({ showStudentSuperCourse: true });
            const onResp = await api.get('/api/student/super-course/status');
            expect(onResp.status()).toBe(200);
            expect(await onResp.json()).toMatchObject({ success: true, enabled: true });
        } finally {
            await api.dispose();
        }
    });

    test('/pool and /chat are 403 when the toggle is off', async ({ baseURL }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: false });

        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const pool = await api.get('/api/student/super-course/pool', { failOnStatusCode: false });
            expect(pool.status()).toBe(403);

            const chat = await api.post('/api/student/super-course/chat', {
                data: { message: 'hello' },
                failOnStatusCode: false,
            });
            expect(chat.status()).toBe(403);
        } finally {
            await api.dispose();
        }
    });

    test('/pool returns only active opted-in courses by default', async ({ baseURL }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true, includeInactiveCourses: false });

        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.get('/api/student/super-course/pool');
            expect(resp.status()).toBe(200);
            const body = await resp.json();
            expect(body.success).toBe(true);
            const ids = (body.courses || []).map((c) => c.courseId);
            expect(ids).toContain(SUPER_OPTED_IN_ID);
            expect(ids).not.toContain(SUPER_OPTED_OUT_ID);
            expect(ids).not.toContain(SUPER_INACTIVE_ID);
        } finally {
            await api.dispose();
        }
    });

    test('/pool includes inactive opted-in courses when includeInactiveCourses is on', async ({ baseURL }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true, includeInactiveCourses: true });

        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.get('/api/student/super-course/pool');
            const body = await resp.json();
            const ids = (body.courses || []).map((c) => c.courseId);
            expect(ids).toContain(SUPER_OPTED_IN_ID);
            expect(ids).toContain(SUPER_INACTIVE_ID);
            expect(ids).not.toContain(SUPER_OPTED_OUT_ID);
        } finally {
            await api.dispose();
        }
    });

    test('/chat rejects an empty message with 400', async ({ baseURL }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true });

        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.post('/api/student/super-course/chat', {
                data: { message: '   ' },
                failOnStatusCode: false,
            });
            expect(resp.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('/chat returns the LLM stub answer and uses the configured student prompt', async ({ baseURL }) => {
        await setSuperCourseSettings({ showStudentSuperCourse: true });

        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, ['Stubbed super-course answer for the student.']);

            const resp = await api.post('/api/student/super-course/chat', {
                data: { message: 'Explain glycolysis briefly.' },
            });
            expect(resp.status()).toBe(200);
            const body = await resp.json();
            expect(body.success).toBe(true);
            expect(body.message).toBe('Stubbed super-course answer for the student.');
            expect(body.sourceAttribution).toBeDefined();
            expect(Array.isArray(body.sourceAttribution.poolCourses)).toBe(true);
            const poolCourseIds = body.sourceAttribution.poolCourses.map((c) => c.courseId);
            expect(poolCourseIds).toContain(SUPER_OPTED_IN_ID);
        } finally {
            await api.dispose();
        }
    });
});
