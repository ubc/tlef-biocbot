// @ts-check
/**
 * Broader coverage for public/instructor/scripts/settings.js.
 *
 * These tests drive the real /instructor/settings page through the Monocart
 * Playwright fixture and seed MongoDB directly for stable course/user state.
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');
const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');

const SETTINGS_COURSE_ID = 'BIOC-E2E-SETTINGS';
const SETTINGS_OTHER_COURSE_ID = 'BIOC-E2E-SETTINGS-OTHER';
const SETTINGS_COURSE_NAME = 'BIOC E2E Settings Test';
const SETTINGS_OTHER_COURSE_NAME = 'BIOC E2E Settings Other Owner';
const SETTINGS_COPY_NAME_PREFIX = 'BIOC E2E Settings Copy';
const SETTINGS_TEST_COURSE_IDS = [SETTINGS_COURSE_ID, SETTINGS_OTHER_COURSE_ID];

let instructorId;
let freshInstructorId;
let taId;
let originalGlobalSettings = null;
let originalLLMSettings = null;
let originalInstructorSystemAdmin = false;
let originalFreshSystemAdmin = false;
let originalInstructorPreferences;
let originalFreshInstructorPreferences;

async function withDb(fn) {
    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI not set; cannot run instructor settings e2e tests.');
    }
    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    try {
        return await fn(client.db());
    } finally {
        await client.close();
    }
}

async function getUserByUsername(username) {
    return withDb(async (db) => {
        const user = await db.collection('users').findOne({ username });
        if (!user) throw new Error(`User ${username} not found in DB.`);
        return user;
    });
}

async function setSystemAdmin(userId, isAdmin) {
    await withDb(async (db) => {
        if (isAdmin) {
            await db.collection('users').updateOne(
                { userId },
                { $set: { 'permissions.systemAdmin': true, updatedAt: new Date() } }
            );
            return;
        }

        await db.collection('users').updateOne(
            { userId },
            { $unset: { 'permissions.systemAdmin': '' }, $set: { updatedAt: new Date() } }
        );
    });
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

function deepClone(value) {
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

async function restoreUserPreferences(userId, preferences) {
    await withDb(async (db) => {
        if (preferences === undefined) {
            await db.collection('users').updateOne(
                { userId },
                { $unset: { preferences: '' }, $set: { updatedAt: new Date() } }
            );
            return;
        }

        await db.collection('users').updateOne(
            { userId },
            { $set: { preferences: deepClone(preferences), updatedAt: new Date() } }
        );
    });
}

function buildSettingsCourse({
    courseId,
    courseName,
    ownerId,
    status = 'active',
    includeSettings = true,
}) {
    const now = new Date();
    const course = {
        courseId,
        courseName,
        courseCode: `${courseId}-STU`,
        instructorCourseCode: `${courseId}-INS`,
        instructorId: ownerId,
        instructors: [ownerId],
        tas: [taId],
        taPermissions: {
            [taId]: {
                canAccessCourses: true,
                canAccessFlags: true,
                updatedAt: now,
            },
        },
        courseDescription: '',
        assessmentCriteria: '',
        courseMaterials: [],
        approvedStruggleTopics: ['Cell signaling'],
        courseStructure: { weeks: 2, lecturesPerWeek: 1, totalUnits: 2 },
        isOnboardingComplete: true,
        status,
        lectures: [
            {
                name: 'Unit 1',
                displayName: 'Intro Unit',
                isPublished: true,
                learningObjectives: ['Describe ATP synthesis'],
                passThreshold: 1,
                documents: [],
                assessmentQuestions: [
                    {
                        questionId: 'settings-q1',
                        questionType: 'true-false',
                        question: 'ATP stores usable cellular energy.',
                        correctAnswer: 'true',
                        isActive: true,
                    },
                ],
                createdAt: now,
                updatedAt: now,
            },
            {
                name: 'Unit 2',
                displayName: 'Advanced Unit',
                isPublished: true,
                learningObjectives: ['Explain membrane gradients'],
                passThreshold: 1,
                documents: [],
                assessmentQuestions: [
                    {
                        questionId: 'settings-q2',
                        questionType: 'short-answer',
                        question: 'What does a proton gradient store?',
                        correctAnswer: 'Potential energy',
                        isActive: true,
                    },
                ],
                createdAt: now,
                updatedAt: now,
            },
        ],
        createdAt: now,
        updatedAt: now,
    };

    if (includeSettings) {
        course.prompts = {
            base: 'Seed base prompt',
            protege: 'Seed protege prompt',
            tutor: 'Seed tutor prompt',
            explain: 'Seed explain prompt',
            directive: 'Seed directive prompt',
            quizHelp: 'Seed quiz help prompt',
            studentIdleTimeout: 180,
        };
        course.isAdditiveRetrieval = false;
        course.quizSettings = {
            enabled: true,
            testableUnits: ['Unit 1'],
            allowLectureMaterialAccess: true,
            allowSourceAttributionDownloads: false,
        };
        course.anonymizeStudents = {
            [ownerId]: {
                enabled: false,
                updatedAt: now,
            },
        };
        course.questionPrompts = {
            systemPrompt: 'Seed question system prompt',
            trueFalse: 'Seed true false prompt',
            multipleChoice: 'Seed multiple choice prompt',
            shortAnswer: 'Seed short answer prompt',
        };
        course.mentalHealthDetectionPrompt = 'Seed mental health detection prompt';
    }

    return course;
}

async function cleanupSettingsCourses() {
    await withDb(async (db) => {
        const copyCourses = await db.collection('courses')
            .find(
                { courseName: { $regex: `^${SETTINGS_COPY_NAME_PREFIX}` } },
                { projection: { courseId: 1 } }
            )
            .toArray();
        const courseIds = [
            ...SETTINGS_TEST_COURSE_IDS,
            ...copyCourses.map((course) => course.courseId),
        ];

        await db.collection('courses').deleteMany({
            $or: [
                { courseId: { $in: SETTINGS_TEST_COURSE_IDS } },
                { courseName: { $regex: `^${SETTINGS_COPY_NAME_PREFIX}` } },
            ],
        });
        await db.collection('documents').deleteMany({ courseId: { $in: courseIds } });
    });
}

async function resetSettingsData() {
    await cleanupSettingsCourses();
    await withDb(async (db) => {
        await db.collection('settings').updateOne(
            { _id: 'global' },
            { $set: { allowLocalLogin: true, updatedAt: new Date() } },
            { upsert: true }
        );
        await db.collection('settings').updateOne(
            { _id: 'llm' },
            {
                $set: {
                    model: 'gpt-5-nano',
                    reasoningEffort: 'minimal',
                    updatedAt: new Date(),
                },
            },
            { upsert: true }
        );

        await db.collection('courses').insertMany([
            buildSettingsCourse({
                courseId: SETTINGS_COURSE_ID,
                courseName: SETTINGS_COURSE_NAME,
                ownerId: instructorId,
            }),
            buildSettingsCourse({
                courseId: SETTINGS_OTHER_COURSE_ID,
                courseName: SETTINGS_OTHER_COURSE_NAME,
                ownerId: freshInstructorId,
                includeSettings: false,
            }),
        ]);
    });
}

async function readCourse(courseId = SETTINGS_COURSE_ID) {
    return withDb((db) => db.collection('courses').findOne({ courseId }));
}

async function findCourseByName(courseName) {
    return withDb((db) => db.collection('courses').findOne({ courseName }));
}

async function readSetting(id) {
    return withDb((db) => db.collection('settings').findOne({ _id: id }));
}

async function openSettings(page, courseId = SETTINGS_COURSE_ID) {
    await page.goto(`/instructor/settings?courseId=${courseId}`);
    await expect(page.locator('h1')).toHaveText('Settings', { timeout: 15_000 });
    await expect(page.locator('#base-prompt')).toHaveValue('Seed base prompt', { timeout: 15_000 });
    await expect(page.locator('#testable-units-container .loading-text')).toHaveCount(0, { timeout: 15_000 });
    await expect(page.locator('#transfer-unit-grid .transfer-unit-row')).toHaveCount(2, { timeout: 15_000 });
}

async function setInputChecked(page, selector, checked) {
    await page.evaluate(
        ({ selector, checked }) => {
            const input = /** @type {HTMLInputElement | null} */ (document.querySelector(selector));
            if (!input) throw new Error(`${selector} not found`);
            input.checked = checked;
            input.dispatchEvent(new Event('change', { bubbles: true }));
        },
        { selector, checked }
    );
}

function jsonResponse(body, status = 200) {
    return {
        status,
        contentType: 'application/json',
        body: JSON.stringify(body),
    };
}

async function setupMockedSettingsRoutes(page, options = {}) {
    const state = {
        canDeleteAll: true,
        courseId: 'MOCK-SETTINGS',
        courseName: 'Mock Settings Course',
        courseStatus: 'active',
        lectures: [
            {
                name: 'Unit 1',
                displayName: 'Intro Unit',
                isPublished: true,
                learningObjectives: ['Objective 1'],
                assessmentQuestions: [{ questionId: 'mock-q1' }],
            },
            {
                name: 'Unit 2',
                displayName: 'Advanced Unit',
                isPublished: true,
                learningObjectives: ['Objective 2'],
                assessmentQuestions: [{ questionId: 'mock-q2' }],
            },
        ],
        admins: [
            {
                email: TEST_USERS.instructor.email,
                displayName: 'E2E Instructor',
                lastLogin: null,
            },
            {
                email: TEST_USERS.instructor_fresh.email,
                displayName: '<Fresh & Admin>',
                lastLogin: 'not-a-date',
            },
        ],
        systemAdminListError: false,
        grantResult: { success: true },
        revokeResult: { success: true },
        promptResetResult: {
            success: true,
            prompts: {
                base: 'Default base prompt',
                protege: 'Default protege prompt',
                tutor: 'Default tutor prompt',
                explain: 'Default explain prompt',
                directive: 'Default directive prompt',
            },
        },
        mhResetResult: { success: true, prompt: 'Default detection prompt' },
        questionResetResult: {
            success: true,
            prompts: {
                systemPrompt: 'Default question system',
                trueFalse: 'Default true false',
                multipleChoice: 'Default multiple choice',
                shortAnswer: 'Default short answer',
            },
        },
        deleteAllResult: {
            success: true,
            data: { qdrantDeletedCount: 4, mongoDeletedCount: 9 },
        },
        promptSaveResult: { success: true },
        transferStatus: 200,
        transferResult: {
            success: true,
            data: {
                courseId: 'MOCK-SETTINGS-COPY',
                courseName: 'Mock Settings Copy',
                warnings: [],
            },
        },
        courseGetStatus: 200,
        courseGetResult: null,
        lifecycleStatus: 200,
        lifecycleResult: { success: true },
        abortPaths: new Set(),
        ...options,
    };

    if (!(state.abortPaths instanceof Set)) {
        state.abortPaths = new Set(state.abortPaths);
    }

    await page.route('**/*', async (route) => {
        const requestUrl = new URL(route.request().url());
        const { pathname } = requestUrl;
        const method = route.request().method();

        if (state.abortPaths.has(pathname)) {
            await route.abort();
            return;
        }

        if (pathname === '/api/settings/can-delete-all') {
            await route.fulfill(jsonResponse({ success: true, canDeleteAll: state.canDeleteAll }));
            return;
        }

        if (pathname === '/api/settings/prompts') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse(state.promptSaveResult));
                return;
            }

            await route.fulfill(jsonResponse({
                success: true,
                prompts: {
                    base: 'Mock base prompt',
                    protege: 'Mock protege prompt',
                    tutor: 'Mock tutor prompt',
                    explain: 'Mock explain prompt',
                    directive: 'Mock directive prompt',
                    quizHelp: 'Mock quiz help prompt',
                    additiveRetrieval: true,
                    studentIdleTimeout: 300,
                },
            }));
            return;
        }

        if (pathname === '/api/settings/prompts/reset') {
            await route.fulfill(jsonResponse(state.promptResetResult));
            return;
        }

        if (pathname === '/api/settings/quiz') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse({ success: true }));
                return;
            }

            await route.fulfill(jsonResponse({
                success: true,
                settings: {
                    enabled: false,
                    testableUnits: 'all',
                    allowLectureMaterialAccess: false,
                    allowSourceAttributionDownloads: true,
                },
            }));
            return;
        }

        if (pathname.startsWith('/api/courses/') && pathname.endsWith('/transfer')) {
            await route.fulfill(jsonResponse(state.transferResult, state.transferStatus));
            return;
        }

        if (pathname.startsWith('/api/courses/') && pathname.endsWith('/publish-status')) {
            await route.fulfill(jsonResponse({ success: true, isPublished: true }));
            return;
        }

        if (pathname.startsWith('/api/courses/')) {
            if (method === 'PUT') {
                await route.fulfill(jsonResponse(state.lifecycleResult, state.lifecycleStatus));
                return;
            }

            const courseId = decodeURIComponent(pathname.split('/').pop() || state.courseId);
            if (state.courseGetResult) {
                await route.fulfill(jsonResponse(state.courseGetResult, state.courseGetStatus));
                return;
            }

            await route.fulfill(jsonResponse({
                success: true,
                data: {
                    courseId,
                    name: courseId === 'MOCK-SETTINGS-COPY' ? 'Mock Settings Copy' : state.courseName,
                    courseName: courseId === 'MOCK-SETTINGS-COPY' ? 'Mock Settings Copy' : state.courseName,
                    status: state.courseStatus,
                    lectures: state.lectures,
                },
            }));
            return;
        }

        if (pathname === '/api/settings/anonymize-students') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse({ success: true }));
                return;
            }

            await route.fulfill(jsonResponse({ success: true, enabled: true }));
            return;
        }

        if (pathname === '/api/settings/mental-health-prompt') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse({ success: true }));
                return;
            }

            await route.fulfill(jsonResponse({ success: true, prompt: 'Mock detection prompt' }));
            return;
        }

        if (pathname === '/api/settings/mental-health-prompt/reset') {
            await route.fulfill(jsonResponse(state.mhResetResult));
            return;
        }

        if (pathname === '/api/settings/global') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse({ success: true }));
                return;
            }

            await route.fulfill(jsonResponse({ success: true, settings: { allowLocalLogin: false } }));
            return;
        }

        if (pathname === '/api/settings/llm') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse({ success: true }));
                return;
            }

            await route.fulfill(jsonResponse({
                success: true,
                settings: { model: 'gpt-4.1-mini', reasoningEffort: 'minimal' },
            }));
            return;
        }

        if (pathname === '/api/settings/question-prompts') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse({ success: true }));
                return;
            }

            await route.fulfill(jsonResponse({
                success: true,
                prompts: {
                    systemPrompt: 'Mock question system prompt',
                    trueFalse: 'Mock true false prompt',
                    multipleChoice: 'Mock multiple choice prompt',
                    shortAnswer: 'Mock short answer prompt',
                },
            }));
            return;
        }

        if (pathname === '/api/settings/question-prompts/reset') {
            await route.fulfill(jsonResponse(state.questionResetResult));
            return;
        }

        if (pathname === '/api/settings/system-admins') {
            if (method === 'POST') {
                await route.fulfill(jsonResponse(state.grantResult));
                return;
            }

            if (state.systemAdminListError) {
                await route.fulfill(jsonResponse({ success: false, error: 'Admin list unavailable' }, 500));
                return;
            }

            await route.fulfill(jsonResponse({ success: true, admins: state.admins }));
            return;
        }

        if (pathname === '/api/settings/system-admins/revoke') {
            await route.fulfill(jsonResponse(state.revokeResult));
            return;
        }

        if (pathname === '/api/qdrant/delete-all-collections') {
            await route.fulfill(jsonResponse(state.deleteAllResult));
            return;
        }

        if (pathname === '/api/auth/set-course') {
            await route.fulfill(jsonResponse({ success: true }));
            return;
        }

        await route.continue();
    });

    return state;
}

async function openMockedSettings(page, options = {}) {
    const state = await setupMockedSettingsRoutes(page, options);
    await page.goto(`/instructor/settings?courseId=${state.courseId}`);
    await expect(page.locator('h1')).toHaveText('Settings', { timeout: 15_000 });
    await expect(page.locator('#base-prompt')).toHaveValue('Mock base prompt', { timeout: 15_000 });
    await expect(page.locator('#testable-units-container .loading-text')).toHaveCount(0, { timeout: 15_000 });
    return state;
}

test.beforeAll(async () => {
    const instructor = await getUserByUsername(TEST_USERS.instructor.username);
    const freshInstructor = await getUserByUsername(TEST_USERS.instructor_fresh.username);
    const ta = await getUserByUsername(TEST_USERS.ta.username);
    instructorId = instructor.userId;
    freshInstructorId = freshInstructor.userId;
    taId = ta.userId;
    originalInstructorSystemAdmin = instructor.permissions?.systemAdmin === true;
    originalFreshSystemAdmin = freshInstructor.permissions?.systemAdmin === true;
    originalInstructorPreferences = deepClone(instructor.preferences);
    originalFreshInstructorPreferences = deepClone(freshInstructor.preferences);
    originalGlobalSettings = await readSetting('global');
    originalLLMSettings = await readSetting('llm');
});

test.beforeEach(async () => {
    await setSystemAdmin(instructorId, false);
    await setSystemAdmin(freshInstructorId, false);
    await resetSettingsData();
});

test.afterEach(async () => {
    await setSystemAdmin(instructorId, false);
    await setSystemAdmin(freshInstructorId, false);
    await restoreUserPreferences(instructorId, originalInstructorPreferences);
    await restoreUserPreferences(freshInstructorId, originalFreshInstructorPreferences);
    await restoreSettingDoc('global', originalGlobalSettings);
    await restoreSettingDoc('llm', originalLLMSettings);
});

test.afterAll(async () => {
    await cleanupSettingsCourses();
    await setSystemAdmin(instructorId, originalInstructorSystemAdmin);
    await setSystemAdmin(freshInstructorId, originalFreshSystemAdmin);
    await restoreUserPreferences(instructorId, originalInstructorPreferences);
    await restoreUserPreferences(freshInstructorId, originalFreshInstructorPreferences);
    await restoreSettingDoc('global', originalGlobalSettings);
    await restoreSettingDoc('llm', originalLLMSettings);
});

test.describe('Instructor settings UI', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('hides system-admin-only settings for a regular instructor and loads course-scoped settings', async ({ page }) => {
        await openSettings(page);

        await expect(page.locator('#database-management-section')).toBeHidden();
        await expect(page.locator('#login-restriction-section')).toBeHidden();
        await expect(page.locator('#question-generation-section')).toBeHidden();
        await expect(page.locator('#mental-health-detection-section')).toBeHidden();
        await expect(page.locator('#system-admin-section')).toBeHidden();
        await expect(page.locator('#llm-model-section')).toBeHidden();

        await expect(page.locator('#idle-timeout-input')).toHaveValue('3');
        await expect(page.locator('#additive-retrieval-toggle')).not.toBeChecked();
        await expect(page.locator('#anonymize-students-toggle')).not.toBeChecked();
        await expect(page.locator('#quiz-enabled-toggle')).toBeChecked();
        await expect(page.locator('.testable-unit-checkbox[value="Unit 1"]')).toBeChecked();
        await expect(page.locator('.testable-unit-checkbox[value="Unit 2"]')).not.toBeChecked();
    });

    test('saves prompts, retrieval, idle timeout, quiz download, and anonymize settings for the selected course', async ({ page }) => {
        await openSettings(page);

        await page.locator('#base-prompt').fill('Updated base prompt from settings UI');
        await page.locator('#protege-prompt').fill('Updated protege prompt from settings UI');
        await page.locator('#tutor-prompt').fill('Updated tutor prompt from settings UI');
        await page.locator('#explain-prompt').fill('Updated explain prompt from settings UI');
        await page.locator('#directive-prompt').fill('Updated directive prompt from settings UI');
        await page.locator('#quiz-help-prompt').fill('Updated quiz help prompt from settings UI');
        await page.locator('#idle-timeout-input').fill('5.5');
        await setInputChecked(page, '#additive-retrieval-toggle', true);
        await setInputChecked(page, '#source-attribution-download-toggle', true);
        await setInputChecked(page, '#anonymize-students-toggle', true);

        await page.locator('#save-settings').click();

        await expect(page.locator('.notification.success', { hasText: 'Settings saved successfully' })).toBeVisible({
            timeout: 10_000,
        });

        await expect.poll(async () => {
            const course = await readCourse();
            return {
                base: course.prompts?.base,
                protege: course.prompts?.protege,
                tutor: course.prompts?.tutor,
                explain: course.prompts?.explain,
                directive: course.prompts?.directive,
                quizHelp: course.prompts?.quizHelp,
                studentIdleTimeout: course.prompts?.studentIdleTimeout,
                isAdditiveRetrieval: course.isAdditiveRetrieval,
                allowSourceAttributionDownloads: course.quizSettings?.allowSourceAttributionDownloads,
                anonymizeEnabled: course.anonymizeStudents?.[instructorId]?.enabled,
            };
        }, { timeout: 10_000 }).toMatchObject({
            base: 'Updated base prompt from settings UI',
            protege: 'Updated protege prompt from settings UI',
            tutor: 'Updated tutor prompt from settings UI',
            explain: 'Updated explain prompt from settings UI',
            directive: 'Updated directive prompt from settings UI',
            quizHelp: 'Updated quiz help prompt from settings UI',
            studentIdleTimeout: 330,
            isAdditiveRetrieval: true,
            allowSourceAttributionDownloads: true,
            anonymizeEnabled: true,
        });
    });

    test('shows admin settings, enforces gpt-5.4-nano reasoning rules, and saves global admin controls', async ({ page }) => {
        await setSystemAdmin(instructorId, true);
        await openSettings(page);

        await expect(page.locator('#database-management-section')).toBeVisible();
        await expect(page.locator('#login-restriction-section')).toBeVisible();
        await expect(page.locator('#question-generation-section')).toBeVisible();
        await expect(page.locator('#mental-health-detection-section')).toBeVisible();
        await expect(page.locator('#system-admin-section')).toBeVisible();
        await expect(page.locator('#llm-model-section')).toBeVisible();
        await expect(page.locator('#mental-health-detection-prompt')).toHaveValue('Seed mental health detection prompt');
        await expect(page.locator('#question-system-prompt')).toHaveValue('Seed question system prompt');

        await expect(page.locator('#llm-model-select')).toHaveValue('gpt-5-nano');
        await expect(page.locator('#llm-reasoning-item')).toBeVisible();
        await expect(page.locator('#llm-reasoning-select')).toHaveValue('minimal');

        await page.locator('#llm-model-select').selectOption('gpt-5.4-nano');
        await expect(page.locator('#llm-reasoning-select')).toHaveValue('low');
        await expect(page.locator('#llm-reasoning-select option[value="minimal"]')).toBeDisabled();
        await setInputChecked(page, '#allow-local-login-toggle', false);

        await page.locator('#save-settings').click();
        await expect(page.locator('.notification.success', { hasText: 'Settings saved successfully' })).toBeVisible({
            timeout: 10_000,
        });

        await expect.poll(async () => {
            const [globalSettings, llmSettings] = await Promise.all([
                readSetting('global'),
                readSetting('llm'),
            ]);
            return {
                allowLocalLogin: globalSettings?.allowLocalLogin,
                model: llmSettings?.model,
                reasoningEffort: llmSettings?.reasoningEffort,
            };
        }, { timeout: 10_000 }).toMatchObject({
            allowLocalLogin: false,
            model: 'gpt-5.4-nano',
            reasoningEffort: 'low',
        });
    });

    test('deactivates and reactivates the selected course from the lifecycle panel', async ({ page }) => {
        await openSettings(page);
        await page.locator('#course-lifecycle-section').scrollIntoViewIfNeeded();

        await expect(page.locator('#course-status-badge')).toHaveText('Active');
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#toggle-course-active-btn').click();

        await expect(page.locator('.notification.success', { hasText: 'Course deactivated' })).toBeVisible({
            timeout: 10_000,
        });
        await expect(page.locator('#course-status-badge')).toHaveText('Inactive');
        await expect.poll(async () => (await readCourse()).status, { timeout: 10_000 }).toBe('inactive');

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#toggle-course-active-btn').click();

        await expect(page.locator('.notification.success', { hasText: 'Course reactivated successfully' })).toBeVisible({
            timeout: 10_000,
        });
        await expect(page.locator('#course-status-badge')).toHaveText('Active');
        await expect.poll(async () => (await readCourse()).status, { timeout: 10_000 }).toBe('active');
    });

    test('previews transfer selections and creates a course copy with selected units and options', async ({ page }) => {
        const copyName = `${SETTINGS_COPY_NAME_PREFIX} ${Date.now()}`;
        await openSettings(page);
        await page.locator('#course-lifecycle-section').scrollIntoViewIfNeeded();

        await page.locator('#transfer-course-name').fill(copyName);
        await setInputChecked(page, '#transfer-settings-toggle', false);
        await setInputChecked(page, '#transfer-tas-toggle', false);
        await setInputChecked(page, '#deactivate-source-after-transfer-toggle', true);
        await setInputChecked(page, '.transfer-unit-row[data-unit-name="Unit 2"] .transfer-objectives-checkbox', false);
        await setInputChecked(page, '.transfer-unit-row[data-unit-name="Unit 1"] .transfer-questions-checkbox', false);

        await page.locator('#transfer-course-btn').click();

        const modal = page.locator('#transfer-course-modal');
        await expect(modal).toHaveClass(/show/);
        await expect(page.locator('#transfer-modal-summary')).toContainText(`New course name: ${copyName}`);
        await expect(page.locator('#transfer-modal-summary')).toContainText('2 of 2 units will copy docs and existing chunks.');
        await expect(page.locator('#transfer-modal-summary')).toContainText('1 of 2 units will copy learning objectives.');
        await expect(page.locator('#transfer-modal-summary')).toContainText('1 of 2 units will copy assessment questions.');
        await expect(page.locator('#transfer-modal-summary')).toContainText('Course settings will not be copied.');
        await expect(page.locator('#transfer-modal-summary')).toContainText('TAs will not be copied.');
        await expect(page.locator('#transfer-modal-summary')).toContainText('The source course will be deactivated after the transfer finishes.');

        await page.locator('#transfer-modal-confirm').click();

        await expect.poll(async () => Boolean(await findCourseByName(copyName)), { timeout: 15_000 }).toBe(true);
        const copiedCourse = await findCourseByName(copyName);
        const sourceCourse = await readCourse();
        const unit1 = copiedCourse.lectures.find((lecture) => lecture.name === 'Unit 1');
        const unit2 = copiedCourse.lectures.find((lecture) => lecture.name === 'Unit 2');

        await expect(page).toHaveURL(new RegExp(`/instructor/settings\\?courseId=${copiedCourse.courseId}`), {
            timeout: 15_000,
        });
        expect(sourceCourse.status).toBe('inactive');
        expect(copiedCourse.status).toBe('active');
        expect(copiedCourse.instructorId).toBe(instructorId);
        expect(copiedCourse.tas).toEqual([]);
        expect(copiedCourse.quizSettings).toBeUndefined();
        expect(copiedCourse.prompts).toBeUndefined();
        expect(unit1.isPublished).toBe(false);
        expect(unit2.isPublished).toBe(false);
        expect(unit1.learningObjectives).toEqual(['Describe ATP synthesis']);
        expect(unit1.assessmentQuestions).toEqual([]);
        expect(unit2.learningObjectives).toEqual([]);
        expect(unit2.assessmentQuestions).toHaveLength(1);
    });

    test('resets course prompts and quiz defaults after confirmation', async ({ page }) => {
        await openMockedSettings(page, { canDeleteAll: false });

        await page.locator('#base-prompt').fill('Dirty base prompt');
        await setInputChecked(page, '#quiz-enabled-toggle', true);
        await setInputChecked(page, '#quiz-material-access-toggle', false);
        await setInputChecked(page, '#source-attribution-download-toggle', true);
        await setInputChecked(page, '.testable-unit-checkbox[value="Unit 1"]', false);

        page.once('dialog', (dialog) => dialog.dismiss());
        await page.locator('#reset-settings').click();
        await expect(page.locator('#base-prompt')).toHaveValue('Dirty base prompt');

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-settings').click();

        await expect(page.locator('#base-prompt')).toHaveValue('Default base prompt');
        await expect(page.locator('#protege-prompt')).toHaveValue('Default protege prompt');
        await expect(page.locator('#tutor-prompt')).toHaveValue('Default tutor prompt');
        await expect(page.locator('#explain-prompt')).toHaveValue('Default explain prompt');
        await expect(page.locator('#directive-prompt')).toHaveValue('Default directive prompt');
        await expect(page.locator('#additive-retrieval-toggle')).toBeChecked();
        await expect(page.locator('#idle-timeout-input')).toHaveValue('4');
        await expect(page.locator('#quiz-enabled-toggle')).not.toBeChecked();
        await expect(page.locator('#quiz-material-access-toggle')).toBeChecked();
        await expect(page.locator('#source-attribution-download-toggle')).not.toBeChecked();
        await expect(page.locator('.testable-unit-checkbox[value="Unit 1"]')).toBeChecked();
        await expect(page.locator('.notification.success', { hasText: 'Settings reset to defaults' })).toBeVisible();
    });

    test('covers admin reset, delete-all, and system-admin management states', async ({ page }) => {
        const state = await openMockedSettings(page);
        await page.locator('#system-admin-section').scrollIntoViewIfNeeded();

        await expect(page.locator('#llm-model-select')).toHaveValue('gpt-4.1-mini');
        await expect(page.locator('#llm-reasoning-item')).toBeHidden();
        await expect(page.locator('#system-admin-list')).toContainText('E2E Instructor');
        await expect(page.locator('#system-admin-list')).toContainText('You');
        await expect(page.locator('#system-admin-list')).toContainText('<Fresh & Admin>');
        await expect(page.locator('#system-admin-list')).toContainText('Last login: Never');

        await page.locator('#grant-system-admin-btn').click();
        await expect(page.locator('.notification.error', { hasText: 'Enter an email address first.' })).toBeVisible();

        await page.locator('#system-admin-email-input').fill(TEST_USERS.instructor_fresh.email);
        await page.locator('#grant-system-admin-btn').click();
        await expect(page.locator('#system-admin-email-input')).toHaveValue('');
        await expect(page.locator('.notification.success', { hasText: `System admin access granted to ${TEST_USERS.instructor_fresh.email}.` })).toBeVisible();

        state.grantResult = { success: false, error: 'Grant rejected' };
        await page.locator('#system-admin-email-input').fill('missing-admin@test.local');
        await page.locator('#grant-system-admin-btn').click();
        await expect(page.locator('.notification.error', { hasText: 'Grant rejected' })).toBeVisible();

        const freshRevoke = page.locator(`.system-admin-revoke-btn[data-email="${TEST_USERS.instructor_fresh.email}"]`);
        page.once('dialog', (dialog) => dialog.dismiss());
        await freshRevoke.click();
        await expect(freshRevoke).toHaveText('Revoke');

        page.once('dialog', (dialog) => dialog.accept());
        await freshRevoke.click();
        await expect(page.locator('.notification.success', { hasText: `System admin access revoked for ${TEST_USERS.instructor_fresh.email}.` })).toBeVisible();

        state.revokeResult = { success: false, error: 'Revoke rejected' };
        page.once('dialog', (dialog) => dialog.accept());
        await freshRevoke.click();
        await expect(page.locator('.notification.error', { hasText: 'Revoke rejected' })).toBeVisible();

        page.once('dialog', (dialog) => dialog.dismiss());
        await page.locator('#reset-mh-prompt').click();
        await expect(page.locator('#mental-health-detection-prompt')).toHaveValue('Mock detection prompt');

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-mh-prompt').click();
        await expect(page.locator('#mental-health-detection-prompt')).toHaveValue('Default detection prompt');
        await expect(page.locator('.notification.success', { hasText: 'Detection prompt reset to default' })).toBeVisible();

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-question-prompts').click();
        await expect(page.locator('#question-system-prompt')).toHaveValue('Default question system');
        await expect(page.locator('#question-true-false-prompt')).toHaveValue('Default true false');
        await expect(page.locator('#question-multiple-choice-prompt')).toHaveValue('Default multiple choice');
        await expect(page.locator('#question-short-answer-prompt')).toHaveValue('Default short answer');
        await expect(page.locator('.notification.success', { hasText: 'Question prompts reset to defaults' })).toBeVisible();

        page.once('dialog', (dialog) => dialog.dismiss());
        await page.locator('#delete-collection').click();
        await expect(page.locator('#delete-collection')).toHaveText('Delete All Data');

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#delete-collection').click();
        await expect(page.locator('.notification.success', { hasText: 'All data deleted successfully! Qdrant: 4, MongoDB: 9 documents removed.' })).toBeVisible();

        state.deleteAllResult = {
            success: false,
            message: 'Delete rejected',
            data: { qdrantDeletedCount: 0, mongoDeletedCount: 0 },
        };
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#delete-collection').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to delete data: Delete rejected' })).toBeVisible();
    });

    test('handles transfer validation, master toggles, modal closing, errors, and warning success', async ({ page }) => {
        const state = await openMockedSettings(page, { canDeleteAll: false });
        await page.locator('#course-lifecycle-section').scrollIntoViewIfNeeded();

        await page.locator('#transfer-course-name').fill('');
        await page.locator('#transfer-course-btn').click();
        await expect(page.locator('.notification.error', { hasText: 'Please enter a name for the new course.' })).toBeVisible();
        await expect(page.locator('#transfer-course-name')).toBeFocused();

        await page.locator('#transfer-course-name').fill('Mock Copy One');
        await setInputChecked(page, '#transfer-all-docs', false);
        await expect(page.locator('.transfer-docs-checkbox:checked')).toHaveCount(0);
        await setInputChecked(page, '.transfer-unit-row[data-unit-name="Unit 1"] .transfer-docs-checkbox', true);
        await expect.poll(async () => page.locator('#transfer-all-docs').evaluate((element) => /** @type {HTMLInputElement} */ (element).indeterminate)).toBe(true);

        await page.locator('#transfer-course-btn').click();
        await expect(page.locator('#transfer-course-modal')).toHaveClass(/show/);
        await expect(page.locator('#transfer-modal-summary')).toContainText('1 of 2 units will copy docs and existing chunks.');
        await page.keyboard.press('Escape');
        await expect(page.locator('#transfer-course-modal')).not.toHaveClass(/show/);

        await page.locator('#transfer-course-btn').click();
        await expect(page.locator('#transfer-course-modal')).toHaveClass(/show/);
        await page.locator('#transfer-modal-cancel').click();
        await expect(page.locator('#transfer-course-modal')).not.toHaveClass(/show/);

        await page.locator('#transfer-course-btn').click();
        await expect(page.locator('#transfer-course-modal')).toHaveClass(/show/);
        await page.locator('#transfer-course-modal').click({ position: { x: 5, y: 5 } });
        await expect(page.locator('#transfer-course-modal')).not.toHaveClass(/show/);

        state.transferStatus = 500;
        state.transferResult = {
            success: false,
            message: 'Transfer rejected',
            data: { courseId: '', courseName: '', warnings: [] },
        };
        await page.locator('#transfer-course-btn').click();
        await page.locator('#transfer-modal-confirm').click();
        await expect(page.locator('.notification.error', { hasText: 'Transfer rejected' })).toBeVisible();
        await expect(page.locator('#transfer-course-btn')).toHaveText('Create Course Copy');

        state.transferStatus = 200;
        state.transferResult = {
            success: true,
            data: {
                courseId: 'MOCK-SETTINGS-COPY',
                courseName: 'Mock Settings Copy',
                warnings: ['Document chunks were skipped'],
            },
        };
        await page.locator('#transfer-course-btn').click();
        page.once('dialog', async (dialog) => {
            expect(dialog.message()).toContain('Course copy created with 1 warning.');
            expect(dialog.message()).toContain('Document chunks were skipped');
            await dialog.accept();
        });
        await page.locator('#transfer-modal-confirm').click();
        await expect(page).toHaveURL(/courseId=MOCK-SETTINGS-COPY/, { timeout: 10_000 });
        await expect(page.locator('.notification.info', { hasText: 'Course copy created with 1 warning. Switched to Mock Settings Copy.' })).toBeVisible();
    });

    test('handles lifecycle cancel and API failure without changing status', async ({ page }) => {
        const state = await openMockedSettings(page, { canDeleteAll: false });
        await page.locator('#course-lifecycle-section').scrollIntoViewIfNeeded();

        page.once('dialog', (dialog) => dialog.dismiss());
        await page.locator('#toggle-course-active-btn').click();
        await expect(page.locator('#course-status-badge')).toHaveText('Active');

        state.lifecycleStatus = 500;
        state.lifecycleResult = { success: false, message: 'Lifecycle rejected' };
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#toggle-course-active-btn').click();
        await expect(page.locator('.notification.error', { hasText: 'Lifecycle rejected' })).toBeVisible();
        await expect(page.locator('#course-status-badge')).toHaveText('Active');
        await expect(page.locator('#toggle-course-active-btn')).toHaveText('Deactivate Course');
    });

    test('renders empty/error states and endpoint failures defensively', async ({ page }) => {
        await setupMockedSettingsRoutes(page, {
            canDeleteAll: true,
            lectures: [],
            admins: [],
            abortPaths: [
                '/api/settings/global',
                '/api/settings/llm',
                '/api/settings/prompts',
                '/api/settings/quiz',
                '/api/settings/anonymize-students',
                '/api/settings/mental-health-prompt',
                '/api/settings/question-prompts',
            ],
        });
        await page.goto('/instructor/settings?courseId=MOCK-SETTINGS');
        await expect(page.locator('h1')).toHaveText('Settings', { timeout: 15_000 });

        await expect(page.locator('#system-admin-list')).toContainText('No system admins found.');
        await expect(page.locator('#transfer-unit-grid')).toContainText('No units found for this course yet.');
        await expect(page.locator('#testable-units-container')).toContainText('Loading units...');

        await page.locator('#base-prompt').fill('Mock base prompt');
        await page.locator('#protege-prompt').fill('Mock protege prompt');
        await page.locator('#tutor-prompt').fill('Mock tutor prompt');
        await page.unroute('**/*');
        const state = await setupMockedSettingsRoutes(page, {
            canDeleteAll: false,
            promptSaveResult: { success: false, message: 'Prompt save rejected' },
        });
        state.abortPaths.add('/api/settings/quiz');
        await page.locator('#save-settings').click();
        await expect(page.locator('.notification.error', { hasText: 'Error saving settings' })).toBeVisible();
    });

    test('uses defensive lifecycle states when course context or course load is missing', async ({ page }) => {
        await page.route('**/api/**', async (route) => {
            const requestUrl = new URL(route.request().url());
            if (requestUrl.pathname === '/api/settings/can-delete-all') {
                await route.fulfill(jsonResponse({ success: true, canDeleteAll: true }));
                return;
            }

            await route.fulfill(jsonResponse({ success: true }));
        });
        await page.route('**/instructor/settings**', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'text/html',
                body: `
                    <!doctype html>
                    <html>
                        <body>
                            <section id="course-lifecycle-section">
                                <button id="toggle-course-active-btn">Deactivate Course</button>
                                <input id="transfer-course-name">
                                <button id="transfer-course-btn">Create Course Copy</button>
                                <div id="transfer-unit-grid"></div>
                            </section>
                            <input type="checkbox" id="transfer-all-docs" checked>
                            <input type="checkbox" id="transfer-all-objectives" checked>
                            <input type="checkbox" id="transfer-all-questions" checked>
                            <script>
                                window.waitForAuth = async () => {};
                                window.getCurrentUser = () => ({ role: 'instructor', email: '${TEST_USERS.instructor.email}' });
                                window.getCurrentCourseId = async () => '';
                                window.getCurrentInstructorId = () => '${instructorId || 'instructor'}';
                                window.setCurrentCourseId = async () => {};
                            </script>
                            <script src="/common/scripts/notifications.js"></script>
                            <script src="/instructor/scripts/settings.js"></script>
                        </body>
                    </html>
                `,
            });
        });
        await page.goto('/instructor/settings?courseId=');
        await expect(page.locator('#transfer-unit-grid')).toContainText('Select a course first to use transfer and deactivate tools.');
        await expect(page.locator('#toggle-course-active-btn')).toBeDisabled();
        await expect(page.locator('#transfer-course-btn')).toBeDisabled();

        await page.unroute('**/api/**');
        await page.unroute('**/instructor/settings**');
        await openMockedSettings(page, {
            canDeleteAll: false,
            courseGetStatus: 500,
            courseGetResult: { success: false, message: 'Course load rejected' },
        });
        await expect(page.locator('#transfer-unit-grid')).toContainText('Unable to load course transfer options right now.');
        await expect(page.locator('#toggle-course-active-btn')).toBeDisabled();
        await expect(page.locator('#transfer-course-btn')).toBeDisabled();
    });

    test('covers defensive admin failures, non-instructor lifecycle, and notification cleanup', async ({ page }) => {
        await page.addInitScript(() => {
            window.sessionStorage.setItem('settingsFlashMessage', '{bad json');
        });
        const state = await openMockedSettings(page, {
            systemAdminListError: true,
            promptSaveResult: { success: false, message: 'Prompt save rejected' },
        });

        await expect(page.locator('#system-admin-list')).toContainText('Failed to load system admins.');

        await page.locator('#base-prompt').fill('Mock base prompt');
        await page.locator('#protege-prompt').fill('Mock protege prompt');
        await page.locator('#tutor-prompt').fill('Mock tutor prompt');
        await page.locator('#save-settings').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to save settings: Prompt save rejected' })).toBeVisible();

        state.promptResetResult = {
            success: false,
            message: 'Reset rejected',
            prompts: { base: '', protege: '', tutor: '', explain: '', directive: '' },
        };
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-settings').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to reset settings: Reset rejected' })).toBeVisible();

        state.abortPaths.add('/api/settings/prompts/reset');
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-settings').click();
        await expect(page.locator('.notification.error', { hasText: 'Error resetting settings' })).toBeVisible();
        state.abortPaths.delete('/api/settings/prompts/reset');

        state.abortPaths.add('/api/settings/mental-health-prompt/reset');
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-mh-prompt').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to reset detection prompt' })).toBeVisible();
        state.abortPaths.delete('/api/settings/mental-health-prompt/reset');

        state.questionResetResult = {
            success: false,
            message: 'Question reset rejected',
            prompts: { systemPrompt: '', trueFalse: '', multipleChoice: '', shortAnswer: '' },
        };
        page.once('dialog', (dialog) => dialog.dismiss());
        await page.locator('#reset-question-prompts').click();
        await expect(page.locator('#reset-question-prompts')).toHaveText('Reset Question Prompts to Default');

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-question-prompts').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to reset question prompts: Question reset rejected' })).toBeVisible();

        state.abortPaths.add('/api/settings/question-prompts/reset');
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#reset-question-prompts').click();
        await expect(page.locator('.notification.error', { hasText: 'Error resetting question prompts' })).toBeVisible();
        state.abortPaths.delete('/api/settings/question-prompts/reset');

        state.abortPaths.add('/api/qdrant/delete-all-collections');
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('#delete-collection').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to delete data: Network or server error' })).toBeVisible();
        state.abortPaths.delete('/api/qdrant/delete-all-collections');

        state.systemAdminListError = false;
        state.abortPaths.add('/api/settings/system-admins');
        await page.locator('#system-admin-email-input').fill('grant-catch@test.local');
        await page.locator('#grant-system-admin-btn').click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to grant system admin access.' })).toBeVisible();
        state.abortPaths.delete('/api/settings/system-admins');

        await page.locator('#system-admin-email-input').fill(TEST_USERS.instructor_fresh.email);
        await page.locator('#grant-system-admin-btn').click();
        await expect(page.locator(`.system-admin-revoke-btn[data-email="${TEST_USERS.instructor_fresh.email}"]`)).toBeVisible();

        await page.locator('#system-admin-list').click({ position: { x: 5, y: 5 } });
        await page.evaluate((email) => {
            const button = document.querySelector(`.system-admin-revoke-btn[data-email="${email}"]`);
            if (button) button.removeAttribute('data-email');
        }, TEST_USERS.instructor_fresh.email);
        await page.locator('.system-admin-revoke-btn').last().click();
        await expect(page.locator('.system-admin-revoke-btn').last()).toHaveText('Revoke');

        await page.evaluate((email) => {
            const button = document.querySelectorAll('.system-admin-revoke-btn')[1];
            if (button) button.setAttribute('data-email', email);
        }, TEST_USERS.instructor_fresh.email);
        state.abortPaths.add('/api/settings/system-admins/revoke');
        page.once('dialog', (dialog) => dialog.accept());
        await page.locator(`.system-admin-revoke-btn[data-email="${TEST_USERS.instructor_fresh.email}"]`).click();
        await expect(page.locator('.notification.error', { hasText: 'Failed to revoke system admin access.' })).toBeVisible();

        const closeButtons = page.locator('.notification-close');
        const closeButtonCount = await closeButtons.count();
        await closeButtons.first().click();
        await expect.poll(async () => closeButtons.count()).toBe(closeButtonCount - 1);

        await setInputChecked(page, '#transfer-all-objectives', false);
        await expect(page.locator('.transfer-objectives-checkbox:checked')).toHaveCount(0);
        await setInputChecked(page, '#transfer-all-questions', false);
        await expect(page.locator('.transfer-questions-checkbox:checked')).toHaveCount(0);

        await page.unroute('**/*');
        await page.route('**/api/**', async (route) => {
            const requestUrl = new URL(route.request().url());
            if (requestUrl.pathname === '/api/settings/can-delete-all') {
                await route.fulfill(jsonResponse({ success: false, canDeleteAll: false }));
                return;
            }
            await route.fulfill(jsonResponse({ success: true }));
        });
        await page.route('**/instructor/settings**', async (route) => {
            await route.fulfill({
                status: 200,
                contentType: 'text/html',
                body: `
                    <!doctype html>
                    <html>
                        <body>
                            <section id="course-lifecycle-section">
                                <button id="transfer-course-btn">Create Course Copy</button>
                            </section>
                            <script>
                                window.waitForAuth = async () => {};
                                window.getCurrentUser = () => ({ role: 'student', email: 'student@test.local' });
                                window.getCurrentCourseId = async () => 'STUDENT-COURSE';
                            </script>
                            <script src="/common/scripts/notifications.js"></script>
                            <script src="/instructor/scripts/settings.js"></script>
                        </body>
                    </html>
                `,
            });
        });
        await page.goto('/instructor/settings?student-role');
        await expect(page.locator('#course-lifecycle-section')).toBeHidden();
        await page.locator('#transfer-course-btn').dispatchEvent('click');
        await expect(page.locator('.notification.warning', { hasText: 'Course data is still loading. Please try again.' })).toBeVisible();

        await page.unroute('**/api/**');
        await page.unroute('**/instructor/settings**');
        await openMockedSettings(page, { abortPaths: ['/api/settings/can-delete-all'] });
        await expect(page.locator('#database-management-section')).toBeHidden();
        await expect(page.locator('#system-admin-section')).toBeHidden();
    });
});

test.describe('Settings API authorization', () => {
    test('non-owner instructor cannot update another instructor course through direct settings API', async ({ baseURL }) => {
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor_fresh'),
        });

        try {
            const response = await api.post('/api/settings/prompts', {
                data: {
                    courseId: SETTINGS_COURSE_ID,
                    base: 'Unauthorized base prompt',
                    protege: 'Unauthorized protege prompt',
                    tutor: 'Unauthorized tutor prompt',
                    explain: 'Unauthorized explain prompt',
                    directive: 'Unauthorized directive prompt',
                    quizHelp: 'Unauthorized quiz help prompt',
                    additiveRetrieval: true,
                    studentIdleTimeout: 120,
                },
                failOnStatusCode: false,
            });

            expect.soft(response.status()).toBe(403);
            const course = await readCourse();
            expect.soft(course.prompts.base).toBe('Seed base prompt');
            expect.soft(course.isAdditiveRetrieval).toBe(false);
        } finally {
            await api.dispose();
        }
    });
});
