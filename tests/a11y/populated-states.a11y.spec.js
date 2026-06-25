// @ts-check
/**
 * Accessibility scans of data-rendered ("populated") states.
 *
 * The baseline scans hit each page in its resting/empty state, so list items,
 * cards, and badges that only exist once data is present are never examined.
 * These tests seed real data and scan the populated view.
 */
const { test, expect } = require('@playwright/test');
const { TEST_USERS, storageStatePath } = require('../e2e/helpers/users');
const { getUserIdByUsername } = require('../e2e/helpers/quiz');
const {
    HUB_COURSE_ID,
    HUB_OTHER_COURSE_ID,
    resetStudentHubData,
    cleanupStudentHubData,
} = require('../e2e/helpers/studentHub');
const {
    STU_COURSE_ID,
    STU_COURSE_NAME,
    getStudentId,
    resetStudentChatData,
    cleanupStudentChatData,
    seedChatSession,
} = require('../e2e/helpers/student');
const { expectNoA11yViolations } = require('./axe-helper');

test.describe('Accessibility: instructor student hub (populated)', () => {
    test.use({ storageState: storageStatePath('instructor') });

    let instructorId;
    let freshInstructorId;
    let taId;

    test.beforeAll(async () => {
        instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
        freshInstructorId = await getUserIdByUsername(TEST_USERS.instructor_fresh.username);
        taId = await getUserIdByUsername(TEST_USERS.ta.username);
        await resetStudentHubData({ instructorId, freshInstructorId, taId, options: {} });
    });

    test.afterAll(async () => {
        await cleanupStudentHubData();
    });

    test('/instructor/student-hub with student cards has no critical/serious a11y violations', async ({ page }) => {
        await page.addInitScript((storedCourseId) => {
            try {
                localStorage.setItem('selectedCourseId', storedCourseId);
            } catch (_) {}
        }, HUB_OTHER_COURSE_ID);

        await page.goto(`/instructor/student-hub?courseId=${HUB_COURSE_ID}`);
        await expect(page.locator('#students-container')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('.student-card').first()).toBeVisible({ timeout: 15_000 });

        await expectNoA11yViolations(page);
    });
});

test.describe('Accessibility: student history (populated)', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeAll(async () => {
        const instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
        await resetStudentChatData({ instructorId });

        const studentId = await getStudentId();
        await seedChatSession({
            sessionId: 'a11y-history-session-1',
            courseId: STU_COURSE_ID,
            studentId,
            studentName: 'A11y Student',
            title: 'Photosynthesis questions',
            messages: [
                { role: 'user', content: 'How does the Calvin cycle work?' },
                { role: 'assistant', content: 'The Calvin cycle fixes carbon in the stroma.' },
            ],
        });
        await seedChatSession({
            sessionId: 'a11y-history-session-2',
            courseId: STU_COURSE_ID,
            studentId,
            studentName: 'A11y Student',
            title: 'Enzyme kinetics review',
            messages: [
                { role: 'user', content: 'Explain Michaelis-Menten kinetics.' },
                { role: 'assistant', content: 'Km is the substrate concentration at half Vmax.' },
            ],
        });
    });

    test.afterAll(async () => {
        await cleanupStudentChatData();
    });

    test('/student/history with saved chats has no critical/serious a11y violations', async ({ page }) => {
        await page.addInitScript((courseId) => {
            try {
                localStorage.setItem('selectedCourseId', courseId);
            } catch (_) {}
        }, STU_COURSE_ID);

        await page.goto('/student/history');
        await page.waitForLoadState('load');
        await expect(page.locator('.chat-history-item').first()).toBeVisible({ timeout: 15_000 });

        await expectNoA11yViolations(page);
    });
});
