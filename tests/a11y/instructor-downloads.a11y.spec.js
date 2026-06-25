// @ts-check
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const {
    DOWNLOAD_COURSE_ID,
    DOWNLOAD_COURSE_NAME,
    DOWNLOAD_OTHER_COURSE_ID,
    getInstructorId,
    setSystemAdmin,
    resetDownloadData,
    cleanupDownloadData,
} = require('../e2e/helpers/downloads');
const { expectNoA11yViolations } = require('./axe-helper');

let instructorId;

test.describe('Accessibility: instructor downloads page', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeAll(async () => {
        instructorId = await getInstructorId();
        await resetDownloadData({ instructorId });
        await setSystemAdmin(instructorId, true);
    });

    test.afterAll(async () => {
        await cleanupDownloadData(instructorId);
    });

    test('/instructor/downloads has no critical/serious a11y violations', async ({ page }) => {
        await page.addInitScript((staleCourseId) => {
            try {
                localStorage.setItem('selectedCourseId', staleCourseId);
            } catch (_) {}
        }, DOWNLOAD_OTHER_COURSE_ID);

        await page.goto(`/instructor/downloads?courseId=${DOWNLOAD_COURSE_ID}`);
        await page.waitForLoadState('load');
        await expect(page.locator('#course-title')).toHaveText(
            `${DOWNLOAD_COURSE_NAME} - Download Chats`,
            { timeout: 15_000 }
        );
        await expect(page.locator('#students-container')).toBeVisible({ timeout: 15_000 });

        await expectNoA11yViolations(page);
    });
});
