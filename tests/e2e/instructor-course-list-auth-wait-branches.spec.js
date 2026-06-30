// @ts-check

const { test, expect } = require('./fixtures/monocart');
const { storageStatePath } = require('./helpers/users');
const { gotoOnboarding, branchCourse } = require('./helpers/onboarding-branches');

test.use({ storageState: storageStatePath('instructor_fresh') });

test.describe('onboarding course list and auth wait branches', () => {
    test('formats inactive, fallback, and deduplicated course options', async ({ page }) => {
        await gotoOnboarding(page, {
            joinableCourses: [
                branchCourse({ courseId: 'ACTIVE-1', courseName: 'Active Branch' }),
                branchCourse({ courseId: 'ACTIVE-1', courseName: 'Duplicate Branch' }),
                branchCourse({ courseId: 'INACTIVE-1', courseName: 'Inactive Branch', status: 'inactive' }),
                { courseId: 'FALLBACK-1', status: 'inactive' },
            ],
        });

        await expect(page.locator('#course-select option[value="ACTIVE-1"]')).toHaveText('Active Branch');
        await expect(page.locator('#course-select option[value="ACTIVE-1"]')).toHaveCount(1);
        await expect(page.locator('#course-select option[value="INACTIVE-1"]')).toHaveText('Inactive Branch (Inactive)');
        await expect(page.locator('#course-select option[value="FALLBACK-1"]')).toHaveText('FALLBACK-1 (Inactive)');
        await expect(page.locator('#course-select optgroup[label="Active Courses"]')).toHaveCount(1);
        await expect(page.locator('#course-select optgroup[label="Inactive Courses"]')).toHaveCount(1);
    });

    test('returns without error when course select is missing', async ({ page }) => {
        await gotoOnboarding(page);

        const result = await page.evaluate(async () => {
            const testWindow = /** @type {any} */ (window);
            document.getElementById('course-select')?.remove();
            await testWindow.loadAvailableCourses();
            return true;
        });

        expect(result).toBe(true);
    });

    test('falls back to custom course option when joinable courses request fails', async ({ page }) => {
        await gotoOnboarding(page, { joinableStatus: 500 });

        await expect(page.locator('#course-select option[value="custom"]')).toHaveText('Create a new course...');
        await expect(page.locator('#course-select option')).toHaveCount(2);
    });

    test('falls back to custom course option when joinable courses response is unsuccessful', async ({ page }) => {
        await gotoOnboarding(page, { joinableSuccess: false });

        await expect(page.locator('#course-select option[value="custom"]')).toHaveText('Create a new course...');
        await expect(page.locator('#course-select option')).toHaveCount(2);
    });

    test('continues after auth never becomes ready', async ({ page }) => {
        await gotoOnboarding(page);

        const warned = await page.evaluate(async () => {
            const testWindow = /** @type {any} */ (window);
            testWindow.getCurrentInstructorId = undefined;
            const originalWarn = console.warn;
            let sawTimeoutWarning = false;
            console.warn = (...args) => {
                sawTimeoutWarning = sawTimeoutWarning || String(args[0]).includes('Authentication not ready');
                originalWarn(...args);
            };
            await testWindow.waitForAuth();
            console.warn = originalWarn;
            return sawTimeoutWarning;
        });

        expect(warned).toBe(true);
    });
});
