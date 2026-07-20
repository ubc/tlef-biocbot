// @ts-check
/// <reference types="node" />
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

/** @param {import('@playwright/test').Page} page */
async function seedFlaggedErrorState(page) {
    await page.addInitScript(() => {
        localStorage.setItem('selectedCourseId', 'A11Y-FLAGGED-FIXTURE');
    });
    await page.route('**/api/flags/course/**', (route) => route.fulfill({
        status: 500,
        json: { success: false, message: 'Deterministic accessibility error-state fixture' },
    }));
}

test.describe('Accessibility: instructor pages', () => {
    test.use({ storageState: storageStatePath('instructor') });

    for (const path of ['/instructor/home', '/instructor/settings', '/instructor/flagged']) {
        test(`${path} has no critical/serious a11y violations`, async ({ page }) => {
            if (path === '/instructor/flagged') await seedFlaggedErrorState(page);
            await page.goto(path);
            await page.waitForLoadState('load');
            if (path === '/instructor/flagged') {
                await expect(page.locator('#empty-state')).toContainText(
                    'Failed to load flagged content. Please try again.'
                );
                await expect(page.locator('#empty-state')).toBeVisible();
            }
            await expectNoA11yViolations(page);
        });
    }
});

test.describe('Accessibility: instructor onboarding page', () => {
    test.use({ storageState: storageStatePath('instructor_fresh') });

    test('/instructor/onboarding has no critical/serious a11y violations', async ({ page }) => {
        await page.goto('/instructor/onboarding');
        await page.waitForLoadState('load');
        await expectNoA11yViolations(page);
    });
});
