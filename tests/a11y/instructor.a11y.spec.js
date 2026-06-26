// @ts-check
const { test } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

test.describe('Accessibility: instructor pages', () => {
    test.use({ storageState: storageStatePath('instructor') });

    for (const path of ['/instructor/home', '/instructor/settings', '/instructor/flagged']) {
        test(`${path} has no critical/serious a11y violations`, async ({ page }) => {
            await page.goto(path);
            await page.waitForLoadState('load');
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
