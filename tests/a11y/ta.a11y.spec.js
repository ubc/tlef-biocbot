// @ts-check
const { test } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

test.describe('Accessibility: TA pages', () => {
    test.use({ storageState: storageStatePath('ta') });

    for (const path of ['/ta', '/ta/onboarding', '/ta/settings', '/ta/courses', '/ta/students']) {
        test(`${path} has no critical/serious a11y violations`, async ({ page }) => {
            await page.goto(path);
            await page.waitForLoadState('load');
            await expectNoA11yViolations(page);
        });
    }
});
