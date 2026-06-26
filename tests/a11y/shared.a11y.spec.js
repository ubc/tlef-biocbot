// @ts-check
const { test } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

test.describe('Accessibility: unauthenticated pages', () => {
    test('/login has no critical/serious a11y violations', async ({ page }) => {
        await page.goto('/login');
        await page.waitForLoadState('load');
        await expectNoA11yViolations(page);
    });
});

test.describe('Accessibility: shared authenticated pages', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('/qdrant-test has no critical/serious a11y violations', async ({ page }) => {
        await page.goto('/qdrant-test');
        await page.waitForLoadState('load');
        await expectNoA11yViolations(page);
    });
});
