// @ts-check
const { test } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

// Authenticated as the seeded student (storage state produced by global-setup).
test.describe('Accessibility: student pages', () => {
    test.use({ storageState: storageStatePath('student') });

    // Start with the main chat page; add more student routes (quiz, super-course)
    // once this check is green in CI.
    test('student chat (/student) has no critical/serious a11y violations', async ({ page }) => {
        await page.goto('/student');
        await page.waitForLoadState('load');
        await expectNoA11yViolations(page);
    });
});
