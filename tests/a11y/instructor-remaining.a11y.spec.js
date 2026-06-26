// @ts-check
const { test } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

test.describe('Accessibility: remaining instructor pages', () => {
    test.use({ storageState: storageStatePath('instructor') });

    for (const path of [
        '/instructor',
        '/instructor/documents',
        '/instructor/chat',
        '/instructor/notes',
        '/instructor/ta-hub',
        '/instructor/student-hub',
    ]) {
        test(`${path} has no critical/serious a11y violations`, async ({ page }) => {
            await page.goto(path);
            await page.waitForLoadState('load');
            await expectNoA11yViolations(page);
        });
    }
});
