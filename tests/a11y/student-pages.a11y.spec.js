// @ts-check
const { test } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { expectNoA11yViolations } = require('./axe-helper');

test.describe('Accessibility: additional student pages', () => {
    test.use({ storageState: storageStatePath('student') });

    for (const path of ['/student/quiz', '/student/super-course']) {
        test(`${path} has no critical/serious a11y violations`, async ({ page }) => {
            await page.goto(path);
            await page.waitForLoadState('load');
            await expectNoA11yViolations(page);
        });
    }
});
