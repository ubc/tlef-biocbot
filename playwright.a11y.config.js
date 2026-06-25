// @ts-check
// Accessibility scans run as their own Playwright check, separate from the e2e
// suite in playwright.config.js. This config reuses the base webServer and
// global-setup (which seeds users and saves per-role auth storage states), but
// scopes test discovery to tests/a11y and writes to its own report directory so
// nothing collides with the e2e run.
const base = require('./playwright.config');

/** @type {import('@playwright/test').PlaywrightTestConfig} */
module.exports = {
    ...base,
    testDir: './tests/a11y',
    reporter: [
        ['html', { open: 'never', outputFolder: 'playwright-report-a11y' }],
        ['list'],
    ],
};
