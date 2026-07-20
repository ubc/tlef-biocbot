// @ts-check
/// <reference types="node" />
const { test, expect } = require('@playwright/test');
const { expectNoA11yViolations } = require('./axe-helper');

/**
 * Navigate to an expected application page and prove the response and stable page
 * identity are valid before axe scans the DOM. This prevents an Express error page
 * or unrelated redirect from satisfying the accessibility assertion.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} path
 * @param {string} identity
 */
async function gotoValidPage(page, path, identity) {
    const response = await page.goto(path);
    expect(response, `${path} should return a navigation response`).not.toBeNull();
    if (!response) throw new Error(`${path} returned no navigation response`);
    expect(response.ok(), `${path} should return a successful response`).toBe(true);
    await expect(page.locator(identity)).toBeVisible();
}

test.describe('Accessibility: unauthenticated pages', () => {
    test('/login has no critical/serious a11y violations', async ({ page }) => {
        await gotoValidPage(page, '/login', 'h1:has-text("BiocBot")');
        await page.waitForLoadState('load');
        await expectNoA11yViolations(page);
    });
});
