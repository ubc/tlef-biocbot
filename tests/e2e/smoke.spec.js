// @ts-check
const { test, expect } = require('@playwright/test');

test.describe('smoke', () => {
    test('login page renders', async ({ page }) => {
        await page.goto('/');

        await expect(page).toHaveTitle('BiocBot - AI Study Assistant');
        await expect(page.locator('.login-card .logo h1')).toHaveText('BiocBot');
        await expect(page.locator('#login-form h2')).toHaveText('Sign In');
        await expect(page.locator('#auth-form input#username')).toBeVisible();
        await expect(page.locator('#auth-form input#password')).toBeVisible();
        await expect(page.locator('#auth-form button#login-btn')).toBeVisible();
    });
});
