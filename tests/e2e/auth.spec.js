// @ts-check
const { test, expect } = require('@playwright/test');
const { TEST_USERS, loadCredentials } = require('./helpers/users');

const credentials = loadCredentials();

test.describe('local login', () => {
    for (const [role, user] of Object.entries(TEST_USERS)) {
        test(`${role} can sign in via the UI`, async ({ page }) => {
            await page.goto('/');

            await page.locator('#auth-form input#username').fill(user.username);
            await page.locator('#auth-form input#password').fill(credentials[role]);
            await page.locator('#auth-form button#login-btn').click();

            await page.waitForURL((url) => !url.pathname.match(/^\/?$/) && url.pathname !== '/login', {
                timeout: 10_000,
            });

            expect(page.url()).toContain(user.landingPath);
        });
    }

    test('invalid credentials show an error message', async ({ page }) => {
        await page.goto('/');

        await page.locator('#auth-form input#username').fill('e2e_does_not_exist');
        await page.locator('#auth-form input#password').fill('wrong-password');
        await page.locator('#auth-form button#login-btn').click();

        const message = page.locator('#message-container #message');
        await expect(message).toBeVisible();
        await expect(message).toContainText(/invalid|incorrect|failed/i);

        await expect(page.locator('#auth-form')).toBeVisible();
    });
});
