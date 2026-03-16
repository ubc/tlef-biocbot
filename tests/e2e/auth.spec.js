// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');

/**
 * Auth / Login flow tests.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

// ── Credentials from .env ────────────────────────────────────────────────────

const student_username = process.env.student_username;
const student_password = process.env.student_password;
const inst_username = process.env.inst_username;
const inst_password = process.env.inst_password;
const ta_username = process.env.ta_username;
const ta_password = process.env.ta_password;

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Log in through the UI and wait for redirect.
 */
async function login(page, username, password) {
  await page.goto('/login');
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('#login-btn');
}

// ── Login page loads ─────────────────────────────────────────────────────────

test.describe('Login page', () => {
  test('renders the login form', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('h1')).toHaveText('BiocBot');
    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('#login-btn')).toBeVisible();
  });

  test('shows registration form when "Create one" is clicked', async ({ page }) => {
    await page.goto('/login');
    await page.click('#show-register');
    await expect(page.locator('#register-form')).toBeVisible();
    await expect(page.locator('#reg-username')).toBeVisible();
  });

  test('shows error on invalid credentials', async ({ page }) => {
    await page.goto('/login');
    await page.fill('#username', 'nonexistent_user');
    await page.fill('#password', 'wrong_password');
    await page.click('#login-btn');

    // The app should show some error feedback (message container or alert)
    await expect(page.locator('#message-container')).toBeVisible({ timeout: 5000 });
  });
});

// ── Successful login flows ───────────────────────────────────────────────────

test.describe('Student login', () => {
  test('logs in and redirects to /student', async ({ page }) => {
    await login(page, student_username, student_password);

    // Should redirect to the student dashboard
    await page.waitForURL('**/student**', { timeout: 10000 });
    expect(page.url()).toContain('/student');
  });

  test('shows student page content after login', async ({ page }) => {
    await login(page, student_username, student_password);
    await page.waitForURL('**/student**', { timeout: 10000 });

    // The page should have loaded (check for body or a known element)
    await expect(page.locator('body')).toBeVisible();
  });
});

test.describe('Instructor login', () => {
  test('logs in and redirects to /instructor', async ({ page }) => {
    await login(page, inst_username, inst_password);

    // Instructor redirects to /instructor/home
    await page.waitForURL('**/instructor**', { timeout: 10000 });
    expect(page.url()).toContain('/instructor');
  });
});

test.describe('TA login', () => {
  test('logs in and redirects to /ta', async ({ page }) => {
    await login(page, ta_username, ta_password);

    await page.waitForURL('**/ta**', { timeout: 10000 });
    expect(page.url()).toContain('/ta');
  });
});

// ── Logout ───────────────────────────────────────────────────────────────────

test.describe('Logout', () => {
  test('can log out and return to login page', async ({ page }) => {
    // Log in first
    await login(page, student_username, student_password);
    await page.waitForURL('**/student**', { timeout: 10000 });

    // Call the logout API directly (the UI logout varies by page)
    const response = await page.request.post('/api/auth/logout');
    expect(response.ok()).toBeTruthy();

    // Navigate to a protected page — should redirect to login
    await page.goto('/student');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });
});

test.describe('Auth API', () => {
  test('auth methods endpoint returns configured method flags', async ({ request }) => {
    const response = await request.get('/api/auth/methods');
    const body = await response.json();

    expect(response.ok()).toBeTruthy();
    expect(body.success).toBeTruthy();
    expect(body.methods).toHaveProperty('local');
    expect(body.methods).toHaveProperty('saml');
    expect(body.methods).toHaveProperty('ubcshib');
    expect(body.methods).toHaveProperty('allowLocalLogin');
  });

  test('auth/me returns the logged-in student profile', async ({ request }) => {
    const loginResponse = await request.post('/api/auth/login', {
      data: { username: student_username, password: student_password },
    });
    expect(loginResponse.ok()).toBeTruthy();

    const response = await request.get('/api/auth/me');
    const body = await response.json();

    expect(body.success).toBeTruthy();
    expect(body.user.role).toBe('student');
    expect(body.user.username).toBe(student_username);
    expect(body.user.displayName).toBeTruthy();
  });

  test('auth/me returns the logged-in TA profile', async ({ request }) => {
    const loginResponse = await request.post('/api/auth/login', {
      data: { username: ta_username, password: ta_password },
    });
    expect(loginResponse.ok()).toBeTruthy();

    const response = await request.get('/api/auth/me');
    const body = await response.json();

    expect(body.success).toBeTruthy();
    expect(body.user.role).toBe('ta');
    expect(body.user.username).toBe(ta_username);
  });
});

// ── Protected routes redirect to login ───────────────────────────────────────

test.describe('Protected routes', () => {
  test('unauthenticated user visiting /student is redirected to login', async ({ page }) => {
    await page.goto('/student');
    // The app should redirect unauthenticated users to /login
    await page.waitForURL('**/login**', { timeout: 10000 });
  });

  test('unauthenticated user visiting /instructor is redirected to login', async ({ page }) => {
    await page.goto('/instructor');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });

  test('unauthenticated user visiting /ta is redirected to login', async ({ page }) => {
    await page.goto('/ta');
    await page.waitForURL('**/login**', { timeout: 10000 });
  });
});
