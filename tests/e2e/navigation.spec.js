// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');

/**
 * Navigation tests — verify pages load and sidebar links work.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

// ── Helpers ──────────────────────────────────────────────────────────────────

async function loginAs(page, role) {
  const creds = {
    student: { username: process.env.student_username, password: process.env.student_password },
    instructor: { username: process.env.inst_username, password: process.env.inst_password },
    ta: { username: process.env.ta_username, password: process.env.ta_password },
  };
  const { username, password } = creds[role];
  await page.goto('/login');
  await page.fill('#username', username);
  await page.fill('#password', password);
  await page.click('#login-btn');
}

// ── Student navigation ──────────────────────────────────────────────────────

test.describe('Student navigation', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
  });

  test('student main page loads', async ({ page }) => {
    await expect(page.locator('body')).toBeVisible();
    // Check the page has meaningful content (not a blank page)
    const bodyText = await page.locator('body').innerText();
    expect(bodyText.length).toBeGreaterThan(0);
  });

  test('student history page loads', async ({ page }) => {
    await page.goto('/student/history');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('student flagged page loads', async ({ page }) => {
    await page.goto('/student/flagged');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });
});

// ── Instructor navigation ────────────────────────────────────────────────────

test.describe('Instructor navigation', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'instructor');
    await page.waitForURL('**/instructor**', { timeout: 10000 });
  });

  test('instructor home page loads', async ({ page }) => {
    await expect(page.locator('body')).toBeVisible();
    const bodyText = await page.locator('body').innerText();
    expect(bodyText.length).toBeGreaterThan(0);
  });

  test('instructor settings page loads', async ({ page }) => {
    await page.goto('/instructor/settings');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('instructor documents page loads', async ({ page }) => {
    await page.goto('/instructor/documents');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('instructor flagged page loads', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });

  test('instructor downloads page loads', async ({ page }) => {
    await page.goto('/instructor/downloads');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('body')).toBeVisible();
  });
});

// ── TA navigation ────────────────────────────────────────────────────────────

test.describe('TA navigation', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'ta');
    await page.waitForURL('**/ta**', { timeout: 10000 });
  });

  test('TA home page loads', async ({ page }) => {
    await expect(page.locator('body')).toBeVisible();
    const bodyText = await page.locator('body').innerText();
    expect(bodyText.length).toBeGreaterThan(0);
  });
});

// ── Health check API ─────────────────────────────────────────────────────────

test.describe('API health', () => {
  test('health endpoint responds', async ({ request }) => {
    const response = await request.get('/api/health');
    // Health returns 200 when all services healthy, 503 when degraded — both are valid
    expect([200, 503]).toContain(response.status());
    const body = await response.json();
    expect(body).toHaveProperty('status');
    expect(body).toHaveProperty('services');
  });
});
