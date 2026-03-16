// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  clearBrowserState,
  getEnrolledStudentCourse,
  loginAs,
  loginViaApi,
  prepareStudentCourse,
} = require('./helpers/e2e');

/**
 * Student dashboard (topic performance) tests.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

// ── Helpers ──────────────────────────────────────────────────────────────────

// ── Dashboard UI tests ───────────────────────────────────────────────────────

test.describe('Student dashboard page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await page.goto('/student/dashboard.html');
    await page.waitForLoadState('networkidle');
  });

  test('dashboard page loads with correct heading', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('Topic Dashboard');
  });

  test('has summary cards section', async ({ page }) => {
    const activeTopics = page.locator('#active-topics-count');
    const directiveStatus = page.locator('#directive-mode-status');

    await expect(activeTopics).toBeAttached();
    await expect(directiveStatus).toBeAttached();
  });

  test('has topics list container', async ({ page }) => {
    const container = page.locator('#topics-list-container');
    await expect(container).toBeAttached();
  });

  test('has reset all button', async ({ page }) => {
    const resetBtn = page.locator('#reset-all-btn');
    await expect(resetBtn).toBeAttached();
  });

  test('has confirmation modal in the DOM', async ({ page }) => {
    const modal = page.locator('#confirm-modal');
    await expect(modal).toBeAttached();

    // Modal should not be visible initially
    await expect(modal).not.toBeVisible();
  });

  test('sidebar navigation links are correct', async ({ page }) => {
    await expect(page.locator('nav.main-nav a[href="/student"]')).toBeVisible();
    await expect(page.locator('nav.main-nav a[href="/student/history"]')).toBeVisible();
    await expect(page.locator('nav.main-nav a[href="/student/dashboard.html"]')).toBeVisible();
  });

  test('reset all button opens the confirmation modal and cancel closes it', async ({ page }) => {
    await page.locator('#reset-all-btn').click();

    await expect(page.locator('#confirm-modal')).toBeVisible();
    await expect(page.locator('#modal-title')).toHaveText('Reset All Topics?');
    await expect(page.locator('#modal-confirm-btn')).toHaveText('Reset All');

    await page.locator('#modal-cancel-btn').click();
    await expect(page.locator('#confirm-modal')).toBeHidden();
  });

  test('shows the selected course name in the sidebar after course setup', async ({ page, request }) => {
    await loginViaApi(request, 'student');
    const enrolledCourse = await getEnrolledStudentCourse(request);

    test.skip(!enrolledCourse, 'Need an enrolled student course for dashboard course context.');

    await prepareStudentCourse(page, enrolledCourse);
    await page.goto('/student/dashboard.html');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('.user-role')).toContainText(enrolledCourse.courseName);
  });
});

test.describe('Student dashboard API', () => {
  test('student struggle endpoint returns the current state structure', async ({ request }) => {
    await loginViaApi(request, 'student');

    const response = await request.get('/api/student/struggle');
    const body = await response.json();

    expect(response.ok()).toBeTruthy();
    expect(body.success).toBeTruthy();
    expect(body.struggleState).toBeDefined();
    expect(Array.isArray(body.struggleState.topics)).toBeTruthy();
  });

  test('student struggle reset validates that a topic is provided', async ({ request }) => {
    await loginViaApi(request, 'student');

    const response = await request.post('/api/student/struggle/reset', {
      data: {},
    });
    expect(response.status()).toBe(400);

    const body = await response.json();
    expect(body.success).toBeFalsy();
    expect(body.message).toContain('Topic is required');
  });

  test('dashboard shows the empty-course prompt when no course is selected', async ({ page }) => {
    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await clearBrowserState(page);
    await page.goto('/student/dashboard.html');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#topics-list-container')).toContainText('Please select a course');
  });
});
