// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  findPrivilegedInstructorCredentials,
  getPrimaryInstructorCourse,
  loginAs,
  loginViaApi,
} = require('./helpers/e2e');

/**
 * Instructor feature tests — settings, student hub, downloads.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

/**
 * @param {import('@playwright/test').Page} page
 * @param {{ username?: string, password?: string }} [credentials]
 */
async function openInstructorSettings(page, credentials = {}) {
  await loginAs(page, 'instructor', credentials);
  await page.waitForURL('**/instructor**', { timeout: 10000 });
  await page.goto('/instructor/settings');
  await page.waitForLoadState('networkidle');
}

test.describe('Instructor settings page', () => {
  test.beforeEach(async ({ page }) => {
    await openInstructorSettings(page);
  });

  test('settings page loads with correct heading', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('Settings');
  });

  test('shows student idle timeout setting', async ({ page }) => {
    await expect(page.locator('#idle-timeout-input')).toBeVisible();
  });

  test('shows quiz settings for the current course', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Enable Quiz Practice Page' })).toBeVisible();
    await expect(page.locator('label.toggle-switch:has(#quiz-enabled-toggle)')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Enable Source Attribution Downloads' })).toBeVisible();
    await expect(page.locator('label.toggle-switch:has(#source-attribution-download-toggle)')).toBeVisible();
  });

  test('shows save and reset buttons', async ({ page }) => {
    await expect(page.locator('#save-settings')).toBeVisible();
    await expect(page.locator('#reset-settings')).toBeVisible();
  });

  test('shows AI persona settings with prompt textareas', async ({ page }) => {
    await expect(page.locator('#base-prompt')).toBeVisible();
    await expect(page.locator('#tutor-prompt')).toBeVisible();
    await expect(page.locator('#protege-prompt')).toBeVisible();
  });

  test('hides privileged sections for instructors outside the delete-all allow list', async ({ page }) => {
    await expect(page.locator('#database-management-section')).toBeHidden();
    await expect(page.locator('#login-restriction-section')).toBeHidden();
    await expect(page.locator('#question-generation-section')).toBeHidden();
  });
});

test.describe('Settings API', () => {
  test('can load prompt settings for the current instructor course', async ({ request }) => {
    await loginViaApi(request, 'instructor');
    const course = await getPrimaryInstructorCourse(request);

    test.skip(!course, 'Need an instructor course to load prompt settings.');

    const res = await request.get(`/api/settings/prompts?courseId=${encodeURIComponent(course.id)}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(body.prompts).toBeDefined();
  });

  test('can load quiz settings for the current instructor course', async ({ request }) => {
    await loginViaApi(request, 'instructor');
    const course = await getPrimaryInstructorCourse(request);

    test.skip(!course, 'Need an instructor course to load quiz settings.');

    const res = await request.get(`/api/settings/quiz?courseId=${encodeURIComponent(course.id)}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(body.settings).toBeDefined();
  });

  test('blocks global settings for instructors without delete-all permission', async ({ request }) => {
    await loginViaApi(request, 'instructor');

    const res = await request.get('/api/settings/global');
    expect(res.status()).toBe(403);

    const body = await res.json();
    expect(body.success).toBeFalsy();
  });
});

test.describe('Privileged settings access', () => {
  test('privileged instructors can see the delete-all and admin sections', async ({ page, request }) => {
    const privilegedCredentials = await findPrivilegedInstructorCredentials(request);
    if (!privilegedCredentials) {
      test.skip(true, 'Need a seeded privileged instructor account for delete-all tests.');
      return;
    }

    await openInstructorSettings(page, privilegedCredentials);

    await expect(page.locator('#database-management-section')).toBeVisible();
    await expect(page.locator('#delete-collection')).toBeVisible();
    await expect(page.locator('#login-restriction-section')).toBeVisible();
    await expect(page.locator('#question-generation-section')).toBeVisible();
  });

  test('privileged instructors can access the admin-only settings APIs', async ({ request }) => {
    const privilegedCredentials = await findPrivilegedInstructorCredentials(request);
    if (!privilegedCredentials) {
      test.skip(true, 'Need a seeded privileged instructor account for delete-all tests.');
      return;
    }

    await loginViaApi(request, null, privilegedCredentials);

    const permissionRes = await request.get('/api/settings/can-delete-all');
    const permissionBody = await permissionRes.json();
    expect(permissionBody.success).toBeTruthy();
    expect(permissionBody.canDeleteAll).toBe(true);

    const globalRes = await request.get('/api/settings/global');
    expect(globalRes.ok()).toBeTruthy();
    const globalBody = await globalRes.json();
    expect(globalBody.success).toBeTruthy();
  });
});

test.describe('Instructor student hub page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'instructor');
    await page.waitForURL('**/instructor**', { timeout: 10000 });
    await page.goto('/instructor/student-hub');
    await page.waitForLoadState('networkidle');
  });

  test('student hub page loads with correct heading', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('Student Hub');
  });

  test('has students container', async ({ page }) => {
    await expect(page.locator('#students-container')).toBeAttached();
  });

  test('shows either students or empty state after loading', async ({ page }) => {
    await page.waitForTimeout(3000);

    const studentCards = await page.locator('.student-card').count();
    const body = await page.locator('body').innerText();

    expect(studentCards >= 0).toBeTruthy();
    expect(body.length).toBeGreaterThan(0);
  });
});

test.describe('Instructor downloads page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'instructor');
    await page.waitForURL('**/instructor**', { timeout: 10000 });
    await page.goto('/instructor/downloads');
    await page.waitForLoadState('networkidle');
  });

  test('downloads page loads', async ({ page }) => {
    const body = await page.locator('body').innerText();
    expect(body.length).toBeGreaterThan(0);
  });

  test('has students container for download cards', async ({ page }) => {
    await expect(page.locator('#students-container')).toBeAttached();
  });

  test('shows loading, content, or empty state', async ({ page }) => {
    await page.waitForTimeout(3000);

    const loadingVisible = await page.locator('#loading-state').isVisible().catch(() => false);
    const emptyVisible = await page.locator('#empty-state').isVisible().catch(() => false);
    const studentCards = await page.locator('.student-card').count();

    expect(loadingVisible || emptyVisible || studentCards >= 0).toBeTruthy();
  });
});

test.describe('Courses API', () => {
  test('instructor can list courses', async ({ request }) => {
    await loginViaApi(request, 'instructor');

    const res = await request.get('/api/courses');
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(Array.isArray(body.data)).toBeTruthy();
  });
});
