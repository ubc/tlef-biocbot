// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const { loginAs } = require('./helpers/e2e');

/**
 * Role-based access control tests for protected page routes.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

test.describe('Role-based page access control', () => {
  test('students are redirected away from instructor settings', async ({ page }) => {
    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });

    await page.goto('/instructor/settings');
    await page.waitForURL('**/student**', { timeout: 10000 });

    expect(page.url()).toContain('/student');
  });

  test('instructors are redirected away from student pages', async ({ page }) => {
    await loginAs(page, 'instructor');
    await page.waitForURL('**/instructor**', { timeout: 10000 });

    await page.goto('/student');
    await page.waitForURL('**/instructor**', { timeout: 10000 });

    expect(page.url()).toContain('/instructor');
  });

  test('TAs are redirected away from instructor-only student hub', async ({ page }) => {
    await loginAs(page, 'ta');
    await page.waitForURL('**/ta**', { timeout: 10000 });

    await page.goto('/instructor/student-hub');
    await page.waitForURL('**/ta**', { timeout: 10000 });

    expect(page.url()).toContain('/ta');
  });
});
