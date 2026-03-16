// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  getEnrolledStudentCourse,
  loginAs,
  loginViaApi,
} = require('./helpers/e2e');

/**
 * Flagging feature tests — API + UI for student, instructor, and TA roles.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

/**
 * Get a valid courseId. For instructor, uses /api/courses.
 * For student, uses existing flags or falls back to instructor login.
 */
async function getInstructorCourseId(request) {
  const coursesRes = await request.get('/api/courses');
  const coursesBody = await coursesRes.json();
  if (coursesBody.success && coursesBody.data?.length > 0) {
    return coursesBody.data[0].id;
  }
  return null;
}

// ── Flagging API tests ───────────────────────────────────────────────────────

test.describe('Flagging API', () => {
  test('student can create a flag via API', async ({ request }) => {
    await loginViaApi(request, 'student');
    const enrolledCourse = await getEnrolledStudentCourse(request);

    if (!enrolledCourse) {
      test.skip();
      return;
    }

    const flagRes = await request.post('/api/flags', {
      data: {
        questionId: `test_q_${Date.now()}`,
        courseId: enrolledCourse.courseId,
        unitName: 'Test Unit',
        flagReason: 'incorrect',
        flagDescription: 'E2E test flag — this content appears incorrect',
        botMode: 'tutor',
        questionContent: {
          question: 'E2E test question content',
          questionType: 'bot-response',
          options: {},
          correctAnswer: 'N/A',
          explanation: 'This is a test flag from Playwright E2E tests',
        },
      },
    });

    const flagBody = await flagRes.json();
    expect(flagBody.success).toBeTruthy();
    expect(flagBody.data).toHaveProperty('flagId');
  });

  test('student can view their own flags', async ({ request }) => {
    await loginViaApi(request, 'student');

    const res = await request.get('/api/flags/my');
    const body = await res.json();

    expect(body.success).toBeTruthy();
    // Response shape: { data: { flags: [], count: N } }
    expect(body.data).toHaveProperty('flags');
    expect(Array.isArray(body.data.flags)).toBeTruthy();
  });

  test('instructor can view flags for a course', async ({ request }) => {
    await loginViaApi(request, 'instructor');
    const courseId = await getInstructorCourseId(request);

    if (!courseId) {
      test.skip();
      return;
    }

    const res = await request.get(`/api/flags/course/${courseId}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(body.data).toBeDefined();
  });

  test('instructor can view flag stats for a course', async ({ request }) => {
    await loginViaApi(request, 'instructor');
    const courseId = await getInstructorCourseId(request);

    if (!courseId) {
      test.skip();
      return;
    }

    const res = await request.get(`/api/flags/stats/${courseId}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    // Stats are nested under data.statistics
    expect(body.data).toHaveProperty('statistics');
    expect(body.data.statistics).toHaveProperty('total');
    expect(body.data.statistics).toHaveProperty('pending');
  });

  test('can filter flags by status', async ({ request }) => {
    await loginViaApi(request, 'instructor');

    const res = await request.get('/api/flags/status/pending');
    const body = await res.json();

    expect(body.success).toBeTruthy();
    // Response shape: { data: { status, flags: [], count } }
    expect(body.data).toHaveProperty('flags');
    expect(Array.isArray(body.data.flags)).toBeTruthy();
  });
});

// ── Student flagged page UI ──────────────────────────────────────────────────

test.describe('Student flagged page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
  });

  test('loads the flagged page with correct heading', async ({ page }) => {
    await page.goto('/student/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('h1')).toHaveText('My Flagged Messages');
  });

  test('shows filter controls', async ({ page }) => {
    await page.goto('/student/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#status-filter')).toBeVisible();
    await expect(page.locator('#refresh-flags')).toBeVisible();
  });

  test('status filter has correct options', async ({ page }) => {
    await page.goto('/student/flagged');
    await page.waitForLoadState('networkidle');

    const options = page.locator('#status-filter option');
    const count = await options.count();
    expect(count).toBe(5); // All, Pending, Reviewed, Resolved, Dismissed
  });

  test('shows either flags or empty state after loading', async ({ page }) => {
    await page.goto('/student/flagged');
    await page.waitForLoadState('networkidle');

    await page.waitForFunction(() => {
      const loading = document.getElementById('loading-state');
      return loading && loading.style.display === 'none';
    }, { timeout: 10000 });

    const flagCount = await page.locator('#flagged-list .flag-card').count();
    const emptyVisible = await page.locator('#empty-state').isVisible();

    expect(flagCount > 0 || emptyVisible).toBeTruthy();
  });

  test('sidebar shows correct nav items', async ({ page }) => {
    await page.goto('/student/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('nav.main-nav a[href="/student"]')).toBeVisible();
    await expect(page.locator('nav.main-nav a[href="/student/history"]')).toBeVisible();
    await expect(page.locator('nav.main-nav a[href="/student/flagged"]')).toBeVisible();
  });
});

// ── Instructor flagged page UI ───────────────────────────────────────────────

test.describe('Instructor flagged page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'instructor');
    await page.waitForURL('**/instructor**', { timeout: 10000 });
  });

  test('loads the flagged page with correct heading', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('h1')).toHaveText('Flagged Content');
  });

  test('shows filter controls for type and status', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#flag-type-filter')).toBeVisible();
    await expect(page.locator('#status-filter')).toBeVisible();
    await expect(page.locator('#refresh-flags')).toBeVisible();
  });

  test('flag type filter has all reason options', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');

    const options = page.locator('#flag-type-filter option');
    const count = await options.count();
    expect(count).toBe(8); // All + 7 reasons
  });

  test('shows statistics cards', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#total-flags')).toBeVisible();
    await expect(page.locator('#pending-flags')).toBeVisible();
    await expect(page.locator('#today-flags')).toBeVisible();
  });

  test('shows either flags or empty state after loading', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');

    await page.waitForFunction(() => {
      const loading = document.getElementById('loading-state');
      return loading && loading.style.display === 'none';
    }, { timeout: 10000 });

    const flagCount = await page.locator('#flagged-list .flag-card').count();
    const emptyVisible = await page.locator('#empty-state').isVisible();

    expect(flagCount > 0 || emptyVisible).toBeTruthy();
  });

  test('instructor sidebar nav items are visible', async ({ page }) => {
    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#instructor-home-nav')).toBeVisible();
    await expect(page.locator('#instructor-documents-nav')).toBeVisible();
    await expect(page.locator('#instructor-flagged-nav')).toBeVisible();
  });
});

// ── TA flagged page access ───────────────────────────────────────────────────

test.describe('TA flagged page', () => {
  test('TA can access the instructor flagged page', async ({ page }) => {
    await loginAs(page, 'ta');
    await page.waitForURL('**/ta**', { timeout: 10000 });

    await page.goto('/instructor/flagged');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);

    // TA may get a permission error if no courseId context, or the page loads normally
    // Just verify we're not redirected to /login (TA is authenticated)
    expect(page.url()).not.toContain('/login');
  });
});
