// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  getDisabledQuizCourse,
  getNonEnrolledStudentCourse,
  getQuizReadyCourse,
  loginAs,
  loginViaApi,
  prepareStudentCourse,
} = require('./helpers/e2e');

/**
 * Quiz practice feature tests — API + UI.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

test.describe('Quiz API', () => {
  test('quiz status endpoint reflects an enrolled course with quiz enabled', async ({ request }) => {
    await loginViaApi(request, 'student');
    const quizContext = await getQuizReadyCourse(request);

    test.skip(!quizContext, 'Need an enrolled student course with quiz enabled and questions.');

    const res = await request.get(`/api/quiz/status?courseId=${encodeURIComponent(quizContext.course.courseId)}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(body.enabled).toBe(true);
  });

  test('quiz status endpoint reflects an enrolled course with quiz disabled', async ({ request }) => {
    await loginViaApi(request, 'student');
    const disabledCourse = await getDisabledQuizCourse(request);

    test.skip(!disabledCourse, 'Need an enrolled student course with quiz disabled.');

    const res = await request.get(`/api/quiz/status?courseId=${encodeURIComponent(disabledCourse.courseId)}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(body.enabled).toBe(false);
  });

  test('quiz questions endpoint returns questions for an enrolled course with quiz enabled', async ({ request }) => {
    await loginViaApi(request, 'student');
    const quizContext = await getQuizReadyCourse(request);

    test.skip(!quizContext, 'Need an enrolled student course with quiz enabled and questions.');

    const res = await request.get(`/api/quiz/questions?courseId=${encodeURIComponent(quizContext.course.courseId)}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(Array.isArray(body.questions)).toBeTruthy();
    expect(body.questions.length).toBeGreaterThan(0);
  });

  test('quiz history endpoint responds for an enrolled course', async ({ request }) => {
    await loginViaApi(request, 'student');
    const quizContext = await getQuizReadyCourse(request);

    test.skip(!quizContext, 'Need an enrolled student course for quiz history.');

    const res = await request.get(`/api/quiz/history?courseId=${encodeURIComponent(quizContext.course.courseId)}`);
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(body.stats).toBeDefined();
  });

  test('quiz endpoints reject a course the student is not enrolled in', async ({ request }) => {
    await loginViaApi(request, 'student');
    const blockedCourse = await getNonEnrolledStudentCourse(request);

    test.skip(!blockedCourse, 'Need a course the student is not enrolled in.');

    const res = await request.get(`/api/quiz/questions?courseId=${encodeURIComponent(blockedCourse.courseId)}`);
    expect(res.status()).toBe(403);

    const body = await res.json();
    expect(body.success).toBeFalsy();
    expect(body.message).toContain('disabled');
  });
});

test.describe('Quiz page UI', () => {
  test.beforeEach(async ({ page, request }) => {
    await loginViaApi(request, 'student');
    const quizContext = await getQuizReadyCourse(request);

    test.skip(!quizContext, 'Need an enrolled student course with quiz enabled and questions.');

    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await prepareStudentCourse(page, quizContext.course);
    await page.goto('/student/quiz');
    await page.waitForLoadState('networkidle');
  });

  test('quiz page loads with correct heading', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('Quiz Practice');
  });

  test('quiz page has stats cards', async ({ page }) => {
    await expect(page.locator('#stat-total')).toBeVisible();
    await expect(page.locator('#stat-correct')).toBeVisible();
    await expect(page.locator('#stat-accuracy')).toBeVisible();
  });

  test('quiz page has filter controls', async ({ page }) => {
    await expect(page.locator('#unit-filter')).toBeVisible();
    await expect(page.locator('#type-filter')).toBeVisible();
  });

  test('quiz page shows a question card for an enabled quiz course', async ({ page }) => {
    await expect(page.locator('#question-card')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#question-text')).not.toHaveText('');
  });

  test('quiz page has submit and navigation buttons when a question is loaded', async ({ page }) => {
    await expect(page.locator('#submit-btn')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#next-btn')).toBeHidden();
  });
});

test.describe('Quiz access gating', () => {
  test('quiz page shows the disabled state when the selected course has quiz turned off', async ({ page, request }) => {
    await loginViaApi(request, 'student');
    const disabledCourse = await getDisabledQuizCourse(request);

    test.skip(!disabledCourse, 'Need an enrolled student course with quiz disabled.');

    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await prepareStudentCourse(page, disabledCourse);
    await page.goto('/student/quiz');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#quiz-disabled')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#question-card')).toBeHidden();
  });
});
