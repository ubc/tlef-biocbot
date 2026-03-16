// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  buildUniqueUsername,
  clearBrowserState,
  getCourseDetails,
  getDisabledQuizCourse,
  getPrimaryInstructorCourse,
  getQuizReadyCourse,
  loginAs,
  loginViaApi,
  registerUser,
  selectStudentCourse,
} = require('./helpers/e2e');

/**
 * Student course access tests — course joining and course-driven navigation.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

test.describe('Student course joining', () => {
  test('a new student can join a course using the instructor-provided course code', async ({ page, request }) => {
    await loginViaApi(request, 'instructor');
    const instructorCourse = await getPrimaryInstructorCourse(request);

    test.skip(!instructorCourse, 'Need an instructor-owned course to test student joins.');

    const courseDetails = await getCourseDetails(request, instructorCourse.id);
    test.skip(!courseDetails.courseCode, 'Need a course code to test student joins.');

    const username = buildUniqueUsername('e2e_student');
    const password = process.env.student_password;
    const registration = await registerUser(request, {
      username,
      password,
      email: `${username}@example.com`,
      role: 'student',
      displayName: 'E2E Student',
    });

    if (registration.response.status() === 403) {
      test.skip(true, 'Local registration is disabled in this environment.');
    }

    expect(registration.response.ok()).toBeTruthy();
    expect(registration.body.success).toBeTruthy();

    const dialogs = [];
    page.on('dialog', async (dialog) => {
      dialogs.push(dialog.type());

      if (dialog.type() === 'prompt') {
        await dialog.accept(courseDetails.courseCode);
        return;
      }

      await dialog.accept();
    });

    await loginAs(page, null, { username, password });
    await page.waitForURL('**/student**', { timeout: 10000 });
    await expect(page.locator('#course-select')).toBeVisible({ timeout: 10000 });

    await page.locator('#course-select').selectOption(instructorCourse.id);

    await expect(page.locator('#course-selection-wrapper')).toBeHidden({ timeout: 15000 });
    await expect.poll(async () => {
      return page.evaluate(() => localStorage.getItem('selectedCourseId'));
    }).toBe(instructorCourse.id);
    await expect.poll(() => dialogs.includes('prompt')).toBe(true);
    await expect.poll(() => dialogs.includes('alert')).toBe(true);
  });
});

test.describe('Student quiz navigation visibility', () => {
  test('shows the quiz nav item when the selected course has quiz enabled', async ({ page, request }) => {
    await loginViaApi(request, 'student');
    const quizContext = await getQuizReadyCourse(request);

    test.skip(!quizContext, 'Need an enrolled course with quiz enabled.');

    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await clearBrowserState(page);
    await page.goto('/student');
    await page.waitForLoadState('networkidle');
    await selectStudentCourse(page, quizContext.course.courseId);
    await expect(page.locator('.course-name')).not.toHaveText('Select Course', { timeout: 15000 });
    await page.goto('/student/history');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#quiz-nav-item')).toBeVisible({ timeout: 10000 });
  });

  test('hides the quiz nav item when the selected course has quiz disabled', async ({ page, request }) => {
    await loginViaApi(request, 'student');
    const disabledCourse = await getDisabledQuizCourse(request);

    test.skip(!disabledCourse, 'Need an enrolled course with quiz disabled.');

    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await clearBrowserState(page);
    await page.goto('/student');
    await page.waitForLoadState('networkidle');
    await selectStudentCourse(page, disabledCourse.courseId);
    await expect(page.locator('.course-name')).not.toHaveText('Select Course', { timeout: 15000 });
    await page.goto('/student/history');
    await page.waitForLoadState('networkidle');

    await expect(page.locator('#quiz-nav-item')).toBeHidden({ timeout: 10000 });
  });
});
