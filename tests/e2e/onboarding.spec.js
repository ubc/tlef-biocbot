// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  buildUniqueUsername,
  loginAs,
  loginViaApi,
  registerUser,
} = require('./helpers/e2e');

/**
 * Instructor onboarding flow tests.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

async function uploadTextMaterial(page, trigger, statusLocator, textContent, manualTopic) {
  await trigger.click();
  await expect(page.locator('#upload-modal')).toBeVisible({ timeout: 10000 });

  await page.locator('#text-input').fill(textContent);
  await page.locator('#upload-btn').click();

  await expect(page.locator('#topic-review-section')).toBeVisible({ timeout: 60000 });

  if (manualTopic) {
    await page.locator('#upload-topic-new-input').fill(manualTopic);
    await page.locator('#upload-topic-add-btn').click();
    await expect.poll(async () => {
      const values = await page.locator('#upload-topic-review-list .topic-review-input').evaluateAll((nodes) => {
        return nodes.map((node) => node.value);
      });
      return values.includes(manualTopic);
    }).toBe(true);
  }

  await page.locator('#save-topics-btn').click();
  await expect(page.locator('#upload-modal')).toBeHidden({ timeout: 15000 });
  await expect(statusLocator).toHaveText(/Uploaded|Added/, { timeout: 15000 });
}

test.describe('Instructor onboarding', () => {
  test('a new instructor can create a custom course and complete onboarding', async ({ page, request }) => {
    test.setTimeout(240000);

    const username = buildUniqueUsername('e2e_instructor_onboarding');
    const password = 'PlaywrightE2E123!';
    const credentials = { username, password };
    const courseName = `BiocBot E2E Onboarding ${Date.now()}`;
    const objectiveText = 'Explain how ATP production is coupled to cellular respiration.';
    const lectureTopic = 'Cellular Respiration';
    const practiceTopic = 'ATP Yield';
    const questionText = 'Which molecule is the main energy currency of the cell?';
    let courseId = null;

    try {
      const registration = await registerUser(request, {
        username,
        password,
        email: `${username}@example.com`,
        role: 'instructor',
        displayName: 'E2E Instructor Onboarding',
      });

      if (registration.response.status() === 403) {
        test.skip(true, 'Local registration is disabled in this environment.');
      }

      expect(registration.response.ok()).toBeTruthy();
      expect(registration.body.success).toBeTruthy();

      await loginAs(page, null, credentials);
      await page.waitForURL('**/instructor**', { timeout: 10000 });

      await page.goto('/instructor/onboarding');
      await page.waitForLoadState('networkidle');

      await expect(page.locator('#step-1.active')).toBeVisible();
      await page.getByRole('button', { name: 'Get Started' }).click();

      await expect(page.locator('#step-2.active')).toBeVisible();
      await expect(page.locator('#course-select')).toBeVisible();
      await expect(page.locator('#course-select option[value="custom"]')).toHaveCount(1, { timeout: 10000 });

      await page.locator('#course-select').selectOption('custom');
      await page.locator('#custom-course-name').fill(courseName);
      await page.locator('#weeks-count').fill('1');
      await page.locator('#lectures-per-week').fill('1');

      const createCourseResponsePromise = page.waitForResponse((response) => {
        return response.url().includes('/api/onboarding') && response.request().method() === 'POST';
      });

      await page.locator('#continue-btn').click();

      const createCourseResponse = await createCourseResponsePromise;
      expect(createCourseResponse.ok()).toBeTruthy();

      const createCourseBody = await createCourseResponse.json();
      expect(createCourseBody.success).toBeTruthy();
      courseId = createCourseBody.data.courseId;

      await expect(page.locator('#step-3.active')).toBeVisible({ timeout: 15000 });
      await expect(page.locator('#substep-objectives.active')).toBeVisible();

      await page.locator('#objective-input').fill(objectiveText);
      await page.locator('.add-objective-btn').click();
      await expect(page.locator('#objectives-list')).toContainText(objectiveText);

      await page.getByRole('button', { name: 'Continue to Course Materials' }).click();
      await expect(page.locator('#substep-materials.active')).toBeVisible();

      const lectureUploadTrigger = page.locator('.material-item.required').nth(0).getByRole('button', { name: 'Upload' });
      await uploadTextMaterial(
        page,
        lectureUploadTrigger,
        page.locator('#lecture-status'),
        'Lecture notes covering glycolysis, the TCA cycle, and oxidative phosphorylation.',
        lectureTopic
      );

      const practiceUploadTrigger = page.locator('.material-item.required').nth(1).getByRole('button', { name: 'Upload' });
      await uploadTextMaterial(
        page,
        practiceUploadTrigger,
        page.locator('#practice-status'),
        'Practice problems focused on ATP yield, electron transport, and redox balancing.',
        practiceTopic
      );

      await page.getByRole('button', { name: 'Continue to Probing Questions' }).click();
      await expect(page.locator('#substep-questions.active')).toBeVisible();

      await page.locator('.add-question-btn').click();
      await expect(page.locator('#question-modal')).toBeVisible();

      await page.locator('#question-type').selectOption('multiple-choice');
      await page.locator('#question-text').fill(questionText);
      await page.locator('.mcq-input[data-option="A"]').fill('ATP');
      await page.locator('.mcq-input[data-option="B"]').fill('DNA');
      await page.locator('.mcq-input[data-option="C"]').fill('Glucose');
      await page.locator('input[name="mcq-correct"][value="A"]').check();
      await page.locator('#question-modal').getByRole('button', { name: 'Save Question' }).click();

      await expect(page.locator('#question-modal')).toBeHidden({ timeout: 10000 });
      await expect(page.locator('#assessment-questions-onboarding')).toContainText(questionText);

      await page.locator('#pass-threshold-onboarding').fill('1');

      const questionSaveResponsePromise = page.waitForResponse((response) => {
        return response.url().includes('/api/questions') && response.request().method() === 'POST';
      });
      const thresholdSaveResponsePromise = page.waitForResponse((response) => {
        return response.url().includes('/api/lectures/pass-threshold') && response.request().method() === 'POST';
      });

      await page.getByRole('button', { name: 'Save Assessment' }).click();

      const [questionSaveResponse, thresholdSaveResponse] = await Promise.all([
        questionSaveResponsePromise,
        thresholdSaveResponsePromise,
      ]);

      expect(questionSaveResponse.ok()).toBeTruthy();
      expect(thresholdSaveResponse.ok()).toBeTruthy();

      const saveOnboardingResponsePromise = page.waitForResponse((response) => {
        return response.url().includes(`/api/onboarding/${courseId}`) && response.request().method() === 'PUT';
      });
      const completeOnboardingResponsePromise = page.waitForResponse((response) => {
        return response.url().includes('/api/onboarding/complete') && response.request().method() === 'POST';
      });

      await page.getByRole('button', { name: 'Complete Unit 1 & Continue' }).click();

      const [saveOnboardingResponse, completeOnboardingResponse] = await Promise.all([
        saveOnboardingResponsePromise,
        completeOnboardingResponsePromise,
        page.waitForURL((url) => url.href.includes(`/instructor/index.html?courseId=${courseId}`), { timeout: 30000 }),
      ]);

      expect(saveOnboardingResponse.ok()).toBeTruthy();
      expect(completeOnboardingResponse.ok()).toBeTruthy();
      expect(page.url()).toContain(`/instructor/index.html?courseId=${courseId}`);

      await loginViaApi(request, null, credentials);

      const onboardingResponse = await request.get(`/api/onboarding/${encodeURIComponent(courseId)}`);
      expect(onboardingResponse.ok()).toBeTruthy();
      const onboardingBody = await onboardingResponse.json();

      expect(onboardingBody.success).toBeTruthy();
      expect(onboardingBody.data.courseName).toBe(courseName);
      expect(onboardingBody.data.isOnboardingComplete).toBe(true);

      const unit1 = (onboardingBody.data.lectures || []).find((lecture) => lecture.name === 'Unit 1');
      expect(unit1).toBeDefined();
      expect(unit1.learningObjectives).toContain(objectiveText);

      const documentsResponse = await request.get(
        `/api/documents/lecture?courseId=${encodeURIComponent(courseId)}&lectureName=${encodeURIComponent('Unit 1')}`
      );
      expect(documentsResponse.ok()).toBeTruthy();
      const documentsBody = await documentsResponse.json();

      expect(documentsBody.success).toBeTruthy();
      expect(documentsBody.data.documents.length).toBeGreaterThanOrEqual(2);
      expect(documentsBody.data.documents.some((doc) => doc.documentType === 'lecture-notes')).toBe(true);
      expect(documentsBody.data.documents.some((doc) => doc.documentType === 'practice-quiz')).toBe(true);

      const questionsResponse = await request.get(
        `/api/questions/lecture?courseId=${encodeURIComponent(courseId)}&lectureName=${encodeURIComponent('Unit 1')}`
      );
      expect(questionsResponse.ok()).toBeTruthy();
      const questionsBody = await questionsResponse.json();

      expect(questionsBody.success).toBeTruthy();
      expect(questionsBody.data.count).toBeGreaterThan(0);
      expect(questionsBody.data.questions.some((question) => question.question === questionText)).toBe(true);

      const passThresholdResponse = await request.get(
        `/api/lectures/pass-threshold?courseId=${encodeURIComponent(courseId)}&lectureName=${encodeURIComponent('Unit 1')}`
      );
      expect(passThresholdResponse.ok()).toBeTruthy();
      const passThresholdBody = await passThresholdResponse.json();

      expect(passThresholdBody.success).toBeTruthy();
      expect(passThresholdBody.data.passThreshold).toBe(1);

      const topicsResponse = await request.get(`/api/courses/${encodeURIComponent(courseId)}/approved-topics`);
      expect(topicsResponse.ok()).toBeTruthy();
      const topicsBody = await topicsResponse.json();

      expect(topicsBody.success).toBeTruthy();
      expect(topicsBody.data.topics).toEqual(expect.arrayContaining([lectureTopic, practiceTopic]));

      await page.goto('/instructor/onboarding');
      await page.waitForURL((url) => url.href.includes(`/instructor/documents?courseId=${courseId}`), { timeout: 15000 });
    } finally {
      if (courseId) {
        try {
          await loginViaApi(request, null, credentials);
          await request.delete(`/api/onboarding/${encodeURIComponent(courseId)}`);
        } catch (error) {
          // Best-effort cleanup only.
        }
      }
    }
  });
});
