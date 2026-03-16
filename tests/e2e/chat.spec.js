// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  clearBrowserState,
  getAssessmentUnitCourse,
  getChatReadyCourse,
  getNonEnrolledStudentCourse,
  loginAs,
  loginViaApi,
  selectStudentCourse,
  selectUnit,
} = require('./helpers/e2e');

/**
 * Chat feature tests — API + UI for the student chat interface.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

async function completeAssessmentIfNeeded(page) {
  const chatInput = page.locator('#chat-input');

  if (await chatInput.isVisible().catch(() => false)) {
    return;
  }

  for (let attempt = 0; attempt < 10; attempt += 1) {
    if (await chatInput.isVisible().catch(() => false)) {
      return;
    }

    const shortAnswerInput = page.locator('.calibration-question .calibration-answer-input').last();
    if (await shortAnswerInput.isVisible().catch(() => false)) {
      await shortAnswerInput.fill('Playwright assessment answer with enough detail to complete the setup flow.');
      await page.locator('.calibration-question .calibration-submit-btn').last().click();
      await page.waitForTimeout(3000);
      continue;
    }

    const optionButton = page.locator('.calibration-question .calibration-option:not([disabled])').first();
    if (await optionButton.isVisible().catch(() => false)) {
      await optionButton.click();
      await page.waitForTimeout(800);
      continue;
    }

    await page.waitForTimeout(1000);
  }

  await expect(chatInput).toBeVisible({ timeout: 20000 });
}

async function openStudentChat(page, request, options = {}) {
  const { requireAssessment = false } = options;

  await loginViaApi(request, 'student');
  const context = requireAssessment
    ? await getAssessmentUnitCourse(request)
    : (await getChatReadyCourse(request)) || await getAssessmentUnitCourse(request);

  test.skip(!context, 'Need an enrolled student course with published units for chat tests.');

  await loginAs(page, 'student');
  await page.waitForURL('**/student**', { timeout: 10000 });

  await clearBrowserState(page);
  await page.goto('/student');
  await page.waitForLoadState('networkidle');
  await selectStudentCourse(page, context.course.courseId);
  await expect(page.locator('.course-name')).toHaveText(context.course.courseName, { timeout: 15000 });
  await expect(page.locator('#unit-selection-container')).toBeVisible({ timeout: 15000 });
  await selectUnit(page, context.unitName);
  await page.waitForTimeout(1000);

  if (!requireAssessment) {
    await completeAssessmentIfNeeded(page);
  }

  return context;
}

test.describe('Chat API', () => {
  test('chat status endpoint responds with connection info', async ({ request }) => {
    await loginViaApi(request, 'student');

    const res = await request.get('/api/chat/status');
    const body = await res.json();

    expect(body).toHaveProperty('success');
    expect(body).toHaveProperty('data');
    expect(body.data).toHaveProperty('isInitialized');
  });

  test('chat test endpoint confirms LLM connection', async ({ request }) => {
    await loginViaApi(request, 'student');

    const res = await request.post('/api/chat/test');
    const body = await res.json();

    expect(body).toHaveProperty('success');
  });

  test('chat models endpoint returns available models', async ({ request }) => {
    await loginViaApi(request, 'student');

    const res = await request.get('/api/chat/models');
    const body = await res.json();

    expect(body).toHaveProperty('success');
  });

  test('sending a chat message returns a response for an enrolled course', async ({ request }) => {
    await loginViaApi(request, 'student');
    const chatContext = (await getChatReadyCourse(request)) || await getAssessmentUnitCourse(request);

    test.skip(!chatContext, 'Need an enrolled student course with a published unit.');

    const res = await request.post('/api/chat', {
      data: {
        message: 'What is the purpose of this course?',
        courseId: chatContext.course.courseId,
        unitName: chatContext.unitName,
        mode: 'tutor',
      },
      timeout: 30000,
    });

    expect(res.ok()).toBeTruthy();
    const body = await res.json();

    expect(body.success).toBeTruthy();
    expect(typeof body.message).toBe('string');
    expect(body.message.length).toBeGreaterThan(0);
  });

  test('chat rejects messages for a course the student is not enrolled in', async ({ request }) => {
    await loginViaApi(request, 'student');
    const blockedCourse = await getNonEnrolledStudentCourse(request);

    test.skip(!blockedCourse, 'Need a course the student is not enrolled in.');

    const res = await request.post('/api/chat', {
      data: {
        message: 'Should not be allowed',
        courseId: blockedCourse.courseId,
        unitName: 'Unit 1',
        mode: 'tutor',
      },
    });

    expect(res.status()).toBe(403);
    const body = await res.json();

    expect(body.success).toBeFalsy();
    expect(body.message).toContain('disabled');
  });
});

test.describe('Chat page UI', () => {
  test.beforeEach(async ({ page, request }) => {
    await openStudentChat(page, request);
  });

  test('chat page loads with correct heading', async ({ page }) => {
    await expect(page.locator('h1')).toHaveText('Chat with BiocBot');
  });

  test('chat input is available after course and unit setup is complete', async ({ page }) => {
    await expect(page.locator('#chat-input')).toBeVisible();
    await expect(page.locator('#send-button')).toBeVisible();
  });

  test('mode toggle is visible after setup', async ({ page }) => {
    await expect(page.locator('#mode-toggle-checkbox')).toBeAttached();
    await expect(page.locator('.mode-toggle-container')).toBeVisible();
    await expect(page.locator('.protege-label')).toBeVisible();
    await expect(page.locator('.tutor-label')).toBeVisible();
  });

  test('new session button exists', async ({ page }) => {
    await expect(page.locator('#new-session-btn')).toBeVisible();
  });

  test('sidebar navigation links are present', async ({ page }) => {
    await expect(page.locator('nav.main-nav a[href="/student"]')).toBeVisible();
    await expect(page.locator('nav.main-nav a[href="/student/history"]')).toBeVisible();
    await expect(page.locator('nav.main-nav a[href="/student/flagged"]')).toBeVisible();
  });

  test('chat disclaimer exists on the page', async ({ page }) => {
    await expect(page.locator('.chat-disclaimer')).toBeVisible();
  });

  test('unit selection is available after course is selected', async ({ page }) => {
    await expect(page.locator('#unit-select')).toBeVisible();
  });
});

test.describe('Chat assessment gating', () => {
  test.beforeEach(async ({ page, request }) => {
    await openStudentChat(page, request, { requireAssessment: true });
  });

  test('assessment questions appear before freeform chat for gated units', async ({ page }) => {
    await expect(page.locator('.calibration-question').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('#chat-input')).toBeHidden();
    await expect(page.locator('.mode-result')).toHaveCount(0);
  });
});

test.describe('Chat interaction', () => {
  test.beforeEach(async ({ page, request }) => {
    await openStudentChat(page, request);
  });

  test('sending a message shows it in the chat and gets a bot response', async ({ page }) => {
    const chatInput = page.locator('#chat-input');

    await expect(chatInput).toBeVisible({ timeout: 10000 });
    await chatInput.fill('Hello, this is a test message from Playwright');
    await page.locator('#send-button').click();

    const userMessage = page.locator('.message.user-message').last();
    await expect(userMessage).toBeVisible({ timeout: 5000 });

    const botMessage = page.locator('.message.bot-message').last();
    await expect(botMessage).toBeVisible({ timeout: 30000 });
  });
});

test.describe('Chat history page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAs(page, 'student');
    await page.waitForURL('**/student**', { timeout: 10000 });
    await page.goto('/student/history');
    await page.waitForLoadState('networkidle');
  });

  test('history page loads with correct heading', async ({ page }) => {
    await expect(page.locator('.history-header h3')).toHaveText('Chat History');
  });

  test('history page has list and preview panels', async ({ page }) => {
    await expect(page.locator('.chat-history-list')).toBeVisible();
    await expect(page.locator('.chat-preview-panel')).toBeVisible();
  });

  test('preview panel shows "Select a Chat" initially', async ({ page }) => {
    await expect(page.locator('#preview-title')).toHaveText('Select a Chat');
  });

  test('shows either history items or no-history message', async ({ page }) => {
    await page.waitForTimeout(3000);

    const historyItems = await page.locator('#chat-history-list .chat-history-item').count();
    const noHistory = await page.locator('#no-history-message').isVisible();

    expect(historyItems > 0 || noHistory).toBeTruthy();
  });
});
