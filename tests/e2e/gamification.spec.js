// @ts-check
/**
 * Gamification end to end, on a server running it (BIOCBOT_GAMIFICATION=1):
 * an instructor turns it on for their course and publishes a badge with the
 * rule builder, a TA sees the rules read-only, the student's chat earns the
 * badge, the chat page's toast says so, and the Achievements page shows it.
 *
 * It skips on a server without gamification (CI's today). Locally:
 *   BIOCBOT_GAMIFICATION=1 TLEF_BIOCBOT_PORT=8052 AGENT_CHAT_MODES= \
 *     npx playwright test tests/e2e/gamification.spec.js
 */
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('./helpers/users');
const {
    GAMI_COURSE_ID,
    GAMI_UNIT,
    serverRunsGamification,
    resetGamificationCourse,
    cleanupGamificationCourse
} = require('./helpers/gamification');

test.describe.configure({ mode: 'serial' });

test.describe('Gamification', () => {
    test.beforeAll(async ({ browser }) => {
        const context = await browser.newContext({ storageState: storageStatePath('instructor') });
        const runs = await serverRunsGamification(context.request);
        await context.close();
        test.skip(!runs, 'The server does not run gamification (BIOCBOT_GAMIFICATION unset).');
        await resetGamificationCourse();
    });

    test.afterAll(async () => {
        await cleanupGamificationCourse();
    });

    /** Keeps the student page's idle timer from signing the shared test student out. */
    async function keepSignedIn(page) {
        await page.route('**/api/auth/logout', route => route.abort());
    }

    test.describe('as the instructor', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('turns it on and publishes a badge with the builder', async ({ page }) => {
            await page.goto(`/instructor/gamification?courseId=${GAMI_COURSE_ID}`);
            await expect(page).toHaveTitle('Gamification | BiocBot');
            await expect(page.getByRole('link', { name: 'Gamification' })).toHaveAttribute('aria-current', 'page');

            const toggle = page.getByLabel('Count badges and points in this course');
            await expect(toggle).not.toBeChecked();
            await toggle.check();
            await expect(page.locator('#gamification-switch-state')).toHaveText(/^On:/);
            await expect(toggle).toBeFocused();

            await page.getByRole('button', { name: 'First time', exact: true }).click();
            await expect(page.getByLabel('Badge name')).toBeFocused();
            await page.getByLabel('Badge name').fill('First chat');
            await page.getByLabel('Action').selectOption('chat.session.started');
            await expect(page.locator('.ubc-g-sentence')).toHaveText('Award First chat the first time a student chats with BiocBot about a unit.');

            await page.getByRole('button', { name: 'Preview on past activity' }).click();
            await expect(page.locator('[data-feedback]')).toContainText('Preview on past activity');

            await page.getByRole('button', { name: 'Publish the rule' }).click();
            await expect(page.locator('[data-feedback]')).toContainText('Published: Award First chat');
            await expect(page.getByRole('heading', { name: 'First chat', level: 3 })).toBeVisible();
            await expect(page.getByRole('button', { name: /^Remove ?: Award First chat/ })).toBeVisible();
        });
    });

    test.describe('as a TA', () => {
        test.use({ storageState: storageStatePath('ta') });

        test('sees the switch and the rules, and can change neither', async ({ page }) => {
            await page.goto(`/instructor/gamification?courseId=${GAMI_COURSE_ID}`);
            await expect(page.locator('#gamification-switch-state')).toHaveText(/^On:/);
            await expect(page.getByLabel('Count badges and points in this course')).toBeHidden();
            await expect(page.getByRole('heading', { name: 'First chat', level: 3 })).toBeVisible();
            await expect(page.getByRole('button', { name: /^Remove/ })).toHaveCount(0);
            await expect(page.getByRole('heading', { name: 'Describe a rule' })).toBeHidden();
        });
    });

    test.describe('as the student', () => {
        test.use({ storageState: storageStatePath('student') });

        test('earns the badge by chatting, hears about it, and finds it under Achievements', async ({ page }) => {
            await keepSignedIn(page);
            await page.addInitScript(courseId => {
                try { localStorage.setItem('selectedCourseId', courseId); } catch (_) { /* private window */ }
            }, GAMI_COURSE_ID);

            await page.goto(`/student?courseId=${GAMI_COURSE_ID}`);
            await expect(page.getByRole('link', { name: 'Achievements' })).toBeVisible();
            const toast = page.locator('ubc-award-toast');
            await expect(toast).toHaveAttribute('course', GAMI_COURSE_ID);

            // The page's own chat request (student-chat-request.js), which tells the toast to look.
            const status = await page.evaluate(async ({ courseId, unit }) => {
                const reply = await requestChatReply({
                    message: 'What is a codon?',
                    conversationId: `e2e-gami-${Date.now()}`,
                    mode: 'tutor',
                    unitName: unit,
                    courseId
                }, { onStatus: () => {} });
                return reply.status;
            }, { courseId: GAMI_COURSE_ID, unit: GAMI_UNIT });
            expect(status).toBe(200);

            await expect(toast.locator('.ubc-g-toast')).toHaveText('You earned the First chat badge.');
            await expect(toast.getByRole('status')).toHaveText('You earned the First chat badge.');

            await page.getByRole('link', { name: 'Achievements' }).click();
            await expect(page).toHaveTitle('Achievements | BiocBot');
            await expect(page.getByRole('heading', { name: 'Badges earned (1)', level: 2 })).toBeVisible();
            await expect(page.getByRole('heading', { name: 'First chat', level: 3 })).toBeVisible();

            await page.getByLabel('Hide badges and points').check();
            await expect(page.getByText('Badges and points are hidden.')).toBeVisible();
            await page.getByLabel('Hide badges and points').uncheck();
            await expect(page.getByRole('heading', { name: 'First chat', level: 3 })).toBeVisible();
        });
    });

    test.describe('once it is off again', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('the student has no Achievements link', async ({ page, browser }) => {
            const off = await page.request.put(`/api/gamification/courses/${GAMI_COURSE_ID}/enabled`, { data: { enabled: false } });
            expect(off.status()).toBe(200);

            const student = await browser.newContext({ storageState: storageStatePath('student') });
            const studentPage = await student.newPage();
            await keepSignedIn(studentPage);
            await studentPage.addInitScript(courseId => {
                try { localStorage.setItem('selectedCourseId', courseId); } catch (_) { /* private window */ }
            }, GAMI_COURSE_ID);
            await studentPage.goto(`/student/achievements?courseId=${GAMI_COURSE_ID}`);
            await expect(studentPage.getByText("Badges and points aren't turned on in this course.")).toBeVisible();
            await expect(studentPage.getByRole('link', { name: 'Achievements' })).toHaveCount(0);
            await student.close();
        });
    });
});
