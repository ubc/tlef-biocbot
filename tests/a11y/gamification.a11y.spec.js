// @ts-check
/**
 * Accessibility of the gamification pages, in each of their states, on a
 * server running gamification (BIOCBOT_GAMIFICATION=1). It skips on a server
 * without it (CI's today). Locally:
 *   BIOCBOT_GAMIFICATION=1 TLEF_BIOCBOT_PORT=8052 AGENT_CHAT_MODES= \
 *     npx playwright test --config=playwright.a11y.config.js tests/a11y/gamification.a11y.spec.js
 *
 * Each state gets axe (no critical or serious violations) and the house
 * toolkit (tests/a11y/toolkit, the LTIC rules): no `fail` or `house` finding
 * inside the parts this feature adds. The page shells around them are the
 * same as every other page's and are audited elsewhere.
 */
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const {
    GAMI_COURSE_ID,
    GAMI_UNIT,
    serverRunsGamification,
    resetGamificationCourse,
    cleanupGamificationCourse
} = require('../e2e/helpers/gamification');
const { expectNoA11yViolations } = require('./axe-helper');
const toolkit = require('./toolkit');

test.describe.configure({ mode: 'serial' });

/** The house toolkit's certain findings (`fail`) and house-style ones (`house`) inside `root`. */
async function expectNoHouseFindings(page, root) {
    const findings = await toolkit.audit(page, { root });
    const blocking = findings.filter(f => f.tier === 'fail' || f.tier === 'house');
    expect(blocking.map(f => `${f.rule}: ${f.message} (${f.selector})`)).toEqual([]);
}

async function checkState(page, roots) {
    await expectNoA11yViolations(page, { include: roots });
    for (const root of roots) await expectNoHouseFindings(page, root);
}

test.describe('Accessibility: gamification', () => {
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

    test.describe('the instructor page', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('in each state: loaded, template chosen, previewed, published, removing', async ({ page }) => {
            await page.goto(`/instructor/gamification?courseId=${GAMI_COURSE_ID}`);
            const builder = page.locator('ubc-rule-builder');
            await expect(builder.getByRole('heading', { name: 'Start from a template' })).toBeVisible();
            await expect(builder.getByRole('button', { name: 'First time', exact: true })).toBeVisible();
            const roots = ['#gamification-switch-section', 'ubc-rule-builder'];
            await checkState(page, roots);

            // The switch: turned on, its state said in text, focus kept.
            const toggle = page.getByLabel('Count badges and points in this course');
            const switched = await toolkit.observeStatusMessages(page, () => toggle.check(), { watchMs: 1500 });
            expect(switched.announcements.map(a => a.text).join(" ")).toContain('Gamification is now on in this course.');
            await expect(toggle).toBeFocused();

            // A template chosen: focus moves to its first blank.
            await builder.getByRole('button', { name: 'First time', exact: true }).click();
            await expect(builder.getByLabel('Badge name')).toBeFocused();
            await builder.getByLabel('Action').selectOption('chat.session.started');
            await checkState(page, roots);

            // Previewed: announced, and focus stays on the button.
            const preview = builder.getByRole('button', { name: 'Preview on past activity' });
            const previewed = await toolkit.observeStatusMessages(page, () => preview.click(), { watchMs: 1500 });
            expect(previewed.announcements.map(a => a.text).join(" ")).toContain('Preview');
            await expect(preview).toBeFocused();
            await checkState(page, roots);

            // Published: the rule is listed, with controls that name it.
            await builder.getByRole('button', { name: 'Publish the rule' }).click();
            await expect(builder.getByRole('button', { name: /^Remove ?: Award First Step/ })).toBeVisible();
            await checkState(page, roots);

            // Removing: the dialog opens with focus on its heading.
            await builder.getByRole('button', { name: /^Remove ?: Award First Step/ }).click();
            const dialog = page.getByRole('dialog', { name: 'Remove this rule?' });
            await expect(dialog).toBeVisible();
            await expect(dialog.getByRole('heading', { name: 'Remove this rule?' })).toBeFocused();
            await checkState(page, ['ubc-rule-builder dialog']);

            // Removed: focus moves to "No rules yet." rather than the page.
            await dialog.getByRole('button', { name: 'Remove the rule' }).click();
            await expect(dialog).toBeHidden();
            await expect(builder.getByText('No rules yet.')).toBeFocused();

            // Publish it again for the student's turn.
            await builder.getByRole('button', { name: 'Publish the rule' }).click();
            await expect(builder.getByRole('button', { name: /^Remove ?: Award First Step/ })).toBeVisible();
        });
    });

    test.describe('the student pages', () => {
        test.use({ storageState: storageStatePath('student') });

        test('the award toast, and the Achievements page with and without badges shown', async ({ page }) => {
            await page.route('**/api/auth/logout', route => route.abort());
            await page.addInitScript(courseId => {
                try { localStorage.setItem('selectedCourseId', courseId); } catch (_) { /* private window */ }
            }, GAMI_COURSE_ID);

            await page.goto(`/student?courseId=${GAMI_COURSE_ID}`);
            const toast = page.locator('ubc-award-toast');
            await expect(toast).toHaveAttribute('course', GAMI_COURSE_ID);
            const chat = await toolkit.observeStatusMessages(page, () => page.evaluate(async ({ courseId, unit }) => {
                await requestChatReply({
                    message: 'What is a codon?',
                    conversationId: `a11y-gami-${Date.now()}`,
                    mode: 'tutor',
                    unitName: unit,
                    courseId
                }, { onStatus: () => {} });
            }, { courseId: GAMI_COURSE_ID, unit: GAMI_UNIT }), { watchMs: 4000 });
            expect(chat.announcements.map(a => a.text).join(" ")).toContain('You earned the First Step badge.');
            await expect(toast.locator('.ubc-g-toast')).toBeVisible();
            await checkState(page, ['ubc-award-toast']);

            await page.goto('/student/achievements');
            const shelf = page.locator('ubc-badge-shelf');
            await expect(shelf.getByRole('heading', { name: 'First Step', level: 3 })).toBeVisible();
            await checkState(page, ['ubc-badge-shelf', '#main']);

            const hide = page.getByLabel('Hide badges and points');
            await hide.check();
            await expect(page.getByText('Badges and points are hidden.')).toBeVisible();
            await expect(hide).toBeFocused();
            await checkState(page, ['ubc-badge-shelf']);
            await hide.uncheck();
        });
    });
});
