// @ts-check
/**
 * A collapsed unit on the Course Upload page must hide its content from
 * screen readers and the keyboard, not just from the eye.
 *
 * Found by the VoiceOver tests in tests/screen-reader: moving by heading,
 * VoiceOver read "Learning Objectives : 2. Enzymes" while unit 2 was
 * collapsed. A collapsed unit's content only gets `max-height: 0` with
 * `overflow: hidden`, which hides it on screen but leaves it in the
 * accessibility tree and the tab order. The issue 724 tests open every unit
 * before they check anything, so they never saw a collapsed one.
 *
 * Unit 1 starts expanded and units 2 and 3 start collapsed.
 */
const { test, expect } = require('@playwright/test');
const { TEST_USERS, storageStatePath } = require('../e2e/helpers/users');
const { seedCourse, cleanupCourses, getUserIdByUsername } = require('../e2e/helpers/courses-test');

const COURSE_ID = 'BIOC-A11Y-COLLAPSED';

test.describe('Course Upload: collapsed units', () => {
    test.use({ storageState: storageStatePath('instructor'), viewport: { width: 1440, height: 1000 } });

    test.beforeAll(async () => {
        const instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
        const now = new Date();
        const unit = (n, displayName, objectives) => ({
            name: `Unit ${n}`, displayName, isPublished: false, learningObjectives: objectives, passThreshold: 1,
            createdAt: now, updatedAt: now, documents: [], assessmentQuestions: [],
        });
        await seedCourse({
            courseId: COURSE_ID, instructorId, courseName: 'Collapsed Units Course',
            lectures: [
                unit(1, 'Cell Structure', ['Describe the cell membrane', 'Name the organelles', 'Explain osmosis']),
                unit(2, 'Enzymes', ['Define activation energy', 'Describe enzyme inhibition']),
                unit(3, 'Metabolism', ['Outline glycolysis', 'Outline the citric acid cycle']),
            ],
        });
    });

    test.afterAll(async () => {
        await cleanupCourses([COURSE_ID]);
    });

    test.beforeEach(async ({ page }) => {
        await page.goto(`/instructor/documents?courseId=${COURSE_ID}`);
        await expect(page.locator('.accordion-item')).toHaveCount(3, { timeout: 20_000 });
        await expect(page.locator('.accordion-item').nth(1).locator('.accordion-trigger')).toHaveAttribute('aria-expanded', 'false');
        // Let the page's staggered loaders fill the units before checking them.
        await page.waitForTimeout(700);
    });

    test('a collapsed unit\'s headings and controls are hidden from screen readers', async ({ page }) => {
        for (const n of [1, 2]) {
            const unit = page.locator('.accordion-item').nth(n);
            const content = unit.locator('.accordion-content');
            await expect(content).toHaveClass(/collapsed/);
            // getByRole skips content hidden from the accessibility tree by
            // display, visibility or aria-hidden. It does not skip `inert`
            // content, which browsers also remove from it, so that is filtered here.
            const exposed = await content.getByRole('heading').or(content.getByRole('button')).or(content.getByRole('textbox'))
                .evaluateAll((els) => els.filter((el) => !el.closest('[inert]')).map((el) => (
                    `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''} "${(el.textContent || '').replace(/\s+/g, ' ').trim()}"`
                )));
            expect(exposed, `collapsed unit ${n + 1} exposes its content`).toEqual([]);
        }
    });

    test('Tab skips over a collapsed unit\'s content', async ({ page }) => {
        const unit = page.locator('.accordion-item').nth(1);
        // The delete button is the last control in the unit's header.
        await unit.locator('.delete-unit-btn').focus();
        await page.keyboard.press('Tab');
        const landed = await page.evaluate(() => {
            const el = document.activeElement;
            return {
                insideCollapsedContent: !!(el && el.closest('.accordion-content.collapsed')),
                element: el ? `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}${el.className ? `.${String(el.className).split(' ').join('.')}` : ''}` : null,
            };
        });
        expect(landed.insideCollapsedContent, `Tab moved into collapsed unit 2, onto ${landed.element}`).toBe(false);
        await expect(page.locator('.accordion-item').nth(2).locator('.accordion-trigger')).toBeFocused();
    });
});
