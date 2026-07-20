// @ts-check
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');

/**
 * Exercise a dialog's keyboard contract from its actual trigger. The modal root
 * may be an overlay; checking containment rather than a CSS class keeps this
 * reusable across the three modal implementations.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} trigger
 * @param {string} modal
 */
async function expectKeyboardModal(page, trigger, modal) {
    const triggerElement = page.locator(trigger).first();
    const modalElement = page.locator(modal);
    await expect(triggerElement).toBeVisible({ timeout: 15_000 });
    await triggerElement.focus();
    await page.keyboard.press('Enter');
    await expect(modalElement).toBeVisible({ timeout: 10_000 });
    await expect
        .poll(() => modalElement.evaluate((element) => element.contains(document.activeElement)))
        .toBe(true);

    for (let index = 0; index < 20; index += 1) {
        await page.keyboard.press('Tab');
        await expect
            .poll(() => modalElement.evaluate((element) => element.contains(document.activeElement)))
            .toBe(true);
    }

    await page.keyboard.press('Escape');
    await expect(modalElement).toBeHidden();
    await expect
        .poll(() => triggerElement.evaluate((element) => document.activeElement === element))
        .toBe(true);
}

test.describe('Accessibility: student modal keyboard interaction', () => {
    test.use({ storageState: storageStatePath('student') });

    test('student dashboard confirmation modal traps focus and restores its trigger', async ({ page }) => {
        await page.goto('/student/dashboard.html');
        await page.waitForLoadState('load');
        await expectKeyboardModal(page, '#reset-all-btn', '#confirm-modal');
    });

});

test.describe('Accessibility: instructor modal keyboard interaction', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('instructor question modal traps focus and restores its trigger', async ({ page }) => {
        test.fixme(true, 'The seeded page lacks a visible question trigger; see audits.md §3.');
        await page.goto('/instructor/documents');
        await page.waitForLoadState('load');
        await expectKeyboardModal(page, '.add-question-btn', '#question-modal');
    });

});

test.describe('Accessibility: TA-management modal keyboard interaction', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('remove TA modal traps focus and restores its trigger', async ({ page }) => {
        test.fixme(true, 'The seeded page lacks a removable TA trigger; see audits.md §3.');
        await page.goto('/instructor/ta-hub');
        await page.waitForLoadState('load');
        await expectKeyboardModal(page, '.btn-small.btn-danger', '#remove-ta-modal');
    });
});
