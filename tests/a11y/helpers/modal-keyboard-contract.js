// @ts-check
const { expect } = require('@playwright/test');

/**
 * @typedef {Object} ModalKeyboardContract
 * @property {string} trigger
 * @property {string} dialog
 * @property {string|RegExp} name
 * @property {string} initialFocus
 * @property {string} [firstFocusable]
 * @property {string} [lastFocusable]
 * @property {'Enter'|'Space'} [activationKey]
 * @property {boolean} [dismissible]
 * @property {string} [permittedClose]
 * @property {string|RegExp} [blockedReason]
 */

/** @param {import('@playwright/test').Page} page @param {ModalKeyboardContract} modal */
async function activateModal(page, modal) {
    const trigger = page.locator(modal.trigger).first();
    await expect(trigger).toBeVisible({ timeout: 15_000 });
    await trigger.focus();
    await page.keyboard.press(modal.activationKey || 'Enter');
    await expect(page.locator(modal.dialog)).toBeVisible({ timeout: 10_000 });
}

/** @param {import('@playwright/test').Page} page @param {ModalKeyboardContract} modal */
async function expectSemanticsAndInitialFocus(page, modal) {
    const dialog = page.locator(modal.dialog);
    await expect(dialog).toHaveRole('dialog');
    await expect(dialog).toHaveAccessibleName(modal.name);
    await expect(page.locator(modal.initialFocus)).toBeFocused();
}

/**
 * Assert the two actual focus boundaries directly. This deliberately does not
 * infer containment by pressing Tab an arbitrary number of times.
 * @param {import('@playwright/test').Page} page
 * @param {ModalKeyboardContract} modal
 */
async function expectTabBoundaryContainment(page, modal) {
    if (!modal.firstFocusable || !modal.lastFocusable) return;

    const first = page.locator(modal.firstFocusable);
    const last = page.locator(modal.lastFocusable);

    await last.focus();
    await page.keyboard.press('Tab');
    await expect(first).toBeFocused();

    await first.focus();
    await page.keyboard.press('Shift+Tab');
    await expect(last).toBeFocused();
}

/** @param {import('@playwright/test').Page} page @param {ModalKeyboardContract} modal */
async function expectFocusReturned(page, modal) {
    await expect(page.locator(modal.trigger).first()).toBeFocused();
}

/** @param {import('@playwright/test').Page} page @param {ModalKeyboardContract} modal */
async function expectBackdropPolicy(page, modal) {
    await page.mouse.click(1, 1);
    if (modal.dismissible === false) {
        await expect(page.locator(modal.dialog)).toBeVisible();
        if (modal.blockedReason) {
            await expect(page.locator(modal.dialog)).toHaveAccessibleDescription(modal.blockedReason);
        }
    } else {
        await expect(page.locator(modal.dialog)).toBeHidden();
        await expectFocusReturned(page, modal);
    }
}

/** @param {import('@playwright/test').Page} page @param {ModalKeyboardContract} modal */
async function expectEscapePolicy(page, modal) {
    await page.keyboard.press('Escape');
    if (modal.dismissible === false) {
        await expect(page.locator(modal.dialog)).toBeVisible();
        if (modal.blockedReason) {
            await expect(page.locator(modal.dialog)).toHaveAccessibleDescription(modal.blockedReason);
        }
    } else {
        await expect(page.locator(modal.dialog)).toBeHidden();
        await expectFocusReturned(page, modal);
    }
}

/**
 * Reopen and dismiss twice to catch duplicate Escape listeners and stale
 * restoration targets.
 * @param {import('@playwright/test').Page} page
 * @param {ModalKeyboardContract} modal
 */
async function expectRepeatOpenClose(page, modal) {
    for (let cycle = 0; cycle < 2; cycle += 1) {
        await activateModal(page, modal);
        await expectSemanticsAndInitialFocus(page, modal);
        await expectEscapePolicy(page, modal);
    }
}

/**
 * Full reusable contract for a real trigger. Dismissible dialogs are tested by
 * backdrop and Escape; forced-choice dialogs prove both are blocked and then
 * use their permitted completion control.
 * @param {import('@playwright/test').Page} page
 * @param {ModalKeyboardContract} modal
 */
async function expectModalKeyboardContract(page, modal) {
    await activateModal(page, modal);
    await expectSemanticsAndInitialFocus(page, modal);
    await expectTabBoundaryContainment(page, modal);
    await expectBackdropPolicy(page, modal);

    if (modal.dismissible === false) {
        await expectEscapePolicy(page, modal);
        if (!modal.permittedClose) throw new Error('Forced-choice modal tests require a permittedClose control.');
        await page.locator(modal.permittedClose).click();
        await expect(page.locator(modal.dialog)).toBeHidden();
        await expectFocusReturned(page, modal);
        return;
    }

    await expectRepeatOpenClose(page, modal);
}

/**
 * Optional assertion for completion handlers that close only after async work.
 * @param {import('@playwright/test').Page} page
 * @param {ModalKeyboardContract & {completion: string}} modal
 */
async function expectAsyncCloseFocusReturn(page, modal) {
    await activateModal(page, modal);
    await page.locator(modal.completion).click();
    await expect(page.locator(modal.dialog)).toBeHidden();
    await expectFocusReturned(page, modal);
}

/**
 * Optional assertion for the shared replacement policy: the replacement closes
 * back to the original outside trigger, never to a control in the old dialog.
 * @param {import('@playwright/test').Page} page
 * @param {ModalKeyboardContract & {replacementTrigger: string, replacementDialog: string, replacementClose: string}} modal
 */
async function expectReplacementFocusReturn(page, modal) {
    await activateModal(page, modal);
    await page.locator(modal.replacementTrigger).click();
    await expect(page.locator(modal.dialog)).toBeHidden();
    await expect(page.locator(modal.replacementDialog)).toBeVisible();
    await page.locator(modal.replacementClose).click();
    await expect(page.locator(modal.replacementDialog)).toBeHidden();
    await expectFocusReturned(page, modal);
}

module.exports = {
    activateModal,
    expectAsyncCloseFocusReturn,
    expectBackdropPolicy,
    expectEscapePolicy,
    expectFocusReturned,
    expectModalKeyboardContract,
    expectRepeatOpenClose,
    expectReplacementFocusReturn,
    expectSemanticsAndInitialFocus,
    expectTabBoundaryContainment,
};
