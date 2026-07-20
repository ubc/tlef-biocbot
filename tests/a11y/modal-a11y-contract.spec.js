// @ts-check
const path = require('path');
const { test, expect } = require('@playwright/test');
const {
    activateModal,
    expectAsyncCloseFocusReturn,
    expectModalKeyboardContract,
    expectReplacementFocusReturn,
} = require('./helpers/modal-keyboard-contract');

const helperScript = path.resolve(__dirname, '../../public/common/scripts/modal-a11y.js');

/** @param {import('@playwright/test').Page} page */
async function loadHarness(page) {
    await page.setContent(`
        <button id="normal-trigger">Open normal dialog</button>
        <button id="forced-trigger">Open forced dialog</button>
        <button id="legacy-trigger">Open legacy dialog</button>

        <dialog id="normal-dialog">
            <h2>Normal contract</h2>
            <button id="normal-first">First</button>
            <button id="normal-replace">Replace</button>
            <button id="normal-suspend">Open child dialog</button>
            <button id="normal-async">Complete asynchronously</button>
            <button id="normal-last">Last</button>
        </dialog>

        <dialog id="replacement-dialog">
            <h2>Replacement contract</h2>
            <button id="replacement-close">Finish replacement</button>
        </dialog>

        <dialog id="child-dialog">
            <h2>Child contract</h2>
            <button id="child-close">Return to parent</button>
        </dialog>

        <dialog id="forced-dialog">
            <h2>Required choice</h2>
            <button id="forced-complete">Complete required action</button>
        </dialog>

        <div id="legacy-dialog" style="display:none; position:fixed; inset:0;">
            <div>
                <h2>Legacy adapter</h2>
                <button id="legacy-close">Close legacy dialog</button>
            </div>
        </div>
    `);
    await page.addScriptTag({ path: helperScript });
    await page.evaluate(() => {
        const testWindow = /** @type {any} */ (window);
        const normal = /** @type {HTMLElement} */ (document.querySelector('#normal-dialog'));
        const replacement = /** @type {HTMLElement} */ (document.querySelector('#replacement-dialog'));
        const child = /** @type {HTMLElement} */ (document.querySelector('#child-dialog'));
        const forced = /** @type {HTMLElement} */ (document.querySelector('#forced-dialog'));
        const legacy = /** @type {HTMLElement} */ (document.querySelector('#legacy-dialog'));

        const closeNormal = () => testWindow.a11yModal.close(normal);
        document.querySelector('#normal-trigger')?.addEventListener('click', () => {
            testWindow.a11yModal.open(normal, { onRequestClose: closeNormal });
        });
        document.querySelector('#normal-last')?.addEventListener('click', closeNormal);
        document.querySelector('#normal-async')?.addEventListener('click', async () => {
            await Promise.resolve();
            closeNormal();
        });
        document.querySelector('#normal-replace')?.addEventListener('click', () => {
            testWindow.a11yModal.open(replacement, {
                onRequestClose: () => testWindow.a11yModal.close(replacement),
            });
        });
        document.querySelector('#replacement-close')?.addEventListener('click', () => {
            testWindow.a11yModal.close(replacement);
        });
        document.querySelector('#normal-suspend')?.addEventListener('click', () => {
            testWindow.a11yModal.suspend(normal);
            testWindow.a11yModal.open(child);
        });
        document.querySelector('#child-close')?.addEventListener('click', () => {
            testWindow.a11yModal.close(child, { restoreFocus: false });
            testWindow.a11yModal.resume(normal, { onRequestClose: closeNormal });
        });

        document.querySelector('#forced-trigger')?.addEventListener('click', () => {
            testWindow.a11yModal.open(forced, {
                escapable: false,
                dismissalBlockedMessage: 'Choose Complete required action to continue.',
            });
        });
        document.querySelector('#forced-complete')?.addEventListener('click', () => {
            testWindow.a11yModal.close(forced);
        });

        document.querySelector('#legacy-trigger')?.addEventListener('click', () => {
            legacy.style.display = 'block';
            testWindow.a11yModal.open(legacy, {
                onRequestClose: () => {
                    testWindow.a11yModal.close(legacy);
                    legacy.style.display = 'none';
                },
            });
        });
        document.querySelector('#legacy-close')?.addEventListener('click', () => {
            testWindow.a11yModal.close(legacy);
            legacy.style.display = 'none';
        });
    });
}

test.beforeEach(async ({ page }) => {
    await loadHarness(page);
});

test('normal native dialog covers semantics, both Tab boundaries, dismissal, and repeat lifecycle', async ({ page }) => {
    await expectModalKeyboardContract(page, {
        trigger: '#normal-trigger',
        activationKey: 'Space',
        dialog: '#normal-dialog',
        name: 'Normal contract',
        initialFocus: '#normal-dialog h2',
        firstFocusable: '#normal-first',
        lastFocusable: '#normal-last',
    });

    await expect(page.locator('dialog[open]')).toHaveCount(0);
    await expect(page.locator('[id="normal-dialog-title-1"]')).toHaveCount(1);
});

test('forced-choice dialog blocks Escape and backdrop with an accessible reason', async ({ page }) => {
    await expectModalKeyboardContract(page, {
        trigger: '#forced-trigger',
        dialog: '#forced-dialog',
        name: 'Required choice',
        initialFocus: '#forced-dialog h2',
        firstFocusable: '#forced-complete',
        lastFocusable: '#forced-complete',
        dismissible: false,
        permittedClose: '#forced-complete',
        blockedReason: /Choose Complete required action to continue/,
    });
});

test('replacement and async completion restore the original outside trigger', async ({ page }) => {
    await expectReplacementFocusReturn(page, {
        trigger: '#normal-trigger',
        dialog: '#normal-dialog',
        name: 'Normal contract',
        initialFocus: '#normal-dialog h2',
        replacementTrigger: '#normal-replace',
        replacementDialog: '#replacement-dialog',
        replacementClose: '#replacement-close',
    });

    await expectAsyncCloseFocusReturn(page, {
        trigger: '#normal-trigger',
        dialog: '#normal-dialog',
        name: 'Normal contract',
        initialFocus: '#normal-dialog h2',
        completion: '#normal-async',
    });
});

test('suspended parent resumes without losing its original focus-return target', async ({ page }) => {
    await page.locator('#normal-trigger').click();
    await page.locator('#normal-suspend').click();
    await expect(page.locator('#child-dialog')).toBeVisible();

    await page.locator('#child-close').click();
    await expect(page.locator('#normal-dialog')).toBeVisible();
    await expect(page.locator('#normal-dialog h2')).toBeFocused();

    await page.locator('#normal-last').click();
    await expect(page.locator('#normal-trigger')).toBeFocused();
});

test('legacy helper callers use one temporary native host without accumulating overlays', async ({ page }) => {
    const modal = {
        trigger: '#legacy-trigger',
        dialog: 'dialog.a11y-modal-host',
        name: 'Legacy adapter',
        initialFocus: '#legacy-dialog h2',
    };

    for (let cycle = 0; cycle < 2; cycle += 1) {
        await activateModal(page, modal);
        await expect(page.locator('dialog.a11y-modal-host')).toHaveCount(1);
        await page.locator('#legacy-close').click();
        await expect(page.locator('dialog.a11y-modal-host')).toHaveCount(0);
        await expect(page.locator('#legacy-trigger')).toBeFocused();
    }
});
