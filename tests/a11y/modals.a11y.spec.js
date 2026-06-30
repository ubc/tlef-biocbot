// @ts-check
/**
 * Accessibility scans of modals / pop-ups.
 *
 * The baseline page scans only ever see each route in its resting state. Modals
 * (`#question-modal`, `#delete-unit-modal`, `#transfer-course-modal`, ...) live in
 * the DOM but are `display:none` until a user action opens them, and axe-core
 * skips hidden subtrees — so the markup that is most prone to a11y problems
 * (dialog roles, focusable close buttons, overlay contrast, select names) was
 * never being audited.
 *
 * Each modal here is static markup in its page's HTML, so we force-reveal it
 * after load rather than reproducing the full open flow (several open handlers
 * early-return without seeded data, AI-generation results, etc.). This audits the
 * modal's structure/naming/contrast deterministically. It does not exercise focus
 * trapping, which only the real handler performs — that is left to e2e coverage.
 *
 * The scan is scoped to the modal subtree (`include`) so failures are attributed
 * to the dialog, not to the host page's separately tracked backlog.
 */
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { getInstructorId, setSystemAdmin } = require('../e2e/helpers/downloads');
const { expectNoA11yViolations } = require('./axe-helper');

/**
 * Reveal a modal in the browser by replicating how the app shows it.
 *
 * - `show`: add the `.show` class (and clear any inline `display:none` / flip
 *   `aria-hidden`) — used by the `.modal.show { display:flex }` /
 *   `.transfer-modal-overlay.show` pages.
 * - `flex` / `block`: set `style.display` directly — used by the pages whose JS
 *   toggles inline display (download progress, student sessions, confirm,
 *   idle-timeout).
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} selector
 * @param {'show' | 'flex' | 'block'} mode
 */
async function revealModal(page, selector, mode) {
    const revealed = await page.evaluate(
        ([sel, m]) => {
            const el = document.querySelector(sel);
            if (!el) return false;
            const node = /** @type {HTMLElement} */ (el);
            if (m === 'show') {
                node.style.display = '';
                node.classList.add('show');
                node.setAttribute('aria-hidden', 'false');
            } else {
                node.style.display = m;
            }
            return true;
        },
        [selector, mode]
    );
    expect(revealed, `modal ${selector} should exist in the DOM`).toBe(true);
    await expect(page.locator(selector)).toBeVisible({ timeout: 10_000 });
}

/**
 * @typedef {Object} ModalCase
 * @property {string} route   Route the modal lives on.
 * @property {string} id      Modal element id (used as selector + test name).
 * @property {'show' | 'flex' | 'block'} mode  How the app reveals it.
 */

/** @param {import('@playwright/test').Page} page @param {ModalCase} modal */
async function scanModal(page, modal) {
    await page.goto(modal.route);
    await page.waitForLoadState('load');
    await revealModal(page, `#${modal.id}`, modal.mode);
    await expectNoA11yViolations(page, { include: `#${modal.id}` });
}

// --- Instructor modals (default instructor session) ---------------------------

/** @type {ModalCase[]} */
const INSTRUCTOR_MODALS = [
    { route: '/instructor/documents', id: 'upload-modal', mode: 'show' },
    { route: '/instructor/documents', id: 'question-modal', mode: 'show' },
    { route: '/instructor/documents', id: 'delete-unit-modal', mode: 'show' },
    { route: '/instructor/documents', id: 'regenerate-modal', mode: 'show' },
    { route: '/instructor/documents', id: 'calibration-modal', mode: 'show' },
    { route: '/instructor/documents', id: 'auto-link-confirmation-modal', mode: 'show' },
    { route: '/instructor/documents', id: 'question-learning-objective-modal', mode: 'show' },
    { route: '/instructor/settings', id: 'transfer-course-modal', mode: 'show' },
    { route: '/instructor/ta-hub', id: 'remove-ta-modal', mode: 'show' },
];

test.describe('Accessibility: instructor modals', () => {
    test.use({ storageState: storageStatePath('instructor') });

    for (const modal of INSTRUCTOR_MODALS) {
        test(`${modal.route} #${modal.id} has no critical/serious a11y violations`, async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});

// --- Instructor downloads modals (needs system-admin to load the page) --------

/** @type {ModalCase[]} */
const DOWNLOADS_MODALS = [
    { route: '/instructor/downloads', id: 'download-modal', mode: 'block' },
    { route: '/instructor/downloads', id: 'student-modal', mode: 'block' },
];

test.describe('Accessibility: instructor downloads modals', () => {
    test.use({ storageState: storageStatePath('instructor') });

    let instructorId;

    test.beforeAll(async () => {
        instructorId = await getInstructorId();
        await setSystemAdmin(instructorId, true);
    });

    test.afterAll(async () => {
        if (instructorId) {
            await setSystemAdmin(instructorId, false);
        }
    });

    for (const modal of DOWNLOADS_MODALS) {
        test(`${modal.route} #${modal.id} has no critical/serious a11y violations`, async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});

// --- Student modals (default student session) ---------------------------------

/** @type {ModalCase[]} */
const STUDENT_MODALS = [
    { route: '/student/dashboard.html', id: 'confirm-modal', mode: 'flex' },
    { route: '/student', id: 'idle-timeout-modal', mode: 'flex' },
];

test.describe('Accessibility: student modals', () => {
    test.use({ storageState: storageStatePath('student') });

    for (const modal of STUDENT_MODALS) {
        test(`${modal.route} #${modal.id} has no critical/serious a11y violations`, async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});
