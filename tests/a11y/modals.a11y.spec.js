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
 * @property {string} [name]  Label used in the test title (defaults to `#id`).
 * @property {string} [id]    Modal element id; revealed via `mode` and scanned by
 *                            `#id` unless `include` / `setup` override it.
 * @property {'show' | 'flex' | 'block'} [mode]  How the app reveals an `id` modal.
 * @property {string} [include]  axe scope selector (defaults to `#id`). Use for
 *                            dynamically-injected popups without a stable id.
 * @property {(page: import('@playwright/test').Page) => Promise<void>} [setup]
 *                            Custom reveal (call the app's own open API / inject a
 *                            toast) instead of the default class/style flip.
 */

/** @param {import('@playwright/test').Page} page @param {ModalCase} modal */
async function scanModal(page, modal) {
    await page.goto(modal.route);
    await page.waitForLoadState('load');

    const include = modal.include || (modal.id ? `#${modal.id}` : undefined);

    if (modal.setup) {
        await modal.setup(page);
        if (include) {
            await expect(page.locator(include).first()).toBeVisible({ timeout: 10_000 });
        }
    } else {
        await revealModal(page, `#${modal.id}`, /** @type {'show'|'flex'|'block'} */ (modal.mode));
    }

    await expectNoA11yViolations(page, { include });
}

/** @param {ModalCase} modal */
function modalTitle(modal) {
    const label = modal.name || `#${modal.id}`;
    return `${modal.route} ${label} has no critical/serious a11y violations`;
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
        test(modalTitle(modal), async ({ page }) => {
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
        test(modalTitle(modal), async ({ page }) => {
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
        test(modalTitle(modal), async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});

// --- Instructor onboarding modals (fresh instructor before onboarding done) ---
// /instructor/onboarding ships its own copies of the documents modals; a
// completed instructor is redirected away, so these use the instructor_fresh
// session (same state the baseline /instructor/onboarding scan uses).

/** @type {ModalCase[]} */
const ONBOARDING_MODALS = [
    { route: '/instructor/onboarding', id: 'upload-modal', mode: 'show' },
    { route: '/instructor/onboarding', id: 'question-modal', mode: 'show' },
    { route: '/instructor/onboarding', id: 'regenerate-modal', mode: 'show' },
    { route: '/instructor/onboarding', id: 'auto-link-confirmation-modal', mode: 'show' },
    { route: '/instructor/onboarding', id: 'question-learning-objective-modal', mode: 'show' },
];

test.describe('Accessibility: instructor onboarding modals', () => {
    test.use({ storageState: storageStatePath('instructor_fresh') });

    for (const modal of ONBOARDING_MODALS) {
        test(modalTitle(modal), async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});

// --- Dynamically-injected popups (no static markup) ---------------------------
// These are built at runtime, so the baseline scans never see them. We drive the
// app's own API to create them, then scope axe to the injected container.

test.describe('Accessibility: student agreement modal', () => {
    test.use({ storageState: storageStatePath('student') });

    /** @type {ModalCase[]} */
    const cases = [
        {
            route: '/student',
            name: 'agreement modal (consent mode)',
            include: '.agreement-modal-overlay',
            setup: async (page) => {
                await page.waitForFunction(() => Boolean(/** @type {any} */(window).agreementModal));
                await page.evaluate(() => /** @type {any} */(window).agreementModal.show(false));
            },
        },
        {
            route: '/student',
            name: 'agreement modal (read-only mode)',
            include: '.agreement-modal-overlay',
            setup: async (page) => {
                await page.waitForFunction(() => Boolean(/** @type {any} */(window).agreementModal));
                await page.evaluate(() => /** @type {any} */(window).agreementModal.show(true));
            },
        },
    ];

    for (const modal of cases) {
        test(modalTitle(modal), async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});

test.describe('Accessibility: instructor notification toasts', () => {
    test.use({ storageState: storageStatePath('instructor') });

    /** @type {ModalCase} */
    const modal = {
        route: '/instructor/documents',
        name: 'notification toasts (all severities)',
        include: '.notification-container',
        setup: async (page) => {
            // Seed one toast of every severity so each variant's contrast/markup is
            // audited (the page backlog already flags `.notification > span`).
            await page.waitForFunction(() => typeof /** @type {any} */(window).showNotification === "function");
            await page.evaluate(() => {
                for (const type of ['success', 'error', 'warning', 'info']) {
                    /** @type {any} */(window).showNotification(`Sample ${type} notification`, type);
                }
            });
        },
    };

    test(modalTitle(modal), async ({ page }) => {
        await scanModal(page, modal);
    });
});

// --- Dynamically-built instructor modals --------------------------------------
// These have no static markup; a global builder constructs them on demand. We
// call the builder, then reveal, then scope axe to the built node.

test.describe('Accessibility: instructor dynamic modals', () => {
    test.use({ storageState: storageStatePath('instructor') });

    /** @type {ModalCase[]} */
    const cases = [
        {
            // Topic-detection review popup shown during question/topic generation.
            route: '/instructor/documents',
            name: 'topic-review modal',
            include: '#topic-review-modal',
            setup: async (page) => {
                await page.waitForFunction(
                    () => typeof /** @type {any} */(window).ensureTopicReviewModal === 'function'
                );
                await page.evaluate(() => {
                    const modal = /** @type {any} */(window).ensureTopicReviewModal();
                    modal.classList.add('show');
                });
            },
        },
        {
            // Assign-topic-to-unit popup on the instructor home dashboard.
            route: '/instructor/home',
            name: 'topic-unit assignment modal',
            include: '#topic-unit-assignment-modal',
            setup: async (page) => {
                await page.waitForFunction(
                    () => typeof /** @type {any} */(window).ensureTopicUnitAssignmentModal === 'function'
                );
                await page.evaluate(() => {
                    const modal = /** @type {any} */(window).ensureTopicUnitAssignmentModal();
                    modal.classList.add('show');
                });
            },
        },
    ];

    for (const modal of cases) {
        test(modalTitle(modal), async ({ page }) => {
            await scanModal(page, modal);
        });
    }
});

// --- Dynamically-built student popups -----------------------------------------

test.describe('Accessibility: student dynamic popups', () => {
    test.use({ storageState: storageStatePath('student') });

    /** @type {ModalCase} */
    const modal = {
        // "Why the message limit?" popup tied to the chat message-count limiter.
        route: '/student',
        name: 'chat-limit info modal',
        include: '#chat-limit-modal-overlay',
        setup: async (page) => {
            await page.waitForFunction(
                () => typeof /** @type {any} */(window).showChatLimitModal === 'function'
            );
            await page.evaluate(() => /** @type {any} */(window).showChatLimitModal());
        },
    };

    test(modalTitle(modal), async ({ page }) => {
        await scanModal(page, modal);
    });
});
