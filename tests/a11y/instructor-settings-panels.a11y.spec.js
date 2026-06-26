// @ts-check
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { getInstructorId, setSystemAdmin } = require('../e2e/helpers/downloads');
const { expectNoA11yViolations } = require('./axe-helper');

// The instructor settings page is a single route that hosts many in-page panels
// (course-basics, student-chat, prompts, ...). They are `hidden` by default and
// revealed by a hash-driven renderer (settings.js renderSettingsView), so a scan
// of /instructor/settings alone never sees their content. Deep-linking to the
// panel hash opens it on load, which lets us scan each sub-page deterministically.
//
// Panel names mirror BASE_PANEL_NAMES / ADMIN_PANEL_NAMES in
// public/instructor/scripts/settings.js. The admin panels only render for a
// system admin, so those are scanned with the seeded instructor temporarily
// granted system-admin access.
const BASE_PANELS = ['course-basics', 'student-chat', 'prompts', 'quiz', 'privacy', 'super-course'];
const ADMIN_PANELS = ['admin-platform', 'admin-access', 'admin-safety', 'admin-database'];

/**
 * Open a settings panel by deep-linking to its hash and scan it once visible.
 * @param {import('@playwright/test').Page} page
 * @param {string} panel
 */
async function scanSettingsPanel(page, panel) {
    await page.goto(`/instructor/settings#${panel}`);
    await page.waitForLoadState('load');

    // renderSettingsView() un-hides the panel matching the hash. If it never
    // becomes visible the panel is gated/unavailable and the scan is meaningless.
    await expect(page.locator(`.settings-panel[data-panel="${panel}"]`)).toBeVisible({ timeout: 10_000 });

    // Give async panel content (admin lists, model options, etc.) a chance to
    // populate before scanning. networkidle can hang on long-poll pages, so cap
    // it and continue regardless.
    await page.waitForLoadState('networkidle', { timeout: 5_000 }).catch(() => {});

    await expectNoA11yViolations(page);
}

test.describe('Accessibility: instructor settings panels', () => {
    test.use({ storageState: storageStatePath('instructor') });

    for (const panel of BASE_PANELS) {
        test(`/instructor/settings#${panel} has no critical/serious a11y violations`, async ({ page }) => {
            await scanSettingsPanel(page, panel);
        });
    }
});

test.describe('Accessibility: instructor settings admin panels', () => {
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

    for (const panel of ADMIN_PANELS) {
        test(`/instructor/settings#${panel} has no critical/serious a11y violations`, async ({ page }) => {
            await scanSettingsPanel(page, panel);
        });
    }
});
