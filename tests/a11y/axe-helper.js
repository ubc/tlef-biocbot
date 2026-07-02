// @ts-check
const AxeBuilder = require('@axe-core/playwright').default;
const { expect } = require('@playwright/test');

// Only critical/serious violations fail the build for now. Moderate/minor issues
// are logged but not enforced, so pre-existing low-severity noise doesn't block
// the PR — ratchet this set wider over time as pages are cleaned up.
const BLOCKING_IMPACTS = new Set(['critical', 'serious']);

/**
 * Run an axe-core accessibility scan on the current page and assert there are no
 * blocking (critical/serious) WCAG 2 A/AA violations.
 *
 * @param {import('@playwright/test').Page} page
 * @param {{ disableRules?: string[], include?: string | string[] }} [options]
 */
async function expectNoA11yViolations(page, { disableRules = [], include } = {}) {
    // Freeze CSS entrance animations/transitions before scanning. Pages like
    // /ta/onboarding fade their content in (opacity 0 -> 1 over 0.5s); if axe
    // samples mid-animation it reads washed-out colors and reports false
    // color-contrast failures. Jumping animations to their final state makes the
    // scan deterministic without changing the page's real (settled) appearance.
    // Some pages (e.g. /qdrant-test) ship a strict Content-Security-Policy that
    // blocks inline <style> injection. Those pages have no entrance animations,
    // so swallow the CSP rejection rather than failing the scan.
    try {
        await page.addStyleTag({
            content: `*, *::before, *::after {
                animation-duration: 0s !important;
                animation-delay: 0s !important;
                transition-duration: 0s !important;
                transition-delay: 0s !important;
            }`,
        });
    } catch (_) {
        // CSP blocked the style tag; continue without freezing animations.
    }

    let builder = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']);
    // Scope the scan to a subtree when requested. Modal scans use this so the
    // audit reports issues inside the open dialog only, instead of re-failing on
    // the host page's pre-existing (separately tracked) violations.
    if (include) {
        builder = builder.include(include);
    }
    if (disableRules.length) {
        builder = builder.disableRules(disableRules);
    }

    const { violations } = await builder.analyze();

    const blocking = violations.filter((v) => BLOCKING_IMPACTS.has(/** @type {string} */ (v.impact)));
    const nonBlocking = violations.filter((v) => !BLOCKING_IMPACTS.has(/** @type {string} */ (v.impact)));

    if (nonBlocking.length) {
        // eslint-disable-next-line no-console
        console.warn(
            `[a11y] ${nonBlocking.length} non-blocking violation(s): ` +
            nonBlocking.map((v) => `${v.id} (${v.impact})`).join(', ')
        );
    }

    const detail = blocking
        .map((v) => ` - ${v.id} [${v.impact}]: ${v.help} (${v.nodes.length} node(s))`)
        .join('\n');

    expect(blocking, `Blocking accessibility violations (critical/serious):\n${detail}`).toEqual([]);
}

module.exports = { expectNoA11yViolations };
