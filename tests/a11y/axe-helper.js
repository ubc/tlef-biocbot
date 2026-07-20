// @ts-check
/// <reference types="node" />
const AxeBuilder = require('@axe-core/playwright').default;
const { expect, test } = require('@playwright/test');

// Only critical/serious violations fail the build for now. Moderate/minor issues
// are logged but not enforced, so pre-existing low-severity noise doesn't block
// the PR — ratchet this set wider over time as pages are cleaned up.
const BLOCKING_IMPACTS = new Set(['critical', 'serious']);
const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/** @param {import('@playwright/test').Page} page */
function pageIdentity(page) {
    const url = new URL(page.url());
    return {
        route: `${url.pathname}${url.search}${url.hash}`,
        page: url.toString(),
    };
}

/**
 * Flatten axe rules to one actionable record per affected target. Axe violations
 * always have nodes, but retain a rule-level record if a future axe result does not.
 *
 * @param {any[]} violations
 * @param {{ route: string, page: string }} identity
 */
function machineReadableViolations(violations, identity) {
    return violations.flatMap((violation) => {
        const nodes = violation.nodes.length ? violation.nodes : [null];
        return nodes.map((/** @type {any} */ node) => ({
            ...identity,
            ruleId: violation.id,
            impact: violation.impact || 'unknown',
            target: node ? node.target : [],
            selector: node ? node.target.join(' ') : '',
            failureSummary: node ? node.failureSummary : '',
            help: violation.help,
            description: violation.description,
            helpUrl: violation.helpUrl,
            html: node ? node.html : '',
        }));
    });
}

/** @param {object} result */
async function attachScanResult(result) {
    await test.info().attach('a11y-scan', {
        body: JSON.stringify(result),
        contentType: 'application/json',
    });
}

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
    // A page with a strict Content-Security-Policy can block inline <style>
    // injection. Swallow that rejection rather than failing the axe scan.
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

    let builder = new AxeBuilder({ page }).withTags(WCAG_TAGS);
    // Scope the scan to a subtree when requested. Modal scans use this so the
    // audit reports issues inside the open dialog only, instead of re-failing on
    // the host page's pre-existing (separately tracked) violations.
    if (include) {
        builder = builder.include(include);
    }
    if (disableRules.length) {
        builder = builder.disableRules(disableRules);
    }

    let violations;
    const identity = pageIdentity(page);
    try {
        ({ violations } = await builder.analyze());
        await attachScanResult({
            status: 'completed',
            ...identity,
            wcagTags: WCAG_TAGS,
            violations: machineReadableViolations(violations, identity),
        });
    } catch (error) {
        await attachScanResult({
            status: 'failed',
            ...identity,
            wcagTags: WCAG_TAGS,
            error: error instanceof Error ? error.message : String(error),
            violations: [],
        });
        throw error;
    }

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
