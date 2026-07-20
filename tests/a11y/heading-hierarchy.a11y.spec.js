// @ts-check
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');

/**
 * Return headings exposed to assistive technology in document order. Hidden UI,
 * including inactive dialogs and closed disclosure content, is deliberately
 * ignored because it is not part of the current page outline.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} [root]
 */
async function getVisibleHeadings(page, root = 'body') {
    return page.locator(root).evaluate((container) => {
        const isHidden = (element) => {
            for (let node = element; node && node instanceof HTMLElement; node = node.parentElement) {
                if (
                    node.hidden ||
                    node.inert ||
                    node.getAttribute('aria-hidden') === 'true' ||
                    (node.matches('details:not([open])') && node !== element) ||
                    (node.matches('dialog:not([open])') && node !== element) ||
                    node.matches('[popover]:not(:popover-open)')
                ) {
                    return true;
                }
                const style = getComputedStyle(node);
                if (style.display === 'none' || style.visibility === 'hidden') return true;
            }
            return false;
        };

        return [...container.querySelectorAll('h1, h2, h3, h4, h5, h6, [role="heading"][aria-level]')]
            .filter((element) => !isHidden(/** @type {HTMLElement} */ (element)))
            .map((element) => ({
                text: (element.textContent || '').trim(),
                level: element.matches('[role="heading"]')
                    ? Number(element.getAttribute('aria-level'))
                    : Number(element.tagName.slice(1)),
                inMain: Boolean(element.closest('main')),
            }));
    });
}

/** @param {import('@playwright/test').Page} page */
async function expectValidHeadingOutline(page) {
    const headings = await getVisibleHeadings(page);
    const mainHeadings = headings.filter((heading) => heading.inMain);
    expect(mainHeadings[0], 'each page needs a visible heading in main').toBeTruthy();
    expect(mainHeadings[0].level, 'the first heading in main must be an h1').toBe(1);

    for (let index = 1; index < headings.length; index += 1) {
        expect(
            headings[index].level,
            `heading level skips from ${headings[index - 1].level} to ${headings[index].level}: ${headings[index].text}`
        ).toBeLessThanOrEqual(headings[index - 1].level + 1);
    }
}

const PAGE_GROUPS = [
    {
        role: 'student',
        paths: ['/student', '/student/history', '/student/flagged', '/student/dashboard.html', '/student/quiz'],
    },
    {
        role: 'instructor',
        paths: [
            '/instructor',
            '/instructor/documents',
            '/instructor/home',
            '/instructor/settings',
            '/instructor/flagged',
            '/instructor/chat',
            '/instructor/notes',
            '/instructor/ta-hub',
            '/instructor/student-hub',
        ],
    },
    { role: 'instructor_fresh', paths: ['/instructor/onboarding'] },
    { role: 'ta', paths: ['/ta', '/ta/onboarding', '/ta/settings', '/ta/courses', '/ta/students'] },
];

for (const { role, paths } of PAGE_GROUPS) {
    test.describe(`Accessibility: heading hierarchy (${role})`, () => {
        test.use({ storageState: storageStatePath(role) });

        for (const path of paths) {
            test(`${path} has a sequential visible heading outline`, async ({ page }) => {
                test.fixme(
                    ['/student', '/student/history'].includes(path),
                    'Known heading-level skip; see audits.md §2.'
                );
                await page.goto(path);
                await page.waitForLoadState('load');
                await expectValidHeadingOutline(page);
            });
        }
    });
}
