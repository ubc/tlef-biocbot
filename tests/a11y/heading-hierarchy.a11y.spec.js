// @ts-check
/// <reference types="node" />
const { test, expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');

const HEADING_STUDENT_ID = 'a11y-heading-student';
const HEADING_COURSE_ID = 'A11Y-HEADING-COURSE';

/**
 * Keep the student chat heading case independent of database state left by other
 * suites. A valid selected course prevents the first-time course picker from
 * racing the heading snapshot.
 *
 * @param {import('@playwright/test').Page} page
 */
async function seedStudentHeadingPage(page) {
    const course = {
        courseId: HEADING_COURSE_ID,
        courseName: 'Accessibility Heading Fixture',
        status: 'active',
        lectures: [{
            name: 'Unit 1',
            displayName: 'Unit 1',
            isPublished: true,
            passThreshold: 0,
            documents: [],
            assessmentQuestions: [],
        }],
    };

    await page.route('**/api/**', async (route) => {
        const url = new URL(route.request().url());
        const pathname = url.pathname;
        if (pathname === '/api/auth/me') {
            await route.fulfill({
                json: {
                    success: true,
                    user: {
                        userId: HEADING_STUDENT_ID,
                        username: 'a11y_heading_student',
                        role: 'student',
                        displayName: 'Accessibility Heading Student',
                        preferences: {},
                    },
                },
            });
        } else if (pathname === '/api/user-agreement/status') {
            await route.fulfill({ json: { success: true, data: { hasAgreed: true, agreementVersion: '1.0' } } });
        } else if (pathname === `/api/courses/${HEADING_COURSE_ID}/student-enrollment`) {
            await route.fulfill({ json: { success: true, data: { enrolled: true, status: 'active' } } });
        } else if (pathname === `/api/courses/${HEADING_COURSE_ID}`) {
            await route.fulfill({ json: { success: true, data: course } });
        } else if (pathname === '/api/courses/available/all') {
            await route.fulfill({
                json: {
                    success: true,
                    data: [{
                        courseId: HEADING_COURSE_ID,
                        courseName: course.courseName,
                        isEnrolled: true,
                    }],
                },
            });
        } else if (pathname === '/api/quiz/status') {
            await route.fulfill({ json: { success: true, enabled: false } });
        } else if (pathname === '/api/questions/lecture') {
            await route.fulfill({ json: { success: true, data: { questions: [] } } });
        } else if (pathname === '/api/student/struggle') {
            await route.fulfill({ json: { success: true, struggleState: { topics: [] } } });
        } else if (pathname === '/api/flags/count' || pathname === '/api/flags') {
            await route.fulfill({ json: { success: true, count: 0, data: [] } });
        } else {
            await route.fulfill({ json: { success: true, data: {} } });
        }
    });

    await page.addInitScript(({ courseId, courseName, studentId }) => {
        const chatData = {
            metadata: {
                courseId,
                courseName,
                studentId,
                studentName: 'Accessibility Heading Student',
                unitName: 'Unit 1',
                currentMode: 'tutor',
                totalMessages: 0,
                version: '1.0',
            },
            messages: [],
            practiceTests: null,
            studentAnswers: { answers: [] },
            sessionInfo: { sessionId: 'a11y-heading-session' },
        };
        localStorage.setItem('selectedCourseId', courseId);
        localStorage.setItem('selectedCourseName', courseName);
        localStorage.setItem('selectedUnitName', 'Unit 1');
        localStorage.setItem(`biocbot_current_chat_${studentId}`, JSON.stringify(chatData));
    }, {
        courseId: HEADING_COURSE_ID,
        courseName: course.courseName,
        studentId: HEADING_STUDENT_ID,
    });
}

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
        const isHidden = (/** @type {Element} */ element) => {
            for (
                let node = /** @type {HTMLElement | null} */ (element);
                node;
                node = node.parentElement
            ) {
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
                if (path === '/student') await seedStudentHeadingPage(page);
                await page.goto(path);
                await page.waitForLoadState('load');
                if (path === '/student') {
                    await expect(page.locator('#unit-select')).toHaveValue('Unit 1');
                }
                await expectValidHeadingOutline(page);
            });
        }
    });
}
