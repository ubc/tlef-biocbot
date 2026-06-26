// @ts-check
const { test, expect } = require('@playwright/test');
const { TEST_USERS, storageStatePath } = require('../e2e/helpers/users');
const {
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
} = require('../e2e/helpers/courses-test');
const {
    seedSuperchat,
    cleanupSuperchats,
} = require('../e2e/helpers/superchats-test');
const { expectNoA11yViolations } = require('./axe-helper');

const SUPER_COURSE_ID = 'BIOC-A11Y-SUPER-COURSE';
const SUPER_COURSE_SOURCE_ID = 'BIOC-A11Y-SUPER-SOURCE';
const SUPER_COURSE_SOURCE_NAME = 'BIOC A11Y Super Source';

test.describe('Accessibility: additional student pages', () => {
    test.use({ storageState: storageStatePath('student') });

    for (const path of ['/student/quiz']) {
        test(`${path} has no critical/serious a11y violations`, async ({ page }) => {
            await page.goto(path);
            await page.waitForLoadState('load');
            await expectNoA11yViolations(page);
        });
    }
});

test.describe('Accessibility: student Super Course page', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeAll(async () => {
        const [instructorId, studentId] = await Promise.all([
            getUserIdByUsername(TEST_USERS.instructor.username),
            getUserIdByUsername(TEST_USERS.student.username),
        ]);

        await Promise.all([
            cleanupCourses([SUPER_COURSE_SOURCE_ID]),
            cleanupSuperchats([SUPER_COURSE_ID]),
        ]);

        await seedSuperchat({
            superchatId: SUPER_COURSE_ID,
            name: 'A11y Super Course',
            yearLevel: 2,
            showToStudents: true,
        });
        await seedCourse({
            courseId: SUPER_COURSE_SOURCE_ID,
            instructorId,
            courseName: SUPER_COURSE_SOURCE_NAME,
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
            overrides: {
                yearLevel: 2,
                superchatIds: [SUPER_COURSE_ID],
            },
        });
    });

    test.afterAll(async () => {
        await Promise.all([
            cleanupCourses([SUPER_COURSE_SOURCE_ID]),
            cleanupSuperchats([SUPER_COURSE_ID]),
        ]);
    });

    test('/student/super-course has no critical/serious a11y violations', async ({ page }) => {
        await page.addInitScript(() => {
            try {
                for (const key of Object.keys(localStorage)) {
                    if (key.startsWith('biocbot_student_super')) {
                        localStorage.removeItem(key);
                    }
                }
            } catch (_) {}
        });

        await page.goto('/student/super-course');
        await page.waitForLoadState('load');
        await expect(page.locator('#superchat-picker')).toBeVisible({ timeout: 10_000 });
        await expect(page.locator(`#superchat-picker option[value="${SUPER_COURSE_ID}"]`)).toHaveCount(1);
        await expect(page.locator('#super-course-pool-list')).toContainText(SUPER_COURSE_SOURCE_NAME, {
            timeout: 10_000,
        });
        await expect(page.locator('#super-course-history-list')).toContainText('No saved Super Chat sessions yet.', {
            timeout: 10_000,
        });

        await expectNoA11yViolations(page);
    });
});
