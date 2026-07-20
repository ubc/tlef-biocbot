// @ts-check
/**
 * Student Topic Dashboard coverage for public/student/scripts/dashboard.js.
 *
 * These tests drive the real /student/dashboard.html page and seed MongoDB
 * directly where the dashboard needs existing struggle state or chat history.
 */

const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const { withDb, getUserIdByUsername } = require('./helpers/quiz');
const {
    STU_COURSE_ID,
    STU_OTHER_COURSE_ID,
    APPROVED_TOPIC,
    getStudentId,
    resetStudentChatData,
    cleanupStudentChatData,
    seedChatSession,
} = require('./helpers/student');

const MAIN_COURSE_NAME = 'BIOC E2E Student Chat';
const OTHER_COURSE_NAME = 'BIOC E2E Student Chat (Other Course)';

let instructorId;
let studentId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getStudentId();
});

test.afterAll(async () => {
    await cleanupStudentChatData();
});

async function clearDashboardAuditData() {
    await withDb(async (db) => {
        await db.collection('struggleActivity').deleteMany({
            userId: studentId,
            courseId: { $in: [STU_COURSE_ID, STU_OTHER_COURSE_ID] },
        });
        await db.collection('persistenceTopics').deleteMany({
            courseId: { $in: [STU_COURSE_ID, STU_OTHER_COURSE_ID] },
        });
    });
}

async function seedStruggleTopics(topics) {
    await withDb(async (db) => {
        await db.collection('users').updateOne(
            { userId: studentId },
            {
                $set: {
                    struggleState: {
                        topics,
                    },
                    updatedAt: new Date(),
                },
            }
        );
    });
}

async function setEnrollment(courseId, enrolled) {
    await withDb(async (db) => {
        await db.collection('courses').updateOne(
            { courseId },
            {
                $set: {
                    [`studentEnrollment.${studentId}.enrolled`]: enrolled,
                    [`studentEnrollment.${studentId}.updatedAt`]: new Date(),
                },
            }
        );
    });
}

async function getStoredTopics() {
    const user = await withDb((db) =>
        db.collection('users').findOne({ userId: studentId })
    );
    return user?.struggleState?.topics ?? [];
}

async function openDashboard(page, {
    courseId = STU_COURSE_ID,
    courseName = MAIN_COURSE_NAME,
    includeCourse = true,
    includeCurrentUser = true,
} = {}) {
    await page.addInitScript(({ courseId, courseName, includeCourse, includeCurrentUser, studentId }) => {
        localStorage.clear();
        if (includeCourse) {
            localStorage.setItem('selectedCourseId', courseId);
            localStorage.setItem('selectedCourseName', courseName);
        }
        if (includeCurrentUser) {
            localStorage.setItem('currentUser', JSON.stringify({
                userId: studentId,
                username: 'e2e_student',
                displayName: 'E2E Student',
                role: 'student',
            }));
        }
    }, { courseId, courseName, includeCourse, includeCurrentUser, studentId });

    await page.goto('/student/dashboard.html');
}

test.describe('Student dashboard page access', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('instructors are redirected away from the student dashboard route', async ({ page }) => {
        await page.goto('/student/dashboard.html');
        await expect(page).toHaveURL(/\/instructor/);
    });
});

test.describe('Student dashboard UI', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetStudentChatData({ instructorId });
        await clearDashboardAuditData();
    });

    test('shows the no-course dashboard state when no course context is selected', async ({ page }) => {
        await openDashboard(page, { includeCourse: false });

        await expect(page.locator('#topics-list-container')).toContainText(
            'Please select a course to view your dashboard.',
            { timeout: 10_000 }
        );
        await expect(page.locator('#active-topics-count')).toHaveText('-');
        await expect(page.locator('#directive-mode-status')).toHaveText('Inactive');
        await expect(page.locator('#course-topics-container')).toContainText(
            'Please select a course to view topics.'
        );
    });

    test('renders sorted struggle topics, active count, directive status, and published course-topic completion', async ({ page }) => {
        await seedStruggleTopics([
            {
                topic: 'mitosis',
                count: 2,
                isActive: false,
                lastStruggle: new Date('2026-01-01T10:00:00.000Z'),
            },
            {
                topic: APPROVED_TOPIC.toLowerCase(),
                count: 4,
                isActive: true,
                lastStruggle: new Date('2026-01-03T10:00:00.000Z'),
            },
        ]);
        await seedChatSession({
            sessionId: 'dashboard_unit_1_completed',
            courseId: STU_COURSE_ID,
            studentId,
            studentName: 'E2E Student',
            title: 'Dashboard Unit 1 completion',
            messages: [
                { type: 'user', content: 'Study Unit 1', timestamp: '2026-01-03T10:00:00.000Z' },
                { type: 'bot', content: 'Unit 1 response', timestamp: '2026-01-03T10:01:00.000Z' },
            ],
        });

        await openDashboard(page);

        await expect(page.locator('#user-display-name')).toHaveText('E2E Student', { timeout: 10_000 });
        await expect(page.locator('.user-role')).toHaveText(`Student - ${MAIN_COURSE_NAME}`);
        await expect(page.locator('#active-topics-count')).toHaveText('1');
        await expect(page.locator('#directive-mode-status')).toHaveText('Active');

        const cards = page.locator('#topics-list-container .topic-card');
        await expect(cards).toHaveCount(2, { timeout: 10_000 });
        await expect(cards.nth(0)).toContainText('Photosynthesis');
        await expect(cards.nth(0)).toContainText('Count: 4');
        await expect(cards.nth(0)).toContainText('Directive Mode On');
        await expect(cards.nth(1)).toContainText('Mitosis');
        await expect(cards.nth(1)).toContainText('Monitoring');

        const courseTopicCards = page.locator('#course-topics-container .topic-item-card');
        await expect(courseTopicCards).toHaveCount(1, { timeout: 10_000 });
        await expect(courseTopicCards.first()).toContainText('Unit 1');
        await expect(courseTopicCards.first()).toContainText('Chatted');
        await expect(page.locator('#course-topics-container')).not.toContainText('Unit 2');
    });

    test('resetting one topic through the modal removes only that topic and writes an inactive audit entry', async ({ page }) => {
        await seedStruggleTopics([
            {
                topic: APPROVED_TOPIC.toLowerCase(),
                count: 4,
                isActive: true,
                lastStruggle: new Date('2026-01-03T10:00:00.000Z'),
            },
            {
                topic: 'mitosis',
                count: 3,
                isActive: true,
                lastStruggle: new Date('2026-01-02T10:00:00.000Z'),
            },
        ]);

        await openDashboard(page);
        await expect(page.locator('#topics-list-container .topic-card')).toHaveCount(2, { timeout: 10_000 });

        await page.locator('.reset-btn[data-topic="photosynthesis"]').click();
        await expect(page.locator('#confirm-modal')).toBeVisible();
        await expect(page.locator('#dashboard-confirm-modal-title')).toHaveText('Reset "Photosynthesis"?');
        await expect(page.locator('#modal-confirm-btn')).toHaveText('I understand Photosynthesis now');
        await page.locator('#modal-confirm-btn').click();

        await expect(page.locator('#confirm-modal')).toBeHidden({ timeout: 10_000 });
        await expect(page.locator('#topics-list-container')).not.toContainText('Photosynthesis');
        await expect(page.locator('#topics-list-container')).toContainText('Mitosis');
        await expect(page.locator('#active-topics-count')).toHaveText('1');

        await expect.poll(async () => {
            const topics = await getStoredTopics();
            return topics.map((topic) => topic.topic).sort();
        }, { timeout: 10_000 }).toEqual(['mitosis']);

        const inactiveAudit = await withDb((db) =>
            db.collection('struggleActivity').findOne({
                userId: studentId,
                courseId: STU_COURSE_ID,
                topic: APPROVED_TOPIC.toLowerCase(),
                state: 'Inactive',
            })
        );
        expect(inactiveAudit).toBeTruthy();
    });

    test('reset all clears dashboard topics and returns the summary to inactive', async ({ page }) => {
        await seedStruggleTopics([
            {
                topic: APPROVED_TOPIC.toLowerCase(),
                count: 4,
                isActive: true,
                lastStruggle: new Date('2026-01-03T10:00:00.000Z'),
            },
            {
                topic: 'mitosis',
                count: 3,
                isActive: true,
                lastStruggle: new Date('2026-01-02T10:00:00.000Z'),
            },
        ]);

        await openDashboard(page);
        await expect(page.locator('#topics-list-container .topic-card')).toHaveCount(2, { timeout: 10_000 });

        await page.locator('#reset-all-btn').click();
        await expect(page.locator('#dashboard-confirm-modal-title')).toHaveText('Reset All Topics?');
        await expect(page.locator('#modal-confirm-btn')).toHaveText('Reset All');
        await page.locator('#modal-confirm-btn').click();

        await expect(page.locator('#topics-list-container')).toContainText(
            'No struggle topics recorded yet. Great job!',
            { timeout: 10_000 }
        );
        await expect(page.locator('#active-topics-count')).toHaveText('0');
        await expect(page.locator('#directive-mode-status')).toHaveText('Inactive');

        await expect.poll(getStoredTopics, { timeout: 10_000 }).toEqual([]);
    });

    test('revoked course access hides dashboard content and shows the disabled-access notice', async ({ page }) => {
        await seedStruggleTopics([
            {
                topic: APPROVED_TOPIC.toLowerCase(),
                count: 4,
                isActive: true,
                lastStruggle: new Date('2026-01-03T10:00:00.000Z'),
            },
        ]);
        await setEnrollment(STU_COURSE_ID, false);

        await openDashboard(page);

        await expect(page.locator('.dashboard-content')).toBeHidden({ timeout: 10_000 });
        await expect(page.locator('.main-content')).toContainText('Access disabled');
        await expect(page.locator('.main-content')).toContainText('Your access in this course is revoked.');
    });

    test('selected course context must not show struggle topics from another course', async ({ page }) => {
        await seedStruggleTopics([
            {
                topic: APPROVED_TOPIC.toLowerCase(),
                courseId: STU_COURSE_ID,
                count: 4,
                isActive: true,
                lastStruggle: new Date('2026-01-03T10:00:00.000Z'),
            },
        ]);

        await openDashboard(page, {
            courseId: STU_OTHER_COURSE_ID,
            courseName: OTHER_COURSE_NAME,
        });

        await expect(page.locator('.user-role')).toHaveText(`Student - ${OTHER_COURSE_NAME}`, {
            timeout: 10_000,
        });
        await expect(page.locator('#topics-list-container')).not.toContainText('Photosynthesis');
        await expect(page.locator('#active-topics-count')).toHaveText('0');
    });
});

test.describe('Student dashboard backing APIs', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetStudentChatData({ instructorId });
        await clearDashboardAuditData();
    });

    test('direct reset API must not reset struggle state for a revoked course', async ({ request: api }) => {
        await seedStruggleTopics([
            {
                topic: APPROVED_TOPIC.toLowerCase(),
                count: 4,
                isActive: true,
                lastStruggle: new Date('2026-01-03T10:00:00.000Z'),
            },
        ]);
        await setEnrollment(STU_COURSE_ID, false);

        const res = await api.post('/api/student/struggle/reset', {
            data: { topic: APPROVED_TOPIC, courseId: STU_COURSE_ID },
            failOnStatusCode: false,
        });

        expect(res.status()).toBe(403);
        const topics = await getStoredTopics();
        expect(topics.map((topic) => topic.topic)).toContain(APPROVED_TOPIC.toLowerCase());
    });
});
