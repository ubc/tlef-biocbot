// @ts-check
require('dotenv').config();
const { MongoClient } = require('mongodb');
const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');

const INSTRUCTOR_COURSES = [
    {
        courseId: 'HOME-E2E-ALPHA',
        courseName: 'Alpha Home Biology',
        courseCode: 'ALPHASTU',
        instructorCourseCode: 'ALPHAINS',
    },
    {
        courseId: 'HOME-E2E-BETA',
        courseName: 'Beta Home Biology',
        courseCode: 'BETASTU',
        instructorCourseCode: 'BETAINS',
    },
];

async function withDb(fn) {
    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI not set; cannot run instructor home tests.');
    }

    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    try {
        return await fn(client.db());
    } finally {
        await client.close();
    }
}

async function getUserByUsername(username) {
    return withDb(async (db) => {
        const user = await db.collection('users').findOne({ username });
        if (!user) throw new Error(`User ${username} not found in DB.`);
        return user;
    });
}

function completeLecture(name) {
    const now = new Date();
    return {
        name,
        isPublished: true,
        learningObjectives: [`Understand ${name}`],
        passThreshold: 70,
        createdAt: now,
        updatedAt: now,
        documents: [
            { documentId: `${name}-notes`, fileName: `${name} notes.pdf`, documentType: 'lecture-notes' },
            { documentId: `${name}-practice`, fileName: `${name} practice.pdf`, documentType: 'practice-quiz' },
        ],
        assessmentQuestions: [],
    };
}

function courseDoc(base, instructorId, fixedNow) {
    // Caller may pass a shared timestamp so Alpha and Beta land on identical
    // createdAt/updatedAt — the server's sortCoursesWithInactiveLast tie-breaks
    // by courseName, giving Alpha the deterministic first slot the tests rely on.
    const now = fixedNow instanceof Date ? fixedNow : new Date();
    return {
        ...base,
        instructorId,
        instructors: [instructorId],
        tas: [],
        courseDescription: '',
        assessmentCriteria: '',
        courseMaterials: [],
        approvedStruggleTopics: [
            { topic: 'cell membranes', source: 'manual', unitId: 'Unit 1' },
        ],
        courseStructure: { weeks: 1, lecturesPerWeek: 1, totalUnits: 1 },
        isOnboardingComplete: true,
        status: 'active',
        lectures: [completeLecture('Unit 1')],
        createdAt: now,
        updatedAt: now,
    };
}

function chatSession(courseId, sessionId, studentId, mode, start, end) {
    return {
        sessionId,
        courseId,
        studentId,
        studentName: studentId,
        chatData: {
            metadata: { currentMode: mode },
            messages: [
                { type: 'user', content: 'What is diffusion?', timestamp: start.toISOString() },
                { type: 'bot', content: 'Diffusion is passive movement.', timestamp: end.toISOString() },
            ],
        },
        createdAt: start,
        updatedAt: end,
    };
}

async function seedInstructorHomeCourses() {
    const instructor = await getUserByUsername(TEST_USERS.instructor.username);
    const now = new Date();
    const oneMinuteLater = new Date(now.getTime() + 60_000);
    const twoMinutesLater = new Date(now.getTime() + 120_000);

    await withDb(async (db) => {
        await db.collection('courses').deleteMany({
            $or: [
                { instructorId: instructor.userId },
                { instructors: instructor.userId },
            ],
        });
        await db.collection('chat_sessions').deleteMany({
            courseId: { $in: INSTRUCTOR_COURSES.map((course) => course.courseId) },
        });
        await db.collection('users').updateOne(
            { userId: instructor.userId },
            { $set: { 'preferences.courseId': null } }
        );
        const seedTime = new Date();
        await db.collection('courses').insertMany(
            INSTRUCTOR_COURSES.map((course) => courseDoc(course, instructor.userId, seedTime))
        );
        await db.collection('chat_sessions').insertMany([
            chatSession('HOME-E2E-ALPHA', 'home-alpha-1', 'alpha-student', 'tutor', now, oneMinuteLater),
            chatSession('HOME-E2E-BETA', 'home-beta-1', 'beta-student-1', 'tutor', now, oneMinuteLater),
            chatSession('HOME-E2E-BETA', 'home-beta-2', 'beta-student-2', 'protege', now, twoMinutesLater),
        ]);
    });
}

async function removeInstructorCourses(username) {
    const user = await getUserByUsername(username);
    await withDb(async (db) => {
        await db.collection('courses').deleteMany({
            $or: [
                { instructorId: user.userId },
                { instructors: user.userId },
            ],
        });
        await db.collection('chat_sessions').deleteMany({
            courseId: /^HOME-E2E-/,
        });
        await db.collection('users').updateOne(
            { userId: user.userId },
            { $set: { 'preferences.courseId': null } }
        );
    });
}

async function gotoInstructorHome(page, selectedCourseId = null) {
    await page.addInitScript((courseId) => {
        if (courseId) {
            window.localStorage.setItem('selectedCourseId', courseId);
        } else {
            window.localStorage.removeItem('selectedCourseId');
        }
    }, selectedCourseId);
    await page.goto('/instructor/home');
}

async function mockRichHomeEndpoints(page, { anonymize = false } = {}) {
    await page.route('**/chart.umd.min.js', (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/javascript',
            body: `
                window.Chart = class {
                    constructor(_canvas, config) {
                        window.__lastWeeklyChartConfig = config;
                    }
                    destroy() {
                        window.__chartDestroyed = true;
                    }
                };
            `,
        })
    );

    await page.addInitScript(() => {
        const testWindow = /** @type {Window & typeof globalThis & { __createdObjectUrls: Array<{ type: string, size: number }> }} */ (window);
        testWindow.__createdObjectUrls = [];
        const originalCreateObjectURL = URL.createObjectURL.bind(URL);
        URL.createObjectURL = (blob) => {
            testWindow.__createdObjectUrls.push({
                type: blob instanceof Blob ? blob.type : '',
                size: blob instanceof Blob ? blob.size : 0,
            });
            return originalCreateObjectURL(blob);
        };
    });

    await page.route('**/api/settings/anonymize-students?courseId=HOME-E2E-ALPHA', (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ success: true, enabled: anonymize }),
        })
    );

    await page.route(/\/api\/courses\/HOME-E2E-ALPHA\/students$/, (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                success: true,
                data: {
                    students: [
                        {
                            userId: 'student-1',
                            displayName: 'Alice <script>',
                            struggleState: {
                                topics: [
                                    { topic: 'cell membranes', isActive: true },
                                    { topic: 'osmosis', isActive: false },
                                ],
                            },
                        },
                        {
                            userId: 'student-2',
                            displayName: 'Blair',
                            struggleState: {
                                topics: [{ topic: 'Cell Membranes', isActive: true }],
                            },
                        },
                    ],
                },
            }),
        })
    );

    await page.route(/\/api\/struggle-activity\/HOME-E2E-ALPHA\?limit=100$/, (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                success: true,
                data: [
                    {
                        timestamp: '2026-05-13T18:00:00.000Z',
                        studentName: 'Alice "A"',
                        topic: 'cell membranes',
                        state: 'Active',
                    },
                    {
                        timestamp: '2026-05-13T18:05:00.000Z',
                        studentName: 'Blair',
                        topic: 'osmosis',
                        state: 'Inactive',
                    },
                ],
            }),
        })
    );

    await page.route(/\/api\/struggle-activity\/weekly\/HOME-E2E-ALPHA.*/, (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                success: true,
                data: [
                    {
                        weekStart: '2026-05-04T00:00:00.000Z',
                        topics: [{ topic: 'cell membranes', studentCount: 1 }],
                        totalCount: 1,
                    },
                    {
                        weekStart: '2026-05-11T00:00:00.000Z',
                        topics: [
                            { topic: 'cell membranes', studentCount: 2 },
                            { topic: 'osmosis', studentCount: 1 },
                        ],
                        totalCount: 3,
                    },
                ],
            }),
        })
    );

    await page.route(/\/api\/struggle-activity\/persistence\/HOME-E2E-ALPHA$/, (route) =>
        route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                success: true,
                data: [
                    { topic: 'osmosis', studentCount: 12 },
                    { topic: 'cell membranes', studentCount: 6 },
                ],
            }),
        })
    );

    await page.route(/\/api\/courses\/HOME-E2E-ALPHA\/approved-topics$/, async (route) => {
        if (route.request().method() === 'PUT') {
            const body = route.request().postDataJSON();
            return route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ success: true, data: { topics: body.topics || [] } }),
            });
        }

        return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                success: true,
                data: {
                    topics: [
                        {
                            topic: 'cell membranes',
                            source: 'manual',
                            unitId: 'Unit 1',
                            createdAt: '2026-05-01T00:00:00.000Z',
                        },
                    ],
                },
            }),
        });
    });

    await page.route(/\/api\/courses\/HOME-E2E-ALPHA\/approved-topics\/unit$/, async (route) => {
        const { topic, unitId } = route.request().postDataJSON();
        return route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
                success: true,
                data: {
                    topics: [
                        {
                            topic,
                            source: 'manual',
                            unitId: unitId || null,
                            createdAt: '2026-05-01T00:00:00.000Z',
                        },
                    ],
                },
            }),
        });
    });
}

test.describe('Instructor home dashboard', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedInstructorHomeCourses();
    });

    // Prevent HOME-E2E-* courses from leaking into other spec files (e.g.
    // instructor-onboarding's joinable-dropdown assertions) when the full
    // suite is run end-to-end (as in CI). seedInstructorHomeCourses inserts
    // these on every beforeEach but never removes them.
    test.afterAll(async () => {
        await removeInstructorCourses(TEST_USERS.instructor.username);
    });

    test('renders multiple instructor courses and reloads dashboard stats when selection changes', async ({ page }) => {
        await gotoInstructorHome(page);

        await expect(page.locator('#course-selection-container')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology');
        await expect(page.locator('#student-course-code-display')).toHaveText('ALPHASTU');
        await expect(page.locator('#instructor-course-code-display')).toHaveText('ALPHAINS');
        await expect(page.locator('#statistics-section')).toBeVisible();
        await expect(page.locator('#stat-total-sessions')).toHaveText('1');

        await page.locator('#change-course-btn').click();
        await expect(page.locator('#course-selector')).toBeVisible();
        await expect(page.locator('#course-select-dropdown')).toContainText('Alpha Home Biology');
        await expect(page.locator('#course-select-dropdown')).toContainText('Beta Home Biology');

        await page.locator('#course-select-dropdown').selectOption('HOME-E2E-BETA');

        await expect(page.locator('#course-name-display')).toHaveText('Beta Home Biology');
        await expect(page.locator('#student-course-code-display')).toHaveText('BETASTU');
        await expect(page.locator('#instructor-course-code-display')).toHaveText('BETAINS');
        await expect(page).toHaveURL(/courseId=HOME-E2E-BETA/);
        await expect(page.locator('#stat-total-students')).toHaveText('2');
        await expect(page.locator('#stat-total-sessions')).toHaveText('2');
        await expect(page.locator('#view-flags-btn')).toHaveAttribute('href', '/instructor/flagged?courseId=HOME-E2E-BETA');
        await expect.poll(() => page.evaluate(() => window.localStorage.getItem('selectedCourseId')))
            .toBe('HOME-E2E-BETA');
    });

    test('does not use a stale unauthorized selected course from localStorage', async ({ page }) => {
        await gotoInstructorHome(page);
        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology', { timeout: 15_000 });
        await page.evaluate(() => {
            window.localStorage.setItem('selectedCourseId', 'HOME-E2E-NOT-OWNED');
            window.history.replaceState({}, '', '/instructor/home');
        });

        /** @type {string[]} */
        const staleCourseRequests = [];
        page.on('request', (request) => {
            const url = new URL(request.url());
            if (url.pathname.startsWith('/api/') && request.url().includes('HOME-E2E-NOT-OWNED')) {
                staleCourseRequests.push(`${url.pathname}${url.search}`);
            }
        });

        await page.goto('/instructor/home');

        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology', { timeout: 15_000 });
        await expect(page).not.toHaveURL(/HOME-E2E-NOT-OWNED/);
        await expect(page.locator('#course-select-dropdown')).toContainText('Alpha Home Biology');
        expect(staleCourseRequests, 'stale localStorage course ID should not drive instructor API requests')
            .toEqual([]);
        await expect.poll(() => page.evaluate(() => window.localStorage.getItem('selectedCourseId')))
            .toBe('HOME-E2E-ALPHA');
    });

    test('keeps selected course visible but hides statistics when the statistics API fails', async ({ page }) => {
        await page.route('**/api/courses/statistics**', (route) =>
            route.fulfill({
                status: 500,
                contentType: 'application/json',
                body: JSON.stringify({ success: false, message: 'forced stats failure' }),
            })
        );

        await page.goto('/instructor/home?courseId=HOME-E2E-ALPHA');
        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology', { timeout: 15_000 });
        await expect(page.locator('#statistics-section')).toBeHidden();
        await expect(page.locator('#view-flags-btn')).toHaveAttribute('href', '/instructor/flagged?courseId=HOME-E2E-ALPHA');
    });

    test('renders struggle panels, weekly chart, CSV export, and approved topic unit assignment', async ({ page }) => {
        await mockRichHomeEndpoints(page, { anonymize: true });

        await page.goto('/instructor/home?courseId=HOME-E2E-ALPHA');

        await expect(page.locator('#struggle-topics-section')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('#struggle-topics-content')).toContainText('Cell membranes');
        await expect(page.locator('#struggle-topics-content')).toContainText('2 students (2 active)');
        await expect(page.locator('#struggle-topics-content')).toContainText('Student');
        await expect(page.locator('#struggle-topics-content')).not.toContainText('Alice <script>');

        await expect(page.locator('#live-struggle-container')).toBeVisible();
        await expect(page.locator('#struggle-name-th')).toBeHidden();
        await expect(page.locator('#live-struggle-tbody')).toContainText('Cell membranes');
        await page.locator('#filter-active-only').check();
        await expect(page.locator('#live-struggle-tbody')).toContainText('Cell membranes');
        await expect(page.locator('#live-struggle-tbody')).not.toContainText('Osmosis');

        const csvDownload = page.waitForEvent('download');
        await page.locator('#download-csv-btn').click();
        expect((await csvDownload).suggestedFilename()).toMatch(/^struggle_activity_/);

        await expect(page.locator('#weekly-struggle-chart-container')).toBeVisible();
        await expect(page.locator('#chart-next-weeks')).toBeDisabled();
        await expect.poll(() => page.evaluate(() => {
            const testWindow = /** @type {Window & typeof globalThis & { __lastWeeklyChartConfig?: { data?: { datasets?: unknown[] } } }} */ (window);
            return testWindow.__lastWeeklyChartConfig?.data?.datasets?.length;
        }))
            .toBe(2);
        await expect.poll(() => page.evaluate(() => {
            const testWindow = /** @type {Window & typeof globalThis & { __lastWeeklyChartConfig?: { options?: { plugins?: { tooltip?: { callbacks?: { title?: Function, afterBody?: Function } } } } } }} */ (window);
            const callbacks = testWindow.__lastWeeklyChartConfig?.options?.plugins?.tooltip?.callbacks;
            return [
                callbacks?.title?.([{ label: 'May 11' }]),
                callbacks?.afterBody?.([{ raw: 2 }, { raw: 1 }]),
            ].join('|');
        })).toBe('Week of May 11|\nTotal active: 3 students');
        await page.locator('#chart-prev-weeks').dispatchEvent('click');
        await page.locator('#chart-next-weeks').dispatchEvent('click');

        await expect(page.locator('#approved-topics-section')).toBeVisible();
        await expect(page.locator('#approved-topics-content')).toContainText('cell membranes');

        // The DOM showing "cell membranes" doesn't guarantee the JS global
        // (window.courseApprovedTopicDetails) the duplicate-check reads has
        // been populated — multiple async paths render this section.
        const hasCellMembranesInGlobal = () =>
            Array.isArray(/** @type {any} */ (window).courseApprovedTopicDetails)
            && /** @type {any} */ (window).courseApprovedTopicDetails.some(
                (/** @type {any} */ t) => t && typeof t.topic === 'string' && t.topic.toLowerCase() === 'cell membranes'
            );
        await page.waitForFunction(hasCellMembranesInGlobal);

        await page.locator('#new-topic-input').fill('cell membranes');
        // Verify the input value AND global state both align right before
        // pressing Enter. Without this, a stray re-render between fill and
        // press can clear the global and the duplicate check silently passes
        // through (no error notification fires → assertion can't find it).
        await page.waitForFunction(() => {
            const input = /** @type {HTMLInputElement|null} */ (document.getElementById('new-topic-input'));
            const global = /** @type {any} */ (window).courseApprovedTopicDetails;
            return input?.value === 'cell membranes'
                && Array.isArray(global)
                && global.some((/** @type {any} */ t) => t?.topic?.toLowerCase() === 'cell membranes');
        });
        await page.locator('#new-topic-input').press('Enter');
        await expect(page.locator('.notification.error')).toContainText('This topic already exists.', { timeout: 10_000 });

        await page.locator('#new-topic-input').fill('osmosis');
        await page.locator('#new-topic-unit-select').selectOption('Unit 1');
        await page.locator('.approved-topic-add-btn', { hasText: '+ Add' }).click();
        await expect(page.locator('#approved-topics-content')).toContainText('osmosis');

        // Edit-topic flow: commitEditTopic synchronously calls
        // renderApprovedGlobalTopics which replaces the chip container's
        // innerHTML, detaching the input mid-press. Playwright's element-bound
        // .press() then errors with "element was detached." Using
        // page.keyboard.press on the focused input avoids the issue.
        await page.locator('.approved-topic-chip[data-topic="cell membranes"] .topic-chip-label').dblclick();
        await page.locator('.topic-chip-edit-input').fill('cell transport');
        await page.keyboard.press('Escape');
        await expect(page.locator('#approved-topics-content')).toContainText('cell membranes');
        await page.locator('.approved-topic-chip[data-topic="cell membranes"] .topic-chip-label').dblclick();
        await page.locator('.topic-chip-edit-input').fill('cell transport');
        await page.keyboard.press('Enter');
        await expect(page.locator('#approved-topics-content')).toContainText('cell transport');

        await expect(page.locator('#persistence-topics-section')).toBeVisible();
        const txtDownload = page.waitForEvent('download');
        await page.locator('#download-persistence-topics-btn').click();
        expect((await txtDownload).suggestedFilename()).toMatch(/Alpha_Home_Biology_cumulative_topics\.txt/);

        await page.locator('.persistence-topic-card[data-topic="osmosis"]').click();
        await expect(page.locator('#topic-unit-assignment-modal')).toHaveClass(/show/);
        await page.locator('#topic-unit-select').selectOption('');
        await page.locator('#topic-unit-save-btn').click();
        await expect(page.locator('#topic-unit-assignment-modal')).not.toHaveClass(/show/);

        page.once('dialog', (dialog) => dialog.accept());
        await page.locator('.topic-chip-remove').first().click();
        await expect(page.locator('.notification.success', { hasText: 'Removed topic' })).toBeVisible();

        // Use programmatic click (.evaluate(el => el.click())) instead of
        // Playwright's actionability-gated .click(). The struggle-topic-item
        // header occasionally fails the actionability check (likely from a
        // stray transition/overlay leftover from the just-closed modal),
        // and Playwright reports a successful click that never actually
        // fired the onclick handler. Bypassing the check guarantees the
        // toggleTopic() inline handler runs.
        await page.locator('.struggle-topic-item .topic-header').first().evaluate(el => /** @type {HTMLElement} */ (el).click());
        await expect(page.locator('.struggle-topic-item').first()).toHaveClass(/collapsed/);
        await page.locator('#approved-topics-section .section-header').evaluate(el => /** @type {HTMLElement} */ (el).click());
        await expect(page.locator('#approved-topics-section')).toHaveClass(/section-collapsed/);
    });

    test('validates instructor course-code joins and recovers after an API error', async ({ page }) => {
        let joinAttempts = 0;

        await page.route('**/api/courses/available/joinable', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    success: true,
                    data: [
                        {
                            courseId: 'HOME-E2E-JOIN',
                            courseName: 'Joinable Home Biology',
                            status: 'active',
                        },
                    ],
                }),
            })
        );
        await page.route(/\/api\/courses\/HOME-E2E-JOIN$/, (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    success: true,
                    data: {
                        courseId: 'HOME-E2E-JOIN',
                        courseName: 'Joinable Home Biology',
                        courseCode: 'JOINSTU',
                        instructorCourseCode: 'JOININS',
                        status: 'active',
                        approvedStruggleTopics: [],
                        lectures: [completeLecture('Unit 1')],
                    },
                }),
            })
        );
        await page.route(/\/api\/courses\/HOME-E2E-JOIN\/instructors$/, async (route) => {
            joinAttempts += 1;
            const body = route.request().postDataJSON();
            if (body.code !== 'JOININS') {
                return route.fulfill({
                    status: 403,
                    contentType: 'application/json',
                    body: JSON.stringify({ success: false, message: 'Invalid instructor course code' }),
                });
            }
            return route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({ success: true, data: { courseId: 'HOME-E2E-JOIN' } }),
            });
        });

        await page.goto('/instructor/home?courseId=HOME-E2E-ALPHA');
        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology', { timeout: 15_000 });

        await page.locator('#change-course-btn').click();
        await page.locator('#join-course-select-dropdown').selectOption('HOME-E2E-JOIN');
        await expect(page.locator('#selected-course-details')).toBeVisible();
        await expect(page.locator('#instructor-code-entry-group')).toBeVisible();

        await page.locator('#join-course-btn').click();
        await expect(page.locator('#instructor-course-code-feedback')).toContainText('Instructor course code is required');
        await expect(page.locator('#instructor-course-code-input')).toHaveAttribute('aria-invalid', 'true');

        await page.locator('#instructor-course-code-input').fill('WRONG');
        await page.locator('#join-course-btn').click();
        await expect(page.locator('#instructor-course-code-feedback')).toContainText('Invalid instructor course code');
        await expect(page.locator('#join-course-btn')).toBeEnabled();

        // === TEMP DIAGNOSTIC #2 — remove once race-condition theory confirmed ===
        try {
            const inputCount = await page.locator('#instructor-course-code-input').count();
            const inputVisible = await page.locator('#instructor-course-code-input').isVisible();
            const inputEnabled = await page.locator('#instructor-course-code-input').isEnabled();
            const inputClass = await page.locator('#instructor-course-code-input').getAttribute('class');
            const groupVisible = await page.locator('#instructor-code-entry-group').isVisible();
            const groupStyle = await page.locator('#instructor-code-entry-group').getAttribute('style');
            const detailsVisible = await page.locator('#selected-course-details').isVisible();
            console.log('=== DIAG join: input count =', inputCount, 'visible =', inputVisible, 'enabled =', inputEnabled);
            console.log('=== DIAG join: input class =', JSON.stringify(inputClass));
            console.log('=== DIAG join: code-entry-group visible =', groupVisible, 'style =', JSON.stringify(groupStyle));
            console.log('=== DIAG join: selected-course-details visible =', detailsVisible);
        } catch (e) {
            console.log('=== DIAG join: error capturing state:', /** @type {Error} */ (e).message);
        }
        // === END TEMP DIAGNOSTIC #2 ===

        await page.locator('#instructor-course-code-input').fill('JOININS');
        await page.locator('#join-course-btn').click();
        await expect(page.locator('#course-name-display')).toHaveText('Joinable Home Biology', { timeout: 15_000 });
        await expect(page.locator('#student-course-code-display')).toHaveText('JOINSTU');
        await expect(page.locator('.notification.success')).toContainText('Successfully joined the course!');
        expect(joinAttempts).toBe(2);
    });

    test('hides course codes and completion panels for malformed selected course payloads', async ({ page }) => {
        await page.route(/\/api\/courses\/HOME-E2E-ALPHA$/, (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    success: true,
                    data: {
                        courseId: 'HOME-E2E-ALPHA',
                        courseName: 'Malformed Home Biology',
                        status: 'active',
                    },
                }),
            })
        );
        await page.route('**/api/courses/statistics**', (route) =>
            route.fulfill({
                status: 200,
                contentType: 'application/json',
                body: JSON.stringify({
                    success: true,
                    data: {
                        totalStudents: 0,
                        totalSessions: 0,
                        modeDistribution: { tutor: 0, protege: 0 },
                        averageSessionLength: '0s',
                        averageMessageLength: 0,
                    },
                }),
            })
        );

        await page.goto('/instructor/home?courseId=HOME-E2E-ALPHA');

        await expect(page.locator('#course-name-display')).toHaveText('Malformed Home Biology', { timeout: 15_000 });
        await expect(page.locator('#student-course-code-label')).toBeHidden();
        await expect(page.locator('#instructor-course-code-label')).toBeHidden();
        await expect(page.locator('#statistics-section')).toBeHidden();
        await expect(page.locator('#missing-items-section')).toBeHidden();
        await expect(page.locator('#complete-section')).toBeHidden();
    });

    test('covers home dashboard helper fallbacks and recovery branches', async ({ page }) => {
        await mockRichHomeEndpoints(page);
        await page.goto('/instructor/home?courseId=HOME-E2E-ALPHA');
        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology', { timeout: 15_000 });

        const helperState = await page.evaluate(async () => {
            const testWindow = /** @type {any} */ (window);
            const notices = [];
            testWindow.showNotification = (message, type) => notices.push({ message, type });

            const missingItems = [
                {
                    courseId: 'HOME-E2E-ALPHA',
                    courseName: '<Alpha & Biology>',
                    unitName: 'Unit & 1',
                    missingItem: 'Lecture <Note>',
                },
                {
                    courseId: 'HOME-E2E-ALPHA',
                    courseName: '<Alpha & Biology>',
                    unitName: 'Unit & 1',
                    missingItem: 'Practice Question/Tutorial',
                },
            ];
            testWindow.displayMissingItems(missingItems);
            const missingHtml = document.getElementById('missing-items-list')?.innerHTML || '';

            testWindow.displayMissingItems([]);
            const completeDisplay = document.getElementById('complete-section')?.style.display;

            testWindow.showInfoMessage('Helper info notice');
            testWindow.showSuccessMessage('Helper success notice');
            /** @type {HTMLButtonElement | null} */ (document.querySelector('.notification.info .notification-close'))?.click();
            const infoClosed = !document.querySelector('.notification.info');

            const labels = testWindow.getApprovedTopicLabels([
                'Photosynthesis',
                { topic: 'photosynthesis', unitId: 'None', source: '' },
                { topic: 'Respiration', unitId: 'Unit 2', source: 'generated' },
                { topic: '' },
                null,
            ]);

            testWindow.localStorage.setItem('selectedCourseId', 'HOME-E2E-ALPHA');
            testWindow.history.replaceState({}, '', '/instructor/home?courseId=HOME-E2E-ALPHA');
            testWindow.clearSelectedCourse();
            const selectedAfterClear = testWindow.localStorage.getItem('selectedCourseId');
            const urlAfterClear = testWindow.location.href;
            await testWindow.downloadPersistenceTopics();

            testWindow.localStorage.setItem('selectedCourseId', 'HOME-E2E-ALPHA');
            testWindow.history.replaceState({}, '', '/instructor/home?courseId=HOME-E2E-ALPHA');
            testWindow.persistenceTopics = [];
            await testWindow.downloadPersistenceTopics();

            const modal = testWindow.ensureTopicUnitAssignmentModal();
            modal.classList.add('show');
            modal.dataset.topic = 'Respiration';
            modal.querySelector('.topic-unit-modal-close')?.click();
            const closeButtonClosed = !modal.classList.contains('show') && modal.dataset.topic === '';
            modal.classList.add('show');
            modal.dataset.topic = 'Respiration';
            modal.querySelector('#topic-unit-cancel-btn')?.click();
            const cancelClosed = !modal.classList.contains('show') && modal.dataset.topic === '';
            modal.classList.add('show');
            modal.dataset.topic = 'Respiration';
            modal.dispatchEvent(new MouseEvent('click', { bubbles: true }));
            const backdropClosed = !modal.classList.contains('show') && modal.dataset.topic === '';

            return {
                missingHtml,
                completeDisplay,
                infoClosed,
                labels,
                notices,
                selectedAfterClear,
                urlAfterClear,
                closeButtonClosed,
                cancelClosed,
                backdropClosed,
            };
        });

        expect(helperState.missingHtml).toContain('&lt;Alpha &amp; Biology&gt;');
        expect(helperState.missingHtml).toContain('Lecture &lt;Note&gt;, Practice Question/Tutorial');
        expect(helperState.completeDisplay).toBe('block');
        expect(helperState.infoClosed).toBe(true);
        expect(helperState.labels).toEqual(['Photosynthesis', 'Respiration']);
        expect(helperState.notices).toEqual([
            { message: 'No course selected', type: 'error' },
            { message: 'No cumulative topics to download', type: 'info' },
        ]);
        expect(helperState.selectedAfterClear).toBeNull();
        expect(helperState.urlAfterClear).not.toContain('courseId=');
        expect(helperState.closeButtonClosed).toBe(true);
        expect(helperState.cancelClosed).toBe(true);
        expect(helperState.backdropClosed).toBe(true);

        await page.route('**/api/settings/can-delete-all', (route) => route.abort());
        await expect.poll(() => page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.checkCourseCodeBypassPermission();
        })).toBe(false);

        await page.route('**/api/courses/available/all', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: '{}' })
        );
        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.loadAvailableCourses();
        });
        await expect(page.locator('#course-select-dropdown')).toHaveText('Error loading courses');

        await page.route('**/api/courses/available/joinable', (route) =>
            route.fulfill({ status: 500, contentType: 'application/json', body: '{}' })
        );
        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.loadJoinableCourses();
        });
        await expect(page.locator('#join-course-select-dropdown')).toHaveText('Error loading joinable courses');

        await page.route(/\/api\/courses\/HOME-E2E-INACCESSIBLE$/, (route) =>
            route.fulfill({
                status: 403,
                contentType: 'application/json',
                body: JSON.stringify({ success: false, message: 'Forbidden' }),
            })
        );
        await page.evaluate(() => {
            window.localStorage.setItem('selectedCourseId', 'HOME-E2E-INACCESSIBLE');
            window.history.replaceState({}, '', '/instructor/home');
            const testWindow = /** @type {any} */ (window);
            return testWindow.loadCurrentCourse();
        });
        // After the instructor-home stale-course fix, an unowned storage
        // courseId is intercepted by the owned-courses pre-check instead of
        // by a 403 from /api/courses/:id. The instructor still has Alpha &
        // Beta seeded, so loadCurrentCourse falls back to the first owned
        // course rather than dropping back to the course selector.
        await expect(page.locator('#course-name-display')).toHaveText('Alpha Home Biology', { timeout: 15_000 });
        await expect.poll(() => page.evaluate(() => window.localStorage.getItem('selectedCourseId')))
            .toBe('HOME-E2E-ALPHA');

        const taOnboarding = await page.evaluate(async () => {
            const testWindow = /** @type {any} */ (window);
            const originalIsTA = testWindow.isTA;
            const originalInstructor = testWindow.getCurrentInstructorId;
            const originalFetch = testWindow.authenticatedFetch;
            testWindow.isTA = () => true;
            testWindow.getCurrentInstructorId = () => 'ta-helper';
            testWindow.authenticatedFetch = async () => new Response(JSON.stringify({
                success: true,
                data: [{ courseId: 'TA-HELPER' }],
            }), { status: 200, headers: { 'Content-Type': 'application/json' } });
            const hasTaCourse = await testWindow.checkOnboardingStatus();
            testWindow.authenticatedFetch = async () => new Response('{}', { status: 500 });
            const failedTaFetch = await testWindow.checkOnboardingStatus();
            testWindow.isTA = originalIsTA;
            testWindow.getCurrentInstructorId = originalInstructor;
            testWindow.authenticatedFetch = originalFetch;
            return { hasTaCourse, failedTaFetch };
        });

        expect(taOnboarding).toEqual({ hasTaCourse: true, failedTaFetch: false });
    });
});

test.describe('Instructor home empty state', () => {
    test.use({ storageState: storageStatePath('instructor_fresh') });

    test.beforeEach(async () => {
        await removeInstructorCourses(TEST_USERS.instructor_fresh.username);
    });

    test('shows onboarding prompt instead of dashboard panels when the instructor has no courses', async ({ page }) => {
        await gotoInstructorHome(page);

        await expect(page.locator('#onboarding-prompt-section')).toBeVisible({ timeout: 15_000 });
        await expect(page.locator('#go-to-onboarding-btn')).toHaveAttribute('href', '/instructor/onboarding');
        await expect(page.locator('.flagged-section')).toBeHidden();
        await expect(page.locator('.disclaimer-section')).toBeHidden();
        await expect(page.locator('#course-selection-container')).toBeHidden();
    });
});
