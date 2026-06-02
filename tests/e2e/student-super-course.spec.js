// @ts-check
/**
 * Student-facing Super Course tests under the MULTIPLE-SUPERCHATS model.
 *
 * A "superchat" is an instructor-curated bucket of courses. A student sees a
 * bucket only if (a) it is `showToStudents: true` AND (b) they are enrolled in
 * >=1 of its courses (enrollment-derived visibility). All student endpoints are
 * scoped by `superchatId`.
 *
 * Covers:
 *   /api/student/super-course/status   (nav gate: >=1 accessible visible bucket)
 *   /api/student/super-course/list     (the picker)
 *   /api/student/super-course/pool     (?superchatId=)
 *   /api/student/super-course/chat     (body.superchatId)
 *   /api/student/super-course/sessions (?superchatId=)
 * plus the /student/super-course page (picker + redirect).
 */

require('dotenv').config();
const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, loadCredentials, storageStatePath } = require('./helpers/users');
const { resetLlmStub, enqueueLlmResponses, addLlmStubRule } = require('./helpers/llm-stub');
const {
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    setStudentEnrollment,
} = require('./helpers/courses-test');
const {
    seedSuperchat,
    cleanupSuperchats,
    cleanupSuperCourseSessions,
} = require('./helpers/superchats-test');

const PREFIX = 'BIOC-E2E-SC';
// Buckets
const BUCKET_VISIBLE = `${PREFIX}-VISIBLE`;     // showToStudents, student enrolled in a member
const BUCKET_HIDDEN = `${PREFIX}-HIDDEN`;       // student enrolled, but not student-visible
const BUCKET_NOACCESS = `${PREFIX}-NOACCESS`;   // visible, but student not enrolled in any member
const ALL_BUCKET_IDS = [BUCKET_VISIBLE, BUCKET_HIDDEN, BUCKET_NOACCESS];
// Courses
const C_OPTED_IN = `${PREFIX}-OPTED-IN`;        // active, in VISIBLE, student enrolled
const C_INACTIVE = `${PREFIX}-INACTIVE`;        // inactive, in VISIBLE
const C_HIDDEN = `${PREFIX}-HIDDEN-COURSE`;     // active, in HIDDEN bucket, student enrolled
const C_NOACCESS = `${PREFIX}-NOACCESS-COURSE`; // active, in NOACCESS bucket, student NOT enrolled
const ALL_COURSE_IDS = [C_OPTED_IN, C_INACTIVE, C_HIDDEN, C_NOACCESS];
const SESSION_IDS = ['e2e-sc-keep', 'e2e-sc-delete'];

let instructorId;
let studentId;
let studentPassword;

async function seedScenario({ visibleIncludesInactive = false } = {}) {
    await Promise.all([
        seedSuperchat({ superchatId: BUCKET_VISIBLE, name: '2nd Year Biochem', yearLevel: 2, showToStudents: true, overrides: { includeInactiveCourses: visibleIncludesInactive } }),
        seedSuperchat({ superchatId: BUCKET_HIDDEN, name: 'Hidden Bucket', yearLevel: 3, showToStudents: false }),
        seedSuperchat({ superchatId: BUCKET_NOACCESS, name: 'No-Access Bucket', yearLevel: 4, showToStudents: true }),
    ]);
    await Promise.all([
        seedCourse({
            courseId: C_OPTED_IN, instructorId, courseName: 'BIOC 202 Opted In',
            overrides: { yearLevel: 2, superchatIds: [BUCKET_VISIBLE] },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
        }),
        seedCourse({
            courseId: C_INACTIVE, instructorId, courseName: 'BIOC 250 Inactive', status: 'inactive',
            overrides: { yearLevel: 2, superchatIds: [BUCKET_VISIBLE] },
        }),
        seedCourse({
            courseId: C_HIDDEN, instructorId, courseName: 'BIOC 301 Hidden',
            overrides: { yearLevel: 3, superchatIds: [BUCKET_HIDDEN] },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
        }),
        seedCourse({
            courseId: C_NOACCESS, instructorId, courseName: 'BIOC 401 No Access',
            overrides: { yearLevel: 4, superchatIds: [BUCKET_NOACCESS] },
        }),
    ]);
}

async function cleanup() {
    await cleanupCourses(ALL_COURSE_IDS);
    await cleanupSuperchats(ALL_BUCKET_IDS);
    await cleanupSuperCourseSessions(SESSION_IDS);
}

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
    studentPassword = loadCredentials().student;
});

test.beforeEach(async () => {
    await seedScenario();
});

test.afterAll(async () => {
    await cleanup();
});

// ---------------------------------------------------------------------------
// Nav visibility + page gating (enrollment-derived)
// ---------------------------------------------------------------------------
test.describe('Super Course nav + page gating', () => {
    test.use({ storageState: storageStatePath('student') });

    test('nav item is visible when the student can access a visible bucket', async ({ page }) => {
        await page.goto('/student');
        await expect(page.locator('#super-course-nav-item')).toBeVisible({ timeout: 10_000 });
    });

    test('nav item is hidden when the student has no accessible visible bucket', async ({ page }) => {
        // Ban the student from the only visible+enrolled bucket's course. HIDDEN
        // is not student-visible and NOACCESS has no enrolled member, so nothing
        // remains accessible.
        await setStudentEnrollment(C_OPTED_IN, studentId, false);
        await page.goto('/student');
        await expect(page.locator('#super-course-nav-item')).toBeHidden({ timeout: 10_000 });
    });

    test('the page renders the picker and the selected bucket pool', async ({ page }) => {
        await page.goto('/student/super-course');
        const picker = page.locator('#superchat-picker');
        await expect(picker).toBeVisible({ timeout: 10_000 });
        // Only the visible+accessible bucket is offered.
        await expect(picker.locator('option')).toHaveCount(1);
        await expect(picker).toContainText('2nd Year Biochem');

        const poolList = page.locator('#super-course-pool-list');
        await expect(poolList).toContainText('BIOC 202 Opted In', { timeout: 10_000 });
        await expect(poolList).not.toContainText('BIOC 250 Inactive');
    });

    test('redirects back to /student when no bucket is accessible', async ({ page }) => {
        await setStudentEnrollment(C_OPTED_IN, studentId, false);
        await page.goto('/student/super-course');
        await page.waitForURL((url) => url.pathname === '/student' || url.pathname === '/student/', {
            timeout: 10_000,
        });
    });

    test('sends a chat message and renders the bot response', async ({ page, baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, ['ATP is the cell\'s energy currency.']);
        } finally {
            await api.dispose();
        }

        await page.goto('/student/super-course');
        await expect(page.locator('#super-course-pool-list')).toContainText('BIOC 202 Opted In', { timeout: 10_000 });

        await page.locator('#chat-input').fill('What is ATP?');
        await page.locator('#send-button').click();

        const messages = page.locator('#chat-messages .bot-message');
        await expect(messages.last()).toContainText("ATP is the cell's energy currency.", { timeout: 15_000 });
    });
});

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
test.describe('Super Course API', () => {
    test('/status is true when a visible bucket is accessible, false otherwise', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const onResp = await api.get('/api/student/super-course/status');
            expect(onResp.status()).toBe(200);
            expect(await onResp.json()).toMatchObject({ success: true, enabled: true });

            await setStudentEnrollment(C_OPTED_IN, studentId, false);
            const offResp = await api.get('/api/student/super-course/status');
            expect(await offResp.json()).toMatchObject({ success: true, enabled: false });
        } finally {
            await api.dispose();
        }
    });

    test('/list returns only visible buckets the student is enrolled into', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.get('/api/student/super-course/list');
            expect(resp.status()).toBe(200);
            const body = await resp.json();
            expect(body.success).toBe(true);
            const ids = body.superchats.map((s) => s.superchatId);
            expect(ids).toContain(BUCKET_VISIBLE);
            expect(ids).not.toContain(BUCKET_HIDDEN);   // not student-visible
            expect(ids).not.toContain(BUCKET_NOACCESS); // not enrolled in any member
        } finally {
            await api.dispose();
        }
    });

    test('/pool requires a superchatId', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.get('/api/student/super-course/pool', { failOnStatusCode: false });
            expect(resp.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('/pool is 404 for a hidden bucket and 403 for a bucket the student is not enrolled into', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const hidden = await api.get(`/api/student/super-course/pool?superchatId=${BUCKET_HIDDEN}`, { failOnStatusCode: false });
            expect(hidden.status()).toBe(404);

            const noAccess = await api.get(`/api/student/super-course/pool?superchatId=${BUCKET_NOACCESS}`, { failOnStatusCode: false });
            expect(noAccess.status()).toBe(403);
        } finally {
            await api.dispose();
        }
    });

    test('/pool returns only active member courses by default', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.get(`/api/student/super-course/pool?superchatId=${BUCKET_VISIBLE}`);
            expect(resp.status()).toBe(200);
            const body = await resp.json();
            expect(body.success).toBe(true);
            expect(body.superchatId).toBe(BUCKET_VISIBLE);
            const ids = (body.courses || []).map((c) => c.courseId);
            expect(ids).toContain(C_OPTED_IN);
            expect(ids).not.toContain(C_INACTIVE);
        } finally {
            await api.dispose();
        }
    });

    test('/pool includes inactive member courses when the bucket opts in', async ({ baseURL }) => {
        await seedScenario({ visibleIncludesInactive: true });
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.get(`/api/student/super-course/pool?superchatId=${BUCKET_VISIBLE}`);
            const body = await resp.json();
            const ids = (body.courses || []).map((c) => c.courseId);
            expect(ids).toContain(C_OPTED_IN);
            expect(ids).toContain(C_INACTIVE);
        } finally {
            await api.dispose();
        }
    });

    test('/chat rejects an empty message with 400', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.post('/api/student/super-course/chat', {
                data: { superchatId: BUCKET_VISIBLE, message: '   ' },
                failOnStatusCode: false,
            });
            expect(resp.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('/chat is 404 for a hidden bucket', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const resp = await api.post('/api/student/super-course/chat', {
                data: { superchatId: BUCKET_HIDDEN, message: 'hello' },
                failOnStatusCode: false,
            });
            expect(resp.status()).toBe(404);
        } finally {
            await api.dispose();
        }
    });

    test('/chat returns the stub answer and reports the bucket pool', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, ['Stubbed super-course answer for the student.']);

            const resp = await api.post('/api/student/super-course/chat', {
                data: { superchatId: BUCKET_VISIBLE, message: 'Explain glycolysis briefly.' },
            });
            expect(resp.status()).toBe(200);
            const body = await resp.json();
            expect(body.success).toBe(true);
            expect(body.message).toBe('Stubbed super-course answer for the student.');
            expect(Array.isArray(body.sourceAttribution.poolCourses)).toBe(true);
            const poolIds = body.sourceAttribution.poolCourses.map((c) => c.courseId);
            expect(poolIds).toContain(C_OPTED_IN);
        } finally {
            await api.dispose();
        }
    });

    test('/chat appends the selected answer-level modifier to the student prompt', async ({ baseURL }) => {
        await seedSuperchat({
            superchatId: BUCKET_VISIBLE, name: '2nd Year Biochem', yearLevel: 2, showToStudents: true,
            overrides: {
                studentLevelModifiers: {
                    intro: 'STUDENT-LEVEL-MARKER-INTRO',
                    undergraduate: 'STUDENT-LEVEL-MARKER-UNDERGRAD',
                    graduate: 'STUDENT-LEVEL-MARKER-GRADUATE',
                },
            },
        });

        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            await resetLlmStub(api);
            await addLlmStubRule(api, {
                matchSystemPrompt: 'STUDENT-LEVEL-MARKER-GRADUATE',
                content: 'GRADUATE-LEVEL-REPLY',
            });
            await enqueueLlmResponses(api, ['FALLBACK-REPLY', 'FALLBACK-REPLY']);

            const gradResp = await api.post('/api/student/super-course/chat', {
                data: { superchatId: BUCKET_VISIBLE, message: 'Explain glycolysis.', level: 'graduate' },
            });
            expect(gradResp.status()).toBe(200);
            expect((await gradResp.json()).message).toBe('GRADUATE-LEVEL-REPLY');

            const introResp = await api.post('/api/student/super-course/chat', {
                data: { superchatId: BUCKET_VISIBLE, message: 'Explain glycolysis.', level: 'intro' },
            });
            expect((await introResp.json()).message).toBe('FALLBACK-REPLY');
        } finally {
            await api.dispose();
        }
    });

    test('/sessions are scoped per bucket and hide deleted sessions', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL, storageState: storageStatePath('student') });
        try {
            const sessions = [
                {
                    superchatId: BUCKET_VISIBLE,
                    sessionId: 'e2e-sc-keep',
                    title: 'Super Course - ATP',
                    messageCount: 2,
                    duration: '5s',
                    savedAt: '2026-05-26T20:00:00.000Z',
                    chatData: {
                        metadata: { studentId, courseId: 'SUPER_COURSE', courseName: 'Super Course', totalMessages: 2 },
                        messages: [
                            { type: 'user', content: 'Explain ATP', timestamp: '2026-05-26T20:00:00.000Z' },
                            { type: 'bot', content: 'ATP carries cellular energy.', timestamp: '2026-05-26T20:00:05.000Z' },
                        ],
                        sessionInfo: { sessionId: 'e2e-sc-keep', duration: '5s' },
                    },
                },
                {
                    superchatId: BUCKET_VISIBLE,
                    sessionId: 'e2e-sc-delete',
                    title: 'Super Course - Delete',
                    messageCount: 1,
                    duration: '0s',
                    savedAt: '2026-05-26T20:05:00.000Z',
                    chatData: {
                        metadata: { studentId, courseId: 'SUPER_COURSE', courseName: 'Super Course', totalMessages: 1 },
                        messages: [{ type: 'user', content: 'Delete this', timestamp: '2026-05-26T20:05:00.000Z' }],
                        sessionInfo: { sessionId: 'e2e-sc-delete', duration: '0s' },
                    },
                },
            ];

            for (const session of sessions) {
                const save = await api.post('/api/student/super-course/save', { data: session });
                expect(save.status()).toBe(200);
                expect(await save.json()).toMatchObject({ success: true, data: { sessionId: session.sessionId, studentId } });
            }

            const listed = await api.get(`/api/student/super-course/sessions?superchatId=${BUCKET_VISIBLE}`);
            expect(listed.status()).toBe(200);
            const listedIds = (await listed.json()).data.sessions.map((s) => s.sessionId);
            expect(listedIds).toContain('e2e-sc-keep');
            expect(listedIds).toContain('e2e-sc-delete');

            const loaded = await api.get(`/api/student/super-course/sessions/e2e-sc-keep?superchatId=${BUCKET_VISIBLE}`);
            expect(loaded.status()).toBe(200);
            expect(await loaded.json()).toMatchObject({
                success: true,
                session: { sessionId: 'e2e-sc-keep', studentId, superchatId: BUCKET_VISIBLE, title: 'Super Course - ATP' },
            });

            const deleted = await api.delete(`/api/student/super-course/sessions/e2e-sc-delete?superchatId=${BUCKET_VISIBLE}`);
            expect(deleted.status()).toBe(200);

            const afterIds = (await (await api.get(`/api/student/super-course/sessions?superchatId=${BUCKET_VISIBLE}`)).json())
                .data.sessions.map((s) => s.sessionId);
            expect(afterIds).toContain('e2e-sc-keep');
            expect(afterIds).not.toContain('e2e-sc-delete');

            // History for a DIFFERENT (inaccessible) bucket must not leak these sessions.
            const otherBucket = await api.get(`/api/student/super-course/sessions?superchatId=${BUCKET_HIDDEN}`, { failOnStatusCode: false });
            expect(otherBucket.status()).toBe(404); // hidden bucket isn't accessible at all
        } finally {
            await api.dispose();
        }
    });
});
