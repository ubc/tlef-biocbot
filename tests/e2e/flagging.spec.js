// @ts-check
/**
 * Flagging e2e tests.
 *
 * Covers the two parallel flag systems:
 *
 *   1. Student-flagged questions (FlaggedQuestion model + /api/flags).
 *      Students create flags on questions they think are wrong/unclear/etc.,
 *      instructors and TAs respond / dismiss / delete, students view their
 *      own flag history and the instructor's reply.
 *
 *   2. AI-detected mental health flags (MentalHealthFlag model +
 *      /api/mental-health-flags). Created by the chat pipeline (not exercised
 *      here — we seed flags directly). Instructors see them anonymized,
 *      can escalate or dismiss. Only system admins can resolve / disregard
 *      escalated flags and see student identities.
 *
 * The TA-side has its own dedicated coverage in ta.spec.js (permission
 * gating, audit trail). This file focuses on the instructor + student +
 * admin halves and the cross-role round-trips.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, loadCredentials, storageStatePath } = require('./helpers/users');
const { withDb, getUserIdByUsername } = require('./helpers/quiz');

const COURSE_ID = 'BIOC-E2E-FLAGS';
const COURSE_NAME = 'BIOC E2E Flagging';
const COURSE_CODE = 'FLAGSS';
const INSTRUCTOR_COURSE_CODE = 'FLAGSI';
// A second course the student is NOT enrolled in — used to prove
// cross-course isolation and to reject flag-creation against a course the
// student doesn't have access to.
const OTHER_COURSE_ID = 'BIOC-E2E-FLAGS-OTHER';
const OTHER_COURSE_NAME = 'BIOC E2E Flagging (Other Course)';
// A third course owned by an UNRELATED instructor (not our test instructor).
// Lets us prove that the test instructor should not see flags from courses
// they have nothing to do with.
const UNRELATED_COURSE_ID = 'BIOC-E2E-FLAGS-UNRELATED';
const UNRELATED_INSTRUCTOR_ID = 'user_e2e_unrelated_instructor_fixed';
const UNRELATED_INSTRUCTOR_USERNAME = 'e2e_unrelated_instructor';
const QUESTION_ID = 'q_e2e_flags_question';
const UNIT_NAME = 'Unit 1';
// Synthetic second student so we can prove /api/flags/my does not leak
// another student's flags.
const OTHER_STUDENT_ID = 'user_e2e_flagging_other_student_fixed';
const OTHER_STUDENT_USERNAME = 'e2e_other_flagging_student';

let instructorId;
let studentId;
let taId;
let studentPassword;
let instructorPassword;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
    taId = await getUserIdByUsername(TEST_USERS.ta.username);
    studentPassword = loadCredentials().student;
    instructorPassword = loadCredentials().instructor;
});

test.afterAll(async () => {
    await withDb(async (db) => {
        const courseIds = [COURSE_ID, OTHER_COURSE_ID, UNRELATED_COURSE_ID];
        await db.collection('courses').deleteMany({ courseId: { $in: courseIds } });
        await db.collection('flaggedQuestions').deleteMany({ courseId: { $in: courseIds } });
        await db.collection('mentalHealthFlags').deleteMany({ courseId: { $in: courseIds } });
        await db.collection('users').deleteMany({
            userId: { $in: [OTHER_STUDENT_ID, UNRELATED_INSTRUCTOR_ID] },
        });
        await db.collection('users').updateOne(
            { userId: instructorId },
            { $unset: { 'permissions.systemAdmin': '' } }
        );
    });
});

/**
 * Idempotent course seed for flagging tests.
 *
 * - Student is always enrolled so /api/flags POST (gated by
 *   requireStudentEnrolled) succeeds.
 * - Instructor is the course owner; never a TA, since TA flag behavior is
 *   covered exhaustively in ta.spec.js.
 * - Synthetic OTHER student is enrolled too so we can seed a flag owned by
 *   them and assert it does not leak into the real student's /my listing.
 */
async function resetCourse({ status = 'active' } = {}) {
    await withDb(async (db) => {
        const courseIds = [COURSE_ID, OTHER_COURSE_ID, UNRELATED_COURSE_ID];
        await db.collection('courses').deleteMany({ courseId: { $in: courseIds } });
        await db.collection('flaggedQuestions').deleteMany({ courseId: { $in: courseIds } });
        await db.collection('mentalHealthFlags').deleteMany({ courseId: { $in: courseIds } });

        // Make sure the instructor isn't lingering as a system admin from a
        // prior failed test — admin-only assertions opt in explicitly.
        await db.collection('users').updateOne(
            { userId: instructorId },
            { $unset: { 'permissions.systemAdmin': '' } }
        );

        // Synthetic "other student" — fixed userId so seeded flags are
        // predictable across runs.
        await db.collection('users').deleteMany({ userId: OTHER_STUDENT_ID });
        await db.collection('users').insertOne({
            userId: OTHER_STUDENT_ID,
            username: OTHER_STUDENT_USERNAME,
            email: 'e2e-other-flagging@test.local',
            role: 'student',
            displayName: 'E2E Other Flagging Student',
            authProvider: 'local',
            createdAt: new Date(),
            updatedAt: new Date(),
        });

        const now = new Date();
        const studentEnrollment = {
            [studentId]: { enrolled: true, enrolledAt: now },
            [OTHER_STUDENT_ID]: { enrolled: true, enrolledAt: now },
        };

        await db.collection('courses').insertOne({
            courseId: COURSE_ID,
            courseName: COURSE_NAME,
            courseCode: COURSE_CODE,
            instructorCourseCode: INSTRUCTOR_COURSE_CODE,
            instructorId,
            instructors: [instructorId],
            tas: [],
            courseDescription: '',
            assessmentCriteria: '',
            courseMaterials: [],
            approvedStruggleTopics: [],
            courseStructure: { weeks: 1, lecturesPerWeek: 1, totalUnits: 1 },
            isOnboardingComplete: true,
            status,
            studentEnrollment,
            lectures: [
                {
                    name: UNIT_NAME,
                    displayName: UNIT_NAME,
                    isPublished: true,
                    learningObjectives: [],
                    passThreshold: 0,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        {
                            questionId: QUESTION_ID,
                            questionType: 'true-false',
                            question: 'A peptide bond joins two amino acids.',
                            correctAnswer: 'true',
                            difficulty: 'easy',
                            points: 1,
                            isActive: true,
                        },
                    ],
                },
            ],
            createdAt: now,
            updatedAt: now,
        });
    });
}

/**
 * Seed a second course. The real student is intentionally NOT enrolled so we
 * can prove cross-course isolation and that a student cannot flag a course
 * they have no access to.
 */
async function seedOtherCourse() {
    await withDb(async (db) => {
        await db.collection('courses').deleteMany({ courseId: OTHER_COURSE_ID });
        const now = new Date();
        await db.collection('courses').insertOne({
            courseId: OTHER_COURSE_ID,
            courseName: OTHER_COURSE_NAME,
            courseCode: `${OTHER_COURSE_ID}-S`,
            instructorCourseCode: `${OTHER_COURSE_ID}-I`,
            instructorId,
            instructors: [instructorId],
            tas: [],
            courseDescription: '',
            assessmentCriteria: '',
            courseMaterials: [],
            approvedStruggleTopics: [],
            courseStructure: { weeks: 1, lecturesPerWeek: 1, totalUnits: 1 },
            isOnboardingComplete: true,
            status: 'active',
            // No studentEnrollment entry for the real student — that's the
            // whole point of this course.
            studentEnrollment: {},
            lectures: [
                {
                    name: UNIT_NAME,
                    displayName: UNIT_NAME,
                    isPublished: true,
                    learningObjectives: [],
                    passThreshold: 0,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        {
                            questionId: 'q_e2e_flags_other_question',
                            questionType: 'true-false',
                            question: 'Cell membranes are made primarily of phospholipids.',
                            correctAnswer: 'true',
                            difficulty: 'easy',
                            points: 1,
                            isActive: true,
                        },
                    ],
                },
            ],
            createdAt: now,
            updatedAt: now,
        });
    });
}

/**
 * Seed a third course owned by an UNRELATED instructor. The test instructor
 * is not in `instructors`, not the `instructorId`, and not a TA. Used to
 * prove that cross-instructor scoping is enforced on read endpoints.
 */
async function seedUnrelatedCourse() {
    await withDb(async (db) => {
        await db.collection('courses').deleteMany({ courseId: UNRELATED_COURSE_ID });
        await db.collection('users').deleteMany({ userId: UNRELATED_INSTRUCTOR_ID });
        const now = new Date();
        await db.collection('users').insertOne({
            userId: UNRELATED_INSTRUCTOR_ID,
            username: UNRELATED_INSTRUCTOR_USERNAME,
            email: 'e2e-unrelated-instructor@test.local',
            role: 'instructor',
            displayName: 'E2E Unrelated Instructor',
            authProvider: 'local',
            createdAt: now,
            updatedAt: now,
        });
        await db.collection('courses').insertOne({
            courseId: UNRELATED_COURSE_ID,
            courseName: 'BIOC E2E Flagging (Unrelated)',
            courseCode: `${UNRELATED_COURSE_ID}-S`,
            instructorCourseCode: `${UNRELATED_COURSE_ID}-I`,
            instructorId: UNRELATED_INSTRUCTOR_ID,
            instructors: [UNRELATED_INSTRUCTOR_ID],
            tas: [],
            studentEnrollment: {},
            status: 'active',
            isOnboardingComplete: true,
            lectures: [{
                name: UNIT_NAME,
                displayName: UNIT_NAME,
                isPublished: true,
                learningObjectives: [],
                passThreshold: 0,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
            createdAt: now,
            updatedAt: now,
        });
    });
}

/**
 * Insert a flag directly without going through POST /api/flags. Lets read-path
 * and moderation tests skip the create-flow plumbing.
 *
 * @param {{
 *   flagId?: string,
 *   courseId?: string,
 *   studentIdForFlag?: string,
 *   studentName?: string,
 *   flagReason?: string,
 *   flagDescription?: string,
 *   flagStatus?: string,
 *   botMode?: string,
 *   instructorResponse?: string | null,
 *   instructorIdForFlag?: string | null,
 *   instructorName?: string | null,
 *   createdAt?: Date,
 * }} [opts]
 */
async function seedFlag({
    flagId,
    courseId = COURSE_ID,
    studentIdForFlag = studentId,
    studentName = TEST_USERS.student.displayName,
    flagReason = 'unclear',
    flagDescription = 'Seeded flagging spec flag',
    flagStatus = 'pending',
    botMode = 'tutor',
    instructorResponse = null,
    instructorIdForFlag = null,
    instructorName = null,
    createdAt = new Date(),
} = {}) {
    const id = flagId || `e2e-flag-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    await withDb(async (db) => {
        await db.collection('flaggedQuestions').insertOne({
            flagId: id,
            questionId: QUESTION_ID,
            courseId,
            unitName: UNIT_NAME,
            studentId: studentIdForFlag,
            studentName,
            flagReason,
            flagDescription,
            botMode,
            flagStatus,
            instructorResponse,
            instructorId: instructorIdForFlag,
            instructorName,
            priority: flagReason === 'incorrect' || flagReason === 'inappropriate' ? 'high' : 'medium',
            questionContent: {
                question: 'A peptide bond joins two amino acids.',
                questionType: 'true-false',
            },
            createdAt,
            updatedAt: createdAt,
        });
    });
    return id;
}

/**
 * @param {{
 *   flagId?: string,
 *   studentIdForFlag?: string,
 *   studentName?: string,
 *   concernLevel?: string,
 *   message?: string,
 *   llmReason?: string,
 *   status?: string,
 *   createdAt?: Date,
 * }} [opts]
 */
async function seedMentalHealthFlag({
    flagId,
    studentIdForFlag = studentId,
    studentName = TEST_USERS.student.displayName,
    concernLevel = 'low concern',
    message = 'I feel overwhelmed by this class.',
    llmReason = 'Student expressed feeling overwhelmed.',
    status = 'pending',
    createdAt = new Date(),
} = {}) {
    const id = flagId || `mhf_e2e_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await withDb(async (db) => {
        await db.collection('mentalHealthFlags').insertOne({
            flagId: id,
            studentId: studentIdForFlag,
            studentName,
            courseId: COURSE_ID,
            unitName: UNIT_NAME,
            message,
            conversationContext: [
                { role: 'user', content: message },
                { role: 'assistant', content: 'I hear you. Have you considered reaching out to the wellness center?' },
            ],
            concernLevel,
            llmReason,
            status,
            escalatedBy: null,
            escalatedAt: null,
            resolvedBy: null,
            resolvedAt: null,
            createdAt,
            updatedAt: createdAt,
        });
    });
    return id;
}

async function setSystemAdmin(userId, isAdmin) {
    await withDb(async (db) => {
        if (isAdmin) {
            await db.collection('users').updateOne(
                { userId },
                { $set: { 'permissions.systemAdmin': true, updatedAt: new Date() } }
            );
        } else {
            await db.collection('users').updateOne(
                { userId },
                { $unset: { 'permissions.systemAdmin': '' }, $set: { updatedAt: new Date() } }
            );
        }
    });
}

async function loginAPI(baseURL, role, password) {
    const apiCtx = await request.newContext({ baseURL });
    const res = await apiCtx.post('/api/auth/login', {
        data: { username: TEST_USERS[role].username, password },
    });
    expect(res.ok()).toBeTruthy();
    return apiCtx;
}

async function loginViaUI(page, role, password) {
    await page.goto('/');
    await page.locator('#auth-form input#username').fill(TEST_USERS[role].username);
    await page.locator('#auth-form input#password').fill(password);
    await page.locator('#auth-form button#login-btn').click();
    await page.waitForURL((url) => url.pathname !== '/' && url.pathname !== '/login', {
        timeout: 10_000,
    });
}

// ============================================================================
// Student-side flag creation — POST /api/flags
// ============================================================================
test.describe('Student creates a flag — POST /api/flags', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetCourse();
    });

    test('happy path: creates a pending flag with the right priority and student attribution', async ({ request: api }) => {
        const res = await api.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'incorrect',
                flagDescription: 'The textbook says this is false.',
                botMode: 'tutor',
                questionContent: {
                    question: 'A peptide bond joins two amino acids.',
                    questionType: 'true-false',
                },
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.flagId).toMatch(/^flag_/);

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId: body.data.flagId })
        );
        expect(stored).toBeTruthy();
        expect(stored.studentId).toBe(studentId);
        expect(stored.studentName).toBe(TEST_USERS.student.displayName);
        expect(stored.flagStatus).toBe('pending');
        expect(stored.priority).toBe('high'); // "incorrect" maps to high
        expect(stored.botMode).toBe('tutor');
        expect(stored.courseId).toBe(COURSE_ID);
    });

    test('400 when required fields are missing', async ({ request: api }) => {
        const res = await api.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                // missing unitName, flagReason, flagDescription
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);

        const count = await withDb((db) =>
            db.collection('flaggedQuestions').countDocuments({ courseId: COURSE_ID })
        );
        expect(count).toBe(0);
    });

    test('400 when botMode is not "protege" or "tutor"', async ({ request: api }) => {
        const res = await api.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'Confused.',
                botMode: 'godmode',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);

        const count = await withDb((db) =>
            db.collection('flaggedQuestions').countDocuments({ courseId: COURSE_ID })
        );
        expect(count).toBe(0);
    });

    test('botMode defaults to "tutor" when omitted (backward compatibility)', async ({ request: api }) => {
        const res = await api.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'No bot mode supplied.',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId: body.data.flagId })
        );
        expect(stored.botMode).toBe('tutor');
    });

    test('403 when posting against a deactivated course', async ({ request: api }) => {
        await resetCourse({ status: 'inactive' });

        const res = await api.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'Should be blocked.',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(403);

        const count = await withDb((db) =>
            db.collection('flaggedQuestions').countDocuments({ courseId: COURSE_ID })
        );
        expect(count).toBe(0);
    });
});

test.describe('Student creates a flag — unauthenticated and wrong role', () => {
    test('401/302 when no session is present', async ({ baseURL }) => {
        await resetCourse();
        const anonCtx = await request.newContext({ baseURL });
        const res = await anonCtx.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'Anonymous attempt.',
            },
            failOnStatusCode: false,
            maxRedirects: 0,
        });
        // requireAuth issues 401 JSON for API paths (req.path starts with /api/)
        // or a 302 redirect when mount-relative path-matching falls through.
        expect([401, 302]).toContain(res.status());
        const count = await withDb((db) =>
            db.collection('flaggedQuestions').countDocuments({ courseId: COURSE_ID })
        );
        expect(count).toBe(0);
        await anonCtx.dispose();
    });

    test('403 when an instructor tries to create a flag', async ({ baseURL }) => {
        await resetCourse();
        const apiCtx = await loginAPI(baseURL, 'instructor', instructorPassword);
        const res = await apiCtx.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'Instructor cannot flag.',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(403);

        const count = await withDb((db) =>
            db.collection('flaggedQuestions').countDocuments({ courseId: COURSE_ID })
        );
        expect(count).toBe(0);
        await apiCtx.dispose();
    });
});

// ============================================================================
// Student views their own flags — GET /api/flags/my
// ============================================================================
test.describe('Student views their flags — GET /api/flags/my', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetCourse();
    });

    test('returns only the authenticated student\'s flags, not another student\'s', async ({ request: api }) => {
        const myFlagId = await seedFlag({ flagDescription: 'My flag' });
        await seedFlag({
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagDescription: 'Someone else\'s flag',
        });

        const res = await api.get('/api/flags/my');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.count).toBe(1);
        expect(body.data.flags).toHaveLength(1);
        expect(body.data.flags[0].flagId).toBe(myFlagId);
        expect(body.data.flags[0].studentId).toBe(studentId);
    });

    test('courseId query parameter scopes the listing to that course', async ({ request: api }) => {
        const id = await seedFlag({ flagDescription: 'In-course flag' });

        // With the matching courseId we get our flag back.
        const matching = await api.get(`/api/flags/my?courseId=${COURSE_ID}`);
        expect(matching.ok()).toBeTruthy();
        const matchingBody = await matching.json();
        expect(matchingBody.data.count).toBe(1);
        expect(matchingBody.data.flags[0].flagId).toBe(id);
        expect(matchingBody.data.flags[0].courseId).toBe(COURSE_ID);

        // Without any courseId the same flag is returned (no filter).
        const all = await api.get('/api/flags/my');
        const allBody = await all.json();
        expect(allBody.data.flags.find((f) => f.flagId === id)).toBeTruthy();
    });

    test('DESIRED: direct /my access does not return flags from courses where the student is not enrolled', async ({ request: api }) => {
        const enrolledFlagId = await seedFlag({
            flagId: 'e2e-my-enrolled-course',
            flagDescription: 'Visible enrolled-course flag',
        });

        await seedOtherCourse();
        const unEnrolledFlagId = await seedFlag({
            flagId: 'e2e-my-unenrolled-course',
            courseId: OTHER_COURSE_ID,
            flagDescription: 'Must not leak from an un-enrolled course',
        });

        const all = await api.get('/api/flags/my');
        expect(all.ok()).toBeTruthy();
        const allBody = await all.json();
        const allIds = allBody.data.flags.map((f) => f.flagId);

        expect(allIds).toContain(enrolledFlagId);
        expect(allIds).not.toContain(unEnrolledFlagId);

        const scoped = await api.get(`/api/flags/my?courseId=${OTHER_COURSE_ID}`, {
            failOnStatusCode: false,
        });
        if (scoped.ok()) {
            const scopedBody = await scoped.json();
            expect(scopedBody.data.flags.map((f) => f.flagId)).not.toContain(unEnrolledFlagId);
        } else {
            expect([403, 404]).toContain(scoped.status());
        }
    });

    test('includes the instructor response once the flag is resolved', async ({ request: api }) => {
        const flagId = await seedFlag({
            flagStatus: 'resolved',
            instructorResponse: 'Thanks for the catch — we corrected it.',
            instructorIdForFlag: instructorId,
            instructorName: TEST_USERS.instructor.displayName,
        });

        const res = await api.get('/api/flags/my');
        const body = await res.json();
        const flag = body.data.flags.find((f) => f.flagId === flagId);
        expect(flag).toBeTruthy();
        expect(flag.flagStatus).toBe('resolved');
        expect(flag.instructorResponse).toContain('Thanks for the catch');
        expect(flag.instructorName).toBe(TEST_USERS.instructor.displayName);
    });
});

test.describe('Student views their flags — unauthenticated and wrong role', () => {
    test('401/302 when no session is present', async ({ baseURL }) => {
        await resetCourse();
        const anonCtx = await request.newContext({ baseURL });
        const res = await anonCtx.get('/api/flags/my', {
            failOnStatusCode: false,
            maxRedirects: 0,
        });
        expect([401, 302]).toContain(res.status());
        await anonCtx.dispose();
    });

    test('403 when an instructor calls GET /my', async ({ baseURL }) => {
        await resetCourse();
        const apiCtx = await loginAPI(baseURL, 'instructor', instructorPassword);
        const res = await apiCtx.get('/api/flags/my', { failOnStatusCode: false });
        expect(res.status()).toBe(403);
        await apiCtx.dispose();
    });
});

// ============================================================================
// Student flagged page UI
// ============================================================================
test.describe('Student flagged page UI', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetCourse();
    });

    test('shows the student\'s own flags and the instructor response when resolved', async ({ page, context }) => {
        const flagId = await seedFlag({
            flagStatus: 'resolved',
            flagDescription: 'I think the answer key has this backwards.',
            instructorResponse: 'You are right, fixed in the next release.',
            instructorIdForFlag: instructorId,
            instructorName: TEST_USERS.instructor.displayName,
        });
        // Seed an "other student" flag too — page must not show it.
        await seedFlag({
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagDescription: 'Should not appear for the real student.',
        });

        // The page reads `selectedCourseId` from localStorage on DOMContentLoaded
        // and shows an error placeholder if it's missing. Seed it before the
        // first navigation so loadStudentFlags() runs against the right course.
        await context.addInitScript((courseId) => {
            try { localStorage.setItem('selectedCourseId', courseId); } catch (e) {}
        }, COURSE_ID);

        await page.goto('/student/flagged');

        const list = page.locator('#flagged-list');
        await expect(list).toContainText('I think the answer key has this backwards.', { timeout: 15_000 });
        await expect(list).toContainText('You are right, fixed in the next release.');
        await expect(list).toContainText(TEST_USERS.instructor.displayName);

        await expect(list).not.toContainText('Should not appear for the real student.');

        await expect(list.locator('.flag-card')).toHaveCount(1);

        const remaining = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(remaining.studentId).toBe(studentId);
    });
});

// ============================================================================
// Instructor flag listings, stats, and lookup
// ============================================================================
test.describe('Instructor reads flags — GET /api/flags/course, /stats, /status, /:flagId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
    });

    test('GET /course/:courseId returns every flag for the course (newest first)', async ({ request: api }) => {
        const older = await seedFlag({
            flagId: 'e2e-flag-older',
            flagDescription: 'Older flag',
            createdAt: new Date(Date.now() - 60_000),
        });
        const newer = await seedFlag({
            flagId: 'e2e-flag-newer',
            flagDescription: 'Newer flag',
            createdAt: new Date(),
        });

        const res = await api.get(`/api/flags/course/${COURSE_ID}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.courseId).toBe(COURSE_ID);
        expect(body.data.count).toBe(2);
        expect(body.data.flags.map((f) => f.flagId)).toEqual([newer, older]);
    });

    test('GET /course/:courseId?status=pending filters by flag status', async ({ request: api }) => {
        await seedFlag({ flagId: 'e2e-flag-p', flagStatus: 'pending' });
        await seedFlag({ flagId: 'e2e-flag-r', flagStatus: 'resolved' });
        await seedFlag({ flagId: 'e2e-flag-d', flagStatus: 'dismissed' });

        const res = await api.get(`/api/flags/course/${COURSE_ID}?status=pending`);
        const body = await res.json();
        const ids = body.data.flags.map((f) => f.flagId);
        expect(ids).toEqual(['e2e-flag-p']);
    });

    test('GET /stats/:courseId aggregates counts by status', async ({ request: api }) => {
        await seedFlag({ flagId: 'e2e-flag-s1', flagStatus: 'pending' });
        await seedFlag({ flagId: 'e2e-flag-s2', flagStatus: 'pending' });
        await seedFlag({ flagId: 'e2e-flag-s3', flagStatus: 'resolved' });
        await seedFlag({ flagId: 'e2e-flag-s4', flagStatus: 'dismissed' });

        const res = await api.get(`/api/flags/stats/${COURSE_ID}`);
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.statistics).toMatchObject({
            total: 4,
            pending: 2,
            resolved: 1,
            dismissed: 1,
        });
    });

    test('GET /:flagId returns the full flag document', async ({ request: api }) => {
        const flagId = await seedFlag({ flagDescription: 'Lookup target' });

        const res = await api.get(`/api/flags/${flagId}`);
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.flagId).toBe(flagId);
        expect(body.data.flagDescription).toBe('Lookup target');
    });

    test('GET /:flagId returns 404 for an unknown flag id', async ({ request: api }) => {
        const res = await api.get('/api/flags/flag_does_not_exist', { failOnStatusCode: false });
        expect(res.status()).toBe(404);
    });
});

// ============================================================================
// Instructor moderation — response, dismissal, deletion
// ============================================================================
test.describe('Instructor moderates flags — PUT /response, PUT /status, DELETE', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
    });

    test('PUT /:flagId/response records the response, instructor identity, and resolved status', async ({ request: api }) => {
        const flagId = await seedFlag({ flagDescription: 'Needs an instructor reply' });

        const res = await api.put(`/api/flags/${flagId}/response`, {
            data: {
                response: 'Looked into it — answer key was right.',
                flagStatus: 'resolved',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.instructorResponse).toBe('Looked into it — answer key was right.');
        expect(stored.instructorId).toBe(instructorId);
        expect(stored.instructorName).toBe(TEST_USERS.instructor.displayName);
        expect(stored.flagStatus).toBe('resolved');
        expect(stored.resolvedAt).toBeTruthy();
    });

    test('PUT /:flagId/response with no response body returns 400', async ({ request: api }) => {
        const flagId = await seedFlag();

        const res = await api.put(`/api/flags/${flagId}/response`, {
            data: { flagStatus: 'resolved' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.flagStatus).toBe('pending');
        expect(stored.instructorResponse).toBeFalsy();
    });

    test('PUT /:flagId/status transitions a pending flag to dismissed', async ({ request: api }) => {
        const flagId = await seedFlag();

        const res = await api.put(`/api/flags/${flagId}/status`, {
            data: { status: 'dismissed' },
        });
        expect(res.ok()).toBeTruthy();

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.flagStatus).toBe('dismissed');
    });

    test('DELETE /:flagId removes the flag entirely', async ({ request: api }) => {
        const flagId = await seedFlag();

        const res = await api.delete(`/api/flags/${flagId}`);
        expect(res.ok()).toBeTruthy();

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored).toBeNull();
    });
});

test.describe('Instructor moderation — wrong role and unauthenticated', () => {
    test.beforeEach(async () => {
        await resetCourse();
    });

    test('PUT /:flagId/response by a student returns 403', async ({ baseURL }) => {
        const flagId = await seedFlag();
        const apiCtx = await loginAPI(baseURL, 'student', studentPassword);

        const res = await apiCtx.put(`/api/flags/${flagId}/response`, {
            data: { response: 'Student should not be able to respond.', flagStatus: 'resolved' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(403);

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.flagStatus).toBe('pending');
        expect(stored.instructorResponse).toBeFalsy();
        await apiCtx.dispose();
    });

    test('PUT /:flagId/status by an anonymous caller is rejected and does not mutate', async ({ baseURL }) => {
        const flagId = await seedFlag();
        const anonCtx = await request.newContext({ baseURL });

        const res = await anonCtx.put(`/api/flags/${flagId}/status`, {
            data: { status: 'dismissed' },
            failOnStatusCode: false,
        });
        // Any non-2xx response is acceptable here (401 JSON, 302 redirect, or
        // a downstream 404 when the auth redirect path is followed). The key
        // assertion is that the flag is NOT mutated.
        expect(res.ok()).toBe(false);

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.flagStatus).toBe('pending');
        await anonCtx.dispose();
    });
});

// ============================================================================
// Instructor flagged page UI — round-trip
// ============================================================================
test.describe('Instructor flagged page UI — student-flagged questions', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
    });

    test('instructor sees pending flag, can dismiss it, and the dismissal persists', async ({ page }) => {
        const flagId = await seedFlag({ flagDescription: 'UI dismissal target' });

        await page.goto(`/instructor/flagged?courseId=${COURSE_ID}`);

        const flagCard = page.locator(`[data-flag-id="${flagId}"]`);
        await expect(flagCard).toBeVisible({ timeout: 15_000 });
        await expect(flagCard).toContainText('UI dismissal target');

        await flagCard.locator('.dismiss-btn').click();

        // The default filter is "pending", so a dismissed flag drops from the list.
        await expect(flagCard).toHaveCount(0, { timeout: 10_000 });

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.flagStatus).toBe('dismissed');
    });

    test('instructor can approve & reply, persisting response and resolving the flag', async ({ page }) => {
        const flagId = await seedFlag({ flagDescription: 'UI response target' });

        await page.goto(`/instructor/flagged?courseId=${COURSE_ID}`);

        const flagCard = page.locator(`[data-flag-id="${flagId}"]`);
        await expect(flagCard).toBeVisible({ timeout: 15_000 });

        await flagCard.locator('.approve-btn').click();

        const textarea = page.locator(`#message-content-${flagId}`);
        await expect(textarea).toBeVisible();
        await textarea.fill('Thanks for flagging this — answer corrected.');
        await flagCard.locator('.send-approve-btn').click();

        await expect(flagCard).toHaveCount(0, { timeout: 10_000 });

        const stored = await withDb((db) =>
            db.collection('flaggedQuestions').findOne({ flagId })
        );
        expect(stored.flagStatus).toBe('resolved');
        expect(stored.instructorResponse).toBe('Thanks for flagging this — answer corrected.');
        expect(stored.instructorId).toBe(instructorId);
    });
});

// ============================================================================
// Cross-role round trip: student → instructor → student
// ============================================================================
test.describe('End-to-end flag round-trip across roles', () => {
    test.beforeEach(async () => {
        await resetCourse();
    });

    test('student-created flag is visible to instructor, resolved with a reply, and the reply appears on /api/flags/my', async ({ baseURL }) => {
        const studentCtx = await loginAPI(baseURL, 'student', studentPassword);
        const instructorCtx = await loginAPI(baseURL, 'instructor', instructorPassword);

        const create = await studentCtx.post('/api/flags', {
            data: {
                questionId: QUESTION_ID,
                courseId: COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'I do not understand why the answer is "true".',
            },
        });
        expect(create.ok()).toBeTruthy();
        const flagId = (await create.json()).data.flagId;

        const list = await instructorCtx.get(`/api/flags/course/${COURSE_ID}?status=pending`);
        const listBody = await list.json();
        expect(listBody.data.flags.map((f) => f.flagId)).toContain(flagId);

        const reply = await instructorCtx.put(`/api/flags/${flagId}/response`, {
            data: {
                response: 'A peptide bond is formed in a condensation reaction — the statement is true.',
                flagStatus: 'resolved',
            },
        });
        expect(reply.ok()).toBeTruthy();

        const myFlags = await studentCtx.get('/api/flags/my');
        const myBody = await myFlags.json();
        const mine = myBody.data.flags.find((f) => f.flagId === flagId);
        expect(mine).toBeTruthy();
        expect(mine.flagStatus).toBe('resolved');
        expect(mine.instructorResponse).toContain('condensation reaction');
        expect(mine.instructorName).toBe(TEST_USERS.instructor.displayName);

        await studentCtx.dispose();
        await instructorCtx.dispose();
    });
});

// ============================================================================
// Mental health flags — instructor-side listing & anonymization
// ============================================================================
test.describe('Mental health flags — GET /api/mental-health-flags/course/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
        await setSystemAdmin(instructorId, false);
    });

    test('regular instructor sees anonymized flags and isAdmin=false', async ({ request: api }) => {
        const flagId = await seedMentalHealthFlag({
            message: 'Everything feels too much right now.',
            concernLevel: 'high concern',
        });

        const res = await api.get(`/api/mental-health-flags/course/${COURSE_ID}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.isAdmin).toBe(false);

        const flag = body.flags.find((f) => f.flagId === flagId);
        expect(flag).toBeTruthy();
        expect(flag.studentName).toBe('Anonymous Student');
        // Anonymization sets studentId to undefined, which JSON drops.
        expect(flag.studentId).toBeUndefined();
        // But message / concernLevel / llmReason are preserved.
        expect(flag.message).toBe('Everything feels too much right now.');
        expect(flag.concernLevel).toBe('high concern');

        expect(body.stats).toMatchObject({ pending: 1 });
    });

    test('system admin sees the real student name and isAdmin=true', async ({ request: api }) => {
        await setSystemAdmin(instructorId, true);
        const flagId = await seedMentalHealthFlag({
            message: 'Real-name visibility check.',
        });

        const res = await api.get(`/api/mental-health-flags/course/${COURSE_ID}`);
        const body = await res.json();
        expect(body.isAdmin).toBe(true);

        const flag = body.flags.find((f) => f.flagId === flagId);
        expect(flag).toBeTruthy();
        expect(flag.studentName).toBe(TEST_USERS.student.displayName);
        expect(flag.studentId).toBe(studentId);
    });

    test('status filter restricts results to that status', async ({ request: api }) => {
        await seedMentalHealthFlag({ flagId: 'mhf_e2e_p', status: 'pending' });
        await seedMentalHealthFlag({ flagId: 'mhf_e2e_e', status: 'escalated' });
        await seedMentalHealthFlag({ flagId: 'mhf_e2e_d', status: 'dismissed' });

        const res = await api.get(`/api/mental-health-flags/course/${COURSE_ID}?status=escalated`);
        const body = await res.json();
        expect(body.flags.map((f) => f.flagId)).toEqual(['mhf_e2e_e']);
    });
});

// ============================================================================
// Mental health flags — instructor escalate / dismiss
// ============================================================================
test.describe('Mental health flags — instructor escalate & dismiss', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
        await setSystemAdmin(instructorId, false);
    });

    test('PUT /:flagId/escalate moves a pending flag to escalated and records who/when', async ({ request: api }) => {
        const flagId = await seedMentalHealthFlag();

        const res = await api.put(`/api/mental-health-flags/${flagId}/escalate`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);

        const stored = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId })
        );
        expect(stored.status).toBe('escalated');
        expect(stored.escalatedBy).toBe(instructorId);
        expect(stored.escalatedAt).toBeTruthy();
    });

    test('PUT /:flagId/dismiss moves a pending flag to dismissed', async ({ request: api }) => {
        const flagId = await seedMentalHealthFlag();

        const res = await api.put(`/api/mental-health-flags/${flagId}/dismiss`);
        expect(res.ok()).toBeTruthy();

        const stored = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId })
        );
        expect(stored.status).toBe('dismissed');
    });
});

// ============================================================================
// Mental health flags — admin-only resolve / disregard
// ============================================================================
test.describe('Mental health flags — admin-only resolve & disregard', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
        await setSystemAdmin(instructorId, false);
    });

    test('non-admin instructor gets 403 on /resolve and /disregard, and flag stays escalated', async ({ request: api }) => {
        const flagId = await seedMentalHealthFlag({ status: 'escalated' });

        const resolveRes = await api.put(`/api/mental-health-flags/${flagId}/resolve`, {
            failOnStatusCode: false,
        });
        expect(resolveRes.status()).toBe(403);

        const disregardRes = await api.put(`/api/mental-health-flags/${flagId}/disregard`, {
            failOnStatusCode: false,
        });
        expect(disregardRes.status()).toBe(403);

        const stored = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId })
        );
        expect(stored.status).toBe('escalated');
        expect(stored.resolvedBy).toBeNull();
    });

    test('system admin can resolve an escalated flag, stamping resolvedBy and resolvedAt', async ({ request: api }) => {
        await setSystemAdmin(instructorId, true);
        const flagId = await seedMentalHealthFlag({ status: 'escalated' });

        const res = await api.put(`/api/mental-health-flags/${flagId}/resolve`);
        expect(res.ok()).toBeTruthy();

        const stored = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId })
        );
        expect(stored.status).toBe('resolved');
        expect(stored.resolvedBy).toBe(instructorId);
        expect(stored.resolvedAt).toBeTruthy();
    });

    test('system admin can disregard an escalated flag', async ({ request: api }) => {
        await setSystemAdmin(instructorId, true);
        const flagId = await seedMentalHealthFlag({ status: 'escalated' });

        const res = await api.put(`/api/mental-health-flags/${flagId}/disregard`);
        expect(res.ok()).toBeTruthy();

        const stored = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId })
        );
        expect(stored.status).toBe('disregarded');
        expect(stored.resolvedBy).toBe(instructorId);
        expect(stored.resolvedAt).toBeTruthy();
    });
});

// ============================================================================
// Mental health flags — instructor UI escalate
// ============================================================================
test.describe('Mental health flags — instructor UI', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
        await setSystemAdmin(instructorId, false);
    });

    test('instructor can escalate a pending mental health flag from the flagged page', async ({ page }) => {
        const flagId = await seedMentalHealthFlag({
            message: 'I am really struggling lately.',
            concernLevel: 'high concern',
        });

        await page.goto(`/instructor/flagged?courseId=${COURSE_ID}`);

        const card = page.locator(`[data-mh-flag-id="${flagId}"]`);
        await expect(card).toBeVisible({ timeout: 15_000 });
        await expect(card).toContainText('I am really struggling lately.');
        // Non-admin instructor: name must be anonymized.
        await expect(card).not.toContainText(TEST_USERS.student.displayName);

        await card.locator('.mh-escalate-btn').click();

        // After escalation the default "pending" filter drops the card.
        await expect(card).toHaveCount(0, { timeout: 10_000 });

        const stored = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId })
        );
        expect(stored.status).toBe('escalated');
        expect(stored.escalatedBy).toBe(instructorId);
    });
});

// ============================================================================
// Cross-course isolation — listings and stats must be scoped to courseId
// ============================================================================
test.describe('Cross-course isolation — student-flagged questions', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
        await seedOtherCourse();
    });

    test('GET /course/:courseId returns only that course\'s flags', async ({ request: api }) => {
        const inCourseId = await seedFlag({
            flagId: 'e2e-flag-in-course',
            flagDescription: 'Belongs to the main course',
        });
        const otherCourseId = await seedFlag({
            flagId: 'e2e-flag-other-course',
            courseId: OTHER_COURSE_ID,
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagDescription: 'Belongs to the OTHER course',
        });

        const a = await api.get(`/api/flags/course/${COURSE_ID}`);
        const aBody = await a.json();
        const aIds = aBody.data.flags.map((f) => f.flagId);
        expect(aIds).toContain(inCourseId);
        expect(aIds).not.toContain(otherCourseId);

        const b = await api.get(`/api/flags/course/${OTHER_COURSE_ID}`);
        const bBody = await b.json();
        const bIds = bBody.data.flags.map((f) => f.flagId);
        expect(bIds).toContain(otherCourseId);
        expect(bIds).not.toContain(inCourseId);
    });

    test('GET /stats/:courseId aggregates only that course\'s flags', async ({ request: api }) => {
        await seedFlag({ flagId: 'e2e-flag-stats-a1', flagStatus: 'pending' });
        await seedFlag({ flagId: 'e2e-flag-stats-a2', flagStatus: 'resolved' });
        await seedFlag({
            flagId: 'e2e-flag-stats-b1',
            courseId: OTHER_COURSE_ID,
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagStatus: 'pending',
        });
        await seedFlag({
            flagId: 'e2e-flag-stats-b2',
            courseId: OTHER_COURSE_ID,
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagStatus: 'dismissed',
        });

        const aRes = await api.get(`/api/flags/stats/${COURSE_ID}`);
        const aBody = await aRes.json();
        expect(aBody.data.statistics).toMatchObject({ total: 2, pending: 1, resolved: 1 });
        expect(aBody.data.statistics.dismissed || 0).toBe(0);

        const bRes = await api.get(`/api/flags/stats/${OTHER_COURSE_ID}`);
        const bBody = await bRes.json();
        expect(bBody.data.statistics).toMatchObject({ total: 2, pending: 1, dismissed: 1 });
        expect(bBody.data.statistics.resolved || 0).toBe(0);
    });
});

// ============================================================================
// Student cannot flag a course they aren't enrolled in
// ============================================================================
test.describe('Student cannot flag a course they aren\'t enrolled in', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetCourse();
        await seedOtherCourse();
    });

    test('POST /api/flags against an un-enrolled course is rejected and creates nothing', async ({ request: api }) => {
        const res = await api.post('/api/flags', {
            data: {
                questionId: 'q_e2e_flags_other_question',
                courseId: OTHER_COURSE_ID,
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'Student should not be able to flag this course.',
            },
            failOnStatusCode: false,
        });
        // requireStudentEnrolled returns 403 for a course the student has no
        // enrollment record in (status === 'none' → enrolled: false).
        expect(res.status()).toBe(403);

        const count = await withDb((db) =>
            db.collection('flaggedQuestions').countDocuments({ courseId: OTHER_COURSE_ID })
        );
        expect(count).toBe(0);
    });

    test('POST /api/flags against a non-existent course returns 404', async ({ request: api }) => {
        const res = await api.post('/api/flags', {
            data: {
                questionId: 'q_does_not_exist',
                courseId: 'BIOC-COURSE-THAT-DOES-NOT-EXIST',
                unitName: UNIT_NAME,
                flagReason: 'unclear',
                flagDescription: 'No such course.',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(404);
    });
});

// ============================================================================
// GET /api/flags/status/:status — cross-course read by status
// ============================================================================
test.describe('GET /api/flags/status/:status — read flags across courses by status', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await resetCourse();
        await seedOtherCourse();
    });

    test('returns pending flags only from courses the caller teaches', async ({ request: api }) => {
        const pendingA = await seedFlag({ flagId: 'e2e-status-a-pending', flagStatus: 'pending' });
        await seedFlag({ flagId: 'e2e-status-a-resolved', flagStatus: 'resolved' });
        const pendingB = await seedFlag({
            flagId: 'e2e-status-b-pending',
            courseId: OTHER_COURSE_ID,
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagStatus: 'pending',
        });

        const res = await api.get('/api/flags/status/pending');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.status).toBe('pending');

        const ids = body.data.flags.map((f) => f.flagId);
        // The instructor sees pending flags from their own courses only.
        expect(ids).toContain(pendingA);
        expect(ids).toContain(pendingB);
        expect(ids).not.toContain('e2e-status-a-resolved');

        // Every returned flag really is pending.
        for (const flag of body.data.flags) {
            expect(flag.flagStatus).toBe('pending');
        }
    });

    test('DESIRED: scopes results to courses the caller teaches — should NOT leak flags from an unrelated instructor\'s course', async ({ request: api }) => {
        // Set up a course owned by a *different* instructor. The test instructor
        // is not in `instructors`, not the `instructorId`, and not a TA. A flag
        // raised inside that course must never appear in our test instructor's
        // /status/pending response.
        await seedUnrelatedCourse();
        const unrelatedFlagId = await seedFlag({
            flagId: 'e2e-status-unrelated-instructor',
            courseId: UNRELATED_COURSE_ID,
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagStatus: 'pending',
        });
        const mineFlagId = await seedFlag({
            flagId: 'e2e-status-mine',
            flagStatus: 'pending',
        });

        const res = await api.get('/api/flags/status/pending');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const ids = body.data.flags.map((f) => f.flagId);

        // The test instructor's own pending flag should still appear.
        expect(ids).toContain(mineFlagId);

        // The unrelated instructor's pending flag should NOT — this is what we
        // expect the fix to enforce. Currently failing: the endpoint has no
        // course/role scoping beyond authentication.
        expect(ids).not.toContain(unrelatedFlagId);
    });

    test('omits flags from the test course when none of them match the requested status', async ({ request: api }) => {
        // Two pending flags in our test courses, no resolved ones.
        await seedFlag({ flagId: 'e2e-status-empty-a', flagStatus: 'pending' });
        await seedFlag({
            flagId: 'e2e-status-empty-b',
            courseId: OTHER_COURSE_ID,
            studentIdForFlag: OTHER_STUDENT_ID,
            studentName: 'E2E Other Flagging Student',
            flagStatus: 'pending',
        });

        const res = await api.get('/api/flags/status/resolved');
        const body = await res.json();
        expect(body.success).toBe(true);

        // The endpoint isn't course-scoped, so the dev DB may carry pre-existing
        // resolved flags. Only assert that none of our seeded test flags appear,
        // and that everything returned really is "resolved".
        const ids = body.data.flags.map((f) => f.flagId);
        expect(ids).not.toContain('e2e-status-empty-a');
        expect(ids).not.toContain('e2e-status-empty-b');
        for (const flag of body.data.flags) {
            expect(flag.flagStatus).toBe('resolved');
        }
    });
});
