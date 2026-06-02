// @ts-check
/**
 * API coverage for src/routes/struggle-activity.js (67.09% → higher).
 *
 * Exercises every endpoint via the live router with seeded MongoDB rows:
 *   - GET /api/struggle-activity/student/:userId
 *   - GET /api/struggle-activity/persistence/:courseId
 *   - GET /api/struggle-activity/weekly/:courseId
 *   - GET /api/struggle-activity/:courseId   (catch-all, must be last in router)
 *
 * Auth and access-control are mounted in src/server.js:
 *   `requireAuth → requireActiveCourseForNonInstructors → router`.
 *
 * Per AGENTS.md, no production code is modified; any bug-exposing tests are
 * left failing and reported in tests/e2e/FINDINGS.md.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
    setCourseStatus,
    setStudentEnrollment,
} = require('./helpers/courses-test');

const COURSE_SA = 'BIOC-E2E-API-STRUGGLE-A';
const COURSE_SB = 'BIOC-E2E-API-STRUGGLE-B';
const COURSE_SA_INACTIVE = 'BIOC-E2E-API-STRUGGLE-INACTIVE';
const ALL_COURSES = [COURSE_SA, COURSE_SB, COURSE_SA_INACTIVE];

let instructorId;
let studentId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await withDb((db) => Promise.all([
        db.collection('struggleActivity').deleteMany({ courseId: { $in: ALL_COURSES } }),
        db.collection('persistenceTopics').deleteMany({ courseId: { $in: ALL_COURSES } }),
    ]));
});

test.afterAll(async () => {
    await cleanupCourses(ALL_COURSES);
    await cleanupCoursesForUser(instructorId);
    await withDb((db) => Promise.all([
        db.collection('struggleActivity').deleteMany({ courseId: { $in: ALL_COURSES } }),
        db.collection('persistenceTopics').deleteMany({ courseId: { $in: ALL_COURSES } }),
    ]));
});

async function seedActivities() {
    const base = { studentName: 'E2E Student', userId: studentId };
    await withDb((db) =>
        db.collection('struggleActivity').insertMany([
            { ...base, courseId: COURSE_SA, topic: 'krebs cycle', state: 'Active',   timestamp: new Date('2026-04-01T00:00:00Z') },
            { ...base, courseId: COURSE_SA, topic: 'krebs cycle', state: 'Inactive', timestamp: new Date('2026-04-02T00:00:00Z') },
            { ...base, courseId: COURSE_SA, topic: 'glycolysis',  state: 'Active',   timestamp: new Date('2026-04-03T00:00:00Z') },
        ])
    );
}

async function seedPersistenceTopics() {
    await withDb((db) =>
        db.collection('persistenceTopics').insertMany([
            { courseId: COURSE_SA, topic: 'krebs cycle', studentIds: [studentId], studentCount: 1, createdAt: new Date(), lastUpdated: new Date() },
            { courseId: COURSE_SA, topic: 'glycolysis',  studentIds: [studentId], studentCount: 1, createdAt: new Date(), lastUpdated: new Date() },
        ])
    );
}

// ---------------------------------------------------------------------------
// GET /api/struggle-activity/:courseId  (catch-all)
// ---------------------------------------------------------------------------
test.describe('GET /api/struggle-activity/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_SA, instructorId });
        await seedActivities();
    });

    test('returns the full activity list with count and success flag', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/${COURSE_SA}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(Array.isArray(body.data)).toBe(true);
        expect(body.count).toBe(body.data.length);
        expect(body.count).toBeGreaterThanOrEqual(3);
    });

    test('honours the `state` filter (only Active rows)', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/${COURSE_SA}?state=Active`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.length).toBeGreaterThan(0);
        expect(body.data.every((e) => e.state === 'Active')).toBe(true);
    });

    test('honours the `limit` query param', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/${COURSE_SA}?limit=1`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.length).toBeLessThanOrEqual(1);
    });

    test('returns an empty list for an unseen course (no DB error)', async ({ request: api }) => {
        // No seed for "BIOC-E2E-API-STRUGGLE-EMPTY". Caller is an instructor, so
        // the inactive-course middleware doesn't trip. Route should succeed
        // with an empty array.
        const res = await api.get('/api/struggle-activity/BIOC-E2E-API-STRUGGLE-EMPTY');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.count).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// GET /api/struggle-activity/student/:userId
// ---------------------------------------------------------------------------
test.describe('GET /api/struggle-activity/student/:userId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_SA, instructorId });
        await seedActivities();
    });

    test('returns activity rows for the named student', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/student/${studentId}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.count).toBe(body.data.length);
        expect(body.data.every((e) => e.userId === studentId)).toBe(true);
    });

    test('respects the `limit` query param', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/student/${studentId}?limit=2`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.length).toBeLessThanOrEqual(2);
    });

    test('returns an empty array for an unknown user id', async ({ request: api }) => {
        const res = await api.get('/api/struggle-activity/student/no-such-user');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.count).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// GET /api/struggle-activity/persistence/:courseId
// ---------------------------------------------------------------------------
test.describe('GET /api/struggle-activity/persistence/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_SA, instructorId });
        await seedPersistenceTopics();
    });

    test('returns persistence topics sorted by cumulative student count', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/persistence/${COURSE_SA}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(Array.isArray(body.data)).toBe(true);
        expect(body.count).toBe(body.data.length);
        const topics = body.data.map((t) => t.topic);
        expect(topics).toContain('krebs cycle');
        expect(topics).toContain('glycolysis');
    });
});

// ---------------------------------------------------------------------------
// GET /api/struggle-activity/weekly/:courseId
// ---------------------------------------------------------------------------
test.describe('GET /api/struggle-activity/weekly/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_SA, instructorId });
        // Seed an Active row inside the last 2-week window so the aggregation
        // returns at least one bucket.
        const recent = new Date(Date.now() - 1000 * 60 * 60 * 24 * 3); // 3 days ago
        await withDb((db) =>
            db.collection('struggleActivity').insertOne({
                userId: studentId,
                studentName: 'E2E Student',
                courseId: COURSE_SA,
                topic: 'photosynthesis',
                state: 'Active',
                timestamp: recent,
            })
        );
    });

    test('returns aggregated weekly buckets (default weeks=8)', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/weekly/${COURSE_SA}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(Array.isArray(body.data)).toBe(true);
        expect(body.count).toBe(body.data.length);
    });

    test('honours the `weeks` query param', async ({ request: api }) => {
        const res = await api.get(`/api/struggle-activity/weekly/${COURSE_SA}?weeks=2`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        // The 3-day-old activity should fall inside a 2-week window.
        expect(body.data.length).toBeGreaterThanOrEqual(1);
    });
});

// ---------------------------------------------------------------------------
// GET /api/struggle-activity/super-course  (cross-course Super Chat aggregate)
// ---------------------------------------------------------------------------
test.describe('GET /api/struggle-activity/super-course', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_SA, instructorId });
        await seedCourse({ courseId: COURSE_SB, instructorId });
        // Two Super Chat struggles attributed to DIFFERENT source courses, plus
        // one normal in-course struggle that must NOT appear in the aggregate.
        await withDb((db) =>
            db.collection('struggleActivity').insertMany([
                { userId: studentId, studentName: 'E2E Student', courseId: COURSE_SA, topic: 'plant diagnostics', state: 'Active', source: 'superCourse', timestamp: new Date('2026-05-01T00:00:00Z') },
                { userId: studentId, studentName: 'E2E Student', courseId: COURSE_SB, topic: 'glycolysis',        state: 'Active', source: 'superCourse', timestamp: new Date('2026-05-02T00:00:00Z') },
                { userId: studentId, studentName: 'E2E Student', courseId: COURSE_SA, topic: 'krebs cycle',       state: 'Active', source: 'course',      timestamp: new Date('2026-05-03T00:00:00Z') },
            ])
        );
    });

    test('returns only superCourse-sourced rows, aggregated across courses', async ({ request: api }) => {
        const res = await api.get('/api/struggle-activity/super-course');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.count).toBe(body.data.length);

        // Invariant: every returned row is Super-Chat-sourced.
        expect(body.data.every((e) => e.source === 'superCourse')).toBe(true);

        // Our two seeded superCourse rows (across two courses) are present...
        const mine = body.data.filter((e) => [COURSE_SA, COURSE_SB].includes(e.courseId));
        const topics = mine.map((e) => e.topic);
        expect(topics).toContain('plant diagnostics');
        expect(topics).toContain('glycolysis');
        // ...and the normal in-course row is excluded.
        expect(topics).not.toContain('krebs cycle');
    });

    test('honours the `state` filter', async ({ request: api }) => {
        const res = await api.get('/api/struggle-activity/super-course?state=Active');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.every((e) => e.state === 'Active' && e.source === 'superCourse')).toBe(true);
    });

    test('weekly aggregate returns buckets across courses', async ({ request: api }) => {
        // Seed a recent superCourse row so the weekly window has data.
        const recent = new Date(Date.now() - 1000 * 60 * 60 * 24 * 3);
        await withDb((db) =>
            db.collection('struggleActivity').insertOne({
                userId: studentId, studentName: 'E2E Student', courseId: COURSE_SB,
                topic: 'plant diagnostics', state: 'Active', source: 'superCourse', timestamp: recent,
            })
        );

        const res = await api.get('/api/struggle-activity/super-course/weekly?weeks=4');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(Array.isArray(body.data)).toBe(true);
        expect(body.data.length).toBeGreaterThanOrEqual(1);
    });
});

// ---------------------------------------------------------------------------
// Auth / access-control branches (mounted in src/server.js)
// ---------------------------------------------------------------------------
test.describe('Auth and access-control', () => {
    test('unauthenticated request returns 401 with JSON body', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.get(`/api/struggle-activity/${COURSE_SA}`);
            expect(res.status()).toBe(401);
            const body = await res.json();
            expect(body.success).toBe(false);
        } finally {
            await api.dispose();
        }
    });

    test('student is blocked from inactive course (requireActiveCourseForNonInstructors)', async ({ baseURL }) => {
        await seedCourse({ courseId: COURSE_SA_INACTIVE, instructorId });
        await setStudentEnrollment(COURSE_SA_INACTIVE, studentId, true);
        await setCourseStatus(COURSE_SA_INACTIVE, 'inactive');

        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('student'),
        });
        try {
            // Pass courseId via query so the middleware can infer it.
            const res = await api.get(
                `/api/struggle-activity/${COURSE_SA_INACTIVE}?courseId=${COURSE_SA_INACTIVE}`
            );
            expect(res.status()).toBe(403);
            const body = await res.json();
            expect(body.success).toBe(false);
        } finally {
            await api.dispose();
        }
    });
});
