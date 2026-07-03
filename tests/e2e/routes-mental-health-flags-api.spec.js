// @ts-check
/**
 * API coverage for src/routes/mentalHealthFlags.js (71.68% → higher).
 *
 *   - GET  /api/mental-health-flags/course/:courseId   (anonymized vs. admin)
 *   - PUT  /api/mental-health-flags/:flagId/escalate
 *   - PUT  /api/mental-health-flags/:flagId/dismiss
 *   - PUT  /api/mental-health-flags/:flagId/resolve    (admin only)
 *   - PUT  /api/mental-health-flags/:flagId/disregard  (admin only)
 *
 * Mounted in src/server.js with
 *   `requireAuth → populateUser → requireActiveCourseForNonInstructors → router`.
 *
 * Per AGENTS.md, no production code is modified; bug-exposing tests are left
 * failing and reported in tests/e2e/FINDINGS.md.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
} = require('./helpers/courses-test');

const COURSE_MHF = 'BIOC-E2E-API-MHF-A';
const FLAG_ID = 'mhf_e2e_route_api';
const FLAG_ID_OTHER = 'mhf_e2e_route_api_other';

let instructorId;
let studentId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await setAdmin(instructorId, false);
    await withDb((db) =>
        db.collection('mentalHealthFlags').deleteMany({
            flagId: { $in: [FLAG_ID, FLAG_ID_OTHER] },
        })
    );
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_MHF]);
    await cleanupCoursesForUser(instructorId);
    await setAdmin(instructorId, false);
    await withDb((db) =>
        db.collection('mentalHealthFlags').deleteMany({ courseId: COURSE_MHF })
    );
});

async function setAdmin(userId, on) {
    const op = on
        ? { $set: { 'permissions.systemAdmin': true, updatedAt: new Date() } }
        : { $unset: { 'permissions.systemAdmin': '' }, $set: { updatedAt: new Date() } };
    await withDb((db) => db.collection('users').updateOne({ userId }, op));
}

async function seedFlag(extras = {}) {
    const flagId = extras.flagId || FLAG_ID;
    const now = new Date();
    await withDb(async (db) => {
        await db.collection('mentalHealthFlags').deleteMany({ flagId });
        await db.collection('mentalHealthFlags').insertOne({
            flagId, studentId, studentName: 'E2E Student', courseId: COURSE_MHF,
            unitName: 'Unit 1', message: 'I feel overwhelmed', conversationContext: [],
            concernLevel: 'high concern', llmReason: 'stress phrasing', status: 'pending',
            escalatedBy: null, escalatedAt: null, resolvedBy: null, resolvedAt: null,
            createdAt: now, updatedAt: now, ...extras,
        });
    });
}

// ---------------------------------------------------------------------------
// GET /api/mental-health-flags/course/:courseId
// ---------------------------------------------------------------------------
test.describe('GET /course/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_MHF, instructorId });
        await seedFlag();
        await seedFlag({ flagId: FLAG_ID_OTHER, status: 'escalated', escalatedBy: instructorId, escalatedAt: new Date() });
    });

    test('non-admin instructor sees anonymized flags + stats', async ({ request: api }) => {
        const res = await api.get(`/api/mental-health-flags/course/${COURSE_MHF}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.isAdmin).toBe(false);
        expect(body.flags.length).toBeGreaterThanOrEqual(2);
        for (const f of body.flags) {
            expect(f.studentName).toBe('Anonymous Student');
            expect(f.studentId).toBeUndefined();
        }
        expect(body.stats.total).toBeGreaterThanOrEqual(2);
    });

    test('honours the `status` query filter', async ({ request: api }) => {
        const res = await api.get(`/api/mental-health-flags/course/${COURSE_MHF}?status=escalated`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.flags.every((f) => f.status === 'escalated')).toBe(true);
        expect(body.flags.length).toBeGreaterThanOrEqual(1);
    });

    test('admin instructor sees full identity', async ({ request: api }) => {
        await setAdmin(instructorId, true);
        const res = await api.get(`/api/mental-health-flags/course/${COURSE_MHF}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.isAdmin).toBe(true);
        expect(body.flags[0].studentName).toBe('E2E Student');
        expect(body.flags[0].studentId).toBe(studentId);
    });
});

// ---------------------------------------------------------------------------
// PUT /api/mental-health-flags/:flagId/escalate
// PUT /api/mental-health-flags/:flagId/dismiss
// ---------------------------------------------------------------------------
test.describe('PUT /:flagId/escalate and /dismiss', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_MHF, instructorId });
        await seedFlag();
    });

    test('escalate transitions to "escalated" and stamps escalatedBy', async ({ request: api }) => {
        const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/escalate`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);

        const updated = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId: FLAG_ID })
        );
        expect(updated.status).toBe('escalated');
        expect(updated.escalatedBy).toBe(instructorId);
        expect(updated.escalatedAt).toBeInstanceOf(Date);
    });

    test('dismiss transitions to "dismissed" without escalation/resolve fields', async ({ request: api }) => {
        const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/dismiss`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);

        const updated = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId: FLAG_ID })
        );
        expect(updated.status).toBe('dismissed');
        expect(updated.escalatedBy).toBeNull();
        expect(updated.resolvedBy).toBeNull();
    });

    test('escalating a missing flag returns 404', async ({ request: api }) => {
        // The staff-access guard looks the flag up first and 404s when it
        // does not exist, instead of replying 200 with success:false.
        const res = await api.put('/api/mental-health-flags/mhf_does_not_exist/escalate');
        expect(res.status()).toBe(404);
        const body = await res.json();
        expect(body.success).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// PUT /api/mental-health-flags/:flagId/resolve  (admin only)
// PUT /api/mental-health-flags/:flagId/disregard (admin only)
// ---------------------------------------------------------------------------
test.describe('PUT /:flagId/resolve and /disregard', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_MHF, instructorId });
        await seedFlag({ status: 'escalated', escalatedBy: instructorId, escalatedAt: new Date() });
    });

    test('resolve is 403 for a non-admin caller', async ({ request: api }) => {
        const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/resolve`);
        expect(res.status()).toBe(403);
        const body = await res.json();
        expect(body.success).toBe(false);
    });

    test('disregard is 403 for a non-admin caller', async ({ request: api }) => {
        const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/disregard`);
        expect(res.status()).toBe(403);
        const body = await res.json();
        expect(body.success).toBe(false);
    });

    test('admin can resolve and the model stamps resolvedBy', async ({ request: api }) => {
        await setAdmin(instructorId, true);
        const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/resolve`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);

        const updated = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId: FLAG_ID })
        );
        expect(updated.status).toBe('resolved');
        expect(updated.resolvedBy).toBe(instructorId);
    });

    test('admin can disregard a flag', async ({ request: api }) => {
        await setAdmin(instructorId, true);
        const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/disregard`);
        expect(res.ok()).toBeTruthy();

        const updated = await withDb((db) =>
            db.collection('mentalHealthFlags').findOne({ flagId: FLAG_ID })
        );
        expect(updated.status).toBe('disregarded');
        expect(updated.resolvedBy).toBe(instructorId);
    });
});

// ---------------------------------------------------------------------------
// Auth gate (requireAuth → 401 for unauthenticated requests)
// ---------------------------------------------------------------------------
test.describe('Auth', () => {
    test('unauthenticated GET /course/:courseId returns 401', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.get(`/api/mental-health-flags/course/${COURSE_MHF}`);
            expect(res.status()).toBe(401);
            const body = await res.json();
            expect(body.success).toBe(false);
        } finally {
            await api.dispose();
        }
    });

    test('unauthenticated PUT /escalate returns 401', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.put(`/api/mental-health-flags/${FLAG_ID}/escalate`);
            expect(res.status()).toBe(401);
        } finally {
            await api.dispose();
        }
    });
});
