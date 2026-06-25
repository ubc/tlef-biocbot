// @ts-check
/**
 * API coverage for src/routes/onboarding.js (~41% → target higher).
 */

const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
} = require('./helpers/courses-test');

const COURSE_A = 'BIOC-E2E-API-ONB-A';
const COURSE_B = 'BIOC-E2E-API-ONB-B';
const VALID_API_KEY = 'sk-test-onboarding-api';

let instructorId;
let instructorFreshId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    instructorFreshId = await getUserIdByUsername(TEST_USERS.instructor_fresh.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_A, COURSE_B]);
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
});

test.describe('GET /api/onboarding/test', () => {
    test.use({ storageState: storageStatePath('instructor') });
    test('returns the health-check payload', async ({ request: api }) => {
        const res = await api.get('/api/onboarding/test');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.message).toMatch(/working/i);
    });
});

test.describe('POST /api/onboarding (create from onboarding)', () => {
    test.describe('as instructor', () => {
        test.use({ storageState: storageStatePath('instructor_fresh') });

        test('400 when required fields missing', async ({ request: api }) => {
            const res = await api.post('/api/onboarding', { data: { courseId: 'X' } });
            expect(res.status()).toBe(400);
        });

        test('happy path creates the course doc', async ({ request: api }) => {
            const courseId = COURSE_B;
            const res = await api.post('/api/onboarding', {
                data: {
                    courseId,
                    courseName: 'Onboarded Course',
                    courseDescription: 'desc',
                    learningOutcomes: ['LO1', 'LO2'],
                    assessmentCriteria: 'crit',
                    courseMaterials: [],
                    unitFiles: {},
                    courseStructure: { weeks: 2, lecturesPerWeek: 2 },
                    apiKey: VALID_API_KEY,
                },
            });
            expect(res.ok()).toBeTruthy();
            const doc = await withDb((db) =>
                db.collection('courses').findOne({ courseId })
            );
            expect(doc.courseName).toBe('Onboarded Course');
            expect(doc.lectures.length).toBe(4);
        });
    });

    test.describe('as student', () => {
        test.use({ storageState: storageStatePath('student') });

        test('403 — only instructors can call', async ({ request: api }) => {
            const res = await api.post('/api/onboarding', {
                data: { courseId: 'X', courseName: 'Y' },
            });
            expect(res.status()).toBe(403);
        });
    });
});

test.describe('GET /api/onboarding/:courseId', () => {
    test.describe('as instructor', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('404 when course does not exist', async ({ request: api }) => {
            const res = await api.get('/api/onboarding/BIOC-E2E-API-NOPE');
            expect(res.status()).toBe(404);
        });

        test('403 when course belongs to a different instructor', async ({ request: api }) => {
            await seedCourse({ courseId: COURSE_B, instructorId: instructorFreshId });
            const res = await api.get(`/api/onboarding/${COURSE_B}`);
            expect(res.status()).toBe(403);
        });

        test('200 happy path returns the course doc', async ({ request: api }) => {
            await seedCourse({ courseId: COURSE_A, instructorId });
            const res = await api.get(`/api/onboarding/${COURSE_A}`);
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.data.courseId).toBe(COURSE_A);
        });
    });
});

test.describe('GET /api/onboarding/instructor/:instructorId', () => {
    test.describe('as instructor', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('403 when asking about a different instructor', async ({ request: api }) => {
            const res = await api.get(`/api/onboarding/instructor/${instructorFreshId}`);
            expect(res.status()).toBe(403);
        });

        test('happy path returns the caller\'s courses (excluding deleted)', async ({ request: api }) => {
            await seedCourse({ courseId: COURSE_A, instructorId });
            await seedCourse({ courseId: 'BIOC-E2E-API-ONB-DEL', instructorId, status: 'deleted' });
            const res = await api.get(`/api/onboarding/instructor/${instructorId}`);
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            const ids = body.data.courses.map((c) => c.courseId);
            expect(ids).toContain(COURSE_A);
            expect(ids).not.toContain('BIOC-E2E-API-ONB-DEL');

            await withDb((db) =>
                db.collection('courses').deleteOne({ courseId: 'BIOC-E2E-API-ONB-DEL' })
            );
        });
    });
});

test.describe('PUT /api/onboarding/:courseId/unit-files', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when fields missing', async ({ request: api }) => {
        const res = await api.put(`/api/onboarding/${COURSE_A}/unit-files`, {
            data: { unitName: 'Unit 1' },
        });
        expect(res.status()).toBe(400);
    });

    test('404 when course not found', async ({ request: api }) => {
        const res = await api.put('/api/onboarding/BIOC-E2E-API-NOPE/unit-files', {
            data: { unitName: 'Unit 1', files: [] },
        });
        expect(res.status()).toBe(404);
    });

    test('403 when caller is not an instructor on the course', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_B, instructorId: instructorFreshId });
        const res = await api.put(`/api/onboarding/${COURSE_B}/unit-files`, {
            data: { unitName: 'Unit 1', files: [{ filename: 'a.txt' }] },
        });
        expect(res.status()).toBe(403);
    });

    test('happy path sets unit files on the lecture', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.put(`/api/onboarding/${COURSE_A}/unit-files`, {
            data: { unitName: 'Unit 1', files: [{ filename: 'a.txt' }, { filename: 'b.txt' }] },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        const unit = doc.lectures.find((l) => l.name === 'Unit 1');
        expect(unit.unitFiles).toHaveLength(2);
    });
});

test.describe('PUT /api/onboarding/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when body is empty', async ({ request: api }) => {
        const res = await api.put(`/api/onboarding/${COURSE_A}`, { data: {} });
        expect(res.status()).toBe(400);
    });

    test('404 when course not found', async ({ request: api }) => {
        const res = await api.put('/api/onboarding/BIOC-E2E-API-NOPE', {
            data: { courseDescription: 'new' },
        });
        expect(res.status()).toBe(404);
    });

    test('happy path updates the fields', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.put(`/api/onboarding/${COURSE_A}`, {
            data: { courseDescription: 'New desc', assessmentCriteria: 'criteria v2' },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc.courseDescription).toBe('New desc');
        expect(doc.assessmentCriteria).toBe('criteria v2');
    });
});

test.describe('DELETE /api/onboarding/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('404 when course does not exist', async ({ request: api }) => {
        const res = await api.delete('/api/onboarding/BIOC-E2E-API-NOPE');
        expect(res.status()).toBe(404);
    });

    test('403 when caller is not an instructor on the course', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_B, instructorId: instructorFreshId });
        const res = await api.delete(`/api/onboarding/${COURSE_B}`);
        expect(res.status()).toBe(403);
    });

    test('happy path deletes the course', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.delete(`/api/onboarding/${COURSE_A}`);
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc).toBeFalsy();
    });
});

test.describe('DELETE /api/onboarding/:courseId/unit/:unitName', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('404 when course not found', async ({ request: api }) => {
        const res = await api.delete('/api/onboarding/BIOC-E2E-API-NOPE/unit/Unit 1');
        expect(res.status()).toBe(404);
    });

    test('happy path removes the unit', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.delete(`/api/onboarding/${COURSE_A}/unit/${encodeURIComponent('Unit 2')}`);
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc.lectures.find((l) => l.name === 'Unit 2')).toBeFalsy();
    });
});

test.describe('GET /api/onboarding/stats', () => {
    // PRODUCT BUG: /stats is registered AFTER /:courseId, so Express matches
    // the request as /:courseId (courseId='stats'). The /stats handler is
    // unreachable. We expect a 200 stats payload; today we get 404.
    test.use({ storageState: storageStatePath('instructor') });

    test('PRODUCT BUG: /stats is shadowed by /:courseId (route ordering)', async ({ request: api }) => {
        const res = await api.get('/api/onboarding/stats');
        expect(res.ok()).toBeTruthy();
    });
});

test.describe('POST /api/onboarding/complete', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required fields missing', async ({ request: api }) => {
        const res = await api.post('/api/onboarding/complete', { data: {} });
        expect(res.status()).toBe(400);
    });

    test('403 when instructorId does not match caller', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/onboarding/complete', {
            data: { courseId: COURSE_A, instructorId: instructorFreshId },
        });
        expect(res.status()).toBe(403);
    });

    test('404 when course does not exist', async ({ request: api }) => {
        const res = await api.post('/api/onboarding/complete', {
            data: { courseId: 'BIOC-E2E-API-NOPE', instructorId },
        });
        expect(res.status()).toBe(404);
    });

    test('happy path sets isOnboardingComplete=true', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId, overrides: { isOnboardingComplete: false } });
        const res = await api.post('/api/onboarding/complete', {
            data: { courseId: COURSE_A, instructorId },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc.isOnboardingComplete).toBe(true);
    });
});
