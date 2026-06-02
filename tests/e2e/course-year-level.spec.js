// @ts-check
/**
 * Tests for the Course "year level" feature (issue #351):
 *
 *   1. Pure helpers in src/models/Course.js — parseYearLevelFromName() and
 *      normalizeYearLevel().
 *   2. Course API — PUT /api/courses/:courseId persists `yearLevel`, and
 *      GET /api/courses/:courseId returns it (deriving a default from the
 *      course name for courses created before the field existed).
 *   3. Super Course — GET /api/student/super-course/pool reports
 *      `hasHigherLevelCourses` by comparing the pool's highest level against
 *      the student's highest enrolled-course level.
 */

require('dotenv').config();
const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
} = require('./helpers/courses-test');
const CourseModel = require('../../src/models/Course');

const PREFIX = 'BIOC-E2E-YEARLEVEL';
const COURSE_LEGACY = `${PREFIX}-LEGACY`;     // no stored yearLevel
const COURSE_STORED = `${PREFIX}-STORED`;     // explicit yearLevel
const COURSE_INVALID = `${PREFIX}-INVALID`;   // PUT with out-of-range value
const POOL_HIGH = `${PREFIX}-POOL-HIGH`;      // opted-in, 4th-year
const ENROLL_LOW = `${PREFIX}-ENROLL-LOW`;    // student enrolled, 2nd-year
const ENROLL_HIGH = `${PREFIX}-ENROLL-HIGH`;  // student enrolled, grad-level
const SUPER_SETTINGS_ID = 'superCourseChat';

const ALL_COURSE_IDS = [
    COURSE_LEGACY,
    COURSE_STORED,
    COURSE_INVALID,
    POOL_HIGH,
    ENROLL_LOW,
    ENROLL_HIGH,
];

// ---------------------------------------------------------------------------
// 1. Pure helpers (no DB / no server needed)
// ---------------------------------------------------------------------------
test.describe('Course year-level helpers (pure)', () => {
    test('parseYearLevelFromName uses the leading digit of the course number', () => {
        expect(CourseModel.parseYearLevelFromName('BIOC 401')).toBe(4);
        expect(CourseModel.parseYearLevelFromName('CHEM 121 - Intro')).toBe(1);
        expect(CourseModel.parseYearLevelFromName('MATH 200')).toBe(2);
        expect(CourseModel.parseYearLevelFromName('BIOC401')).toBe(4);
        // 4-digit codes: leading digit is still the year.
        expect(CourseModel.parseYearLevelFromName('PHYS 1010')).toBe(1);
        // 5xx+ maps to Graduate (clamped to 5).
        expect(CourseModel.parseYearLevelFromName('BIOC 530')).toBe(5);
        expect(CourseModel.parseYearLevelFromName('BIOC 600')).toBe(5);
    });

    test('parseYearLevelFromName returns null when no usable number is present', () => {
        expect(CourseModel.parseYearLevelFromName('Special Topics')).toBeNull();
        expect(CourseModel.parseYearLevelFromName('course 099')).toBeNull(); // leading 0
        expect(CourseModel.parseYearLevelFromName('')).toBeNull();
        expect(CourseModel.parseYearLevelFromName(null)).toBeNull();
        expect(CourseModel.parseYearLevelFromName(undefined)).toBeNull();
    });

    test('normalizeYearLevel accepts integers 1-5 and rejects everything else', () => {
        expect(CourseModel.normalizeYearLevel(1)).toBe(1);
        expect(CourseModel.normalizeYearLevel(5)).toBe(5);
        expect(CourseModel.normalizeYearLevel('4')).toBe(4); // numeric strings coerce
        expect(CourseModel.normalizeYearLevel(0)).toBeNull();
        expect(CourseModel.normalizeYearLevel(6)).toBeNull();
        expect(CourseModel.normalizeYearLevel(2.5)).toBeNull();
        expect(CourseModel.normalizeYearLevel('abc')).toBeNull();
        expect(CourseModel.normalizeYearLevel(null)).toBeNull();
        expect(CourseModel.normalizeYearLevel(undefined)).toBeNull();
    });
});

// ---------------------------------------------------------------------------
// 2. Course API — instructor reads/writes the year level
// ---------------------------------------------------------------------------
test.describe('Course year-level API', () => {
    test.use({ storageState: storageStatePath('instructor') });

    let instructorId;

    test.beforeAll(async () => {
        instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    });

    test.afterAll(async () => {
        await cleanupCourses(ALL_COURSE_IDS);
    });

    test('GET derives the year level from the course name when none is stored', async ({ request: api }) => {
        // Seeded without a yearLevel field — mimics a pre-feature course.
        await seedCourse({ courseId: COURSE_LEGACY, instructorId, courseName: 'BIOC 301 Legacy Course' });

        const res = await api.get(`/api/courses/${COURSE_LEGACY}`);
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.yearLevel).toBe(3);
    });

    test('PUT persists an explicit year level and GET returns the stored value', async ({ request: api }) => {
        await seedCourse({
            courseId: COURSE_STORED,
            instructorId,
            courseName: 'BIOC 200',
            overrides: { yearLevel: 2 },
        });

        const put = await api.put(`/api/courses/${COURSE_STORED}?instructorId=${encodeURIComponent(instructorId)}`, {
            data: { instructorId, yearLevel: 5 },
        });
        expect(put.status()).toBe(200);

        // Stored value wins over the name-derived default (which would be 2).
        const res = await api.get(`/api/courses/${COURSE_STORED}`);
        expect((await res.json()).data.yearLevel).toBe(5);

        const doc = await withDb((db) => db.collection('courses').findOne({ courseId: COURSE_STORED }));
        expect(doc.yearLevel).toBe(5);
    });

    test('PUT normalizes an out-of-range year level to null', async ({ request: api }) => {
        await seedCourse({
            courseId: COURSE_INVALID,
            instructorId,
            courseName: 'BIOC 250',
            overrides: { yearLevel: 2 },
        });

        const put = await api.put(`/api/courses/${COURSE_INVALID}?instructorId=${encodeURIComponent(instructorId)}`, {
            data: { instructorId, yearLevel: 99 },
        });
        expect(put.status()).toBe(200);

        // Stored value is cleared to null; GET then falls back to the
        // name-derived default (BIOC 250 -> 2).
        const doc = await withDb((db) => db.collection('courses').findOne({ courseId: COURSE_INVALID }));
        expect(doc.yearLevel).toBeNull();

        const res = await api.get(`/api/courses/${COURSE_INVALID}`);
        expect((await res.json()).data.yearLevel).toBe(2);
    });
});

// ---------------------------------------------------------------------------
// 3. Super Course — "above your level" detection
// ---------------------------------------------------------------------------
test.describe('Super Course year-level detection', () => {
    test.use({ storageState: storageStatePath('student') });

    let studentId;
    let originalSuperSettings = null;

    async function enableSuperCourse() {
        await withDb(async (db) => {
            await db.collection('settings').updateOne(
                { _id: SUPER_SETTINGS_ID },
                {
                    $set: {
                        studentTopK: 5,
                        instructorTopK: 5,
                        includeInactiveCourses: false,
                        showStudentSuperCourse: true,
                        instructorPrompt: 'E2E instructor super prompt',
                        studentPrompt: 'E2E student super prompt',
                        updatedAt: new Date(),
                    },
                    $setOnInsert: { createdAt: new Date() },
                },
                { upsert: true }
            );
        });
    }

    test.beforeAll(async () => {
        studentId = await getUserIdByUsername(TEST_USERS.student.username);
        originalSuperSettings = await withDb((db) => db.collection('settings').findOne({ _id: SUPER_SETTINGS_ID }));
    });

    test.afterAll(async () => {
        await cleanupCourses(ALL_COURSE_IDS);
        await withDb(async (db) => {
            if (originalSuperSettings) {
                await db.collection('settings').replaceOne({ _id: SUPER_SETTINGS_ID }, originalSuperSettings, { upsert: true });
            } else {
                await db.collection('settings').deleteOne({ _id: SUPER_SETTINGS_ID });
            }
        });
    });

    test.beforeEach(async () => {
        await enableSuperCourse();
        // A 4th-year course in the Super Course pool.
        await seedCourse({
            courseId: POOL_HIGH,
            instructorId: studentId, // owner irrelevant for the pool
            courseName: 'BIOC 401 Advanced',
            overrides: { allowInSuperCourse: true, yearLevel: 4 },
        });
    });

    test('hasHigherLevelCourses is true when the pool reaches above the student level', async ({ request: api }) => {
        // Student is enrolled in a 2nd-year course only.
        await seedCourse({
            courseId: ENROLL_LOW,
            instructorId: studentId,
            courseName: 'BIOC 200 Intro',
            overrides: { yearLevel: 2 },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
        });

        const res = await api.get('/api/student/super-course/pool');
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.studentYearLevel).toBe(2);
        expect(body.poolMaxYearLevel).toBe(4);
        expect(body.hasHigherLevelCourses).toBe(true);
    });

    test('hasHigherLevelCourses is false when the student is already at/above the pool level', async ({ request: api }) => {
        // Student is enrolled in a graduate-level course (>= the pool's max).
        await seedCourse({
            courseId: ENROLL_HIGH,
            instructorId: studentId,
            courseName: 'BIOC 530 Graduate Seminar',
            overrides: { yearLevel: 5 },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
        });

        const res = await api.get('/api/student/super-course/pool');
        const body = await res.json();
        expect(body.studentYearLevel).toBe(5);
        expect(body.poolMaxYearLevel).toBe(4);
        expect(body.hasHigherLevelCourses).toBe(false);
    });
});
