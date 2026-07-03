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
const { seedSuperchat, cleanupSuperchats } = require('./helpers/superchats-test');
const CourseModel = require('../../src/models/Course');

const PREFIX = 'BIOC-E2E-YEARLEVEL';
const COURSE_LEGACY = `${PREFIX}-LEGACY`;     // no stored yearLevel
const COURSE_STORED = `${PREFIX}-STORED`;     // explicit yearLevel
const COURSE_INVALID = `${PREFIX}-INVALID`;   // PUT with out-of-range value
const POOL_HIGH = `${PREFIX}-POOL-HIGH`;      // in bucket, 4th-year (not enrolled)
const ENROLL_LOW = `${PREFIX}-ENROLL-LOW`;    // student enrolled, 2nd-year, in bucket
const ENROLL_HIGH = `${PREFIX}-ENROLL-HIGH`;  // student enrolled, grad-level, in bucket
const SUPER_BUCKET_ID = `${PREFIX}-BUCKET`;   // the superchat the student chats

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
        // A standalone digit is accepted only when it is a valid year label (1-5).
        expect(CourseModel.parseYearLevelFromName('Year 3 Seminar')).toBe(3);
        // 4-digit codes: leading digit is still the year.
        expect(CourseModel.parseYearLevelFromName('PHYS 1010')).toBe(1);
        // 5xx+ maps to Graduate (clamped to 5).
        expect(CourseModel.parseYearLevelFromName('BIOC 530')).toBe(5);
        expect(CourseModel.parseYearLevelFromName('BIOC 600')).toBe(5);
    });

    test('parseYearLevelFromName returns null when no usable number is present', () => {
        expect(CourseModel.parseYearLevelFromName('Special Topics')).toBeNull();
        // Course numbers glued to letters no longer match (no word boundary),
        // and the old any-integer fallback is gone.
        expect(CourseModel.parseYearLevelFromName('BIOC401')).toBeNull();
        expect(CourseModel.parseYearLevelFromName('Section 7')).toBeNull(); // standalone digit outside 1-5
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
//
// Under the multi-superchat model the pool comes from a bucket's member courses,
// and the student must be enrolled in >=1 of those courses to access it. The
// student's effective level is the highest year among their enrolled courses.
// ---------------------------------------------------------------------------
test.describe('Super Course year-level detection', () => {
    test.use({ storageState: storageStatePath('student') });

    let studentId;

    test.beforeAll(async () => {
        studentId = await getUserIdByUsername(TEST_USERS.student.username);
    });

    test.afterAll(async () => {
        await cleanupCourses(ALL_COURSE_IDS);
        await cleanupSuperchats([SUPER_BUCKET_ID]);
    });

    test.beforeEach(async () => {
        // A student-visible bucket; a 4th-year course already sits in it.
        await seedSuperchat({ superchatId: SUPER_BUCKET_ID, name: 'Year-Level E2E Bucket', yearLevel: 4, showToStudents: true });
        await seedCourse({
            courseId: POOL_HIGH,
            instructorId: studentId, // owner irrelevant for the pool
            courseName: 'BIOC 401 Advanced',
            overrides: { yearLevel: 4, superchatIds: [SUPER_BUCKET_ID] },
        });
    });

    test('hasHigherLevelCourses is true when the pool reaches above the student level', async ({ request: api }) => {
        // Student is enrolled in a 2nd-year course that's also in the bucket
        // (enrollment is what grants bucket access).
        await seedCourse({
            courseId: ENROLL_LOW,
            instructorId: studentId,
            courseName: 'BIOC 200 Intro',
            overrides: { yearLevel: 2, superchatIds: [SUPER_BUCKET_ID] },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
        });

        const res = await api.get(`/api/student/super-course/pool?superchatId=${encodeURIComponent(SUPER_BUCKET_ID)}`);
        expect(res.status()).toBe(200);
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.studentYearLevel).toBe(2);
        expect(body.poolMaxYearLevel).toBe(4);
        expect(body.hasHigherLevelCourses).toBe(true);
    });

    test('hasHigherLevelCourses is false when the student is already at/above the pool level', async ({ request: api }) => {
        // Student is enrolled in a graduate-level course (also in the bucket), so
        // the pool's max no longer exceeds the student's level.
        await seedCourse({
            courseId: ENROLL_HIGH,
            instructorId: studentId,
            courseName: 'BIOC 530 Graduate Seminar',
            overrides: { yearLevel: 5, superchatIds: [SUPER_BUCKET_ID] },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: new Date() } },
        });

        const res = await api.get(`/api/student/super-course/pool?superchatId=${encodeURIComponent(SUPER_BUCKET_ID)}`);
        const body = await res.json();
        expect(body.studentYearLevel).toBe(5);
        // Pool now contains the grad course too, so its max is 5 (not above the student).
        expect(body.poolMaxYearLevel).toBe(5);
        expect(body.hasHigherLevelCourses).toBe(false);
    });
});
