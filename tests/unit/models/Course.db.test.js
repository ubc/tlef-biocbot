/**
 * Unit tests for the DB-backed helpers of src/models/Course.js, run against the
 * in-memory Mongo double (tests/unit/helpers/memory-db.js).
 *
 * NOTE on the positional `$` operator: updateAssessmentQuestions /
 * deleteAssessmentQuestion write via `lectures.$.assessmentQuestions`, which
 * memory-db does NOT apply (see unit_tests.md §7). Their branch decisions and
 * return contracts come from the pre-write findOne(), so we assert those — not
 * the array mutation. Helpers that use computed-key $set (studentEnrollment.<id>,
 * taPermissions.<id>) ARE fully supported, so those get write->read round-trips.
 */
const { memoryDb } = require('../helpers/memory-db');
const Course = require('../../../src/models/Course');

beforeAll(() => {
    // Course logs verbosely on creates/updates/deletes.
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => {
    jest.restoreAllMocks();
});

describe('Course.updateCourseSuperchats', () => {
    test('normalizes, persists, and returns the new bucket list', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', superchatIds: ['old'] }] });
        const res = await Course.updateCourseSuperchats(db, 'C1', ['b', ' b ', 'a', '']);
        expect(res).toEqual({ success: true, superchatIds: ['b', 'a'], error: null });

        const stored = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(stored.superchatIds).toEqual(['b', 'a']);
    });

    test('returns "Course not found" for an unknown or deleted course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', status: 'deleted' }] });
        expect(await Course.updateCourseSuperchats(db, 'C1', ['x'])).toMatchObject({
            success: false,
            error: 'Course not found',
        });
        expect(await Course.updateCourseSuperchats(db, 'NOPE', ['x'])).toMatchObject({
            success: false,
            error: 'Course not found',
        });
    });
});

describe('Course.getLecturePublishStatus', () => {
    test('maps each lecture name to its isPublished flag', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [
                { name: 'Unit 1', isPublished: true },
                { name: 'Unit 2', isPublished: false },
            ] }],
        });
        expect(await Course.getLecturePublishStatus(db, 'C1')).toEqual({ 'Unit 1': true, 'Unit 2': false });
    });

    test('returns {} when the course or its lectures are missing', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C2' }] });
        expect(await Course.getLecturePublishStatus(db, 'C2')).toEqual({});
        expect(await Course.getLecturePublishStatus(db, 'NOPE')).toEqual({});
    });
});

describe('Course.getPublishedLectures', () => {
    test('returns the names (strings) of only the published lectures', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [
                { name: 'Unit 1', isPublished: true },
                { name: 'Unit 2', isPublished: false },
                { name: 'Unit 3', isPublished: true },
            ] }],
        });
        expect(await Course.getPublishedLectures(db, 'C1')).toEqual(['Unit 1', 'Unit 3']);
    });

    test('returns [] when nothing is published or the course is missing', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1', isPublished: false }] }] });
        expect(await Course.getPublishedLectures(db, 'C1')).toEqual([]);
        expect(await Course.getPublishedLectures(db, 'NOPE')).toEqual([]);
    });
});

describe('Course.getAssessmentQuestions', () => {
    test('returns the questions stored on the named lecture', async () => {
        const questions = [{ questionId: 'q1' }, { questionId: 'q2' }];
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: questions }] }],
        });
        expect(await Course.getAssessmentQuestions(db, 'C1', 'Unit 1')).toEqual(questions);
    });

    test('returns [] for a missing lecture, a lecture with no questions, or no course', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1' }] }],
        });
        expect(await Course.getAssessmentQuestions(db, 'C1', 'Unit 1')).toEqual([]);
        expect(await Course.getAssessmentQuestions(db, 'C1', 'Unit 99')).toEqual([]);
        expect(await Course.getAssessmentQuestions(db, 'NOPE', 'Unit 1')).toEqual([]);
    });
});

describe('Course.updateAssessmentQuestions (return contract; positional write not asserted)', () => {
    test('rejects when the course does not exist', async () => {
        const db = memoryDb({ courses: [] });
        expect(await Course.updateAssessmentQuestions(db, 'NOPE', 'Unit 1', {}, 'i1')).toEqual({
            success: false,
            error: 'Course not found',
        });
    });

    test('rejects when the lecture does not exist', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1' }] }] });
        expect(await Course.updateAssessmentQuestions(db, 'C1', 'Unit 9', {}, 'i1')).toEqual({
            success: false,
            error: 'Lecture not found',
        });
    });

    test('auto-generates a questionId and reports created:true for a new question', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: [] }] }] });
        const res = await Course.updateAssessmentQuestions(db, 'C1', 'Unit 1', { question: 'Q?' }, 'i1');
        expect(res.success).toBe(true);
        expect(res.created).toBe(true);
        expect(res.questionId).toMatch(/^q_\d+_[a-z0-9]+$/);
    });

    test('reports created:false when the questionId already exists on the lecture', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: [{ questionId: 'q1' }] }] }],
        });
        const res = await Course.updateAssessmentQuestions(db, 'C1', 'Unit 1', { questionId: 'q1', question: 'Edited' }, 'i1');
        expect(res).toMatchObject({ success: true, created: false, questionId: 'q1' });
    });
});

describe('Course.deleteAssessmentQuestion (return contract; positional write not asserted)', () => {
    test('rejects when course or lecture is missing', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1' }] }] });
        expect(await Course.deleteAssessmentQuestion(db, 'NOPE', 'Unit 1', 'q1', 'i1')).toMatchObject({
            success: false, error: 'Course not found',
        });
        expect(await Course.deleteAssessmentQuestion(db, 'C1', 'Unit 9', 'q1', 'i1')).toMatchObject({
            success: false, error: 'Lecture not found',
        });
    });

    test('is a no-op (deletedCount 0) when the question is not on the lecture', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: [{ questionId: 'q1' }] }] }],
        });
        expect(await Course.deleteAssessmentQuestion(db, 'C1', 'Unit 1', 'missing', 'i1')).toEqual({
            success: true, deletedCount: 0, questionId: 'missing',
        });
    });

    test('reports deletedCount 1 when the question exists', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1', assessmentQuestions: [{ questionId: 'q1' }] }] }],
        });
        expect(await Course.deleteAssessmentQuestion(db, 'C1', 'Unit 1', 'q1', 'i1')).toEqual({
            success: true, deletedCount: 1, questionId: 'q1',
        });
    });
});

describe('Course.userHasCourseAccess', () => {
    test('instructor: matches the primary instructorId or the instructors array', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1', instructors: ['i1', 'i2'] }],
        });
        expect(await Course.userHasCourseAccess(db, 'C1', 'i1', 'instructor')).toBe(true);
        expect(await Course.userHasCourseAccess(db, 'C1', 'i2', 'instructor')).toBe(true);
        expect(await Course.userHasCourseAccess(db, 'C1', 'someone', 'instructor')).toBe(false);
    });

    test('ta: matches an assigned TA but not on a deleted course', async () => {
        const active = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'] }] });
        expect(await Course.userHasCourseAccess(active, 'C1', 't1', 'ta')).toBe(true);
        expect(await Course.userHasCourseAccess(active, 'C1', 't2', 'ta')).toBe(false);

        const deleted = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'], status: 'deleted' }] });
        expect(await Course.userHasCourseAccess(deleted, 'C1', 't1', 'ta')).toBe(false);
    });

    test('student: true only when enrollment override is enrolled', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', studentEnrollment: { s1: { enrolled: true }, s2: { enrolled: false } } }],
        });
        expect(await Course.userHasCourseAccess(db, 'C1', 's1', 'student')).toBe(true);
        expect(await Course.userHasCourseAccess(db, 'C1', 's2', 'student')).toBe(false);
        expect(await Course.userHasCourseAccess(db, 'C1', 's3', 'student')).toBe(false);
    });

    test('unknown course is always false', async () => {
        const db = memoryDb({ courses: [] });
        expect(await Course.userHasCourseAccess(db, 'NOPE', 'i1', 'instructor')).toBe(false);
    });
});

describe('Course.getTAPermissions / updateTAPermissions', () => {
    test('getTAPermissions rejects for a missing course or unassigned TA', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'] }] });
        expect(await Course.getTAPermissions(db, 'NOPE', 't1')).toMatchObject({ success: false, error: 'Course not found' });
        expect(await Course.getTAPermissions(db, 'C1', 't2')).toMatchObject({
            success: false, error: 'TA is not assigned to this course',
        });
    });

    test('getTAPermissions defaults to full access when none are stored', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'] }] });
        expect(await Course.getTAPermissions(db, 'C1', 't1')).toEqual({
            success: true,
            permissions: { canAccessCourses: true, canAccessFlags: true },
        });
    });

    test('updateTAPermissions persists, and getTAPermissions reads it back', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'] }] });
        const upd = await Course.updateTAPermissions(db, 'C1', 't1', { canAccessCourses: false, canAccessFlags: true });
        expect(upd.success).toBe(true);

        const read = await Course.getTAPermissions(db, 'C1', 't1');
        expect(read.success).toBe(true);
        expect(read.permissions).toMatchObject({ canAccessCourses: false, canAccessFlags: true });
    });

    test('updateTAPermissions rejects for a missing course or unassigned TA', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'] }] });
        expect(await Course.updateTAPermissions(db, 'NOPE', 't1', {})).toMatchObject({ success: false, error: 'Course not found' });
        expect(await Course.updateTAPermissions(db, 'C1', 't2', {})).toMatchObject({
            success: false, error: 'TA is not assigned to this course',
        });
    });
});

describe('Course.checkTAPermission', () => {
    test('reflects the stored per-feature permission', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', tas: ['t1'], taPermissions: { t1: { canAccessCourses: true, canAccessFlags: false } } }],
        });
        expect(await Course.checkTAPermission(db, 'C1', 't1', 'courses')).toBe(true);
        expect(await Course.checkTAPermission(db, 'C1', 't1', 'flags')).toBe(false);
    });

    test('returns false for an unknown feature, an unassigned TA, or a deleted course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'] }] });
        expect(await Course.checkTAPermission(db, 'C1', 't1', 'banana')).toBe(false);
        expect(await Course.checkTAPermission(db, 'C1', 't2', 'courses')).toBe(false);

        const deleted = memoryDb({ courses: [{ courseId: 'C1', tas: ['t1'], status: 'deleted' }] });
        expect(await Course.checkTAPermission(deleted, 'C1', 't1', 'courses')).toBe(false);
    });
});

describe('Course.getStudentEnrollment / updateStudentEnrollment', () => {
    test('reports "none" when the student has no enrollment entry', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        expect(await Course.getStudentEnrollment(db, 'C1', 's1')).toEqual({
            success: true, enrolled: false, status: 'none',
        });
    });

    test('distinguishes enrolled (true) from banned (explicit false)', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', studentEnrollment: { s1: { enrolled: true }, s2: { enrolled: false } } }],
        });
        expect(await Course.getStudentEnrollment(db, 'C1', 's1')).toMatchObject({ enrolled: true, status: 'enrolled' });
        expect(await Course.getStudentEnrollment(db, 'C1', 's2')).toMatchObject({ enrolled: false, status: 'banned' });
    });

    test('an inactive/deleted course bans everyone with reason course_inactive', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', status: 'inactive', studentEnrollment: { s1: { enrolled: true } } }] });
        expect(await Course.getStudentEnrollment(db, 'C1', 's1')).toEqual({
            success: true, enrolled: false, status: 'banned', reason: 'course_inactive',
        });
    });

    test('rejects when the course is missing', async () => {
        const db = memoryDb({ courses: [] });
        expect(await Course.getStudentEnrollment(db, 'NOPE', 's1')).toMatchObject({ success: false, error: 'Course not found' });
    });

    test('updateStudentEnrollment persists and is read back by getStudentEnrollment', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        const upd = await Course.updateStudentEnrollment(db, 'C1', 's1', true);
        expect(upd.success).toBe(true);
        expect(await Course.getStudentEnrollment(db, 'C1', 's1')).toMatchObject({ enrolled: true, status: 'enrolled' });
    });

    test('updateStudentEnrollment rejects for a missing course', async () => {
        const db = memoryDb({ courses: [] });
        expect(await Course.updateStudentEnrollment(db, 'NOPE', 's1', true)).toMatchObject({
            success: false, error: 'Course not found',
        });
    });
});

describe('Course.createCourseFromOnboarding', () => {
    const onboarding = {
        courseId: 'BIOC401',
        courseName: 'BIOC 401',
        instructorId: 'i1',
        learningOutcomes: ['Explain glycolysis', 'Describe the Krebs cycle'],
        courseStructure: { weeks: 2, lecturesPerWeek: 3 },
    };

    test('creates a course with weeks*lecturesPerWeek units and inserts it', async () => {
        const db = memoryDb({ courses: [] });
        const res = await Course.createCourseFromOnboarding(db, onboarding);
        expect(res).toMatchObject({ success: true, created: true, courseId: 'BIOC401', totalUnits: 6 });

        const stored = await db.collection('courses').findOne({ courseId: 'BIOC401' });
        expect(stored.lectures).toHaveLength(6);
        expect(stored.instructors).toEqual(['i1']);
        expect(stored.superchatIds).toEqual([]);
        expect(stored.yearLevel).toBe(4); // derived from "BIOC 401"
    });

    test('seeds Unit 1 with the onboarding learning outcomes; later units start empty', async () => {
        const db = memoryDb({ courses: [] });
        await Course.createCourseFromOnboarding(db, onboarding);
        const stored = await db.collection('courses').findOne({ courseId: 'BIOC401' });

        const unit1 = stored.lectures.find(l => l.name === 'Unit 1');
        const unit2 = stored.lectures.find(l => l.name === 'Unit 2');
        expect(unit1.learningObjectives).toEqual(onboarding.learningOutcomes);
        expect(unit1.passThreshold).toBe(2);
        expect(unit1.isPublished).toBe(false);
        expect(unit2.learningObjectives).toEqual([]);
    });

    test('does not recreate when a course with the same courseId already exists', async () => {
        const db = memoryDb({ courses: [{ courseId: 'BIOC401', instructorId: 'other', courseStructure: { totalUnits: 9 } }] });
        const res = await Course.createCourseFromOnboarding(db, onboarding);
        expect(res).toMatchObject({ success: true, created: false, modifiedCount: 0, message: 'Course already exists', totalUnits: 9 });
    });

    test('does not recreate when the instructor already owns a course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'OTHER', instructorId: 'i1' }] });
        const res = await Course.createCourseFromOnboarding(db, onboarding);
        expect(res).toMatchObject({ success: true, created: false, courseId: 'OTHER' });
    });
});
