// @ts-check
/**
 * Focused coverage for src/models/PersistenceTopic.js.
 *
 * The read path is exercised through the real instructor API. Model write-path
 * coverage lives in tests/unit/models/PersistenceTopic.test.js.
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

const COURSE_A = 'BIOC-E2E-PERSISTENCE-A';
const COURSE_B = 'BIOC-E2E-PERSISTENCE-B';

let instructorId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await cleanupPersistenceTopics();
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_A, COURSE_B]);
    await cleanupCoursesForUser(instructorId);
    await cleanupPersistenceTopics();
});

async function cleanupPersistenceTopics() {
    await withDb((db) =>
        db.collection('persistenceTopics').deleteMany({
            courseId: { $in: [COURSE_A, COURSE_B, 'BIOC-E2E-PERSISTENCE'] },
        })
    );
}

test.describe('/api/struggle-activity/persistence/:courseId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('returns only the selected course persistence topics sorted by student count', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        await seedCourse({ courseId: COURSE_B, instructorId });

        await withDb((db) =>
            db.collection('persistenceTopics').insertMany([
                {
                    courseId: COURSE_A,
                    topic: 'photosynthesis',
                    studentIds: ['student-a', 'student-b', 'student-c'],
                    studentCount: 3,
                    createdAt: new Date('2026-01-01T00:00:00Z'),
                    lastUpdated: new Date('2026-01-03T00:00:00Z'),
                },
                {
                    courseId: COURSE_A,
                    topic: 'glycolysis',
                    studentIds: ['student-d'],
                    studentCount: 1,
                    createdAt: new Date('2026-01-02T00:00:00Z'),
                    lastUpdated: new Date('2026-01-02T00:00:00Z'),
                },
                {
                    courseId: COURSE_B,
                    topic: 'mitosis',
                    studentIds: ['student-x', 'student-y', 'student-z', 'student-w'],
                    studentCount: 4,
                    createdAt: new Date('2026-01-04T00:00:00Z'),
                    lastUpdated: new Date('2026-01-04T00:00:00Z'),
                },
            ])
        );

        const res = await api.get(`/api/struggle-activity/persistence/${COURSE_A}`);
        expect(res.ok()).toBeTruthy();

        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.count).toBe(2);
        expect(body.data.map((topic) => topic.topic)).toEqual(['photosynthesis', 'glycolysis']);
        expect(body.data.map((topic) => topic.studentCount)).toEqual([3, 1]);
        expect(body.data.some((topic) => topic.courseId === COURSE_B)).toBe(false);
    });
});
