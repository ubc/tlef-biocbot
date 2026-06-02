// @ts-check
/**
 * Instructor-facing Super Course "bucket" (superchat) management.
 *
 * Buckets are shared/global and any instructor (or admin) may create, edit, and
 * delete them via /api/superchats. Course->bucket membership is set per-course
 * via /api/settings/ai-settings (course owner or admin). Deleting a bucket
 * soft-deletes it and detaches it from every course.
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
const { readSuperchat } = require('./helpers/superchats-test');

const PREFIX = 'BIOC-E2E-SCAPI';
const COURSE_ID = `${PREFIX}-COURSE`;
const NAME_TAG = `${PREFIX}::bucket`; // unique marker so cleanup can find created buckets

let instructorId;
/** Track buckets created through the API so we can clean them up. */
const createdBucketIds = [];

async function cleanupCreatedBuckets() {
    await withDb((db) =>
        db.collection('superchats').deleteMany({
            $or: [
                { superchatId: { $in: createdBucketIds } },
                { name: { $regex: PREFIX } },
            ],
        })
    );
    createdBucketIds.length = 0;
}

test.use({ storageState: storageStatePath('instructor') });

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
});

test.beforeEach(async () => {
    await seedCourse({ courseId: COURSE_ID, instructorId, courseName: 'BIOC 202 SCAPI', overrides: { yearLevel: 2 } });
});

test.afterEach(async () => {
    await cleanupCreatedBuckets();
    await cleanupCourses([COURSE_ID]);
});

test.describe('Superchats CRUD (instructor)', () => {
    test('an instructor can create, list, edit, and delete a bucket', async ({ request: api }) => {
        // Create
        const create = await api.post('/api/superchats', {
            data: { name: `${NAME_TAG} create` },
        });
        expect(create.status()).toBe(201);
        const createBody = await create.json();
        expect(createBody.success).toBe(true);
        const id = createBody.superchat.superchatId;
        createdBucketIds.push(id);
        // New buckets are hidden from students by default.
        expect(createBody.superchat.showToStudents).toBe(false);

        // List includes it
        const list = await api.get('/api/superchats');
        expect(list.status()).toBe(200);
        const listIds = (await list.json()).superchats.map((b) => b.superchatId);
        expect(listIds).toContain(id);

        // Edit: rename, set a year level, make it student-visible
        const update = await api.put(`/api/superchats/${id}`, {
            data: { name: `${NAME_TAG} renamed`, yearLevel: 3, showToStudents: true, studentTopK: 7 },
        });
        expect(update.status()).toBe(200);
        const updated = (await update.json()).superchat;
        expect(updated.name).toBe(`${NAME_TAG} renamed`);
        expect(updated.yearLevel).toBe(3);
        expect(updated.showToStudents).toBe(true);
        expect(updated.settings.studentTopK).toBe(7);

        // Persisted
        const doc = await readSuperchat(id);
        expect(doc).toMatchObject({ name: `${NAME_TAG} renamed`, yearLevel: 3, showToStudents: true, studentTopK: 7 });

        // Delete (soft)
        const del = await api.delete(`/api/superchats/${id}`);
        expect(del.status()).toBe(200);
        const afterDoc = await readSuperchat(id);
        expect(afterDoc.isDeleted).toBe(true);

        // No longer listed
        const list2 = await api.get('/api/superchats');
        const list2Ids = (await list2.json()).superchats.map((b) => b.superchatId);
        expect(list2Ids).not.toContain(id);
    });

    test('create requires a name', async ({ request: api }) => {
        const resp = await api.post('/api/superchats', { data: {}, failOnStatusCode: false });
        expect(resp.status()).toBe(400);
    });

    test('GET/PUT/DELETE return 404 for an unknown bucket', async ({ request: api }) => {
        const getRes = await api.get('/api/superchats/does-not-exist', { failOnStatusCode: false });
        expect(getRes.status()).toBe(404);
        const putRes = await api.put('/api/superchats/does-not-exist', { data: { name: 'x' }, failOnStatusCode: false });
        expect(putRes.status()).toBe(404);
        const delRes = await api.delete('/api/superchats/does-not-exist', { failOnStatusCode: false });
        expect(delRes.status()).toBe(404);
    });
});

test.describe('Per-course bucket membership (instructor)', () => {
    test('assigning a course to buckets round-trips and is reflected in availableSuperchats', async ({ request: api }) => {
        // Create two buckets.
        const b1 = (await (await api.post('/api/superchats', { data: { name: `${NAME_TAG} A` } })).json()).superchat.superchatId;
        const b2 = (await (await api.post('/api/superchats', { data: { name: `${NAME_TAG} B` } })).json()).superchat.superchatId;
        createdBucketIds.push(b1, b2);

        // GET ai-settings lists both buckets and shows no membership yet.
        const before = await api.get(`/api/settings/ai-settings?courseId=${COURSE_ID}`);
        expect(before.status()).toBe(200);
        const beforeBody = await before.json();
        expect(beforeBody.settings.superchatIds).toEqual([]);
        const availIds = beforeBody.availableSuperchats.map((b) => b.superchatId);
        expect(availIds).toEqual(expect.arrayContaining([b1, b2]));

        // Assign the course to both buckets.
        const save = await api.put('/api/settings/ai-settings', {
            data: { courseId: COURSE_ID, superchatIds: [b1, b2], studentTopK: 3 },
        });
        expect(save.status()).toBe(200);

        const course = await withDb((db) => db.collection('courses').findOne({ courseId: COURSE_ID }));
        expect(course.superchatIds).toEqual(expect.arrayContaining([b1, b2]));

        // Re-read via the API.
        const after = await api.get(`/api/settings/ai-settings?courseId=${COURSE_ID}`);
        expect((await after.json()).settings.superchatIds).toEqual(expect.arrayContaining([b1, b2]));
    });

    test('deleting a bucket detaches it from member courses', async ({ request: api }) => {
        const bucketId = (await (await api.post('/api/superchats', { data: { name: `${NAME_TAG} detach` } })).json()).superchat.superchatId;
        createdBucketIds.push(bucketId);

        await api.put('/api/settings/ai-settings', {
            data: { courseId: COURSE_ID, superchatIds: [bucketId], studentTopK: 3 },
        });
        let course = await withDb((db) => db.collection('courses').findOne({ courseId: COURSE_ID }));
        expect(course.superchatIds).toContain(bucketId);

        // Delete the bucket -> it should be pulled from the course.
        const del = await api.delete(`/api/superchats/${bucketId}`);
        expect(del.status()).toBe(200);
        expect((await del.json()).coursesUpdated).toBeGreaterThanOrEqual(1);

        course = await withDb((db) => db.collection('courses').findOne({ courseId: COURSE_ID }));
        expect(course.superchatIds || []).not.toContain(bucketId);
    });
});
