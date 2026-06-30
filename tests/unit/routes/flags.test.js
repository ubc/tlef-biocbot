/**
 * In-process route tests for src/routes/flags.js (supertest).
 * No heavy deps — the router uses FlaggedQuestion + Course models over memory-db
 * and req.user. Covers flag creation, the student "my flags" view, and the
 * instructor/TA-gated status-update / stats / delete paths.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const flagsRouter = require('../../../src/routes/flags');

const student = { userId: 's1', role: 'student', username: 'stu', displayName: 'Stu' };
const instructor = { userId: 'i1', role: 'instructor', username: 'ins' };
const ta = { userId: 't1', role: 'ta' };
const app = (opts) => makeRouteApp(flagsRouter, opts);

const validFlag = { questionId: 'q1', courseId: 'C1', unitName: 'Unit 1', flagReason: 'incorrect', flagDescription: 'wrong answer' };

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST / — create a flag', () => {
    test('401 without a user, 403 for a TA', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/').send(validFlag)).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: ta })).post('/').send(validFlag)).status).toBe(403);
    });

    test('400 when required fields are missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: student })).post('/').send({ courseId: 'C1' });
        expect(res.status).toBe(400);
    });

    test('404 when the (non-super) course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: student })).post('/').send(validFlag);
        expect(res.status).toBe(404);
    });

    test('403 when the student is not enrolled in the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', courseName: 'Bio' }] }); // exists, but s1 not enrolled
        expect((await request(app({ db, user: student })).post('/').send(validFlag)).status).toBe(403);
    });

    test('201/200 creates the flag for an enrolled student', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', courseName: 'Bio', studentEnrollment: { s1: { enrolled: true } } }] });
        const res = await request(app({ db, user: student })).post('/').send(validFlag);
        expect(res.status).toBe(200);
        expect(res.body.data.flagId).toBeTruthy();
        expect(await db.collection('flaggedQuestions').findOne({ flagId: res.body.data.flagId })).toBeTruthy();
    });
});

describe('GET /my — student\'s own flags', () => {
    test('401 without a user, 403 for a non-student', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/my')).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: instructor })).get('/my')).status).toBe(403);
    });

    test('returns the student\'s flags for an enrolled course', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', studentEnrollment: { s1: { enrolled: true } } }],
            flaggedQuestions: [{ flagId: 'f1', studentId: 's1', courseId: 'C1', status: 'pending' }],
        });
        const res = await request(app({ db, user: student })).get('/my?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.flags.map(f => f.flagId)).toContain('f1');
    });
});

describe('PUT /:flagId/status — instructor/TA review', () => {
    test('400 when status is missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).put('/f1/status').send({});
        expect(res.status).toBe(400);
    });

    test('403 when a student tries to update status', async () => {
        const res = await request(app({ db: memoryDb({}), user: student })).put('/f1/status').send({ status: 'resolved' });
        expect(res.status).toBe(403);
    });

    test('400 when the flag does not exist (legacy not-found contract)', async () => {
        const db = memoryDb({ flaggedQuestions: [] });
        const res = await request(app({ db, user: instructor })).put('/missing/status').send({ status: 'resolved' });
        expect(res.status).toBe(400);
    });

    test('200 when the course instructor updates the status', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }],
            flaggedQuestions: [{ flagId: 'f1', courseId: 'C1', status: 'pending' }],
        });
        const res = await request(app({ db, user: instructor })).put('/f1/status').send({ status: 'resolved' });
        expect(res.status).toBe(200);
        // The model persists the status under `flagStatus` (the API param is `status`).
        expect((await db.collection('flaggedQuestions').findOne({ flagId: 'f1' })).flagStatus).toBe('resolved');
    });
});

describe('GET /stats/:courseId', () => {
    test('403 when the user cannot read the course flags', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'someone-else' }] });
        expect((await request(app({ db, user: instructor })).get('/stats/C1')).status).toBe(403);
    });

    test('200 returns statistics for the course instructor', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }],
            flaggedQuestions: [{ flagId: 'f1', courseId: 'C1', status: 'pending' }],
        });
        const res = await request(app({ db, user: instructor })).get('/stats/C1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ courseId: 'C1' });
        expect(res.body.data.statistics).toBeDefined();
    });
});

describe('DELETE /:flagId', () => {
    test('the course instructor can delete a flag', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }],
            flaggedQuestions: [{ flagId: 'f1', courseId: 'C1', status: 'pending' }],
        });
        const res = await request(app({ db, user: instructor })).delete('/f1');
        expect(res.status).toBe(200);
        expect(await db.collection('flaggedQuestions').findOne({ flagId: 'f1' })).toBeNull();
    });
});

describe('instructor and TA flag review readers', () => {
    test('GET /course filters flags and enforces course access', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }],
            flaggedQuestions: [
                { flagId: 'f1', courseId: 'C1', flagStatus: 'pending' },
                { flagId: 'f2', courseId: 'C1', flagStatus: 'resolved' },
            ],
        });
        let res = await request(app({ db, user: instructor })).get('/course/C1?status=pending');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ courseId: 'C1', count: 1 });
        res = await request(app({ db, user: student })).get('/course/C1');
        expect(res.status).toBe(403);
    });

    test('GET /status scopes results to readable instructor courses', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }, { courseId: 'C2', instructorId: 'other' }],
            flaggedQuestions: [
                { flagId: 'f1', courseId: 'C1', flagStatus: 'pending' },
                { flagId: 'f2', courseId: 'C2', flagStatus: 'pending' },
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/status/pending');
        expect(res.status).toBe(200);
        expect(res.body.data.flags.map(flag => flag.flagId)).toEqual(['f1']);
        expect((await request(app({ db, user: student })).get('/status/pending')).status).toBe(403);
    });

    test('GET /:flagId returns an authorized flag and hides inaccessible flags', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }],
            flaggedQuestions: [{ flagId: 'f1', courseId: 'C1', flagStatus: 'pending' }],
        });
        expect((await request(app({ db, user: instructor })).get('/f1')).body.data.flagId).toBe('f1');
        expect((await request(app({ db, user: student })).get('/f1')).status).toBe(403);
        expect((await request(app({ db, user: instructor })).get('/missing')).status).toBe(404);
    });
});

describe('PUT /:flagId/response', () => {
    test('validates response and access', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).put('/f1/response').send({})).status).toBe(400);
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'other' }],
            flaggedQuestions: [{ flagId: 'f1', courseId: 'C1' }],
        });
        expect((await request(app({ db, user: instructor })).put('/f1/response').send({ response: 'Reviewed' })).status).toBe(403);
    });

    test('persists the authenticated instructor response and optional status', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1' }],
            flaggedQuestions: [{ flagId: 'f1', courseId: 'C1', flagStatus: 'pending' }],
        });
        const res = await request(app({ db, user: instructor })).put('/f1/response').send({ response: 'Corrected explanation', flagStatus: 'resolved' });
        expect(res.status).toBe(200);
        const stored = await db.collection('flaggedQuestions').findOne({ flagId: 'f1' });
        expect(stored).toMatchObject({ instructorResponse: 'Corrected explanation', flagStatus: 'resolved', instructorId: 'i1' });
    });
});
