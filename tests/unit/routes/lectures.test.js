/**
 * In-process route tests for src/routes/lectures.js (supertest).
 *
 * Real: the Course model over the in-memory Mongo double, and llmKeyStore's pure
 * key helpers (isKeyValid / structuredKeyError — no network at load). Covers the
 * publish toggle + its API-key gate, publish-status / student-visible readers, the
 * pass-threshold validators, and published-with-questions filtering.
 *
 * NOTE: memory-db does not apply positional `lectures.$.x` writes, so the publish
 * tests assert the route's response contract + read paths, not the flipped flag.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/lectures');

const instructor = { userId: 'i1', role: 'instructor' };
const app = (opts) => makeRouteApp(router, opts);

// Course owned by i1 with a Unit 1 lecture and a valid course key.
const course = (over = {}) => ({
    courseId: 'C1', courseName: 'Bio', instructorId: 'i1',
    llmApiKey: { status: 'valid', last4: '1234' },
    lectures: [{ name: 'Unit 1', isPublished: false }],
    ...over,
});

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST /publish', () => {
    test('400 when required fields are missing or wrong type', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor }))
            .post('/publish').send({ lectureName: 'Unit 1', courseId: 'C1' }); // no isPublished boolean
        expect(res.status).toBe(400);
    });

    test('401 without a user, 403 without course access', async () => {
        const body = { lectureName: 'Unit 1', isPublished: false, courseId: 'C1' };
        expect((await request(app({ db: memoryDb({ courses: [course()] }) })).post('/publish').send(body)).status).toBe(401);

        const stranger = { userId: 'nope', role: 'instructor' };
        expect((await request(app({ db: memoryDb({ courses: [course()] }), user: stranger })).post('/publish').send(body)).status).toBe(403);
    });

    test('publishing requires a valid course API key', async () => {
        const db = memoryDb({ courses: [course({ llmApiKey: { status: 'missing' } })] });
        const res = await request(app({ db, user: instructor }))
            .post('/publish').send({ lectureName: 'Unit 1', isPublished: true, courseId: 'C1' });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('LLM_KEY_MISSING');
        expect(res.body.message).toMatch(/valid course OpenAI API key/i);
    });

    test('publishes a lecture when the course key is valid', async () => {
        const db = memoryDb({ courses: [course()] });
        const res = await request(app({ db, user: instructor }))
            .post('/publish').send({ lectureName: 'Unit 1', isPublished: true, courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, data: { lectureName: 'Unit 1', isPublished: true, created: false } });
    });

    test('unpublishing does not require a key check', async () => {
        const db = memoryDb({ courses: [course({ llmApiKey: { status: 'missing' } })] });
        const res = await request(app({ db, user: instructor }))
            .post('/publish').send({ lectureName: 'Unit 1', isPublished: false, courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body.message).toMatch(/unpublished successfully/i);
    });

    test('404 when the lecture name is unknown', async () => {
        const db = memoryDb({ courses: [course()] });
        const res = await request(app({ db, user: instructor }))
            .post('/publish').send({ lectureName: 'Ghost Unit', isPublished: false, courseId: 'C1' });
        expect(res.status).toBe(404);
        expect(res.body).toEqual({ success: false, message: 'Lecture not found' });
    });
});

describe('GET /publish-status', () => {
    test('400 when instructorId or courseId is missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/publish-status?courseId=C1');
        expect(res.status).toBe(400);
    });

    test('returns an empty map for a course that does not exist (legacy contract)', async () => {
        const db = memoryDb({ courses: [] });
        const res = await request(app({ db, user: instructor })).get('/publish-status?instructorId=i1&courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.publishStatus).toEqual({});
    });

    test('403 when the caller has no access to an existing course', async () => {
        const db = memoryDb({ courses: [course({ instructorId: 'someone-else' })] });
        const res = await request(app({ db, user: instructor })).get('/publish-status?instructorId=i1&courseId=C1');
        expect(res.status).toBe(403);
    });

    test('returns the lecture→published map for the course instructor', async () => {
        const db = memoryDb({ courses: [course({ lectures: [
            { name: 'Unit 1', isPublished: true },
            { name: 'Unit 2', isPublished: false },
        ] })] });
        const res = await request(app({ db, user: instructor })).get('/publish-status?instructorId=i1&courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.publishStatus).toEqual({ 'Unit 1': true, 'Unit 2': false });
    });
});

describe('GET /student-visible', () => {
    test('400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/student-visible')).status).toBe(400);
    });

    test('returns the names of published lectures only', async () => {
        const db = memoryDb({ courses: [course({ lectures: [
            { name: 'Unit 1', isPublished: true },
            { name: 'Unit 2', isPublished: false },
            { name: 'Unit 3', isPublished: true },
        ] })] });
        const res = await request(app({ db })).get('/student-visible?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.publishedLectures).toEqual(['Unit 1', 'Unit 3']);
        expect(res.body.data.count).toBe(2);
    });
});

describe('POST /pass-threshold', () => {
    const base = { courseId: 'C1', lectureName: 'Unit 1', passThreshold: 60, instructorId: 'i1' };

    test('400 when passThreshold is not a number', async () => {
        const res = await request(app({ db: memoryDb({ courses: [course()] }), user: instructor }))
            .post('/pass-threshold').send({ ...base, passThreshold: 'high' });
        expect(res.status).toBe(400);
    });

    test('400 when passThreshold is out of the 0–100 range', async () => {
        const res = await request(app({ db: memoryDb({ courses: [course()] }), user: instructor }))
            .post('/pass-threshold').send({ ...base, passThreshold: 150 });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/between 0 and 100/i);
    });

    test('200 updates the threshold for an existing lecture', async () => {
        const db = memoryDb({ courses: [course()] });
        const res = await request(app({ db, user: instructor })).post('/pass-threshold').send(base);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ lectureName: 'Unit 1', passThreshold: 60 });
    });
});

describe('GET /pass-threshold', () => {
    test('400 when params are missing', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/pass-threshold?courseId=C1')).status).toBe(400);
    });

    test('returns the stored threshold for a lecture', async () => {
        const db = memoryDb({ courses: [course({ lectures: [{ name: 'Unit 1', isPublished: true, passThreshold: 75 }] })] });
        const res = await request(app({ db })).get('/pass-threshold?courseId=C1&lectureName=Unit 1');
        expect(res.status).toBe(200);
        expect(res.body.data.passThreshold).toBe(75);
    });
});

describe('GET /published-with-questions', () => {
    test('400 without courseId', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/published-with-questions')).status).toBe(400);
    });

    test('returns an empty list for a course with no lectures', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', courseName: 'Bio' }] });
        const res = await request(app({ db })).get('/published-with-questions?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ publishedLectures: [], count: 0 });
    });

    test('includes only published lectures, carrying their questions and objectives', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1', courseName: 'Bio',
            lectures: [
                { name: 'Unit 1', isPublished: true, learningObjectives: ['LO1'], assessmentQuestions: [{ questionId: 'q1' }] },
                { name: 'Unit 2', isPublished: false, assessmentQuestions: [{ questionId: 'q2' }] },
            ],
        }] });
        const res = await request(app({ db })).get('/published-with-questions?courseId=C1');
        expect(res.status).toBe(200);
        expect(res.body.data.count).toBe(1);
        expect(res.body.data.publishedLectures[0]).toMatchObject({
            name: 'Unit 1', passThreshold: 0, learningObjectives: ['LO1'], assessmentQuestions: [{ questionId: 'q1' }],
        });
    });
});

describe('db guards (503) and model failure paths (500)', () => {
    const CourseModel = require('../../../src/models/Course');

    test('every endpoint returns 503 when the db is unavailable', async () => {
        const noDb = app({ db: null, user: instructor });
        expect((await request(noDb).post('/publish').send({ lectureName: 'Unit 1', isPublished: false, courseId: 'C1' })).status).toBe(503);
        expect((await request(noDb).get('/publish-status?instructorId=i1&courseId=C1')).status).toBe(503);
        expect((await request(noDb).get('/student-visible?courseId=C1')).status).toBe(503);
        expect((await request(noDb).post('/pass-threshold').send({ courseId: 'C1', lectureName: 'Unit 1', passThreshold: 50, instructorId: 'i1' })).status).toBe(503);
        expect((await request(noDb).get('/pass-threshold?courseId=C1&lectureName=Unit 1')).status).toBe(503);
        expect((await request(noDb).get('/published-with-questions?courseId=C1')).status).toBe(503);
    });

    test('POST /publish 500 when the model throws', async () => {
        const spy = jest.spyOn(CourseModel, 'updateLecturePublishStatus').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({ courses: [course()] }), user: instructor }))
            .post('/publish').send({ lectureName: 'Unit 1', isPublished: false, courseId: 'C1' });
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/updating publish status/i);
        spy.mockRestore();
    });

    test('GET /publish-status 500 when the course lookup throws', async () => {
        const spy = jest.spyOn(CourseModel, 'getCourseById').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor }))
            .get('/publish-status?instructorId=i1&courseId=C1');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/fetching publish status/i);
        spy.mockRestore();
    });

    test('GET /student-visible 500 when the model throws', async () => {
        const spy = jest.spyOn(CourseModel, 'getPublishedLectures').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/student-visible?courseId=C1');
        expect(res.status).toBe(500);
        spy.mockRestore();
    });

    test('POST /pass-threshold 500 when the model throws', async () => {
        const spy = jest.spyOn(CourseModel, 'updatePassThreshold').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor }))
            .post('/pass-threshold').send({ courseId: 'C1', lectureName: 'Unit 1', passThreshold: 60, instructorId: 'i1' });
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/updating pass threshold/i);
        spy.mockRestore();
    });

    test('GET /pass-threshold 500 when the model throws', async () => {
        const spy = jest.spyOn(CourseModel, 'getPassThreshold').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/pass-threshold?courseId=C1&lectureName=Unit 1');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/fetching pass threshold/i);
        spy.mockRestore();
    });

    test('GET /published-with-questions 500 when the collection read throws', async () => {
        const throwingDb = { collection: () => ({ findOne: async () => { throw new Error('mongo down'); } }) };
        const res = await request(app({ db: throwingDb, user: instructor })).get('/published-with-questions?courseId=C1');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/fetching published lectures/i);
    });
});

describe('publish-status auth gate', () => {
    test('401 when there is no authenticated user', async () => {
        const res = await request(app({ db: memoryDb({ courses: [course()] }) }))
            .get('/publish-status?instructorId=i1&courseId=C1');
        expect(res.status).toBe(401);
    });
});
