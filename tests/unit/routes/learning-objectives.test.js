/**
 * In-process route tests for src/routes/learning-objectives.js (supertest).
 *
 * No heavy deps: the router reads the Course model over the in-memory Mongo double.
 * Covers required-field validation (with the week/lectureName alias), the read path,
 * the happy-path save, authorization, session-derived actor identity, and
 * missing-course/lecture failures.
 *
 * NOTE: memory-db does not apply positional `lectures.$.x` writes, so the save test
 * asserts the route's response contract, not the mutated objectives (the read path is
 * covered separately with seeded objectives).
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/learning-objectives');

const app = (opts) => makeRouteApp(router, opts);
const instructor = { userId: 'i1', role: 'instructor' };
const ownedCourse = (lectures = [{ name: 'Unit 1' }]) => ({
    courseId: 'C1', instructorId: 'i1', lectures,
});

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST /', () => {
    const body = { lectureName: 'Unit 1', objectives: ['LO1', 'LO2'], instructorId: 'i1', courseId: 'C1' };

    test('400 when objectives is not an array', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ ...body, objectives: 'nope' });
        expect(res.status).toBe(400);
    });

    test('400 when courseId / instructorId / unitName are missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ objectives: ['LO1'] });
        expect(res.status).toBe(400);
    });

    test('accepts `week` as an alias for the unit name', async () => {
        const db = memoryDb({ courses: [ownedCourse()] });
        const res = await request(app({ db, user: instructor })).post('/').send({ week: 'Unit 1', objectives: ['LO1'], instructorId: 'spoofed', courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body.data.unitName).toBe('Unit 1');
        expect(res.body.data.instructorId).toBe('i1');
    });

    test('200 saves objectives for an existing lecture (echoes the request)', async () => {
        const db = memoryDb({ courses: [ownedCourse()] });
        const res = await request(app({ db, user: instructor })).post('/').send(body);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ unitName: 'Unit 1', objectives: ['LO1', 'LO2'], instructorId: 'i1' });
    });

    test('401 without a session user and 403 without course management access', async () => {
        const db = memoryDb({ courses: [ownedCourse()] });
        expect((await request(app({ db })).post('/').send(body)).status).toBe(401);
        expect((await request(app({ db, user: { userId: 's1', role: 'student' } })).post('/').send(body)).status).toBe(403);
    });

    test('404 when the course or lecture does not exist', async () => {
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/').send(body)).status).toBe(404);

        const db = memoryDb({ courses: [ownedCourse()] });
        const res = await request(app({ db, user: instructor })).post('/').send({ ...body, lectureName: 'Ghost' });
        expect(res.status).toBe(404);
        expect(res.body.message).toBe('Lecture not found');
    });
});

describe('GET /', () => {
    test('400 when params are missing', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/?courseId=C1')).status).toBe(400);
    });

    test('returns the lecture\'s stored objectives', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [
            { name: 'Unit 1', learningObjectives: ['LO1', 'LO2'] },
            { name: 'Unit 2', learningObjectives: ['other'] },
        ] }] });
        const res = await request(app({ db })).get('/?courseId=C1&lectureName=Unit 1');
        expect(res.status).toBe(200);
        expect(res.body.data.objectives).toEqual(['LO1', 'LO2']);
    });

    test('returns an empty list for an unknown lecture', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db })).get('/?courseId=C1&lectureName=Ghost');
        expect(res.status).toBe(200);
        expect(res.body.data.objectives).toEqual([]);
    });
});

describe('db guard and model failure paths', () => {
    const CourseModel = require('../../../src/models/Course');

    test('503 on POST and GET when the db is unavailable', async () => {
        const body = { lectureName: 'Unit 1', objectives: ['LO1'], instructorId: 'i1', courseId: 'C1' };
        expect((await request(app({ db: null, user: instructor })).post('/').send(body)).status).toBe(503);
        expect((await request(app({ db: null })).get('/?courseId=C1&lectureName=Unit 1')).status).toBe(503);
    });

    test('POST 500 when the model throws', async () => {
        const spy = jest.spyOn(CourseModel, 'updateLearningObjectives').mockRejectedValueOnce(new Error('mongo down'));
        const body = { lectureName: 'Unit 1', objectives: ['LO1'], instructorId: 'i1', courseId: 'C1' };
        const res = await request(app({ db: memoryDb({ courses: [ownedCourse()] }), user: instructor })).post('/').send(body);
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/saving learning objectives/i);
        spy.mockRestore();
    });

    test('GET 500 when the model throws', async () => {
        const spy = jest.spyOn(CourseModel, 'getLearningObjectives').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}) })).get('/?courseId=C1&lectureName=Unit 1');
        expect(res.status).toBe(500);
        expect(res.body.message).toMatch(/fetching learning objectives/i);
        spy.mockRestore();
    });
});
