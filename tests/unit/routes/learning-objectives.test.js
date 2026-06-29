/**
 * In-process route tests for src/routes/learning-objectives.js (supertest).
 *
 * No heavy deps: the router reads the Course model over the in-memory Mongo double.
 * Covers required-field validation (with the week/lectureName alias), the read path,
 * the happy-path save, and the swallow-on-not-found characterization.
 *
 * NOTE: memory-db does not apply positional `lectures.$.x` writes, so the save test
 * asserts the route's response contract, not the mutated objectives (the read path is
 * covered separately with seeded objectives).
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/learning-objectives');

const app = (opts) => makeRouteApp(router, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('POST /', () => {
    const body = { lectureName: 'Unit 1', objectives: ['LO1', 'LO2'], instructorId: 'i1', courseId: 'C1' };

    test('400 when objectives is not an array', async () => {
        const res = await request(app({ db: memoryDb({}) })).post('/').send({ ...body, objectives: 'nope' });
        expect(res.status).toBe(400);
    });

    test('400 when courseId / instructorId / unitName are missing', async () => {
        const res = await request(app({ db: memoryDb({}) })).post('/').send({ objectives: ['LO1'] });
        expect(res.status).toBe(400);
    });

    test('accepts `week` as an alias for the unit name', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db })).post('/').send({ week: 'Unit 1', objectives: ['LO1'], instructorId: 'i1', courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body.data.unitName).toBe('Unit 1');
    });

    test('200 saves objectives for an existing lecture (echoes the request)', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db })).post('/').send(body);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ unitName: 'Unit 1', objectives: ['LO1', 'LO2'], instructorId: 'i1' });
    });

    test('still returns 200 even when the course does not exist (model not-found is swallowed)', async () => {
        // updateLearningObjectives returns { success:false } for a missing course/lecture,
        // but the route never inspects the result and always responds success. Characterized.
        const res = await request(app({ db: memoryDb({ courses: [] }) })).post('/').send(body);
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
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
