/**
 * Deeper in-process route tests for src/routes/courses.js (supertest) — the
 * lifecycle/mutation endpoints not covered by courses.test.js: create, update,
 * retrieval-mode, soft-delete, and unit add/delete/rename. Same mock set as
 * courses.test.js (Qdrant/GridFS/llmKeyStore/llmKeyMiddleware) so requiring the
 * router is side-effect-free; the Course model runs real over the in-memory Mongo.
 */
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => ({
    initialize: jest.fn().mockResolvedValue(undefined),
    deleteDocumentChunks: jest.fn().mockResolvedValue(undefined),
})));
jest.mock('../../../src/services/gridfs', () => ({}));
jest.mock('../../../src/services/llmKeyStore', () => ({
    publicKeySummary: jest.fn((key) => (key ? { status: 'valid' } : { status: 'none' })),
    buildKeySubdocument: jest.fn(() => ({ enc: 'stub' })),
    decryptApiKey: jest.fn(() => 'sk'),
    validateApiKey: jest.fn(async () => ({ ok: true })),
}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({ resolveCourseAi: jest.fn() }));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const llmKeyStore = require('../../../src/services/llmKeyStore');
const coursesRouter = require('../../../src/routes/courses');

const instructor = { userId: 'i1', role: 'instructor' };
const otherInstructor = { userId: 'i2', role: 'instructor' };
const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(coursesRouter, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());
beforeEach(() => llmKeyStore.validateApiKey.mockResolvedValue({ ok: true }));

describe('POST / — create course', () => {
    // NOTE: contentTypes must be an array — the success path calls
    // generateCourseStructure(...contentTypes) which does contentTypes.includes(),
    // so omitting it 500s even though every other use treats it as optional.
    const body = { course: 'Biochem 200', weeks: 2, lecturesPerWeek: 2, apiKey: 'sk-test', contentTypes: ['practice-quizzes'] };

    test('401 without a user, 403 for a non-instructor', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/').send(body)).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: student })).post('/').send(body)).status).toBe(403);
    });

    test('400 when required fields are missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ course: 'X' });
        expect(res.status).toBe(400);
    });

    test('400 when weeks is out of the 1–20 range', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ ...body, weeks: 50 });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/weeks/i);
    });

    test('400 when lecturesPerWeek is out of the 1–5 range', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ ...body, lecturesPerWeek: 9 });
        expect(res.status).toBe(400);
    });

    test('400 when the API key fails validation', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'invalid' });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send(body);
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('LLM_KEY_INVALID');
    });

    test('201 creates the course and persists the key', async () => {
        const db = memoryDb({});
        const res = await request(app({ db, user: instructor })).post('/').send(body);
        expect(res.status).toBe(201);
        expect(res.body.data).toMatchObject({ name: 'Biochem 200', totalUnits: 4, aiAvailable: true, llmKey: { status: 'valid' } });
        const saved = await db.collection('courses').findOne({ courseId: res.body.data.id });
        expect(saved.llmApiKey).toEqual({ enc: 'stub' });
    });
});

describe('PUT /:courseId — update course', () => {
    test('400 when instructorId is absent', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).put('/C1').send({ name: 'X' });
        expect(res.status).toBe(400);
    });

    test('403 when the body instructorId does not match the session user', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).put('/C1').send({ name: 'X', instructorId: 'i2' });
        expect(res.status).toBe(403);
    });

    test('403 when the instructor has no access to the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i2' }] });
        const res = await request(app({ db, user: instructor })).put('/C1').send({ name: 'X', instructorId: 'i1' });
        expect(res.status).toBe(403);
    });

    test('200 updates the course name + status for the owner', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', courseName: 'Old' }] });
        const res = await request(app({ db, user: instructor })).put('/C1').send({ name: 'New Name', status: 'inactive', instructorId: 'i1' });
        expect(res.status).toBe(200);
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved).toMatchObject({ courseName: 'New Name', status: 'inactive' });
    });
});

describe('PUT /:courseId/retrieval-mode', () => {
    test('400 when isAdditiveRetrieval is not a boolean', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: 'yes' });
        expect(res.status).toBe(400);
    });

    test('404 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true });
        expect(res.status).toBe(404);
    });

    test('403 when the instructor is not on the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i2' }] });
        const res = await request(app({ db, user: instructor })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true });
        expect(res.status).toBe(403);
    });

    test('200 flips the retrieval mode', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', isAdditiveRetrieval: false }] });
        const res = await request(app({ db, user: instructor })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true });
        expect(res.status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).isAdditiveRetrieval).toBe(true);
    });
});

describe('DELETE /:courseId — soft delete', () => {
    test('400 when instructorId query param is missing', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).delete('/C1')).status).toBe(400);
    });

    test('404 when no owned course matches', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i2' }] });
        const res = await request(app({ db, user: instructor })).delete('/C1?instructorId=i1');
        expect(res.status).toBe(404);
    });

    test('200 sets status to deleted', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', status: 'active' }] });
        const res = await request(app({ db, user: instructor })).delete('/C1?instructorId=i1');
        expect(res.status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).status).toBe('deleted');
    });
});

describe('POST /:courseId/units — add a unit', () => {
    test('403 when the body instructorId does not match the user', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/C1/units').send({ instructorId: 'i2' });
        expect(res.status).toBe(403);
    });

    test('appends the next sequential unit and bumps totalUnits', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1', instructorId: 'i1',
            lectures: [{ name: 'Unit 1' }], courseStructure: { totalUnits: 1 },
        }] });
        const res = await request(app({ db, user: instructor })).post('/C1/units').send({ instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ totalUnits: 2, unit: { name: 'Unit 2' } });
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved.lectures.map(l => l.name)).toEqual(['Unit 1', 'Unit 2']);
        expect(saved.courseStructure.totalUnits).toBe(2);
    });
});

describe('DELETE /:courseId/units/:unitName', () => {
    test('400 when instructorId is absent from body and query', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).delete('/C1/units/Unit 1')).status).toBe(400);
    });

    test('404 when the unit is not in the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', lectures: [{ name: 'Unit 1', documents: [] }] }] });
        const res = await request(app({ db, user: instructor })).delete('/C1/units/Ghost?instructorId=i1');
        expect(res.status).toBe(404);
        expect(res.body.message).toMatch(/unit not found/i);
    });

    test('removes the unit (no documents) and decrements totalUnits', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1', instructorId: 'i1',
            lectures: [{ name: 'Unit 1', documents: [] }, { name: 'Unit 2', documents: [] }],
            courseStructure: { totalUnits: 2 },
        }] });
        const res = await request(app({ db, user: instructor })).delete('/C1/units/Unit 1?instructorId=i1');
        expect(res.status).toBe(200);
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved.lectures.map(l => l.name)).toEqual(['Unit 2']);
        expect(saved.courseStructure.totalUnits).toBe(1);
    });
});

describe('PUT /:courseId/units/:unitName/rename', () => {
    test('404 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor }))
            .put('/C1/units/Unit 1/rename').send({ displayName: 'Biology', instructorId: 'i1' });
        expect(res.status).toBe(404);
    });

    test('200 returns the new display name for an existing unit', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db, user: instructor }))
            .put('/C1/units/Unit 1/rename').send({ displayName: 'Biology', instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ unitName: 'Unit 1', displayName: 'Biology' });
    });

    test('404 when the unit does not exist', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db, user: instructor }))
            .put('/C1/units/Ghost/rename').send({ displayName: 'X', instructorId: 'i1' });
        expect(res.status).toBe(404);
    });
});
