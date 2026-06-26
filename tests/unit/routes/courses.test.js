/**
 * In-process route tests for src/routes/courses.js (supertest) — a cross-section
 * of the large router: the instructor course list, single-course access, and TA
 * management. Heavy collaborators (Qdrant vector service, GridFS, the LLM key
 * store/middleware) are mocked so requiring the router is side-effect-free; the
 * Course model runs for real over the in-memory Mongo.
 */
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => ({
    initialize: jest.fn().mockResolvedValue(undefined),
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
const coursesRouter = require('../../../src/routes/courses');

const instructor = { userId: 'i1', role: 'instructor' };
const ta = { userId: 't1', role: 'ta' };
const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(coursesRouter, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET / — instructor course list', () => {
    test('401 without a user', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/')).status).toBe(401);
    });

    test('403 for a non-instructor', async () => {
        expect((await request(app({ db: memoryDb({}), user: student })).get('/')).status).toBe(403);
    });

    test('503 when the db is unavailable', async () => {
        expect((await request(app({ db: null, user: instructor })).get('/')).status).toBe(503);
    });

    test('200 returns the instructor\'s active courses, transformed, excluding deleted', async () => {
        const db = memoryDb({ courses: [
            { courseId: 'C1', courseName: 'Bio', instructorId: 'i1', llmApiKey: { enc: 'k' }, courseStructure: { weeks: 2, lecturesPerWeek: 3, totalUnits: 6 } },
            { courseId: 'C2', courseName: 'Gone', instructorId: 'i1', status: 'deleted' },
            { courseId: 'C3', courseName: 'Other', instructorId: 'someone-else' },
        ] });
        const res = await request(app({ db, user: instructor })).get('/');
        expect(res.status).toBe(200);
        expect(res.body.data).toHaveLength(1);
        expect(res.body.data[0]).toMatchObject({ id: 'C1', name: 'Bio', aiAvailable: true, weeks: 2, totalUnits: 6 });
    });
});

describe('GET /:courseId', () => {
    test('401 without a user', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/C1')).status).toBe(401);
    });

    test('404 when the instructor has no access to the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'someone-else' }] });
        expect((await request(app({ db, user: instructor })).get('/C1')).status).toBe(404);
    });

    test('200 for the course instructor', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', courseName: 'Bio', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).get('/C1');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
    });

    test('200 for a TA assigned to the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', courseName: 'Bio', tas: ['t1'] }] });
        expect((await request(app({ db, user: ta })).get('/C1')).status).toBe(200);
    });
});

describe('POST /:courseId/tas — add a TA', () => {
    test('403 for a non-instructor', async () => {
        expect((await request(app({ db: memoryDb({}), user: ta })).post('/C1/tas').send({ taId: 't2' })).status).toBe(403);
    });

    test('400 when taId is missing', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        expect((await request(app({ db, user: instructor })).post('/C1/tas').send({})).status).toBe(400);
    });

    test('200 adds the TA and persists it', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).post('/C1/tas').send({ taId: 't1' });
        expect(res.status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).tas).toContain('t1');
    });

    test('400 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/NOPE/tas').send({ taId: 't1' });
        expect(res.status).toBe(400);
    });
});
