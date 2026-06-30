/**
 * In-process route tests for src/routes/onboarding.js (supertest).
 *
 * Real: the Course model over the in-memory Mongo double, and llmKeyStore's crypto
 * helpers (buildKeySubdocument / publicKeySummary / stripPrivateKeyFields all run
 * for real under NODE_ENV=test). Only the network call `validateApiKey` is stubbed.
 * Covers the create gate + key validation, the access guards on read/update/delete,
 * the instructor course list ordering, completion, and the /stats route ordering.
 */
jest.mock('../../../src/services/llmKeyStore', () => {
    const actual = jest.requireActual('../../../src/services/llmKeyStore');
    return { ...actual, validateApiKey: jest.fn(async () => ({ ok: true })) };
});

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/onboarding');
const llmKeyStore = require('../../../src/services/llmKeyStore');

const instructor = { userId: 'i1', role: 'instructor' };
const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(router, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());
beforeEach(() => llmKeyStore.validateApiKey.mockReset().mockResolvedValue({ ok: true }));

describe('POST / — create course from onboarding', () => {
    const body = { courseId: 'C1', courseName: 'BIOC 202', apiKey: 'sk-test', courseStructure: { weeks: 1, lecturesPerWeek: 1 } };

    test('401 without a user, 403 for a non-instructor', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/').send(body)).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: student })).post('/').send(body)).status).toBe(403);
    });

    test('400 when courseId or courseName is missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ courseId: 'C1' });
        expect(res.status).toBe(400);
    });

    test('400 LLM_KEY_INVALID when the key fails validation', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'invalid', message: 'bad key' });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send(body);
        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ code: 'LLM_KEY_INVALID' });
    });

    test('400 LLM_KEY_QUOTA when the key is out of credits', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'quota_exhausted' });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send(body);
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });

    test('creates the course and stores a valid key summary', async () => {
        const db = memoryDb({});
        const res = await request(app({ db, user: instructor })).post('/').send(body);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ courseId: 'C1', created: true, llmKey: { status: 'valid' } });
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved.instructorId).toBe('i1');
        expect(saved.llmApiKey.status).toBe('valid');
    });

    test('evicts the course from the LLM registry cache after a key change', async () => {
        const llmRegistry = { evictCourse: jest.fn() };
        const db = memoryDb({});
        await request(app({ db, user: instructor, locals: { llmRegistry } })).post('/').send(body);
        expect(llmRegistry.evictCourse).toHaveBeenCalledWith('C1');
    });
});

describe('GET /test and GET /stats (static routes resolve before /:courseId)', () => {
    test('GET /test confirms the router is mounted', async () => {
        const res = await request(app({ db: memoryDb({}) })).get('/test');
        expect(res.status).toBe(200);
        expect(res.body.message).toMatch(/working/i);
    });

    test('GET /stats aggregates course + instructor counts (not treated as courseId="stats")', async () => {
        const db = memoryDb({ courses: [
            { courseId: 'C1', instructorId: 'i1' },
            { courseId: 'C2', instructorId: 'i2' },
        ] });
        const res = await request(app({ db, user: instructor })).get('/stats');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ totalCourses: 2, totalInstructors: 2 });
    });
});

describe('GET /:courseId', () => {
    test('404 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).get('/C1');
        expect(res.status).toBe(404);
    });

    test('403 when the caller is not an instructor/TA on the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'someone-else' }] });
        const res = await request(app({ db, user: instructor })).get('/C1');
        expect(res.status).toBe(403);
    });

    test('returns the course with private key fields stripped for an owning instructor', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', llmApiKey: { status: 'valid', ciphertext: 'secret' } }] });
        const res = await request(app({ db, user: instructor })).get('/C1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ courseId: 'C1', aiAvailable: true });
        expect(res.body.data).not.toHaveProperty('llmApiKey'); // ciphertext never leaves the server
        expect(res.body.data.llmKey).toMatchObject({ status: 'valid' });
    });
});

describe('GET /instructor/:instructorId', () => {
    test('403 when requesting another instructor\'s course list', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/instructor/someone-else');
        expect(res.status).toBe(403);
    });

    test('returns the instructor\'s own courses, active ones first', async () => {
        const db = memoryDb({ courses: [
            { courseId: 'C-inactive', instructorId: 'i1', status: 'inactive', courseName: 'Old' },
            { courseId: 'C-active', instructorId: 'i1', courseName: 'New', updatedAt: new Date() },
            { courseId: 'C-deleted', instructorId: 'i1', status: 'deleted' }, // excluded
        ] });
        const res = await request(app({ db, user: instructor })).get('/instructor/i1');
        expect(res.status).toBe(200);
        expect(res.body.data.count).toBe(2);
        expect(res.body.data.courses[0].courseId).toBe('C-active');
        expect(res.body.data.courses[1].courseId).toBe('C-inactive');
    });
});

describe('PUT /:courseId — update fields', () => {
    test('400 when there are no updates', async () => {
        const res = await request(app({ db: memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] }), user: instructor })).put('/C1').send({});
        expect(res.status).toBe(400);
    });

    test('403 when a non-owning instructor tries to update', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'someone-else' }] });
        const res = await request(app({ db, user: instructor })).put('/C1').send({ courseDescription: 'x' });
        expect(res.status).toBe(403);
    });

    test('200 persists the updated fields', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).put('/C1').send({ courseDescription: 'Updated desc' });
        expect(res.status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).courseDescription).toBe('Updated desc');
    });
});

describe('PUT /:courseId/unit-files', () => {
    test('400 when files is not an array', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).put('/C1/unit-files').send({ unitName: 'Unit 1', files: 'x' });
        expect(res.status).toBe(400);
    });

    test('200 for an owning instructor on an existing unit', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db, user: instructor })).put('/C1/unit-files').send({ unitName: 'Unit 1', files: ['a.pdf'] });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ unitName: 'Unit 1', filesCount: 1 });
    });
});

describe('DELETE /:courseId', () => {
    test('404 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).delete('/C1');
        expect(res.status).toBe(404);
    });

    test('an owning instructor deletes the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).delete('/C1');
        expect(res.status).toBe(200);
        expect(res.body.data.deletedCount).toBe(1);
        expect(await db.collection('courses').findOne({ courseId: 'C1' })).toBeNull();
    });
});

describe('DELETE /:courseId/unit/:unitName', () => {
    test('removes the named unit from the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', lectures: [{ name: 'Unit 1' }, { name: 'Unit 2' }] }] });
        const res = await request(app({ db, user: instructor })).delete('/C1/unit/Unit 1');
        expect(res.status).toBe(200);
        const saved = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(saved.lectures.map(l => l.name)).toEqual(['Unit 2']);
    });
});

describe('POST /complete', () => {
    test('403 when the body instructorId does not match the session user', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/complete').send({ courseId: 'C1', instructorId: 'other' });
        expect(res.status).toBe(403);
    });

    test('404 when the course does not exist', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/complete').send({ courseId: 'C1', instructorId: 'i1' });
        expect(res.status).toBe(404);
    });

    test('200 marks onboarding complete on the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).post('/complete').send({ courseId: 'C1', instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).isOnboardingComplete).toBe(true);
    });
});
