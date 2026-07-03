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
const { resolveCourseAi } = require('../../../src/routes/llmKeyMiddleware');
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
beforeEach(() => llmKeyStore.validateApiKey.mockReset().mockResolvedValue({ ok: true }));

describe('course-scoped LLM keys', () => {
    const keyedCourse = { courseId: 'C1', instructorId: 'i1', llmApiKey: { ciphertext: 'encrypted', status: 'unknown' } };

    test('PUT requires DB, authentication, an existing course, and instructor access', async () => {
        expect((await request(app({ db: null, user: instructor })).put('/C1/llm-key').send({ apiKey: 'sk' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [keyedCourse] }) })).put('/C1/llm-key').send({ apiKey: 'sk' })).status).toBe(401);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).put('/C1/llm-key').send({ apiKey: 'sk' })).status).toBe(404);
        expect((await request(app({ db: memoryDb({ courses: [{ ...keyedCourse, instructorId: 'i2' }] }), user: instructor })).put('/C1/llm-key').send({ apiKey: 'sk' })).status).toBe(403);
    });

    test('PUT maps invalid and exhausted key validation results', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'invalid', message: 'bad key', detail: 'detail' });
        let res = await request(app({ db: memoryDb({ courses: [keyedCourse] }), user: instructor })).put('/C1/llm-key').send({ apiKey: 'bad' });
        expect(res.body).toMatchObject({ success: false, code: 'LLM_KEY_INVALID', message: 'bad key' });
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'quota_exhausted', message: 'quota' });
        res = await request(app({ db: memoryDb({ courses: [keyedCourse] }), user: instructor })).put('/C1/llm-key').send({ apiKey: 'spent' });
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });

    test('PUT saves the key and evicts the course service cache', async () => {
        const db = memoryDb({ courses: [keyedCourse] });
        const registry = { evictCourse: jest.fn() };
        const res = await request(app({ db, user: instructor, locals: { llmRegistry: registry } })).put('/C1/llm-key').send({ apiKey: 'sk-new' });
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, aiAvailable: true });
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).llmApiKey).toEqual({ enc: 'stub' });
        expect(registry.evictCourse).toHaveBeenCalledWith('C1');
    });

    test('POST test reports a missing saved key', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1' }] });
        const res = await request(app({ db, user: instructor })).post('/C1/llm-key/test');
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('LLM_KEY_MISSING');
    });

    test('POST test persists valid status and evicts the cache', async () => {
        const db = memoryDb({ courses: [keyedCourse] });
        const registry = { evictCourse: jest.fn() };
        const res = await request(app({ db, user: instructor, locals: { llmRegistry: registry } })).post('/C1/llm-key/test');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, message: 'Course API key is valid', aiAvailable: true });
        expect(registry.evictCourse).toHaveBeenCalledWith('C1');
    });

    test('POST test maps quota and invalid statuses', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'quota_exhausted', message: 'spent' });
        let res = await request(app({ db: memoryDb({ courses: [keyedCourse] }), user: instructor })).post('/C1/llm-key/test');
        expect(res.body).toMatchObject({ success: false, code: 'LLM_KEY_QUOTA', aiAvailable: false });
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'invalid', message: 'bad' });
        res = await request(app({ db: memoryDb({ courses: [keyedCourse] }), user: instructor })).post('/C1/llm-key/test');
        expect(res.body.code).toBe('LLM_KEY_INVALID');
    });
});

describe('POST /:courseId/extract-topics — mocked LLM', () => {
    const topicCourse = {
        courseId: 'C1', instructorId: 'i1', tas: ['t1'],
        additionalMaterialSecondarySearch: false,
    };

    test('requires authentication, DB, course existence, and course access', async () => {
        expect((await request(app({ db: memoryDb({ courses: [topicCourse] }) })).post('/C1/extract-topics').send({ content: 'enzyme kinetics' })).status).toBe(401);
        expect((await request(app({ db: null, user: instructor })).post('/C1/extract-topics').send({ content: 'enzyme kinetics' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/C1/extract-topics').send({ content: 'enzyme kinetics' })).status).toBe(404);
        expect((await request(app({ db: memoryDb({ courses: [topicCourse] }), user: otherInstructor })).post('/C1/extract-topics').send({ content: 'enzyme kinetics' })).status).toBe(403);
    });

    test('filters mocked LLM suggestions to biochemical topics and clamps the limit', async () => {
        const sendMessage = jest.fn(async () => ({
            content: 'Result: {"topics":["Enzyme Kinetics","Protein Structure","Colonial History","ATP Synthesis","Enzyme Kinetics"]}',
        }));
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage } });
        const res = await request(app({ db: memoryDb({ courses: [topicCourse] }), user: instructor }))
            .post('/C1/extract-topics').send({ content: 'A long discussion of enzymes, proteins, and ATP.', maxTopics: 2 });
        expect(res.status).toBe(200);
        expect(res.body.data.topics).toEqual(['Enzyme Kinetics', 'Protein Structure']);
        expect(sendMessage).toHaveBeenCalledWith(expect.stringContaining('Return 2 or fewer'), expect.objectContaining({ temperature: 0.1 }));
    });

    test('accepts a TA assigned to the course', async () => {
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage: jest.fn(async () => ({ content: '{"topics":["DNA Replication"]}' })) } });
        const res = await request(app({ db: memoryDb({ courses: [topicCourse] }), user: { userId: 't1', role: 'ta' } }))
            .post('/C1/extract-topics').send({ content: 'DNA replication and nucleotides' });
        expect(res.status).toBe(200);
        expect(res.body.data.topics).toEqual(['DNA Replication']);
    });

    test('loads source content from a course document', async () => {
        const db = memoryDb({
            courses: [topicCourse],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'Protein folding and hydrophobic interactions', documentType: 'lecture_notes' }],
        });
        const sendMessage = jest.fn(async () => ({ content: '{"topics":["Protein Folding","Hydrophobic Interactions"]}' }));
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage } });
        const res = await request(app({ db, user: instructor })).post('/C1/extract-topics').send({ documentId: 'd1' });
        expect(res.status).toBe(200);
        expect(res.body.data.topics).toEqual(['Protein Folding', 'Hydrophobic Interactions']);
        expect(sendMessage.mock.calls[0][0]).toContain('Protein folding');
    });

    test('skips secondary additional material without invoking an LLM', async () => {
        const db = memoryDb({
            courses: [{ ...topicCourse, additionalMaterialSecondarySearch: true }],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'ATP', documentType: 'additional' }],
        });
        const res = await request(app({ db, user: instructor })).post('/C1/extract-topics').send({ documentId: 'd1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ topics: [], skippedAdditionalMaterial: true });
        expect(resolveCourseAi).not.toHaveBeenCalled();
    });

    test('rejects missing documents and empty source content', async () => {
        const db = memoryDb({ courses: [topicCourse], documents: [] });
        expect((await request(app({ db, user: instructor })).post('/C1/extract-topics').send({ documentId: 'missing' })).status).toBe(404);
        expect((await request(app({ db, user: instructor })).post('/C1/extract-topics').send({ content: '   ' })).status).toBe(400);
    });

    test('malformed or unavailable mocked LLM responses safely return no topics', async () => {
        resolveCourseAi.mockResolvedValueOnce({ llm: { sendMessage: jest.fn(async () => ({ content: 'not JSON' })) } });
        let res = await request(app({ db: memoryDb({ courses: [topicCourse] }), user: instructor }))
            .post('/C1/extract-topics').send({ content: 'enzyme kinetics' });
        expect(res.body.data.topics).toEqual([]);
        resolveCourseAi.mockResolvedValueOnce({ llm: null });
        res = await request(app({ db: memoryDb({ courses: [topicCourse] }), user: instructor }))
            .post('/C1/extract-topics').send({ content: 'enzyme kinetics' });
        expect(res.body.data.topics).toEqual([]);
    });
});

describe('document removal and material confirmation', () => {
    test('remove-document validates required fields and DB availability', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).post('/C1/remove-document').send({})).status).toBe(400);
        expect((await request(app({ db: null, user: instructor })).post('/C1/remove-document').send({ documentId: 'd1', instructorId: 'i1' })).status).toBe(503);
    });

    test('remove-document enforces course access', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i2' }] });
        const res = await request(app({ db, user: instructor })).post('/C1/remove-document').send({ documentId: 'd1', instructorId: 'i1' });
        expect(res.status).toBe(403);
    });

    test('remove-document maps model failure and success', async () => {
        const access = jest.spyOn(require('../../../src/models/Course'), 'userHasCourseAccess').mockResolvedValue(true);
        const remove = jest.spyOn(require('../../../src/models/Course'), 'removeDocumentFromAnyUnit');
        remove.mockResolvedValueOnce({ success: false, error: 'not attached' });
        let res = await request(app({ db: memoryDb({}), user: instructor })).post('/C1/remove-document').send({ documentId: 'd1', instructorId: 'i1' });
        expect(res.status).toBe(404);
        expect(res.body.message).toBe('not attached');
        remove.mockResolvedValueOnce({ success: true, removedCount: 2 });
        res = await request(app({ db: memoryDb({}), user: instructor })).post('/C1/remove-document').send({ documentId: 'd1', instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ documentId: 'd1', courseId: 'C1', removedCount: 2 });
        access.mockRestore();
        remove.mockRestore();
    });

    test('course-material confirmation validates fields, DB, and matching course/unit', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/course-materials/confirm').send({})).status).toBe(400);
        expect((await request(app({ db: null })).post('/course-materials/confirm').send({ week: 'Unit 1', instructorId: 'i1' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }) })).post('/course-materials/confirm').send({ week: 'Unit 1', instructorId: 'i1' })).status).toBe(404);
    });

    test('course-material confirmation updates the matching unit', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', lectures: [{ name: 'Unit 1' }] }] });
        const res = await request(app({ db })).post('/course-materials/confirm').send({ week: 'Unit 1', instructorId: 'i1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ week: 'Unit 1', courseId: 'C1', materialsConfirmed: true });
    });
});

describe('POST /:courseId/transfer', () => {
    const sourceCourse = {
        courseId: 'C1', courseName: 'BIOC 200', instructorId: 'i1', instructors: ['i1'],
        tas: ['t1'], taPermissions: { t1: { courses: true } },
        courseDescription: 'Source description', assessmentCriteria: 'Criteria',
        approvedStruggleTopics: [{ topic: 'ATP Synthesis', unitId: 'Unit 1' }],
        prompts: { base: 'Custom base' }, quizSettings: { enabled: true },
        questionPrompts: { systemPrompt: 'Question system' },
        mentalHealthDetectionPrompt: 'Safety prompt', isAdditiveRetrieval: true,
        lectures: [{
            name: 'Unit 1', displayName: 'Energy', isPublished: true,
            learningObjectives: ['Explain ATP'], passThreshold: 3,
            assessmentQuestions: [{ questionId: 'q1', question: 'ATP?' }],
            documents: [], materialsConfirmed: true,
        }],
    };

    test('requires authentication, instructor role, and a new course name', async () => {
        expect((await request(app({ db: memoryDb({ courses: [sourceCourse] }) })).post('/C1/transfer').send({ newCourseName: 'New' })).status).toBe(401);
        expect((await request(app({ db: memoryDb({ courses: [sourceCourse] }), user: student })).post('/C1/transfer').send({ newCourseName: 'New' })).status).toBe(403);
        expect((await request(app({ db: memoryDb({ courses: [sourceCourse] }), user: instructor })).post('/C1/transfer').send({ newCourseName: '   ' })).status).toBe(400);
    });

    test('rejects missing and inaccessible source courses', async () => {
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/missing/transfer').send({ newCourseName: 'New', apiKey: 'sk' })).status).toBe(404);
        const db = memoryDb({ courses: [{ ...sourceCourse, instructorId: 'i2', instructors: ['i2'] }] });
        expect((await request(app({ db, user: instructor })).post('/C1/transfer').send({ newCourseName: 'New', apiKey: 'sk' })).status).toBe(403);
    });

    test('maps mocked API-key quota validation', async () => {
        llmKeyStore.validateApiKey.mockResolvedValueOnce({ ok: false, status: 'quota_exhausted', message: 'spent' });
        const res = await request(app({ db: memoryDb({ courses: [sourceCourse] }), user: instructor })).post('/C1/transfer').send({ newCourseName: 'New', apiKey: 'spent' });
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
    });

    test('copies selected settings, TAs, objectives, and questions into an unpublished course', async () => {
        const db = memoryDb({ courses: [sourceCourse], documents: [] });
        const res = await request(app({ db, user: instructor })).post('/C1/transfer').send({
            newCourseName: ' BIOC 300 ', apiKey: 'sk-new', transferSettings: true, transferTAs: true,
        });
        expect(res.status).toBe(200);
        expect(res.body.data.summary).toEqual({ totalUnits: 1, documentsCopied: 0, settingsTransferred: true, tasTransferred: true });
        const target = await db.collection('courses').findOne({ courseId: res.body.data.courseId });
        expect(target).toMatchObject({
            courseName: 'BIOC 300', instructorId: 'i1', tas: ['t1'], status: 'active',
            prompts: { base: 'Custom base' }, quizSettings: { enabled: true }, isAdditiveRetrieval: true,
            lectures: [{ name: 'Unit 1', displayName: 'Energy', isPublished: false, learningObjectives: ['Explain ATP'], passThreshold: 3 }],
        });
        expect(target.lectures[0].assessmentQuestions).toHaveLength(1);
        expect(target.courseCode).not.toBe(target.instructorCourseCode);
    });

    test('honors per-unit exclusions and can deactivate the source', async () => {
        const db = memoryDb({ courses: [sourceCourse], documents: [] });
        const res = await request(app({ db, user: instructor })).post('/C1/transfer').send({
            newCourseName: 'Minimal Copy', apiKey: 'sk', transferSettings: false, transferTAs: false,
            deactivateSourceCourse: true,
            units: [{ unitName: 'Unit 1', transferDocuments: false, transferLearningObjectives: false, transferAssessmentQuestions: false }],
        });
        expect(res.status).toBe(200);
        const target = await db.collection('courses').findOne({ courseId: res.body.data.courseId });
        expect(target.tas).toEqual([]);
        expect(target.prompts).toBeUndefined();
        expect(target.lectures[0].learningObjectives).toEqual([]);
        expect(target.lectures[0].assessmentQuestions).toEqual([]);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).status).toBe('inactive');
    });
});

describe('POST / — create course', () => {
    const body = { course: 'Biochem 200', weeks: 2, lecturesPerWeek: 2, apiKey: 'sk-test', contentTypes: ['practice-quizzes'] };

    test('401 without a user, 403 for a non-instructor', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/').send(body)).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: student })).post('/').send(body)).status).toBe(403);
    });

    test('400 when required fields are missing', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ course: 'X' });
        expect(res.status).toBe(400);
    });

    test('400 when contentTypes is supplied with a non-array value', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor }))
            .post('/').send({ ...body, contentTypes: 'practice-quizzes' });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/contentTypes must be an array/i);
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

    test('201 creates a course with no contentTypes and returns empty material folders', async () => {
        const db = memoryDb({});
        const { contentTypes, ...withoutContentTypes } = body;

        const res = await request(app({ db, user: instructor })).post('/').send(withoutContentTypes);

        expect(res.status).toBe(201);
        expect(res.body.data.contentTypes).toEqual([]);
        expect(res.body.data.structure.specialFolders).toEqual([]);
        const saved = await db.collection('courses').findOne({ courseId: res.body.data.id });
        expect(saved.courseMaterials).toEqual([]);
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
