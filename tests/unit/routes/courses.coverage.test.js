/** Focused branch coverage for the larger courses router. */
const mockQdrant = {
    initialize: jest.fn().mockResolvedValue(undefined),
    cloneDocumentChunks: jest.fn().mockResolvedValue({ success: true, clonedCount: 2 }),
    deleteDocumentChunks: jest.fn().mockResolvedValue(undefined),
};
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => mockQdrant));
jest.mock('../../../src/services/gridfs', () => ({ copyFile: jest.fn(async () => 'copied-file') }));
jest.mock('../../../src/services/llmKeyStore', () => ({
    publicKeySummary: jest.fn((key) => key ? { status: key.status || 'valid' } : { status: 'none' }),
    buildKeySubdocument: jest.fn(() => ({ ciphertext: 'encrypted', status: 'valid' })),
    decryptApiKey: jest.fn(() => 'sk'),
    validateApiKey: jest.fn(async () => ({ ok: true })),
}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({ resolveCourseAi: jest.fn() }));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const CourseModel = require('../../../src/models/Course');
const DocumentModel = require('../../../src/models/Document');
const coursesRouter = require('../../../src/routes/courses');

const instructor = { userId: 'i1', role: 'instructor' };
const ta = { userId: 't1', role: 'ta' };
const student = { userId: 's1', role: 'student' };
const app = (opts) => makeRouteApp(coursesRouter, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());
beforeEach(() => jest.clearAllMocks());

describe('GET /statistics', () => {
    test('enforces authentication, role, and database availability', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/statistics')).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: student })).get('/statistics')).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).get('/statistics')).status).toBe(503);
    });

    test('returns numeric zeroes when no accessible course exists', async () => {
        const res = await request(app({ db: memoryDb({ courses: [] }), user: instructor })).get('/statistics?courseId=missing');
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({
            totalStudents: 0, totalSessions: 0, modeDistribution: { tutor: 0, protege: 0 },
            averageSessionLength: 0, averageMessagesPerSession: 0, averageMessageLength: 0,
        });
    });

    test('aggregates modes, messages, students, and a seconds-long session', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', instructorId: 'i1', status: 'active' }],
            chat_sessions: [
                { courseId: 'C1', studentId: 's1', chatData: { metadata: { currentMode: 'protege' }, messages: [
                    { type: 'user', content: '12345', timestamp: '2026-01-01T00:00:00Z' },
                    { type: 'bot', content: '123456789', timestamp: '2026-01-01T00:00:45Z' },
                ] } },
                { courseId: 'C1', studentId: 's1', isDeleted: false, chatData: { messages: [{ type: 'user', content: 42 }] } },
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/statistics');
        expect(res.body.data).toEqual({
            totalStudents: 1, totalSessions: 2, modeDistribution: { tutor: 1, protege: 1 },
            averageSessionLength: '45s', averageSessionLengthSeconds: 45,
            averageMessagesPerSession: 1.5, averageMessageLength: 7,
        });
    });

    test('supports TA scoping, the accented mode, and hour formatting', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', tas: ['t1'] }, { courseId: 'C2', tas: ['other'] }],
            chat_sessions: [{ courseId: 'C1', studentId: 's2', chatData: { metadata: { currentMode: 'protégé' }, messages: [
                { type: 'user', content: 'a', timestamp: '2026-01-01T00:00:00Z' },
                { type: 'bot', content: 'b', timestamp: '2026-01-01T01:01:00Z' },
            ] } }],
        });
        const res = await request(app({ db, user: ta })).get('/statistics?courseId=C1');
        expect(res.body.data).toMatchObject({ totalStudents: 1, modeDistribution: { tutor: 0, protege: 1 }, averageSessionLength: '1h 1m' });
    });
});

describe('stub content upload and richer transfer behavior', () => {
    test('content upload validates fields and applies defaults', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/C1/content').send({})).status).toBe(400);
        const res = await request(app({ db: memoryDb({}) })).post('/C1/content').send({
            title: 'Notes', week: '2', type: 'notes', instructorId: 'i1', fileName: 'n.txt', fileSize: 10,
        });
        expect(res.status).toBe(201);
        expect(res.body.data).toMatchObject({ courseId: 'C1', title: 'Notes', description: '', week: 2, status: 'processing', fileName: 'n.txt', fileSize: 10 });
    });

    test('transfer clones text and GridFS documents and records successful references', async () => {
        const source = {
            courseId: 'C1', courseName: 'Source', instructorId: 'i1', instructors: ['i1'], lectures: [{
                name: 'Unit 1', documents: [{ documentId: 'd1' }, { documentId: 'd2' }],
            }],
        };
        const db = memoryDb({ courses: [source], documents: [
            { documentId: 'd1', courseId: 'C1', lectureName: 'Unit 1', contentType: 'text', content: 'ATP text', filename: 'a.txt', status: 'parsed', metadata: { x: 1 } },
            { documentId: 'd2', courseId: 'C1', lectureName: 'Unit 1', contentType: 'file', fileId: 'old-file', filename: 'b.pdf', mimeType: 'application/pdf', size: 12 },
        ] });
        const res = await request(app({ db, user: instructor })).post('/C1/transfer').send({ newCourseName: 'Clone', apiKey: 'sk' });
        expect(res.status).toBe(200);
        expect(res.body.data.summary.documentsCopied).toBe(2);
        expect(res.body.data.warnings).toEqual([]);
        expect(mockQdrant.cloneDocumentChunks).toHaveBeenCalledTimes(2);
        expect(await db.collection('documents').find({ courseId: res.body.data.courseId }).toArray()).toHaveLength(2);
    });

    test('transfer preserves progress while reporting missing chunks as a warning', async () => {
        mockQdrant.cloneDocumentChunks.mockResolvedValueOnce({ success: true, clonedCount: 0 });
        const db = memoryDb({
            courses: [{ courseId: 'C1', courseName: 'Source', instructorId: 'i1', lectures: [{ name: 'Unit 1', documents: [{ documentId: 'd1' }] }] }],
            documents: [{ documentId: 'd1', courseId: 'C1', lectureName: 'Unit 1', contentType: 'file', fileData: Buffer.from('markdown').toString('base64'), mimeType: 'text/markdown', status: 'parsed' }],
        });
        const res = await request(app({ db, user: instructor })).post('/C1/transfer').send({ newCourseName: 'Clone', apiKey: 'sk' });
        expect(res.status).toBe(200);
        expect(res.body.data.warnings[0]).toMatch(/No stored chunks/);
    });
});

describe('student course view and TA course listing', () => {
    test('student view handles DB, missing-course, inactive, and instructor-disabled enrollment', async () => {
        expect((await request(app({ db: null, user: student })).get('/C1')).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: student })).get('/C1')).status).toBe(404);
        let db = memoryDb({ courses: [{ courseId: 'C1', status: 'inactive' }] });
        let res = await request(app({ db, user: student })).get('/C1');
        expect(res.status).toBe(403);
        expect(res.body.message).toMatch(/deactivated/);
        db = memoryDb({ courses: [{ courseId: 'C1', studentEnrollment: { s1: { enrolled: false } } }] });
        res = await request(app({ db, user: student })).get('/C1');
        expect(res.status).toBe(403);
        expect(res.body.message).toMatch(/disabled/);
    });

    test('student view returns the complete student-safe course projection', async () => {
        const db = memoryDb({ courses: [{
            courseId: 'C1', courseName: 'BIOC 301', status: 'active', llmApiKey: { status: 'valid' },
            studentEnrollment: { s1: { enrolled: true } },
            courseStructure: { weeks: 2, lecturesPerWeek: 2 }, approvedStruggleTopics: ['ATP'],
            prompts: { studentIdleTimeout: 90 }, isAdditiveRetrieval: true,
            lectures: [{ id: 'u1', name: 'Unit 1', displayName: 'Energy', isPublished: true, documents: [{ documentId: 'd1' }], questions: ['q'], passThreshold: 3 }],
        }] });
        const res = await request(app({ db, user: student })).get('/C1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ id: 'C1', name: 'BIOC 301', yearLevel: 3, studentIdleTimeout: 90, isAdditiveRetrieval: true });
        expect(res.body.data.lectures[0]).toMatchObject({ id: 'u1', displayName: 'Energy', isPublished: true, passThreshold: 3 });
        expect(res.body.data.structure.weeks[0]).toMatchObject({ id: 'week-1', documents: 1 });
    });

    test('TA listing validates identity and transforms assigned courses', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/ta/t1')).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: instructor })).get('/ta/t1')).status).toBe(403);
        expect((await request(app({ db: null, user: ta })).get('/ta/t1')).status).toBe(503);
        const now = new Date('2026-01-01T00:00:00Z');
        const db = memoryDb({ courses: [{ courseId: 'C1', courseName: 'Course', instructorId: 'i1', tas: ['t1'], llmApiKey: { status: 'valid' }, createdAt: now, updatedAt: now, courseStructure: { totalUnits: 4 } }] });
        const res = await request(app({ db, user: ta })).get('/ta/t1');
        expect(res.status).toBe(200);
        expect(res.body.data[0]).toMatchObject({ courseId: 'C1', instructors: ['i1'], tas: ['t1'], aiAvailable: true, totalUnits: 4 });
    });
});

describe('unhappy-path contracts', () => {
    test('router catch blocks map database exceptions without leaking them', async () => {
        const broken = { collection: () => { throw new Error('db exploded'); } };
        expect((await request(app({ db: broken, user: instructor })).get('/')).status).toBe(500);
        expect((await request(app({ db: broken, user: instructor })).get('/statistics')).status).toBe(500);
        expect((await request(app({ db: broken, user: instructor })).get('/C1')).status).toBe(500);
        expect((await request(app({ db: broken, user: instructor })).post('/C1/tas').send({ taId: 't1' })).status).toBe(500);
        expect((await request(app({ db: broken, user: instructor })).put('/C1/student-enrollment/s1').send({ enrolled: true })).status).toBe(500);
        expect((await request(app({ db: broken, user: ta })).get('/ta/t1')).status).toBe(500);
        expect((await request(app({ db: broken, user: student })).get('/C1')).status).toBe(500);
    });

    test('model failure responses are preserved for TA and enrollment mutations', async () => {
        const add = jest.spyOn(CourseModel, 'addTAToCourse').mockResolvedValueOnce({ success: false, error: 'no course' });
        let res = await request(app({ db: memoryDb({}), user: instructor })).post('/C1/tas').send({ taId: 't1' });
        expect(res.status).toBe(400);
        expect(res.body.message).toBe('no course');
        add.mockRestore();

        const access = jest.spyOn(CourseModel, 'userHasCourseAccess').mockResolvedValueOnce(true);
        const update = jest.spyOn(CourseModel, 'updateStudentEnrollment').mockResolvedValueOnce({ success: false, error: 'bad enrollment' });
        res = await request(app({ db: memoryDb({}), user: instructor })).put('/C1/student-enrollment/s1').send({ enrolled: true });
        expect(res.status).toBe(400);
        expect(res.body.message).toBe('bad enrollment');
        access.mockRestore(); update.mockRestore();
    });

    test('unit deletion tolerates document and vector cleanup failures', async () => {
        const del = jest.spyOn(DocumentModel, 'deleteDocument').mockRejectedValueOnce(new Error('mongo cleanup'));
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', courseStructure: { totalUnits: 1 }, lectures: [{ name: 'Unit 1', documents: [{ documentId: 'd1' }] }] }] });
        const res = await request(app({ db, user: instructor })).delete('/C1/units/Unit%201?instructorId=i1');
        expect(res.status).toBe(200);
        expect(res.body.data.deletedDocumentsCount).toBe(0);
        del.mockRestore();
    });
});

describe('remaining public validation and role branches', () => {
    const course = { courseId: 'C1', courseName: 'Course', instructorId: 'i1', instructors: ['i1'], tas: ['t1'], courseCode: 'STUDENT', instructorCourseCode: 'TEACHER' };

    test('approved-topic routes cover missing DB/course/auth and model failures', async () => {
        expect((await request(app({ db: null, user: instructor })).get('/C1/approved-topics')).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).get('/C1/approved-topics')).status).toBe(404);
        expect((await request(app({ db: memoryDb({ courses: [course] }) })).put('/C1/approved-topics').send({ topics: [] })).status).toBe(401);
        expect((await request(app({ db: null, user: instructor })).put('/C1/approved-topics').send({ topics: [] })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).put('/C1/approved-topics').send({ topics: [] })).status).toBe(404);
        expect((await request(app({ db: memoryDb({ courses: [course] }) })).patch('/C1/approved-topics/unit').send({ topic: 'ATP' })).status).toBe(401);
        expect((await request(app({ db: null, user: instructor })).patch('/C1/approved-topics/unit').send({ topic: 'ATP' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).patch('/C1/approved-topics/unit').send({ topic: 'ATP' })).status).toBe(404);
        const set = jest.spyOn(CourseModel, 'setApprovedStruggleTopics').mockResolvedValueOnce({ success: false, error: 'gone' });
        expect((await request(app({ db: memoryDb({ courses: [course] }), user: instructor })).put('/C1/approved-topics').send({ topics: [] })).status).toBe(404);
        set.mockRestore();
    });

    test('update covers DB/auth, year/structure/prompts/lectures, and unmatched write', async () => {
        expect((await request(app({ db: null, user: instructor })).put('/C1').send({ instructorId: 'i1' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [course] }) })).put('/C1').send({ instructorId: 'i1' })).status).toBe(401);
        let db = memoryDb({ courses: [{ ...course, prompts: { old: 'keep' } }] });
        let res = await request(app({ db, user: instructor })).put('/C1').send({
            instructorId: 'i1', yearLevel: '4', weeks: 3, lecturesPerWeek: 2,
            base: 'base', protege: 'p', tutor: 't', lectures: [{ name: 'New' }],
        });
        expect(res.status).toBe(200);
        expect(await db.collection('courses').findOne({ courseId: 'C1' })).toMatchObject({
            yearLevel: 4, courseStructure: { weeks: 3, lecturesPerWeek: 2, totalUnits: 6 },
            prompts: { old: 'keep', base: 'base', protege: 'p', tutor: 't' }, lectures: [{ name: 'New' }],
        });
        const access = jest.spyOn(CourseModel, 'userHasCourseAccess').mockResolvedValueOnce(true);
        db = memoryDb({ courses: [] });
        res = await request(app({ db, user: instructor })).put('/C1').send({ instructorId: 'i1', prompts: { direct: true }, yearLevel: null });
        expect(res.status).toBe(404);
        access.mockRestore();
    });

    test('retrieval/delete/material/remove-document catch and availability guards', async () => {
        expect((await request(app({ db: memoryDb({}), user: instructor })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true })).status).toBe(404);
        expect((await request(app({ db: memoryDb({ courses: [course] }) })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true })).status).toBe(401);
        expect((await request(app({ db: memoryDb({ courses: [course] }), user: student })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true })).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).put('/C1/retrieval-mode').send({ isAdditiveRetrieval: true })).status).toBe(503);
        expect((await request(app({ db: null, user: instructor })).delete('/C1?instructorId=i1')).status).toBe(503);
        expect((await request(app({ db: null })).get('/available/all')).status).toBe(503);
        expect((await request(app({ db: null, user: instructor })).get('/available/joinable')).status).toBe(503);
        const broken = { collection: () => { throw new Error('boom'); } };
        expect((await request(app({ db: broken, user: instructor })).delete('/C1?instructorId=i1')).status).toBe(500);
        expect((await request(app({ db: broken })).post('/course-materials/confirm').send({ week: 'U', instructorId: 'i1' })).status).toBe(500);
        expect((await request(app({ db: broken })).get('/available/all')).status).toBe(500);
        expect((await request(app({ db: broken, user: instructor })).post('/C1/remove-document').send({ documentId: 'd', instructorId: 'i1' })).status).toBe(500);
    });

    test('join status and join endpoints cover remaining gates and roles', async () => {
        expect((await request(app({ db: null, user: instructor })).get('/C1/instructor-join-status')).status).toBe(503);
        expect((await request(app({ db: memoryDb({}), user: student })).get('/C1/instructor-join-status')).status).toBe(403);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).get('/C1/instructor-join-status')).status).toBe(404);
        let res = await request(app({ db: memoryDb({ courses: [course] }), user: instructor })).get('/C1/instructor-join-status');
        expect(res.body.data).toMatchObject({ requiresCode: false, reason: 'alreadyInstructor' });
        expect((await request(app({ db: memoryDb({ courses: [course] }), user: instructor })).post('/C1/join').send({})).status).toBe(403);
        expect((await request(app({ db: memoryDb({ courses: [course] }) })).post('/C1/join').send({})).status).toBe(401);
        expect((await request(app({ db: null, user: student })).post('/C1/join').send({ code: 'x' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: ta })).post('/missing/join').send({ code: 'x' })).status).toBe(404);
        const inactive = { ...course, status: 'inactive', tas: [] };
        expect((await request(app({ db: memoryDb({ courses: [inactive] }), user: ta })).post('/C1/join').send({ code: 'STUDENT' })).status).toBe(403);
        expect((await request(app({ db: memoryDb({ courses: [course] }), user: { ...ta, invitedCourses: ['C1'] } })).post('/C1/join').send({ code: 'wrong' })).status).toBe(403);
    });

    test('instructor/TA mutation endpoints cover auth, DB, missing and failure paths', async () => {
        expect((await request(app({ db: memoryDb({}) })).post('/C1/instructors').send({ instructorId: 'i1' })).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: student })).post('/C1/instructors').send({ instructorId: 's1' })).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).post('/C1/instructors').send({ instructorId: 'i1' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/C1/instructors').send({ instructorId: 'i1' })).status).toBe(404);
        expect((await request(app({ db: memoryDb({}) })).post('/C1/tas').send({ taId: 't1' })).status).toBe(401);
        expect((await request(app({ db: null, user: instructor })).post('/C1/tas').send({ taId: 't1' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({}) })).delete('/C1/tas/t1')).status).toBe(401);
        expect((await request(app({ db: null, user: instructor })).delete('/C1/tas/t1')).status).toBe(503);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).delete('/C1/tas/t1')).status).toBe(404);
    });

    test('permission endpoints cover every guard and model failure response', async () => {
        const db = memoryDb({ courses: [course] });
        expect((await request(app({ db })).put('/C1/ta-permissions/t1').send({ canAccessCourses: true, canAccessFlags: true })).status).toBe(401);
        expect((await request(app({ db, user: student })).put('/C1/ta-permissions/t1').send({ canAccessCourses: true, canAccessFlags: true })).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).put('/C1/ta-permissions/t1').send({ canAccessCourses: true, canAccessFlags: true })).status).toBe(503);
        expect((await request(app({ db })).get('/C1/ta-permissions/t1')).status).toBe(401);
        expect((await request(app({ db: null, user: ta })).get('/C1/ta-permissions/t1')).status).toBe(503);
        expect((await request(app({ db })).get('/C1/ta-permissions')).status).toBe(401);
        expect((await request(app({ db, user: ta })).get('/C1/ta-permissions')).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).get('/C1/ta-permissions')).status).toBe(503);
        const access = jest.spyOn(CourseModel, 'userHasCourseAccess').mockResolvedValueOnce(true);
        const update = jest.spyOn(CourseModel, 'updateTAPermissions').mockResolvedValueOnce({ success: false, error: 'bad perms' });
        expect((await request(app({ db, user: instructor })).put('/C1/ta-permissions/t1').send({ canAccessCourses: true, canAccessFlags: true })).status).toBe(400);
        access.mockRestore(); update.mockRestore();
    });

    test('student/enrollment/unit routes cover remaining guards', async () => {
        expect((await request(app({ db: memoryDb({}) })).get('/C1/students')).status).toBe(401);
        expect((await request(app({ db: memoryDb({}), user: student })).get('/C1/students')).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).get('/C1/students')).status).toBe(503);
        expect((await request(app({ db: memoryDb({}) })).put('/C1/student-enrollment/s1').send({ enrolled: true })).status).toBe(401);
        expect((await request(app({ db: null, user: instructor })).put('/C1/student-enrollment/s1').send({ enrolled: true })).status).toBe(503);
        expect((await request(app({ db: memoryDb({}), user: student })).get('/C1/student-enrollment')).status).toBe(404);
        expect((await request(app({ db: null, user: student })).get('/C1/student-enrollment')).status).toBe(503);
        expect((await request(app({ db: null, user: instructor })).post('/C1/units').send({ instructorId: 'i1' })).status).toBe(503);
        expect((await request(app({ db: memoryDb({}), user: instructor })).post('/C1/units').send({ instructorId: 'i1' })).status).toBe(403);
        expect((await request(app({ db: null, user: instructor })).delete('/C1/units/U?instructorId=i1')).status).toBe(503);
        expect((await request(app({ db: null, user: instructor })).put('/C1/units/U/rename').send({ instructorId: 'i1' })).status).toBe(503);
    });

    test('executes every remaining collection projection callback', async () => {
        let db = memoryDb({ courses: [{
            ...course, courseStructure: { lecturesPerWeek: 1 },
            lectures: [{ name: 'Unit 1', documents: [{ documentId: 'd1' }] }],
        }] });
        let res = await request(app({ db, user: instructor })).get('/');
        expect(res.body.data[0].documentCount).toBe(1);
        res = await request(app({ db, user: instructor })).get('/C1');
        expect(res.body.data.lectures[0].name).toBe('Unit 1');
        expect(res.body.data.structure.weeks[0].documents).toBe(1);

        db = memoryDb({ courses: [{ ...course, status: 'inactive' }, { courseId: 'C2', status: 'active' }] });
        res = await request(app({ db, user: ta })).get('/available/all');
        expect(res.body.data.map((c) => c.courseId)).toContain('C1');

        db = memoryDb({
            courses: [{ ...course, studentEnrollment: { inactive: { enrolled: true }, missing: { enrolled: true } } }],
            users: [{ userId: 'inactive', role: 'student', isActive: false }], chat_sessions: [],
        });
        res = await request(app({ db, user: instructor })).get('/C1/students');
        expect(res.body.data.students.map((s) => s.userId)).toEqual(['missing']);
    });
});
