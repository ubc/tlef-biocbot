/**
 * In-process route tests for src/routes/students.js (supertest).
 * No heavy deps to mock — the router only uses req.app.locals.db (chat_sessions
 * + courses) and req.user. Exercises the auth gates, the student-grouping +
 * duration logic, and the rename / student-delete write paths.
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const studentsRouter = require('../../../src/routes/students');

const adminInstructor = { userId: 'i1', role: 'instructor', permissions: { systemAdmin: true } };
const plainInstructor = { userId: 'i1', role: 'instructor' }; // not a system admin
const student = (id) => ({ userId: id, role: 'student' });

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /:courseId — instructor-admin student list', () => {
    test('401 without a user', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}) })).get('/C1');
        expect(res.status).toBe(401);
    });

    test('503 when the db is unavailable', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: null, user: adminInstructor })).get('/C1');
        expect(res.status).toBe(503);
    });

    test('403 for a plain instructor (download data is system-admin only)', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}), user: plainInstructor })).get('/C1');
        expect(res.status).toBe(403);
        expect(res.body.message).toMatch(/system admins/i);
    });

    test('404 when the admin has no access to the course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'someone-else' }] });
        const res = await request(makeRouteApp(studentsRouter, { db, user: adminInstructor })).get('/C1');
        expect(res.status).toBe(404);
    });

    test('200 groups sessions by student, extracts names, and computes duration', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', courseName: 'Bio 101', instructorId: 'i1' }],
            chat_sessions: [
                {
                    sessionId: 'a', courseId: 'C1', studentId: 's1', studentName: 'Alice',
                    savedAt: new Date('2026-02-01'), messageCount: 2,
                    chatData: { messages: [
                        { type: 'user', timestamp: '2026-02-01T00:00:00Z' },
                        { type: 'bot', timestamp: '2026-02-01T00:01:30Z' },
                    ] },
                },
                { sessionId: 'b', courseId: 'C1', studentId: 's1', studentName: 'Alice', savedAt: new Date('2026-01-01') },
                { sessionId: 'c', courseId: 'C1', studentId: 's2', studentName: { displayName: 'Bob' }, savedAt: new Date('2026-01-15') },
            ],
        });
        const res = await request(makeRouteApp(studentsRouter, { db, user: adminInstructor })).get('/C1');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ courseName: 'Bio 101', totalStudents: 2, totalSessions: 3 });

        const alice = res.body.data.students.find(s => s.studentId === 's1');
        const bob = res.body.data.students.find(s => s.studentId === 's2');
        expect(alice.totalSessions).toBe(2);
        expect(bob.studentName).toBe('Bob'); // extracted from the object form
        expect(alice.sessions.find(s => s.sessionId === 'a').duration).toBe('1m 30s');
        // Sorted by last activity: Alice (Feb) before Bob (Jan).
        expect(res.body.data.students[0].studentId).toBe('s1');
    });
});

describe('GET /:courseId/:studentId/sessions/own — student access', () => {
    test('403 when a student requests another student\'s sessions', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}), user: student('s1') }))
            .get('/C1/s2/sessions/own');
        expect(res.status).toBe(403);
        expect(res.body.message).toMatch(/your own chat sessions/i);
    });

    test('403 for a plain instructor (not a system admin)', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}), user: plainInstructor }))
            .get('/C1/s1/sessions/own');
        expect(res.status).toBe(403);
    });

    test('200 when a student requests their own sessions in an existing course', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }], chat_sessions: [] });
        const res = await request(makeRouteApp(studentsRouter, { db, user: student('s1') }))
            .get('/C1/s1/sessions/own');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
    });
});

describe('PUT /:courseId/:studentId/sessions/:sessionId/title — rename', () => {
    test('400 when the title is missing', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}), user: student('s1') }))
            .put('/C1/s1/sessions/sess1/title').send({});
        expect(res.status).toBe(400);
    });

    test('403 when a student renames another student\'s session', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}), user: student('s1') }))
            .put('/C1/s2/sessions/sess1/title').send({ title: 'x' });
        expect(res.status).toBe(403);
    });

    test('404 when the session does not exist', async () => {
        const db = memoryDb({ chat_sessions: [] });
        const res = await request(makeRouteApp(studentsRouter, { db, user: student('s1') }))
            .put('/C1/s1/sessions/missing/title').send({ title: 'x' });
        expect(res.status).toBe(404);
    });

    test('200 updates the title and persists it', async () => {
        const db = memoryDb({ chat_sessions: [{ sessionId: 'sess1', courseId: 'C1', studentId: 's1', title: 'Old' }] });
        const res = await request(makeRouteApp(studentsRouter, { db, user: student('s1') }))
            .put('/C1/s1/sessions/sess1/title').send({ title: 'Renamed' });
        expect(res.status).toBe(200);
        expect((await db.collection('chat_sessions').findOne({ sessionId: 'sess1' })).title).toBe('Renamed');
    });
});

describe('DELETE /:courseId/:studentId/sessions/:sessionId/own — student soft-delete', () => {
    test('403 when a student deletes another student\'s session', async () => {
        const res = await request(makeRouteApp(studentsRouter, { db: memoryDb({}), user: student('s1') }))
            .delete('/C1/s2/sessions/sess1/own');
        expect(res.status).toBe(403);
    });

    test('404 when the session does not exist', async () => {
        const db = memoryDb({ chat_sessions: [] });
        const res = await request(makeRouteApp(studentsRouter, { db, user: student('s1') }))
            .delete('/C1/s1/sessions/missing/own');
        expect(res.status).toBe(404);
    });

    test('200 marks the session studentDeleted (kept visible to instructors)', async () => {
        const db = memoryDb({ chat_sessions: [{ sessionId: 'sess1', courseId: 'C1', studentId: 's1' }] });
        const res = await request(makeRouteApp(studentsRouter, { db, user: student('s1') }))
            .delete('/C1/s1/sessions/sess1/own');
        expect(res.status).toBe(200);
        const stored = await db.collection('chat_sessions').findOne({ sessionId: 'sess1' });
        expect(stored.studentDeleted).toBe(true);
        expect(stored.isDeleted).toBeUndefined(); // not hidden from instructors
    });
});
