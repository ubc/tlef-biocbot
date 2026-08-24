const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/studentPseudonyms');

const admin = { userId: 'admin_1', role: 'instructor', permissions: { systemAdmin: true } };
const instructor = { userId: 'instructor_1', role: 'instructor' };

describe('student pseudonym routes', () => {
    test('requires a system admin', async () => {
        const anonymous = await request(makeRouteApp(router, { db: memoryDb({}) })).get('/scopes');
        const forbidden = await request(makeRouteApp(router, { db: memoryDb({}), user: instructor })).get('/scopes');
        expect(anonymous.status).toBe(401);
        expect(forbidden.status).toBe(403);
    });

    test('lists every course and superchat for an admin', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', courseName: 'BIOC 301' }, { courseId: 'gone', status: 'deleted' }],
            superchats: [{ superchatId: 'S1', name: 'Year 3' }, { superchatId: 'gone', isDeleted: true }]
        });
        const response = await request(makeRouteApp(router, { db, user: admin })).get('/scopes');
        expect(response.status).toBe(200);
        expect(response.body.data.courses.map(row => row.courseId)).toEqual(['C1']);
        expect(response.body.data.superchats.map(row => row.superchatId)).toEqual(['S1']);
    });

    test('imports a CSV, reports status, and exports the admin mapping with PUID', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', studentEnrollment: { user_1: {} } }],
            users: [{ userId: 'user_1', role: 'student', displayName: 'Eden', puid: '12345678' }]
        });
        const app = makeRouteApp(router, { db, user: admin });

        const imported = await request(app)
            .post('/course/C1/import')
            .set('Content-Type', 'text/csv')
            .send('Student,Student_ID\n0042,user_1\n');
        expect(imported.status).toBe(200);
        expect(imported.body.data.importedCount).toBe(1);

        const status = await request(app).get('/course/C1');
        expect(status.body.data).toMatchObject({ complete: true, mappingCount: 1 });
        expect(status.body.data.mappings[0]).toMatchObject({
            student: '0042', studentId: 'user_1', puid: '12345678'
        });

        const csv = await request(app).get('/course/C1/mapping.csv');
        expect(csv.status).toBe(200);
        expect(csv.headers['content-type']).toMatch(/text\/csv/);
        expect(csv.text).toContain('Student,Student_ID,PUID');
        expect(csv.text).toContain('"0042","user_1","12345678"');
    });

    test('generates stable, separate mappings for superchat buckets', async () => {
        const db = memoryDb({
            superchats: [{ superchatId: 'S1' }, { superchatId: 'S2' }],
            student_super_course_chat_sessions: [
                { superchatId: 'S1', studentId: 'user_1' },
                { superchatId: 'S2', studentId: 'user_1' }
            ]
        });
        const app = makeRouteApp(router, { db, user: admin });
        const first = await request(app).post('/superchat/S1/generate');
        const second = await request(app).post('/superchat/S2/generate');
        expect(first.status).toBe(200);
        expect(second.status).toBe(200);
        expect(await db.collection('student_pseudonyms').countDocuments({ studentId: 'user_1' })).toBe(2);
    });
});
