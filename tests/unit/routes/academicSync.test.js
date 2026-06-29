const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const academicSyncRouter = require('../../../src/routes/academicSync');

const instructor = {
    userId: 'inst-1',
    role: 'instructor',
    puid: 'puid-inst-1',
    displayName: 'Instructor One'
};

describe('academicSync routes', () => {
    test('fetches instructor sections through the injected academic API client', async () => {
        const academicApi = {
            getInstructorSections: jest.fn().mockResolvedValue([{
                courseSectionId: 'SEC-1',
                sectionNumber: '101',
                sectionStatus: { code: 'Open', description: 'Open' },
                course: {
                    courseNumber: '110',
                    title: 'Computation, Programs, and Programming',
                    courseSubject: { code: 'CPSC', description: 'CPSC' }
                }
            }])
        };
        const app = makeRouteApp(academicSyncRouter, {
            db: memoryDb(),
            user: instructor,
            locals: { academicApi }
        });

        const res = await request(app)
            .get('/instructor-sections?academicPeriod=AP-2024W1')
            .expect(200);

        expect(academicApi.getInstructorSections).toHaveBeenCalledWith('puid-inst-1', 'AP-2024W1');
        expect(res.body).toMatchObject({
            success: true,
            data: [{
                courseSectionId: 'SEC-1',
                picker: {
                    sectionId: 'SEC-1',
                    displayName: 'CPSC 110 Section 101',
                    meta: 'SEC-1 · Open · Computation, Programs, and Programming'
                }
            }]
        });
    });

    test('rejects instructor section lookup when the authenticated user has no PUID', async () => {
        const app = makeRouteApp(academicSyncRouter, {
            db: memoryDb(),
            user: { ...instructor, puid: null, authProvider: 'basic' },
            locals: { academicApi: { getInstructorSections: jest.fn() } }
        });

        const res = await request(app)
            .get('/instructor-sections?academicPeriod=AP-2026W1')
            .expect(400);

        expect(res.body.message).toContain('missing a PUID');
    });

    test('links sections only for an instructor who owns the course', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'BIOC-401', instructorId: 'inst-1', instructors: ['inst-1'] }]
        });
        const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

        const res = await request(app)
            .put('/courses/BIOC-401/link')
            .send({ academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1', 'SEC-2'] })
            .expect(200);

        expect(res.body).toMatchObject({
            success: true,
            data: {
                courseId: 'BIOC-401',
                academicSync: {
                    academicPeriod: 'AP-2024W1',
                    sectionIds: ['SEC-1', 'SEC-2'],
                    linkedBy: 'inst-1'
                }
            }
        });

        const course = await db.collection('courses').findOne({ courseId: 'BIOC-401' });
        expect(course.academicSync).toMatchObject({
            academicPeriod: 'AP-2024W1',
            sectionIds: ['SEC-1', 'SEC-2']
        });
    });

    test('rejects linking a course owned by a different instructor', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'BIOC-402', instructorId: 'someone-else', instructors: ['someone-else'] }]
        });
        const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

        await request(app)
            .put('/courses/BIOC-402/link')
            .send({ academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] })
            .expect(403);
    });

    test('sync endpoint calls the roster service path and returns the summary', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'BIOC-403',
                instructorId: 'inst-1',
                instructors: ['inst-1'],
                academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] }
            }]
        });
        const academicApi = {
            getStudentsFromSections: jest.fn().mockResolvedValue([
                { puid: 'puid-student', ID: '33333333', email: 'student@ubc.ca', preferredName: 'Student Three' }
            ])
        };
        const app = makeRouteApp(academicSyncRouter, {
            db,
            user: instructor,
            locals: { academicApi }
        });

        const res = await request(app)
            .post('/courses/BIOC-403/sync')
            .send({})
            .expect(200);

        expect(res.body).toMatchObject({
            success: true,
            data: {
                incomingCount: 1,
                added: 1,
                removed: 0
            }
        });
    });
});
