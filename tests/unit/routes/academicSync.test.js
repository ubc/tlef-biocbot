const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const CourseModel = require('../../../src/models/Course');
const academicSyncRouter = require('../../../src/routes/academicSync');

const instructor = {
    userId: 'inst-1',
    role: 'instructor',
    puid: 'puid-inst-1',
    displayName: 'Instructor One'
};

// The academic-sync router is gated behind the instance-wide academic-API
// setting, so every test here must seed it on.
const GATE_ON = [{ _id: 'global', academicApiEnabled: true }];

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
            db: memoryDb({ settings: GATE_ON }),
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
            db: memoryDb({ settings: GATE_ON }),
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
            settings: GATE_ON,
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
            settings: GATE_ON,
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
            settings: GATE_ON,
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

describe('academicSync gate (academic API disabled)', () => {
    test('GET endpoints degrade to an empty, disabled response', async () => {
        const academicApi = { getInstructorSections: jest.fn() };
        const app = makeRouteApp(academicSyncRouter, {
            db: memoryDb(), // no global setting → gate off (default)
            user: instructor,
            locals: { academicApi }
        });

        const res = await request(app)
            .get('/instructor-sections?academicPeriod=AP-2024W1')
            .expect(200);

        expect(res.body).toMatchObject({ success: true, disabled: true, data: [] });
        expect(academicApi.getInstructorSections).not.toHaveBeenCalled();
    });

    test('write endpoints are refused with a clear code', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'BIOC-401', instructorId: 'inst-1', instructors: ['inst-1'] }]
        });
        const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

        const res = await request(app)
            .put('/courses/BIOC-401/link')
            .send({ academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] })
            .expect(403);

        expect(res.body).toMatchObject({ success: false, code: 'ACADEMIC_API_DISABLED' });
    });
});

// A toolkit-missing error (the optional UBC academic toolkit not being installed)
// is mapped to 503; every other downstream failure becomes a 502 bad-gateway.
const toolkitMissingError = () => Object.assign(new Error('Academic toolkit not installed'), {
    code: 'ACADEMIC_API_TOOLKIT_MISSING'
});

describe('academicSync routes — deepened coverage', () => {
    // Error responses are exercised intentionally below. Keep those expected
    // failures from flooding Jest's output with stack traces.
    beforeEach(() => jest.spyOn(console, 'error').mockImplementation(() => {}));
    afterEach(() => jest.restoreAllMocks());

    describe('GET /academic-periods', () => {
        test('returns periods using the default campus when none is supplied', async () => {
            const academicApi = {
                getAcademicPeriods: jest.fn().mockResolvedValue([{ id: 'AP-2024W1' }])
            };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor,
                locals: { academicApi }
            });

            const res = await request(app).get('/academic-periods').expect(200);

            expect(academicApi.getAcademicPeriods).toHaveBeenCalledWith('V');
            expect(res.body).toEqual({ success: true, data: [{ id: 'AP-2024W1' }] });
        });

        test('passes an explicit campus query through to the toolkit', async () => {
            const academicApi = { getAcademicPeriods: jest.fn().mockResolvedValue([]) };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor,
                locals: { academicApi }
            });

            await request(app).get('/academic-periods?campus=O').expect(200);
            expect(academicApi.getAcademicPeriods).toHaveBeenCalledWith('O');
        });

        test('maps a missing-toolkit failure to 503', async () => {
            const academicApi = {
                getAcademicPeriods: jest.fn().mockRejectedValue(toolkitMissingError())
            };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor,
                locals: { academicApi }
            });

            const res = await request(app).get('/academic-periods').expect(503);
            expect(res.body).toMatchObject({ success: false, message: 'Academic toolkit not installed' });
        });

        test('maps any other downstream failure to 502', async () => {
            const academicApi = {
                getAcademicPeriods: jest.fn().mockRejectedValue(new Error('upstream exploded'))
            };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor,
                locals: { academicApi }
            });

            const res = await request(app).get('/academic-periods').expect(502);
            expect(res.body).toMatchObject({ success: false, message: 'upstream exploded' });
        });
    });

    describe('GET /instructor-sections', () => {
        test('rejects a non-instructor before touching the toolkit', async () => {
            const academicApi = { getInstructorSections: jest.fn() };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: { userId: 'stu-1', role: 'student', puid: 'puid-stu' },
                locals: { academicApi }
            });

            const res = await request(app)
                .get('/instructor-sections?academicPeriod=AP-2024W1')
                .expect(403);

            expect(res.body.message).toContain('Only instructors');
            expect(academicApi.getInstructorSections).not.toHaveBeenCalled();
        });

        test('requires an academicPeriod (no query and no env default)', async () => {
            const prev = process.env.UBC_API_CURRENT_ACADEMIC_PERIOD;
            delete process.env.UBC_API_CURRENT_ACADEMIC_PERIOD;
            try {
                const app = makeRouteApp(academicSyncRouter, {
                    db: memoryDb({ settings: GATE_ON }),
                    user: instructor,
                    locals: { academicApi: { getInstructorSections: jest.fn() } }
                });

                const res = await request(app).get('/instructor-sections').expect(400);
                expect(res.body.message).toContain('academicPeriod is required');
            } finally {
                if (prev === undefined) delete process.env.UBC_API_CURRENT_ACADEMIC_PERIOD;
                else process.env.UBC_API_CURRENT_ACADEMIC_PERIOD = prev;
            }
        });

        test('marks sections already linked to a BiocBot course and tolerates empty display fields', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                // A non-deleted course already linked to SEC-1 → the picker should flag it.
                courses: [{
                    courseId: 'BIOC-500',
                    status: 'active',
                    academicSync: { sectionIds: ['SEC-1'] }
                }]
            });
            const academicApi = {
                getInstructorSections: jest.fn().mockResolvedValue([
                    {
                        courseSectionId: 'SEC-1',
                        // courseSubject is an object with no preferred keys → getDisplayValue
                        // exhausts its preferred-key loop and returns '' (final fallback).
                        course: { courseSubject: { unrelated: 'x' }, courseNumber: '200' }
                    },
                    { courseSectionId: 'SEC-9', course: { courseSubject: { code: 'BIOC' } } }
                ])
            };
            const app = makeRouteApp(academicSyncRouter, {
                db,
                user: instructor,
                locals: { academicApi }
            });

            const res = await request(app)
                .get('/instructor-sections?academicPeriod=AP-2024W1')
                .expect(200);

            const [linked, unlinked] = res.body.data;
            expect(linked.picker).toMatchObject({
                sectionId: 'SEC-1',
                alreadySetUp: true,
                linkedCourseId: 'BIOC-500'
            });
            // Empty subject means the display name falls back to the section id.
            expect(linked.picker.displayName).toBe('200');
            expect(unlinked.picker).toMatchObject({
                sectionId: 'SEC-9',
                alreadySetUp: false,
                linkedCourseId: null
            });
        });

        test('maps a missing-toolkit failure to 503', async () => {
            const academicApi = {
                getInstructorSections: jest.fn().mockRejectedValue(toolkitMissingError())
            };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor,
                locals: { academicApi }
            });

            await request(app)
                .get('/instructor-sections?academicPeriod=AP-2024W1')
                .expect(503);
        });

        test('maps any other downstream failure to 502', async () => {
            const academicApi = {
                getInstructorSections: jest.fn().mockRejectedValue(new Error('boom'))
            };
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor,
                locals: { academicApi }
            });

            const res = await request(app)
                .get('/instructor-sections?academicPeriod=AP-2024W1')
                .expect(502);
            expect(res.body.message).toBe('boom');
        });
    });

    describe('GET /courses/:courseId (read sync status)', () => {
        test('returns the stored academicSync for an owning instructor', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                courses: [{
                    courseId: 'BIOC-600',
                    instructorId: 'inst-1',
                    instructors: ['inst-1'],
                    academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] }
                }]
            });
            const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

            const res = await request(app).get('/courses/BIOC-600').expect(200);
            expect(res.body).toEqual({
                success: true,
                data: {
                    courseId: 'BIOC-600',
                    academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] }
                }
            });
        });

        test('returns null academicSync when the course was never linked', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                courses: [{ courseId: 'BIOC-601', instructorId: 'inst-1' }]
            });
            const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

            const res = await request(app).get('/courses/BIOC-601').expect(200);
            expect(res.body.data.academicSync).toBeNull();
        });

        test('rejects a non-instructor user', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                courses: [{ courseId: 'BIOC-602', instructorId: 'inst-1' }]
            });
            const app = makeRouteApp(academicSyncRouter, {
                db,
                user: { userId: 'ta-1', role: 'ta' }
            });

            const res = await request(app).get('/courses/BIOC-602').expect(403);
            expect(res.body.message).toContain('Only instructors');
        });

        test('returns 404 for a missing or deleted course', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                courses: [{ courseId: 'BIOC-603', instructorId: 'inst-1', status: 'deleted' }]
            });
            const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

            await request(app).get('/courses/does-not-exist').expect(404);
            await request(app).get('/courses/BIOC-603').expect(404);
        });

        test('returns 500 when reading the course throws', async () => {
            jest.spyOn(CourseModel, 'getCourseById').mockRejectedValue(new Error('mongo down'));
            const app = makeRouteApp(academicSyncRouter, {
                db: memoryDb({ settings: GATE_ON }),
                user: instructor
            });

            const res = await request(app).get('/courses/BIOC-604').expect(500);
            expect(res.body).toMatchObject({
                success: false,
                message: 'Failed to read academic sync status'
            });
        });
    });

    describe('PUT /courses/:courseId/link', () => {
        const ownedCourse = () => ({
            courseId: 'BIOC-700',
            instructorId: 'inst-1',
            instructors: ['inst-1']
        });

        test('requires an academicPeriod', async () => {
            const db = memoryDb({ settings: GATE_ON, courses: [ownedCourse()] });
            const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

            const res = await request(app)
                .put('/courses/BIOC-700/link')
                .send({ sectionIds: ['SEC-1'] })
                .expect(400);
            expect(res.body.message).toContain('academicPeriod is required');
        });

        test('requires at least one section id (after trimming blanks)', async () => {
            const db = memoryDb({ settings: GATE_ON, courses: [ownedCourse()] });
            const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

            const res = await request(app)
                .put('/courses/BIOC-700/link')
                .send({ academicPeriod: 'AP-2024W1', sectionIds: ['', '  '] })
                .expect(400);
            expect(res.body.message).toContain('Select at least one section');
        });

        test('returns 500 when the persistence write throws', async () => {
            const db = memoryDb({ settings: GATE_ON, courses: [ownedCourse()] });
            jest.spyOn(db.collection('courses'), 'updateOne').mockRejectedValue(new Error('write failed'));
            const app = makeRouteApp(academicSyncRouter, { db, user: instructor });

            const res = await request(app)
                .put('/courses/BIOC-700/link')
                .send({ academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] })
                .expect(500);
            expect(res.body).toMatchObject({
                success: false,
                message: 'Failed to link academic sections'
            });
        });
    });

    describe('POST /courses/:courseId/sync', () => {
        test('returns 400 with the service error when the course is not linked', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                // Owned course but with no academicSync and an empty sync body →
                // syncCourseRoster returns { success: false, error: ... }.
                courses: [{ courseId: 'BIOC-800', instructorId: 'inst-1', instructors: ['inst-1'] }]
            });
            const app = makeRouteApp(academicSyncRouter, {
                db,
                user: instructor,
                locals: { academicApi: { getStudentsFromSections: jest.fn() } }
            });

            const res = await request(app)
                .post('/courses/BIOC-800/sync')
                .send({})
                .expect(400);
            expect(res.body).toMatchObject({
                success: false,
                message: 'Course is not linked to academic sections'
            });
        });

        test('maps a missing-toolkit failure during sync to 503', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                courses: [{
                    courseId: 'BIOC-801',
                    instructorId: 'inst-1',
                    instructors: ['inst-1'],
                    academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] }
                }]
            });
            const app = makeRouteApp(academicSyncRouter, {
                db,
                user: instructor,
                locals: { academicApi: { getStudentsFromSections: jest.fn().mockRejectedValue(toolkitMissingError()) } }
            });

            await request(app).post('/courses/BIOC-801/sync').send({}).expect(503);
        });

        test('maps any other sync failure to 502', async () => {
            const db = memoryDb({
                settings: GATE_ON,
                courses: [{
                    courseId: 'BIOC-802',
                    instructorId: 'inst-1',
                    instructors: ['inst-1'],
                    academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] }
                }]
            });
            const app = makeRouteApp(academicSyncRouter, {
                db,
                user: instructor,
                locals: { academicApi: { getStudentsFromSections: jest.fn().mockRejectedValue(new Error('roster boom')) } }
            });

            const res = await request(app).post('/courses/BIOC-802/sync').send({}).expect(502);
            expect(res.body.message).toBe('roster boom');
        });
    });
});
