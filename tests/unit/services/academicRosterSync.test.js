const { memoryDb } = require('../helpers/memory-db');
const { syncCourseRoster, normalizeAcademicPerson } = require('../../../src/services/academicRosterSync');

describe('academicRosterSync', () => {
    test('normalizes toolkit person variants into the fields BIOCBOT stores', () => {
        expect(normalizeAcademicPerson({
            PUID: ' puid-1 ',
            Student_ID: ' 12345678 ',
            Email: 'Student@Example.UBC.CA ',
            Preferred_Name: ' Student One '
        })).toEqual({
            puid: 'puid-1',
            studentId: '12345678',
            email: 'student@example.ubc.ca',
            preferredName: 'Student One'
        });
    });

    test('adds incoming academic students and enrolls them on the course', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'BIOC-301',
                academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-1'] },
                studentEnrollment: {
                    manual_user: { enrolled: true, joinedAt: new Date('2026-01-01') }
                }
            }]
        });

        const academicApi = {
            getStudentsFromSections: jest.fn().mockResolvedValue([
                { puid: 'puid-1', ID: '11111111', email: 'new@student.ubc.ca', preferredName: 'New Student' }
            ])
        };

        const result = await syncCourseRoster(db, 'BIOC-301', { academicApi });
        expect(result).toMatchObject({
            success: true,
            incomingCount: 1,
            added: 1,
            updated: 0,
            removed: 0
        });

        const user = await db.collection('users').findOne({ puid: 'puid-1' });
        expect(user).toMatchObject({
            email: 'new@student.ubc.ca',
            role: 'student',
            authProvider: 'saml',
            academicStudentId: '11111111',
            preferences: expect.objectContaining({ courseId: 'BIOC-301' })
        });

        const course = await db.collection('courses').findOne({ courseId: 'BIOC-301' });
        expect(course.studentEnrollment[user.userId]).toMatchObject({
            enrolled: true,
            source: 'academicSync',
            puid: 'puid-1',
            studentId: '11111111'
        });
        expect(course.studentEnrollment.manual_user).toMatchObject({ enrolled: true });
        expect(course.academicSync.lastSyncSummary).toMatchObject({ incomingCount: 1, added: 1 });
    });

    test('updates existing PUID users and only removes students previously managed by academic sync', async () => {
        const db = memoryDb({
            users: [{
                userId: 'existing_student',
                username: 'existing@student.ubc.ca',
                email: 'existing@student.ubc.ca',
                role: 'student',
                authProvider: 'saml',
                puid: 'puid-existing',
                isActive: true,
                preferences: { courseId: null }
            }],
            courses: [{
                courseId: 'BIOC-302',
                academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-2'] },
                studentEnrollment: {
                    existing_student: { enrolled: true, source: 'academicSync', puid: 'puid-existing' },
                    dropped_student: { enrolled: true, source: 'academicSync', puid: 'puid-dropped' },
                    manual_student: { enrolled: true }
                }
            }]
        });

        const academicApi = {
            getStudentsFromSections: jest.fn().mockResolvedValue([
                { puid: 'puid-existing', ID: '22222222', email: 'existing@student.ubc.ca', preferredName: 'Existing Student' }
            ])
        };

        const result = await syncCourseRoster(db, 'BIOC-302', { academicApi });
        expect(result).toMatchObject({
            success: true,
            incomingCount: 1,
            added: 0,
            updated: 1,
            removed: 1
        });

        const course = await db.collection('courses').findOne({ courseId: 'BIOC-302' });
        expect(course.studentEnrollment.existing_student).toMatchObject({
            enrolled: true,
            source: 'academicSync',
            puid: 'puid-existing',
            studentId: '22222222'
        });
        expect(course.studentEnrollment.dropped_student).toMatchObject({
            enrolled: false,
            source: 'academicSync',
            puid: 'puid-dropped'
        });
        expect(course.studentEnrollment.manual_student).toMatchObject({ enrolled: true });
    });

    test('fails closed when roster records are present but none have PUIDs', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'BIOC-303',
                academicSync: { academicPeriod: 'AP-2024W1', sectionIds: ['SEC-3'] },
                studentEnrollment: {
                    managed_student: { enrolled: true, source: 'academicSync', puid: 'puid-managed' }
                }
            }]
        });

        const academicApi = {
            getStudentsFromSections: jest.fn().mockResolvedValue([
                { ID: '44444444', email: 'missing-puid@student.ubc.ca', preferredName: 'Missing Puid' }
            ])
        };

        const result = await syncCourseRoster(db, 'BIOC-303', { academicApi });
        expect(result).toMatchObject({
            success: false,
            skipped: 1
        });

        const course = await db.collection('courses').findOne({ courseId: 'BIOC-303' });
        expect(course.studentEnrollment.managed_student).toMatchObject({ enrolled: true });
    });
});

describe('academicRosterSync coverage: missing course and identifier-less students', () => {
    test('syncCourseRoster reports Course not found for an unknown course id', async () => {
        const db = memoryDb({ courses: [] });
        expect(await syncCourseRoster(db, 'nope')).toEqual({ success: false, error: 'Course not found' });
    });

    test('upsertAcademicStudent creates a fresh user when the student carries no identifiers', async () => {
        const { upsertAcademicStudent } = require('../../../src/services/academicRosterSync');
        const db = memoryDb({ users: [] });
        const user = await upsertAcademicStudent(db, { puid: '', studentId: '', email: '', preferredName: 'Mystery Student' }, 'C1');
        // No puid/email/studentId → the existing-user lookup cannot match; a new
        // user is created with a generated username and the course preference set.
        expect(user.created).toBe(true);
        expect(user.username).toMatch(/^user_\d+_/);
        expect(user).toMatchObject({ displayName: 'Mystery Student', role: 'student', preferences: expect.objectContaining({ courseId: 'C1' }) });
    });

    test('syncCourseRoster refuses a course with no linked academic sections', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C-unlinked' }] });
        expect(await syncCourseRoster(db, 'C-unlinked')).toEqual({
            success: false,
            error: 'Course is not linked to academic sections'
        });
    });
});
