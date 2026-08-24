const { memoryDb } = require('../helpers/memory-db');
const pseudonyms = require('../../../src/services/studentPseudonyms');

describe('studentPseudonyms service', () => {
    test('parses historical CSV while preserving numeric leading zeroes', () => {
        expect(pseudonyms.parseCsv('Student,Student_ID\n0042,user_177\nA9Z0,user_178\n')).toEqual([
            { line: 2, pseudonym: '0042', studentId: 'user_177' },
            { line: 3, pseudonym: 'A9Z0', studentId: 'user_178' }
        ]);
    });

    test('generates unique four-character mappings once and only fills gaps', async () => {
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                studentEnrollment: {
                    user_1: { enrolled: true },
                    user_2: { enrolled: false }
                }
            }],
            users: [{ userId: 'user_3', role: 'student', preferences: { courseId: 'C1' } }],
            chat_sessions: [{ courseId: 'C1', studentId: 'user_4' }]
        });

        const first = await pseudonyms.generateMissingMappings(db, 'course', 'C1', 'admin_1');
        expect(first.createdCount).toBe(4);
        expect(first.status.complete).toBe(true);
        const codes = first.status.mappings.map(row => row.pseudonym);
        expect(new Set(codes).size).toBe(4);
        codes.forEach(code => expect(code).toMatch(/^[A-Z0-9]{4}$/));

        const second = await pseudonyms.generateMissingMappings(db, 'course', 'C1', 'admin_1');
        expect(second.createdCount).toBe(0);
        expect(second.status.mappings.map(row => row.pseudonym).sort()).toEqual(codes.sort());
    });

    test('imports valid course mappings and rejects the entire invalid CSV', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', studentEnrollment: { user_1: {}, user_2: {} } }]
        });

        const imported = await pseudonyms.importCourseCsv(
            db,
            'C1',
            'Student,Student_ID\n0042,user_1\nB7Q9,user_2\n',
            'admin_1'
        );
        expect(imported.importedCount).toBe(2);
        expect(imported.status.complete).toBe(true);

        await expect(pseudonyms.importCourseCsv(
            db,
            'C1',
            'Student,Student_ID\nZZZZ,user_1\nBAD,user_unknown\n',
            'admin_1'
        )).rejects.toMatchObject({ statusCode: 400 });
        expect(await db.collection(pseudonyms.COLLECTION).countDocuments({ scopeId: 'C1' })).toBe(2);
    });

    test('joins PUID only when producing the admin mapping view', async () => {
        const db = memoryDb({
            courses: [{ courseId: 'C1', studentEnrollment: { user_1: {} } }],
            users: [{ userId: 'user_1', role: 'student', displayName: 'Eden', puid: '12345678' }],
            student_pseudonyms: [{
                scopeType: 'course', scopeId: 'C1', studentId: 'user_1', pseudonym: '0042', source: 'imported'
            }]
        });

        const result = await pseudonyms.getMappingRows(db, 'course', 'C1');
        expect(result.mappings).toEqual([{
            student: '0042',
            studentId: 'user_1',
            puid: '12345678',
            displayName: 'Eden',
            source: 'imported'
        }]);
        expect(pseudonyms.mappingRowsToCsv(result.mappings)).toContain('"0042","user_1","12345678"');
    });

    test('removes stored identity fields recursively from anonymized export data', () => {
        expect(pseudonyms.stripIdentifyingFields({
            studentId: 'user_1',
            studentName: 'Eden',
            chatData: { metadata: { studentId: 'user_1', email: 'eden@example.test' }, messages: [{ content: 'hello' }] }
        })).toEqual({ chatData: { metadata: {}, messages: [{ content: 'hello' }] } });
    });
});
