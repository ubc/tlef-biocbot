const Superchat = require('../../../src/models/Superchat');
const { memoryDb } = require('../helpers/memory-db');

// ensureSuperchatsFromLegacy logs migration progress; keep output quiet.
beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
afterAll(() => jest.restoreAllMocks());

describe('Superchat.yearLabel / generateSuperchatId', () => {
    test('yearLabel maps 1-5 to labels and anything else to null', () => {
        expect(Superchat.yearLabel(1)).toBe('1st Year');
        expect(Superchat.yearLabel(5)).toBe('Graduate');
        expect(Superchat.yearLabel(99)).toBeNull();
        expect(Superchat.yearLabel(null)).toBeNull();
    });

    test('generateSuperchatId produces unique, prefixed ids', () => {
        const ids = new Set(Array.from({ length: 5 }, () => Superchat.generateSuperchatId()));
        expect(ids.size).toBe(5);
        for (const id of ids) expect(id).toMatch(/^sc_[0-9a-f-]{36}$/i);
    });
});

describe('Superchat.createSuperchat', () => {
    test('fills sensible defaults and persists the bucket', async () => {
        const db = memoryDb({});
        const doc = await Superchat.createSuperchat(db, { name: 'Year 2 Biochem', yearLevel: 2 }, 'admin-1');

        expect(doc).toMatchObject({
            name: 'Year 2 Biochem',
            description: '',
            yearLevel: 2,
            showToStudents: false,
            createdBy: 'admin-1',
            isDeleted: false,
        });
        expect(doc.superchatId).toMatch(/^sc_/);
        expect(doc.createdAt).toBeInstanceOf(Date);

        // It is actually stored.
        const stored = await Superchat.getSuperchatById(db, doc.superchatId);
        expect(stored.name).toBe('Year 2 Biochem');
    });

    test('name falls back to the year label, then to a generic default', async () => {
        const db = memoryDb({});
        const withYear = await Superchat.createSuperchat(db, { yearLevel: 3 });
        expect(withYear.name).toBe('3rd Year');
        const noYear = await Superchat.createSuperchat(db, {});
        expect(noYear.name).toBe('Untitled Super Course');
    });

    test('normalizes description / showToStudents / yearLevel and honors a custom id', async () => {
        const db = memoryDb({});
        const doc = await Superchat.createSuperchat(db, {
            superchatId: 'custom-id',
            name: 'X',
            description: '  trimmed  ',
            showToStudents: 'true', // not strictly true -> false
            yearLevel: 9,           // out of range -> null
        });
        expect(doc.superchatId).toBe('custom-id');
        expect(doc.description).toBe('trimmed');
        expect(doc.showToStudents).toBe(false);
        expect(doc.yearLevel).toBeNull();
    });

    test('keeps only recognized chat-settings keys and an object llmApiKey', async () => {
        const db = memoryDb({});
        const doc = await Superchat.createSuperchat(db, {
            name: 'Y',
            studentTopK: 5,
            instructorPrompt: 'Hi',
            bogusField: 'drop me',
            llmApiKey: { status: 'valid', last4: '1234' },
        });
        expect(doc.studentTopK).toBe(5);
        expect(doc.instructorPrompt).toBe('Hi');
        expect(doc).not.toHaveProperty('bogusField');
        expect(doc.llmApiKey).toEqual({ status: 'valid', last4: '1234' });

        const docNoKey = await Superchat.createSuperchat(db, { name: 'Z', llmApiKey: 'not-an-object' });
        expect(docNoKey).not.toHaveProperty('llmApiKey');
    });
});

describe('Superchat.listSuperchats', () => {
    function seeded() {
        return memoryDb({
            superchats: [
                { superchatId: 'b2', name: 'B', yearLevel: 2, isDeleted: false },
                { superchatId: 'b1a', name: 'A', yearLevel: 1, isDeleted: false },
                { superchatId: 'b1c', name: 'C', yearLevel: 1, isDeleted: false },
                { superchatId: 'bd', name: 'Deleted', yearLevel: 1, isDeleted: true },
            ],
        });
    }

    test('excludes soft-deleted buckets and orders by year then name', async () => {
        const list = await Superchat.listSuperchats(seeded());
        expect(list.map((b) => b.superchatId)).toEqual(['b1a', 'b1c', 'b2']);
    });

    test('includeDeleted returns everything', async () => {
        const list = await Superchat.listSuperchats(seeded(), { includeDeleted: true });
        expect(list.map((b) => b.superchatId)).toContain('bd');
        expect(list).toHaveLength(4);
    });
});

describe('Superchat.getSuperchatById', () => {
    function seeded() {
        return memoryDb({
            superchats: [
                { superchatId: 'live', name: 'Live', isDeleted: false },
                { superchatId: 'dead', name: 'Dead', isDeleted: true },
            ],
        });
    }

    test('returns null for an empty id without touching the db', async () => {
        expect(await Superchat.getSuperchatById(seeded(), '')).toBeNull();
    });

    test('finds live buckets and hides deleted ones unless asked', async () => {
        const db = seeded();
        expect((await Superchat.getSuperchatById(db, 'live')).name).toBe('Live');
        expect(await Superchat.getSuperchatById(db, 'dead')).toBeNull();
        expect((await Superchat.getSuperchatById(db, 'dead', { includeDeleted: true })).name).toBe('Dead');
        expect(await Superchat.getSuperchatById(db, 'missing')).toBeNull();
    });
});

describe('Superchat.updateSuperchat', () => {
    function seeded() {
        return memoryDb({
            superchats: [
                { superchatId: 'b1', name: 'Original', description: 'orig', yearLevel: 2, showToStudents: false, isDeleted: false },
                { superchatId: 'gone', name: 'Gone', isDeleted: true },
            ],
        });
    }

    test('updates only the provided fields and returns the fresh doc', async () => {
        const db = seeded();
        const updated = await Superchat.updateSuperchat(db, 'b1', { description: '  new desc  ', studentTopK: 7, bogus: 'x' });
        expect(updated.description).toBe('new desc');
        expect(updated.studentTopK).toBe(7);
        expect(updated.name).toBe('Original'); // untouched
        expect(updated).not.toHaveProperty('bogus');
        expect(updated.updatedAt).toBeInstanceOf(Date);
    });

    test('normalizes name, showToStudents, and yearLevel (null allowed)', async () => {
        const db = seeded();
        const updated = await Superchat.updateSuperchat(db, 'b1', { name: '  Renamed  ', showToStudents: true, yearLevel: null });
        expect(updated.name).toBe('Renamed');
        expect(updated.showToStudents).toBe(true);
        expect(updated.yearLevel).toBeNull();

        const reupdated = await Superchat.updateSuperchat(db, 'b1', { yearLevel: 42 });
        expect(reupdated.yearLevel).toBeNull(); // out of range normalizes to null
    });

    test('returns null for a missing or already-deleted bucket', async () => {
        const db = seeded();
        expect(await Superchat.updateSuperchat(db, 'missing', { name: 'x' })).toBeNull();
        expect(await Superchat.updateSuperchat(db, 'gone', { name: 'x' })).toBeNull();
    });
});

describe('Superchat.softDeleteSuperchat', () => {
    test('soft-deletes the bucket and detaches it from every course', async () => {
        const db = memoryDb({
            superchats: [{ superchatId: 'b1', name: 'B1', isDeleted: false }],
            courses: [
                { courseId: 'C1', superchatIds: ['b1', 'b2'] },
                { courseId: 'C2', superchatIds: ['b1'] },
                { courseId: 'C3', superchatIds: ['bX'] },
            ],
        });

        const result = await Superchat.softDeleteSuperchat(db, 'b1');
        expect(result).toEqual({ success: true, coursesUpdated: 2 });

        // Hidden from normal reads, recoverable with includeDeleted.
        expect(await Superchat.getSuperchatById(db, 'b1')).toBeNull();
        const deleted = await Superchat.getSuperchatById(db, 'b1', { includeDeleted: true });
        expect(deleted.isDeleted).toBe(true);
        expect(deleted.deletedAt).toBeInstanceOf(Date);

        // Membership cleaned up.
        const courses = db.collection('courses');
        expect((await courses.findOne({ courseId: 'C1' })).superchatIds).toEqual(['b2']);
        expect((await courses.findOne({ courseId: 'C2' })).superchatIds).toEqual([]);
        expect((await courses.findOne({ courseId: 'C3' })).superchatIds).toEqual(['bX']);
    });

    test('reports failure when the bucket does not exist', async () => {
        const db = memoryDb({ superchats: [], courses: [] });
        const result = await Superchat.softDeleteSuperchat(db, 'nope');
        expect(result).toEqual({ success: false, coursesUpdated: 0 });
    });
});

describe('Superchat.ensureSuperchatsFromLegacy', () => {
    function legacyDb() {
        return memoryDb({
            superchats: [],
            settings: [{ _id: 'superCourseChat', showStudentSuperCourse: true, studentTopK: 7 }],
            courses: [
                { courseId: 'C1', courseName: 'BIOC 202', yearLevel: 2, allowInSuperCourse: true },   // year 2 (explicit)
                { courseId: 'C2', courseName: 'BIOC 301', allowInSuperCourse: true },                  // year 3 (from name)
                { courseId: 'C3', courseName: 'Seminar', allowInSuperCourse: true },                   // ungrouped (no number)
                { courseId: 'C4', courseName: 'BIOC 202', allowInSuperCourse: false },                 // not opted in
                { courseId: 'C5', courseName: 'BIOC 202', allowInSuperCourse: true, superchatIds: ['existing'] }, // already converted
            ],
        });
    }

    test('seeds year/ungrouped buckets, carries settings, and attaches courses', async () => {
        const db = legacyDb();
        await Superchat.ensureSuperchatsFromLegacy(db);

        const year2 = await Superchat.getSuperchatById(db, 'year-2');
        expect(year2).toMatchObject({ name: '2nd Year', yearLevel: 2, showToStudents: true, studentTopK: 7 });

        const year3 = await Superchat.getSuperchatById(db, 'year-3');
        expect(year3).toMatchObject({ name: '3rd Year', yearLevel: 3 });

        const ungrouped = await Superchat.getSuperchatById(db, 'ungrouped');
        expect(ungrouped).toMatchObject({ name: 'Other Biochemistry', yearLevel: null });

        const courses = db.collection('courses');
        expect((await courses.findOne({ courseId: 'C1' })).superchatIds).toEqual(['year-2']);
        expect((await courses.findOne({ courseId: 'C2' })).superchatIds).toEqual(['year-3']);
        expect((await courses.findOne({ courseId: 'C3' })).superchatIds).toEqual(['ungrouped']);
        // Opted-out and already-converted courses are left alone.
        expect(await courses.findOne({ courseId: 'C4' }).then((c) => c.superchatIds)).toBeUndefined();
        expect((await courses.findOne({ courseId: 'C5' })).superchatIds).toEqual(['existing']);
    });

    test('is idempotent — a second run makes no further changes', async () => {
        const db = legacyDb();
        await Superchat.ensureSuperchatsFromLegacy(db);
        await Superchat.ensureSuperchatsFromLegacy(db);

        const all = await Superchat.listSuperchats(db, { includeDeleted: true });
        expect(all).toHaveLength(3); // no duplicate buckets
        // Membership not doubled up by the second pass.
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).superchatIds).toEqual(['year-2']);
    });
});
