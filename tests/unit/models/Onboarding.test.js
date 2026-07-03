/**
 * Unit tests for src/models/Onboarding.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const Onboarding = require('../../../src/models/Onboarding');

const COLL = 'onboarding';

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
    jest.restoreAllMocks();
});

describe('Onboarding.getOnboardingCollection', () => {
    test('returns the onboarding collection', () => {
        const db = memoryDb({});
        expect(Onboarding.getOnboardingCollection(db)).toBe(db.collection(COLL));
    });
});

describe('Onboarding.upsertOnboarding', () => {
    test('creates a new onboarding record with defaults', async () => {
        const db = memoryDb({});

        const result = await Onboarding.upsertOnboarding(db, {
            courseId: 'C1',
            courseName: 'BIOC 202',
            instructorId: 'i1',
        });

        expect(result).toEqual({
            success: true,
            created: true,
            modifiedCount: 0,
            courseId: 'C1',
        });

        const stored = await Onboarding.getOnboardingByCourseId(db, 'C1');
        expect(stored).toMatchObject({
            courseId: 'C1',
            courseName: 'BIOC 202',
            instructorId: 'i1',
            courseDescription: '',
            learningOutcomes: [],
            assessmentCriteria: '',
            courseMaterials: [],
            unitFiles: {},
            courseStructure: {},
        });
        expect(stored.createdAt).toBeInstanceOf(Date);
        expect(stored.updatedAt).toBeInstanceOf(Date);
    });

    test('updates an existing onboarding record and reports created false', async () => {
        const db = memoryDb({});
        const createdAt = new Date('2026-01-01T00:00:00Z');

        await Onboarding.upsertOnboarding(db, {
            courseId: 'C1',
            courseName: 'Old name',
            instructorId: 'i1',
            createdAt,
        });
        const result = await Onboarding.upsertOnboarding(db, {
            courseId: 'C1',
            courseName: 'New name',
            instructorId: 'i1',
            courseDescription: 'Updated description',
            learningOutcomes: ['Outcome 1'],
            createdAt,
        });

        expect(result).toEqual({
            success: true,
            created: false,
            modifiedCount: 1,
            courseId: 'C1',
        });
        const stored = await Onboarding.getOnboardingByCourseId(db, 'C1');
        expect(stored).toMatchObject({
            courseName: 'New name',
            courseDescription: 'Updated description',
            learningOutcomes: ['Outcome 1'],
            createdAt,
        });
    });

    test('preserves createdAt on update when the caller omits createdAt', async () => {
        const originalCreatedAt = new Date('2026-01-01T00:00:00Z');
        const db = memoryDb({
            [COLL]: [{
                courseId: 'C1',
                courseName: 'Existing',
                instructorId: 'i1',
                createdAt: originalCreatedAt,
                updatedAt: originalCreatedAt,
            }],
        });

        await Onboarding.upsertOnboarding(db, {
            courseId: 'C1',
            courseName: 'Updated',
            instructorId: 'i1',
        });

        const stored = await Onboarding.getOnboardingByCourseId(db, 'C1');
        expect(stored.createdAt).toBeInstanceOf(Date);
        expect(stored.createdAt.getTime()).toBe(originalCreatedAt.getTime());
    });
});

describe('Onboarding read helpers', () => {
    test('gets onboarding data by course id or null', async () => {
        const db = memoryDb({ [COLL]: [{ courseId: 'C1', courseName: 'BIOC 202' }] });

        await expect(Onboarding.getOnboardingByCourseId(db, 'C1'))
            .resolves.toMatchObject({ courseName: 'BIOC 202' });
        await expect(Onboarding.getOnboardingByCourseId(db, 'missing')).resolves.toBeNull();
    });

    test('gets all onboarding records for an instructor', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', instructorId: 'i1' },
                { courseId: 'C2', instructorId: 'i2' },
                { courseId: 'C3', instructorId: 'i1' },
            ],
        });

        const records = await Onboarding.getOnboardingByInstructor(db, 'i1');
        expect(records.map(record => record.courseId)).toEqual(['C1', 'C3']);
    });
});

describe('Onboarding.updateOnboardingFields', () => {
    test('updates arbitrary fields and stamps updatedAt', async () => {
        const db = memoryDb({
            [COLL]: [{ courseId: 'C1', courseName: 'BIOC 202', learningOutcomes: [] }],
        });

        const result = await Onboarding.updateOnboardingFields(db, 'C1', {
            courseDescription: 'New description',
            learningOutcomes: ['LO1', 'LO2'],
        });

        expect(result).toEqual({ success: true, modifiedCount: 1, courseId: 'C1' });
        const stored = await Onboarding.getOnboardingByCourseId(db, 'C1');
        expect(stored).toMatchObject({
            courseDescription: 'New description',
            learningOutcomes: ['LO1', 'LO2'],
        });
        expect(stored.updatedAt).toBeInstanceOf(Date);
    });

    test('reports success with zero modifications when the course is missing', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Onboarding.updateOnboardingFields(db, 'missing', { courseName: 'Nope' }))
            .resolves.toEqual({ success: true, modifiedCount: 0, courseId: 'missing' });
    });
});

describe('Onboarding.updateUnitFiles', () => {
    test('sets files for a unit under unitFiles and stamps updatedAt', async () => {
        const db = memoryDb({
            [COLL]: [{ courseId: 'C1', unitFiles: { 'Unit 0': [{ name: 'old.pdf' }] } }],
        });
        const files = [{ filename: 'unit1.pdf', originalName: 'Unit 1.pdf' }];

        const result = await Onboarding.updateUnitFiles(db, 'C1', 'Unit 1', files);

        expect(result).toEqual({
            success: true,
            modifiedCount: 1,
            courseId: 'C1',
            unitName: 'Unit 1',
        });
        const stored = await Onboarding.getOnboardingByCourseId(db, 'C1');
        expect(stored.unitFiles).toMatchObject({
            'Unit 0': [{ name: 'old.pdf' }],
            'Unit 1': files,
        });
        expect(stored.updatedAt).toBeInstanceOf(Date);
    });

    test('reports zero modifications when the course is missing', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Onboarding.updateUnitFiles(db, 'missing', 'Unit 1', []))
            .resolves.toEqual({ success: true, modifiedCount: 0, courseId: 'missing', unitName: 'Unit 1' });
    });
});

describe('Onboarding.deleteOnboarding', () => {
    test('deletes the course onboarding record', async () => {
        const db = memoryDb({ [COLL]: [{ courseId: 'C1' }, { courseId: 'C2' }] });

        await expect(Onboarding.deleteOnboarding(db, 'C1'))
            .resolves.toEqual({ success: true, deletedCount: 1, courseId: 'C1' });
        await expect(Onboarding.getOnboardingByCourseId(db, 'C1')).resolves.toBeNull();
        await expect(Onboarding.getOnboardingByCourseId(db, 'C2')).resolves.toMatchObject({ courseId: 'C2' });
    });

    test('reports zero deletions when the course is missing', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Onboarding.deleteOnboarding(db, 'missing'))
            .resolves.toEqual({ success: true, deletedCount: 0, courseId: 'missing' });
    });
});

describe('Onboarding.getOnboardingStats', () => {
    test('counts courses and distinct instructors', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', instructorId: 'i1' },
                { courseId: 'C2', instructorId: 'i1' },
                { courseId: 'C3', instructorId: 'i2' },
            ],
        });

        const stats = await Onboarding.getOnboardingStats(db);
        expect(stats).toMatchObject({
            totalCourses: 3,
            totalInstructors: 2,
        });
        expect(Number.isNaN(Date.parse(stats.lastUpdated))).toBe(false);
    });

    test('returns zero counts for an empty collection', async () => {
        const db = memoryDb({ [COLL]: [] });

        const stats = await Onboarding.getOnboardingStats(db);
        expect(stats).toMatchObject({ totalCourses: 0, totalInstructors: 0 });
        expect(Number.isNaN(Date.parse(stats.lastUpdated))).toBe(false);
    });
});

describe('Onboarding error propagation', () => {
    // The collection lookup happens before each try block, so the failure must
    // come from the collection operations themselves.
    const reject = async () => { throw new Error('mongo down'); };
    const throwingDb = { collection: () => ({
        updateOne: reject, findOne: reject, find: () => { throw new Error('mongo down'); }, deleteOne: reject,
        countDocuments: reject, distinct: reject, aggregate: () => { throw new Error('mongo down'); },
    }) };

    test('every helper logs and rethrows when the collection is unavailable', async () => {
        await expect(Onboarding.upsertOnboarding(throwingDb, { courseId: 'C1' })).rejects.toThrow('mongo down');
        await expect(Onboarding.getOnboardingByCourseId(throwingDb, 'C1')).rejects.toThrow('mongo down');
        await expect(Onboarding.getOnboardingByInstructor(throwingDb, 'i1')).rejects.toThrow('mongo down');
        await expect(Onboarding.updateOnboardingFields(throwingDb, 'C1', { x: 1 })).rejects.toThrow('mongo down');
        await expect(Onboarding.updateUnitFiles(throwingDb, 'C1', 'Unit 1', [])).rejects.toThrow('mongo down');
        await expect(Onboarding.deleteOnboarding(throwingDb, 'C1')).rejects.toThrow('mongo down');
        await expect(Onboarding.getOnboardingStats(throwingDb)).rejects.toThrow('mongo down');
    });
});
