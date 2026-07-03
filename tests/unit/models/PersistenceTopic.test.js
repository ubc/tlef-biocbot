/**
 * Unit tests for src/models/PersistenceTopic.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const PersistenceTopic = require('../../../src/models/PersistenceTopic');

const COLL = 'persistenceTopics';

describe('PersistenceTopic.incrementStudentCount', () => {
    test('upserts a normalized topic and stores the first unique student count', async () => {
        const db = memoryDb({});

        const result = await PersistenceTopic.incrementStudentCount(
            db,
            'C1',
            '  Glycolysis  ',
            'student-1'
        );

        expect(result).toEqual({
            success: true,
            topic: 'glycolysis',
            count: 1,
            isNew: true,
        });

        const stored = await db.collection(COLL).findOne({ courseId: 'C1', topic: 'glycolysis' });
        expect(stored).toMatchObject({
            courseId: 'C1',
            topic: 'glycolysis',
            studentIds: ['student-1'],
            studentCount: 1,
        });
        expect(stored._id).toBe('mem-upsert-1');
        expect(stored.createdAt).toBeInstanceOf(Date);
        expect(stored.lastUpdated).toBeInstanceOf(Date);
    });

    test('matches existing topics case-insensitively and does not double-count the same student', async () => {
        const db = memoryDb({
            [COLL]: [{
                _id: 'topic-1',
                courseId: 'C1',
                topic: 'Glycolysis',
                studentIds: ['student-1'],
                studentCount: 1,
                createdAt: new Date('2026-01-01'),
            }],
        });

        await expect(PersistenceTopic.incrementStudentCount(db, 'C1', 'glycolysis', 'student-2'))
            .resolves.toEqual({
                success: true,
                topic: 'Glycolysis',
                count: 2,
                isNew: false,
            });
        await expect(PersistenceTopic.incrementStudentCount(db, 'C1', 'GLYCOLYSIS', 'student-2'))
            .resolves.toEqual({
                success: true,
                topic: 'Glycolysis',
                count: 2,
                isNew: false,
            });

        const stored = await db.collection(COLL).findOne({ _id: 'topic-1' });
        expect(stored.studentIds).toEqual(['student-1', 'student-2']);
        expect(stored.studentCount).toBe(2);
        expect(stored.lastUpdated).toBeInstanceOf(Date);
    });

    test('keeps counts scoped to the provided course', async () => {
        const db = memoryDb({
            [COLL]: [{
                _id: 'topic-other-course',
                courseId: 'C2',
                topic: 'glycolysis',
                studentIds: ['student-9'],
                studentCount: 1,
            }],
        });

        const result = await PersistenceTopic.incrementStudentCount(db, 'C1', 'Glycolysis', 'student-1');

        expect(result).toMatchObject({ success: true, topic: 'glycolysis', count: 1, isNew: true });
        expect(await db.collection(COLL).countDocuments({ topic: 'glycolysis' })).toBe(2);
        await expect(db.collection(COLL).findOne({ _id: 'topic-other-course' }))
            .resolves.toMatchObject({ studentIds: ['student-9'], studentCount: 1 });
    });

    test('treats regex metacharacters as literal topic text', async () => {
        const db = memoryDb({
            [COLL]: [{
                _id: 'topic-1',
                courseId: 'C1',
                topic: 'atpase',
                studentIds: ['student-1'],
                studentCount: 1,
            }],
        });

        const result = await PersistenceTopic.incrementStudentCount(db, 'C1', 'ATP.se', 'student-2');

        expect(result).toEqual({
            success: true,
            topic: 'atp.se',
            count: 1,
            isNew: true,
        });
        expect(await db.collection(COLL).countDocuments({ courseId: 'C1' })).toBe(2);
        await expect(db.collection(COLL).findOne({ _id: 'topic-1' }))
            .resolves.toMatchObject({
                topic: 'atpase',
                studentIds: ['student-1'],
                studentCount: 1,
            });
        await expect(db.collection(COLL).findOne({ topic: 'atp.se' }))
            .resolves.toMatchObject({ studentIds: ['student-2'], studentCount: 1 });
    });

    test('returns success with count zero when the returned document has no studentIds array', async () => {
        const collection = {
            findOneAndUpdate: jest.fn(async () => ({
                value: { _id: 'topic-1', topic: 'mitosis' },
            })),
            updateOne: jest.fn(async () => ({ modifiedCount: 1 })),
        };
        const db = { collection: jest.fn(() => collection) };

        const result = await PersistenceTopic.incrementStudentCount(db, 'C1', 'Mitosis', 'student-1');

        expect(result).toEqual({
            success: true,
            topic: 'mitosis',
            count: 0,
            isNew: false,
        });
        expect(collection.updateOne).toHaveBeenCalledWith(
            { _id: 'topic-1' },
            { $set: { studentCount: 0 } }
        );
    });

    test('returns failure when findOneAndUpdate does not return a document', async () => {
        const collection = {
            findOneAndUpdate: jest.fn(async () => ({ value: null })),
        };
        const db = { collection: jest.fn(() => collection) };

        await expect(PersistenceTopic.incrementStudentCount(db, 'C1', 'No Result', 'student-1'))
            .resolves.toEqual({ success: false });
    });
});

describe('PersistenceTopic.getPersistenceTopics', () => {
    test('returns topics for one course sorted by studentCount descending', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', topic: 'glycolysis', studentCount: 1 },
                { courseId: 'C1', topic: 'photosynthesis', studentCount: 3 },
                { courseId: 'C2', topic: 'mitosis', studentCount: 9 },
                { courseId: 'C1', topic: 'krebs cycle', studentCount: 2 },
            ],
        });

        const topics = await PersistenceTopic.getPersistenceTopics(db, 'C1');

        expect(topics.map(topic => topic.topic)).toEqual(['photosynthesis', 'krebs cycle', 'glycolysis']);
        expect(topics.map(topic => topic.studentCount)).toEqual([3, 2, 1]);
    });

    test('returns an empty list when the course has no persistence topics', async () => {
        const db = memoryDb({ [COLL]: [{ courseId: 'C2', topic: 'mitosis', studentCount: 1 }] });

        await expect(PersistenceTopic.getPersistenceTopics(db, 'C1')).resolves.toEqual([]);
    });
});
