/**
 * Unit tests for src/models/StruggleActivity.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const StruggleActivity = require('../../../src/models/StruggleActivity');

const COLL = 'struggleActivity';

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
    jest.useRealTimers();
});

afterAll(() => {
    jest.restoreAllMocks();
});

function activity(overrides = {}) {
    return {
        id: 'activity-1',
        userId: 's1',
        studentName: 'Student One',
        courseId: 'C1',
        topic: 'photosynthesis',
        state: 'Active',
        source: 'course',
        superchatId: null,
        timestamp: new Date('2026-06-01T12:00:00Z'),
        ...overrides,
    };
}

describe('StruggleActivity.createActivityEntry', () => {
    test('stores a normalized course activity entry with timestamps', async () => {
        const db = memoryDb({});
        const timestamp = new Date('2026-03-01T12:00:00Z');

        const result = await StruggleActivity.createActivityEntry(db, {
            userId: 's1',
            studentName: 'Alice',
            courseId: 'BIOC202',
            topic: '  Krebs Cycle  ',
            state: 'Active',
            timestamp,
        });

        expect(result).toEqual({ acknowledged: true, insertedId: 'mem-1' });
        const stored = await db.collection(COLL).findOne({ userId: 's1' });
        expect(stored).toMatchObject({
            userId: 's1',
            studentName: 'Alice',
            courseId: 'BIOC202',
            topic: 'krebs cycle',
            state: 'Active',
            source: 'course',
            superchatId: null,
            timestamp,
        });
        expect(stored.createdAt).toBeInstanceOf(Date);
    });

    test('only exact superCourse source stores a superchat bucket', async () => {
        const db = memoryDb({});

        await StruggleActivity.createActivityEntry(db, {
            userId: 'super',
            studentName: 'Sam',
            courseId: 'C1',
            topic: 'Topic A',
            state: 'Active',
            source: 'superCourse',
            superchatId: 'sc-1',
        });
        await StruggleActivity.createActivityEntry(db, {
            userId: 'unknown',
            studentName: 'Uma',
            courseId: 'C1',
            topic: 'Topic B',
            state: 'Active',
            source: 'other',
            superchatId: 'ignored',
        });
        await StruggleActivity.createActivityEntry(db, {
            userId: 'legacy',
            studentName: 'Lee',
            courseId: 'C1',
            topic: 'Topic C',
            state: 'Active',
            source: 'superCourse',
        });

        await expect(db.collection(COLL).findOne({ userId: 'super' }))
            .resolves.toMatchObject({ source: 'superCourse', superchatId: 'sc-1' });
        await expect(db.collection(COLL).findOne({ userId: 'unknown' }))
            .resolves.toMatchObject({ source: 'course', superchatId: null });
        await expect(db.collection(COLL).findOne({ userId: 'legacy' }))
            .resolves.toMatchObject({ source: 'superCourse', superchatId: null });
    });
});

describe('StruggleActivity.getActivityByCourse', () => {
    test('returns one course newest first and ignores other courses', async () => {
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'old', courseId: 'C1', timestamp: new Date('2026-01-01') }),
                activity({ id: 'new', courseId: 'C1', timestamp: new Date('2026-03-01') }),
                activity({ id: 'mid', courseId: 'C1', timestamp: new Date('2026-02-01') }),
                activity({ id: 'other-course', courseId: 'C2', timestamp: new Date('2026-04-01') }),
            ],
        });

        const rows = await StruggleActivity.getActivityByCourse(db, 'C1');
        expect(rows.map(row => row.id)).toEqual(['new', 'mid', 'old']);
    });

    test('applies state, source, and limit filters together', async () => {
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'active-super-new', state: 'Active', source: 'superCourse', timestamp: new Date('2026-03-01') }),
                activity({ id: 'active-super-old', state: 'Active', source: 'superCourse', timestamp: new Date('2026-01-01') }),
                activity({ id: 'inactive-super', state: 'Inactive', source: 'superCourse', timestamp: new Date('2026-04-01') }),
                activity({ id: 'active-course', state: 'Active', source: 'course', timestamp: new Date('2026-05-01') }),
            ],
        });

        const rows = await StruggleActivity.getActivityByCourse(db, 'C1', {
            state: 'Active',
            source: 'superCourse',
            limit: 1,
        });
        expect(rows.map(row => row.id)).toEqual(['active-super-new']);
    });
});

describe('StruggleActivity.getSuperCourseActivity', () => {
    test('returns Super Chat rows across courses newest first', async () => {
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'c1-old', courseId: 'C1', source: 'superCourse', timestamp: new Date('2026-01-01') }),
                activity({ id: 'c2-new', courseId: 'C2', source: 'superCourse', timestamp: new Date('2026-03-01') }),
                activity({ id: 'normal-course', courseId: 'C1', source: 'course', timestamp: new Date('2026-04-01') }),
            ],
        });

        const rows = await StruggleActivity.getSuperCourseActivity(db);
        expect(rows.map(row => row.id)).toEqual(['c2-new', 'c1-old']);
    });

    test('filters Super Chat rows by state, bucket, and limit', async () => {
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'sc1-new', source: 'superCourse', superchatId: 'sc-1', state: 'Active', timestamp: new Date('2026-04-01') }),
                activity({ id: 'sc1-old', source: 'superCourse', superchatId: 'sc-1', state: 'Active', timestamp: new Date('2026-02-01') }),
                activity({ id: 'sc1-inactive', source: 'superCourse', superchatId: 'sc-1', state: 'Inactive', timestamp: new Date('2026-05-01') }),
                activity({ id: 'sc2-newer', source: 'superCourse', superchatId: 'sc-2', state: 'Active', timestamp: new Date('2026-06-01') }),
            ],
        });

        const rows = await StruggleActivity.getSuperCourseActivity(db, {
            state: 'Active',
            superchatId: 'sc-1',
            limit: 1,
        });
        expect(rows.map(row => row.id)).toEqual(['sc1-new']);
    });
});

describe('StruggleActivity.getActivityByStudent', () => {
    test('returns one student newest first with an optional limit', async () => {
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'old', userId: 's1', timestamp: new Date('2026-01-01') }),
                activity({ id: 'new', userId: 's1', timestamp: new Date('2026-03-01') }),
                activity({ id: 'mid', userId: 's1', timestamp: new Date('2026-02-01') }),
                activity({ id: 'other-student', userId: 's2', timestamp: new Date('2026-04-01') }),
            ],
        });

        const rows = await StruggleActivity.getActivityByStudent(db, 's1', { limit: 2 });
        expect(rows.map(row => row.id)).toEqual(['new', 'mid']);
    });
});

describe('StruggleActivity.getWeeklyActiveTopics', () => {
    test('groups active topics by ISO week with unique student counts', async () => {
        jest.useFakeTimers().setSystemTime(new Date('2026-06-25T12:00:00Z'));
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'p1', userId: 's1', topic: 'Photosynthesis', timestamp: new Date('2026-06-10T12:00:00Z') }),
                activity({ id: 'p1-duplicate', userId: 's1', topic: 'photosynthesis', timestamp: new Date('2026-06-11T12:00:00Z') }),
                activity({ id: 'p2', userId: 's2', topic: 'PHOTOSYNTHESIS', timestamp: new Date('2026-06-12T12:00:00Z') }),
                activity({ id: 'm1', userId: 's3', topic: 'Mitosis', timestamp: new Date('2026-06-12T12:00:00Z') }),
                activity({ id: 'next-week', userId: 's4', topic: 'ATP', timestamp: new Date('2026-06-16T12:00:00Z') }),
                activity({ id: 'inactive', userId: 's5', state: 'Inactive', topic: 'ignored', timestamp: new Date('2026-06-12T12:00:00Z') }),
                activity({ id: 'other-course', userId: 's6', courseId: 'C2', topic: 'ignored', timestamp: new Date('2026-06-12T12:00:00Z') }),
                activity({ id: 'too-old', userId: 's7', topic: 'ignored', timestamp: new Date('2026-05-01T12:00:00Z') }),
            ],
        });

        const rows = await StruggleActivity.getWeeklyActiveTopics(db, 'C1', { weeks: 4 });

        expect(rows).toHaveLength(2);
        expect(rows[0].weekStart).toEqual(new Date('2026-06-08T00:00:00.000Z'));
        expect(rows[0].totalCount).toBe(3);
        expect(rows[0].topics).toEqual(expect.arrayContaining([
            { topic: 'photosynthesis', studentCount: 2 },
            { topic: 'mitosis', studentCount: 1 },
        ]));
        expect(rows[1]).toMatchObject({
            weekStart: new Date('2026-06-15T00:00:00.000Z'),
            totalCount: 1,
            topics: [{ topic: 'atp', studentCount: 1 }],
        });
    });

    test('can aggregate global Super Chat rows within one superchat bucket', async () => {
        jest.useFakeTimers().setSystemTime(new Date('2026-06-25T12:00:00Z'));
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'c1-sc1', userId: 's1', courseId: 'C1', topic: 'Topic A', source: 'superCourse', superchatId: 'sc-1', timestamp: new Date('2026-06-10T12:00:00Z') }),
                activity({ id: 'c2-sc1', userId: 's2', courseId: 'C2', topic: 'topic a', source: 'superCourse', superchatId: 'sc-1', timestamp: new Date('2026-06-11T12:00:00Z') }),
                activity({ id: 'c3-sc2', userId: 's3', courseId: 'C3', topic: 'Topic A', source: 'superCourse', superchatId: 'sc-2', timestamp: new Date('2026-06-12T12:00:00Z') }),
                activity({ id: 'normal', userId: 's4', courseId: 'C4', topic: 'Topic A', source: 'course', timestamp: new Date('2026-06-12T12:00:00Z') }),
            ],
        });

        const rows = await StruggleActivity.getWeeklyActiveTopics(db, null, {
            weeks: 4,
            source: 'superCourse',
            superchatId: 'sc-1',
        });

        expect(rows).toEqual([{
            weekStart: new Date('2026-06-08T00:00:00.000Z'),
            topics: [{ topic: 'topic a', studentCount: 2 }],
            totalCount: 2,
        }]);
    });

    test('snaps a Sunday lookback start back to the prior Monday', async () => {
        jest.useFakeTimers().setSystemTime(new Date('2026-06-28T12:00:00Z'));
        const db = memoryDb({
            [COLL]: [
                activity({ id: 'included', userId: 's1', topic: 'Included', timestamp: new Date('2026-06-16T12:00:00Z') }),
                activity({ id: 'too-early', userId: 's2', topic: 'Too early', timestamp: new Date('2026-06-14T12:00:00Z') }),
            ],
        });

        const rows = await StruggleActivity.getWeeklyActiveTopics(db, 'C1', { weeks: 1 });

        expect(rows).toEqual([{
            weekStart: new Date('2026-06-15T00:00:00.000Z'),
            topics: [{ topic: 'included', studentCount: 1 }],
            totalCount: 1,
        }]);
    });
});
