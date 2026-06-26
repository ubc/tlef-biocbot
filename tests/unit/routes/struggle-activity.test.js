/**
 * In-process route tests for src/routes/struggle-activity.js (supertest).
 *
 * No heavy deps: the router reads StruggleActivity + PersistenceTopic models over
 * the in-memory Mongo double and req.user. Covers the per-student access guard, the
 * per-course / persistence / weekly readers, the Super Chat aggregates, and the
 * route-ordering contract (specific prefixes resolve before the /:courseId catch-all).
 */
const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/struggle-activity');

const student = { userId: 's1', role: 'student' };
const otherStudent = { userId: 's2', role: 'student' };
const instructor = { userId: 'i1', role: 'instructor' };
const app = (opts) => makeRouteApp(router, opts);

// A struggle row as createActivityEntry would have stored it (topic lower-cased).
const row = (over = {}) => ({
    userId: 's1', studentName: 'Stu', courseId: 'C1', topic: 'glycolysis',
    state: 'Active', source: 'course', superchatId: null,
    timestamp: new Date('2026-06-20T10:00:00Z'), createdAt: new Date('2026-06-20T10:00:00Z'),
    ...over,
});

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET /student/:userId', () => {
    test('a student may read their own activity', async () => {
        const db = memoryDb({ struggleActivity: [row({ userId: 's1' }), row({ userId: 's2', topic: 'krebs' })] });
        const res = await request(app({ db, user: student })).get('/student/s1');
        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.count).toBe(1);
        expect(res.body.data.map(a => a.userId)).toEqual(['s1']);
    });

    test('a student may NOT read another student\'s activity', async () => {
        const res = await request(app({ db: memoryDb({}), user: otherStudent })).get('/student/s1');
        expect(res.status).toBe(403);
        expect(res.body.message).toMatch(/only view your own/i);
    });

    test('an instructor may read any student\'s activity', async () => {
        const db = memoryDb({ struggleActivity: [row({ userId: 's1' })] });
        const res = await request(app({ db, user: instructor })).get('/student/s1');
        expect(res.status).toBe(200);
        expect(res.body.count).toBe(1);
    });

    test('limit query param caps the number of rows returned', async () => {
        const db = memoryDb({ struggleActivity: [row(), row({ topic: 'krebs' }), row({ topic: 'atp' })] });
        const res = await request(app({ db, user: instructor })).get('/student/s1?limit=2');
        expect(res.status).toBe(200);
        expect(res.body.data).toHaveLength(2);
    });
});

describe('GET /persistence/:courseId', () => {
    test('returns persistence topics sorted by studentCount desc', async () => {
        const db = memoryDb({
            persistenceTopics: [
                { courseId: 'C1', topic: 'glycolysis', studentCount: 2, studentIds: ['s1', 's2'] },
                { courseId: 'C1', topic: 'krebs', studentCount: 5, studentIds: ['s1'] },
                { courseId: 'C2', topic: 'other', studentCount: 9 }, // different course, excluded
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/persistence/C1');
        expect(res.status).toBe(200);
        expect(res.body.count).toBe(2);
        expect(res.body.data.map(t => t.topic)).toEqual(['krebs', 'glycolysis']);
    });
});

describe('GET /weekly/:courseId', () => {
    test('aggregates Active topics into ISO-week buckets', async () => {
        const db = memoryDb({
            struggleActivity: [
                row({ userId: 's1', state: 'Active', timestamp: new Date() }),
                row({ userId: 's2', state: 'Active', timestamp: new Date(), topic: 'glycolysis' }),
                row({ userId: 's3', state: 'Inactive', timestamp: new Date(), topic: 'glycolysis' }), // excluded
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/weekly/C1');
        expect(res.status).toBe(200);
        expect(res.body.data).toHaveLength(1);
        const week = res.body.data[0];
        // Two unique students struggled with glycolysis this week.
        expect(week.totalCount).toBe(2);
        expect(week.topics[0]).toMatchObject({ topic: 'glycolysis', studentCount: 2 });
    });
});

describe('GET /super-course (and /super-course/weekly)', () => {
    test('returns only superCourse-sourced activity, ignoring courseId', async () => {
        const db = memoryDb({
            struggleActivity: [
                row({ source: 'superCourse', superchatId: 'sc1', courseId: 'C1' }),
                row({ source: 'superCourse', superchatId: 'sc2', courseId: 'C9', topic: 'krebs' }),
                row({ source: 'course' }), // in-course struggle, excluded from the Super Chat view
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/super-course');
        expect(res.status).toBe(200);
        expect(res.body.count).toBe(2);
        expect(res.body.data.every(a => a.source === 'superCourse')).toBe(true);
    });

    test('superchatId query param scopes to a single bucket', async () => {
        const db = memoryDb({
            struggleActivity: [
                row({ source: 'superCourse', superchatId: 'sc1' }),
                row({ source: 'superCourse', superchatId: 'sc2', topic: 'krebs' }),
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/super-course?superchatId=sc1');
        expect(res.body.count).toBe(1);
        expect(res.body.data[0].superchatId).toBe('sc1');
    });

    test('/super-course/weekly resolves to the weekly handler, NOT the /:courseId catch-all', async () => {
        const db = memoryDb({
            struggleActivity: [row({ source: 'superCourse', superchatId: 'sc1', state: 'Active', timestamp: new Date() })],
        });
        const res = await request(app({ db, user: instructor })).get('/super-course/weekly');
        expect(res.status).toBe(200);
        // The weekly aggregate shape (buckets with totalCount) proves the prefix
        // route won, not getActivityByCourse(courseId='super-course').
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(res.body.data[0]).toHaveProperty('totalCount');
    });
});

describe('GET /:courseId (catch-all)', () => {
    test('returns course activity filtered by state', async () => {
        const db = memoryDb({
            struggleActivity: [
                row({ state: 'Active' }),
                row({ state: 'Inactive', topic: 'krebs' }),
            ],
        });
        const res = await request(app({ db, user: instructor })).get('/C1?state=Active');
        expect(res.status).toBe(200);
        expect(res.body.count).toBe(1);
        expect(res.body.data[0].state).toBe('Active');
    });

    test('returns an empty list (count 0) for a course with no activity', async () => {
        const res = await request(app({ db: memoryDb({ struggleActivity: [] }), user: instructor })).get('/C-unknown');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ success: true, count: 0, data: [] });
    });
});
