/**
 * Unit tests for src/models/MentalHealthFlag.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const MentalHealthFlag = require('../../../src/models/MentalHealthFlag');

const COLL = 'mentalHealthFlags';

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
    jest.restoreAllMocks();
});

describe('MentalHealthFlag.createMentalHealthFlag', () => {
    test('creates a pending flag with defaults and returns its generated id', async () => {
        const db = memoryDb({});
        const result = await MentalHealthFlag.createMentalHealthFlag(db, {
            studentId: 's1',
            courseId: 'C1',
            message: 'I feel overwhelmed',
            concernLevel: 'high concern',
        });

        expect(result).toMatchObject({
            success: true,
            insertedId: 'mem-1',
        });
        expect(result.flagId).toMatch(/^mhf_[0-9a-f-]{36}$/i);

        const stored = await db.collection(COLL).findOne({ flagId: result.flagId });
        expect(stored).toMatchObject({
            flagId: result.flagId,
            studentId: 's1',
            studentName: 'Unknown Student',
            courseId: 'C1',
            unitName: 'Unknown Unit',
            message: 'I feel overwhelmed',
            conversationContext: [],
            concernLevel: 'high concern',
            llmReason: '',
            status: 'pending',
            escalatedBy: null,
            escalatedAt: null,
            resolvedBy: null,
            resolvedAt: null,
        });
        expect(stored.createdAt).toBeInstanceOf(Date);
        expect(stored.updatedAt).toBeInstanceOf(Date);
    });

    test('preserves provided student, unit, conversation context, and LLM reason', async () => {
        const db = memoryDb({});
        const context = [{ role: 'student', content: 'I need help' }];

        const result = await MentalHealthFlag.createMentalHealthFlag(db, {
            studentId: 's1',
            studentName: 'Student One',
            courseId: 'C1',
            unitName: 'Unit 2',
            message: 'I need help',
            conversationContext: context,
            concernLevel: 'low concern',
            llmReason: 'Student expressed distress.',
        });

        const stored = await db.collection(COLL).findOne({ flagId: result.flagId });
        expect(stored).toMatchObject({
            studentName: 'Student One',
            unitName: 'Unit 2',
            conversationContext: context,
            llmReason: 'Student expressed distress.',
        });
    });
});

describe('MentalHealthFlag.getMentalHealthFlagsForCourse', () => {
    test('returns course flags newest first when no status filter is provided', async () => {
        const db = memoryDb({
            [COLL]: [
                { flagId: 'old', courseId: 'C1', status: 'pending', createdAt: new Date('2026-01-01') },
                { flagId: 'new', courseId: 'C1', status: 'resolved', createdAt: new Date('2026-03-01') },
                { flagId: 'other-course', courseId: 'C2', status: 'pending', createdAt: new Date('2026-04-01') },
            ],
        });

        const flags = await MentalHealthFlag.getMentalHealthFlagsForCourse(db, 'C1');
        expect(flags.map(flag => flag.flagId)).toEqual(['new', 'old']);
    });

    test('filters by status unless the filter is "all"', async () => {
        const db = memoryDb({
            [COLL]: [
                { flagId: 'pending', courseId: 'C1', status: 'pending', createdAt: new Date('2026-01-01') },
                { flagId: 'resolved', courseId: 'C1', status: 'resolved', createdAt: new Date('2026-02-01') },
            ],
        });

        const pending = await MentalHealthFlag.getMentalHealthFlagsForCourse(db, 'C1', 'pending');
        expect(pending.map(flag => flag.flagId)).toEqual(['pending']);

        const all = await MentalHealthFlag.getMentalHealthFlagsForCourse(db, 'C1', 'all');
        expect(all.map(flag => flag.flagId)).toEqual(['resolved', 'pending']);
    });
});

describe('MentalHealthFlag.updateFlagStatus', () => {
    test('escalates a flag and records who escalated it', async () => {
        const db = memoryDb({ [COLL]: [{ flagId: 'mhf-1', status: 'pending' }] });

        await expect(MentalHealthFlag.updateFlagStatus(db, 'mhf-1', 'escalated', 'instructor-1')).resolves.toEqual({
            success: true,
        });

        const stored = await db.collection(COLL).findOne({ flagId: 'mhf-1' });
        expect(stored).toMatchObject({
            status: 'escalated',
            escalatedBy: 'instructor-1',
        });
        expect(stored.escalatedAt).toBeInstanceOf(Date);
        expect(stored.updatedAt).toBeInstanceOf(Date);
        expect(stored.resolvedBy).toBeUndefined();
    });

    test('resolved and disregarded statuses record resolver metadata', async () => {
        const db = memoryDb({
            [COLL]: [
                { flagId: 'resolve-me', status: 'escalated' },
                { flagId: 'disregard-me', status: 'pending' },
            ],
        });

        await expect(MentalHealthFlag.updateFlagStatus(db, 'resolve-me', 'resolved', 'admin-1')).resolves.toEqual({ success: true });
        await expect(MentalHealthFlag.updateFlagStatus(db, 'disregard-me', 'disregarded', 'admin-2')).resolves.toEqual({ success: true });

        const resolved = await db.collection(COLL).findOne({ flagId: 'resolve-me' });
        expect(resolved).toMatchObject({ status: 'resolved', resolvedBy: 'admin-1' });
        expect(resolved.resolvedAt).toBeInstanceOf(Date);

        const disregarded = await db.collection(COLL).findOne({ flagId: 'disregard-me' });
        expect(disregarded).toMatchObject({ status: 'disregarded', resolvedBy: 'admin-2' });
        expect(disregarded.resolvedAt).toBeInstanceOf(Date);
    });

    test('dismissed only updates status and updatedAt', async () => {
        const db = memoryDb({ [COLL]: [{ flagId: 'dismiss-me', status: 'pending' }] });

        await expect(MentalHealthFlag.updateFlagStatus(db, 'dismiss-me', 'dismissed', 'instructor-1')).resolves.toEqual({
            success: true,
        });

        const stored = await db.collection(COLL).findOne({ flagId: 'dismiss-me' });
        expect(stored).toMatchObject({ status: 'dismissed' });
        expect(stored.updatedAt).toBeInstanceOf(Date);
        expect(stored.escalatedBy).toBeUndefined();
        expect(stored.resolvedBy).toBeUndefined();
    });

    test('returns failure when no flag matches', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(MentalHealthFlag.updateFlagStatus(db, 'missing', 'resolved', 'admin-1')).resolves.toEqual({
            success: false,
            error: 'Flag not found or no changes made',
        });
    });
});

describe('MentalHealthFlag.getMentalHealthFlagStats', () => {
    test('returns zeroed stats when a course has no flags', async () => {
        const db = memoryDb({ [COLL]: [{ courseId: 'C2', status: 'pending' }] });

        expect(await MentalHealthFlag.getMentalHealthFlagStats(db, 'C1')).toEqual({
            total: 0,
            pending: 0,
            escalated: 0,
            dismissed: 0,
            resolved: 0,
            disregarded: 0,
        });
    });

    test('aggregates status counts for the requested course only', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', status: 'pending' },
                { courseId: 'C1', status: 'pending' },
                { courseId: 'C1', status: 'escalated' },
                { courseId: 'C1', status: 'dismissed' },
                { courseId: 'C1', status: 'resolved' },
                { courseId: 'C1', status: 'disregarded' },
                { courseId: 'C2', status: 'pending' },
            ],
        });

        expect(await MentalHealthFlag.getMentalHealthFlagStats(db, 'C1')).toEqual({
            total: 6,
            pending: 2,
            escalated: 1,
            dismissed: 1,
            resolved: 1,
            disregarded: 1,
        });
    });
});
