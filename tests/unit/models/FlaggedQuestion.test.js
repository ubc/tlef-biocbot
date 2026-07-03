/**
 * Unit tests for src/models/FlaggedQuestion.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const FlaggedQuestion = require('../../../src/models/FlaggedQuestion');

const COLL = 'flaggedQuestions';

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
    jest.restoreAllMocks();
});

function flag(overrides = {}) {
    return {
        flagId: 'flag-1',
        questionId: 'q1',
        courseId: 'C1',
        studentId: 's1',
        flagReason: 'unclear',
        flagStatus: 'pending',
        createdAt: new Date('2026-01-01T00:00:00Z'),
        ...overrides,
    };
}

describe('FlaggedQuestion.createFlaggedQuestion', () => {
    test('stores a pending flag with generated id, timestamps, and derived priority', async () => {
        const db = memoryDb({});

        const result = await FlaggedQuestion.createFlaggedQuestion(db, {
            questionId: 'q1',
            courseId: 'C1',
            courseName: 'BIOC 202',
            unitName: 'Unit 1',
            studentId: 's1',
            studentName: 'Student One',
            flagReason: 'incorrect',
            flagDescription: 'The answer key appears wrong.',
            botMode: 'tutor',
            questionContent: { question: 'What stores genetic information?' },
            flagStatus: 'dismissed',
        });

        expect(result).toMatchObject({ success: true, insertedId: 'mem-1' });
        expect(result.flagId).toMatch(/^flag_[0-9a-f-]{36}$/i);

        const stored = await FlaggedQuestion.getFlaggedQuestionById(db, result.flagId);
        expect(stored).toMatchObject({
            flagId: result.flagId,
            questionId: 'q1',
            courseId: 'C1',
            courseName: 'BIOC 202',
            studentId: 's1',
            flagReason: 'incorrect',
            flagStatus: 'pending',
            priority: 'high',
            questionContent: { question: 'What stores genetic information?' },
        });
        expect(stored.createdAt).toBeInstanceOf(Date);
        expect(stored.updatedAt).toBeInstanceOf(Date);
    });

    test('derives medium and low priorities from the exact stored reason buckets', async () => {
        const db = memoryDb({});

        const medium = await FlaggedQuestion.createFlaggedQuestion(db, {
            questionId: 'q-medium',
            courseId: 'C1',
            studentId: 's1',
            flagReason: 'typo',
        });
        const low = await FlaggedQuestion.createFlaggedQuestion(db, {
            questionId: 'q-low',
            courseId: 'C1',
            studentId: 's1',
            flagReason: 'other',
        });

        await expect(FlaggedQuestion.getFlaggedQuestionById(db, medium.flagId))
            .resolves.toMatchObject({ priority: 'medium' });
        await expect(FlaggedQuestion.getFlaggedQuestionById(db, low.flagId))
            .resolves.toMatchObject({ priority: 'low' });
    });

    test('ignores a caller-provided flagId and stores the generated id', async () => {
        const db = memoryDb({});

        const result = await FlaggedQuestion.createFlaggedQuestion(db, {
            flagId: 'caller-id',
            questionId: 'q1',
            courseId: 'C1',
            studentId: 's1',
            flagReason: 'unclear',
        });

        expect(result.flagId).toMatch(/^flag_[0-9a-f-]{36}$/i);
        expect(result.flagId).not.toBe('caller-id');
        await expect(FlaggedQuestion.getFlaggedQuestionById(db, result.flagId))
            .resolves.toMatchObject({ flagId: result.flagId, questionId: 'q1' });
        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'caller-id')).resolves.toBeNull();
    });
});

describe('FlaggedQuestion read helpers', () => {
    test('gets course flags newest first and optionally filters by status', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ flagId: 'old-pending', courseId: 'C1', flagStatus: 'pending', createdAt: new Date('2026-01-01') }),
                flag({ flagId: 'new-reviewed', courseId: 'C1', flagStatus: 'reviewed', createdAt: new Date('2026-03-01') }),
                flag({ flagId: 'mid-pending', courseId: 'C1', flagStatus: 'pending', createdAt: new Date('2026-02-01') }),
                flag({ flagId: 'other-course', courseId: 'C2', flagStatus: 'pending', createdAt: new Date('2026-04-01') }),
            ],
        });

        const all = await FlaggedQuestion.getFlaggedQuestionsForCourse(db, 'C1');
        expect(all.map(item => item.flagId)).toEqual(['new-reviewed', 'mid-pending', 'old-pending']);

        const pending = await FlaggedQuestion.getFlaggedQuestionsForCourse(db, 'C1', 'pending');
        expect(pending.map(item => item.flagId)).toEqual(['mid-pending', 'old-pending']);
    });

    test('gets status flags across courses newest first', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ flagId: 'old', courseId: 'C1', flagStatus: 'pending', createdAt: new Date('2026-01-01') }),
                flag({ flagId: 'resolved', courseId: 'C1', flagStatus: 'resolved', createdAt: new Date('2026-03-01') }),
                flag({ flagId: 'new', courseId: 'C2', flagStatus: 'pending', createdAt: new Date('2026-02-01') }),
            ],
        });

        const flags = await FlaggedQuestion.getFlaggedQuestionsByStatus(db, 'pending');
        expect(flags.map(item => item.flagId)).toEqual(['new', 'old']);
    });

    test('gets one flag by id or null', async () => {
        const db = memoryDb({ [COLL]: [flag({ flagId: 'flag-a', flagDescription: 'Needs review' })] });

        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'flag-a'))
            .resolves.toMatchObject({ flagDescription: 'Needs review' });
        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'missing')).resolves.toBeNull();
    });

    test('gets student flags newest first and can scope to one course', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ flagId: 'c1-old', studentId: 's1', courseId: 'C1', createdAt: new Date('2026-01-01') }),
                flag({ flagId: 'c2-new', studentId: 's1', courseId: 'C2', createdAt: new Date('2026-03-01') }),
                flag({ flagId: 'c1-mid', studentId: 's1', courseId: 'C1', createdAt: new Date('2026-02-01') }),
                flag({ flagId: 'other-student', studentId: 's2', courseId: 'C1', createdAt: new Date('2026-04-01') }),
            ],
        });

        const all = await FlaggedQuestion.getFlaggedQuestionsForStudent(db, 's1');
        expect(all.map(item => item.flagId)).toEqual(['c2-new', 'c1-mid', 'c1-old']);

        const scoped = await FlaggedQuestion.getFlaggedQuestionsForStudent(db, 's1', 'C1');
        expect(scoped.map(item => item.flagId)).toEqual(['c1-mid', 'c1-old']);
    });
});

describe('FlaggedQuestion.updateInstructorResponse', () => {
    test('defaults to resolved, stores instructor response fields, and stamps resolvedAt', async () => {
        const db = memoryDb({ [COLL]: [flag({ flagId: 'flag-a' })] });

        const result = await FlaggedQuestion.updateInstructorResponse(db, 'flag-a', {
            response: 'Thanks, this has been corrected.',
            instructorId: 'i1',
            instructorName: 'Instructor One',
        });

        expect(result).toEqual({ success: true, modifiedCount: 1 });
        const updated = await FlaggedQuestion.getFlaggedQuestionById(db, 'flag-a');
        expect(updated).toMatchObject({
            instructorResponse: 'Thanks, this has been corrected.',
            instructorId: 'i1',
            instructorName: 'Instructor One',
            flagStatus: 'resolved',
        });
        expect(updated.updatedAt).toBeInstanceOf(Date);
        expect(updated.resolvedAt).toBeInstanceOf(Date);
    });

    test('honors an explicit non-resolved status without stamping resolvedAt', async () => {
        const db = memoryDb({ [COLL]: [flag({ flagId: 'flag-a' })] });

        const result = await FlaggedQuestion.updateInstructorResponse(db, 'flag-a', {
            response: 'We are reviewing this.',
            instructorId: 'ta1',
            instructorName: 'TA One',
            flagStatus: 'reviewed',
        });

        expect(result).toEqual({ success: true, modifiedCount: 1 });
        const updated = await FlaggedQuestion.getFlaggedQuestionById(db, 'flag-a');
        expect(updated).toMatchObject({
            instructorResponse: 'We are reviewing this.',
            instructorId: 'ta1',
            flagStatus: 'reviewed',
        });
        expect(updated.resolvedAt).toBeUndefined();
    });

    test('returns a failure object when no flag matches', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(FlaggedQuestion.updateInstructorResponse(db, 'missing', {
            response: 'No-op',
            instructorId: 'i1',
            instructorName: 'Instructor One',
        })).resolves.toEqual({
            success: false,
            error: 'Flag not found or no changes made',
        });
    });

    test('rejects an invalid explicit status without changing the flag', async () => {
        const db = memoryDb({ [COLL]: [flag({ flagId: 'flag-a' })] });

        await expect(FlaggedQuestion.updateInstructorResponse(db, 'flag-a', {
            response: 'Invalid transition',
            instructorId: 'i1',
            flagStatus: 'banana',
        })).resolves.toEqual({ success: false, error: 'Invalid flag status' });

        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'flag-a'))
            .resolves.toMatchObject({ flagStatus: 'pending' });
    });
});

describe('FlaggedQuestion.updateFlagStatus', () => {
    test('updates status and instructor, stamping resolvedAt only for resolved status', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ flagId: 'resolved-flag' }),
                flag({ flagId: 'dismissed-flag' }),
            ],
        });

        await expect(FlaggedQuestion.updateFlagStatus(db, 'resolved-flag', 'resolved', 'i1'))
            .resolves.toEqual({ success: true, modifiedCount: 1 });
        await expect(FlaggedQuestion.updateFlagStatus(db, 'dismissed-flag', 'dismissed', 'i2'))
            .resolves.toEqual({ success: true, modifiedCount: 1 });

        const resolved = await FlaggedQuestion.getFlaggedQuestionById(db, 'resolved-flag');
        expect(resolved).toMatchObject({ flagStatus: 'resolved', instructorId: 'i1' });
        expect(resolved.updatedAt).toBeInstanceOf(Date);
        expect(resolved.resolvedAt).toBeInstanceOf(Date);

        const dismissed = await FlaggedQuestion.getFlaggedQuestionById(db, 'dismissed-flag');
        expect(dismissed).toMatchObject({ flagStatus: 'dismissed', instructorId: 'i2' });
        expect(dismissed.updatedAt).toBeInstanceOf(Date);
        expect(dismissed.resolvedAt).toBeUndefined();
    });

    test('returns a failure object when no flag matches', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(FlaggedQuestion.updateFlagStatus(db, 'missing', 'resolved', 'i1'))
            .resolves.toEqual({
                success: false,
                error: 'Flag not found or no changes made',
            });
    });

    test('rejects an invalid status without changing the flag', async () => {
        const db = memoryDb({ [COLL]: [flag({ flagId: 'flag-a' })] });

        await expect(FlaggedQuestion.updateFlagStatus(db, 'flag-a', 'banana', 'i1'))
            .resolves.toEqual({ success: false, error: 'Invalid flag status' });

        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'flag-a'))
            .resolves.toMatchObject({ flagStatus: 'pending' });
    });
});

describe('FlaggedQuestion.getFlagStatistics', () => {
    test('returns the empty statistics shape when a course has no flags', async () => {
        const db = memoryDb({ [COLL]: [flag({ courseId: 'C2', flagStatus: 'pending' })] });

        await expect(FlaggedQuestion.getFlagStatistics(db, 'C1')).resolves.toEqual({
            total: 0,
            pending: 0,
            reviewed: 0,
            resolved: 0,
            dismissed: 0,
        });
    });

    test('aggregates flag counts by status for the requested course', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ courseId: 'C1', flagStatus: 'pending' }),
                flag({ courseId: 'C1', flagStatus: 'pending' }),
                flag({ courseId: 'C1', flagStatus: 'reviewed' }),
                flag({ courseId: 'C1', flagStatus: 'resolved' }),
                flag({ courseId: 'C1', flagStatus: 'dismissed' }),
                flag({ courseId: 'C2', flagStatus: 'pending' }),
            ],
        });

        await expect(FlaggedQuestion.getFlagStatistics(db, 'C1')).resolves.toEqual({
            total: 5,
            pending: 2,
            reviewed: 1,
            resolved: 1,
            dismissed: 1,
        });
    });

    test('keeps unexpected statuses as additional keys while counting totals', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ courseId: 'C1', flagStatus: 'pending' }),
                flag({ courseId: 'C1', flagStatus: 'escalated' }),
            ],
        });

        await expect(FlaggedQuestion.getFlagStatistics(db, 'C1')).resolves.toEqual({
            total: 2,
            pending: 1,
            reviewed: 0,
            resolved: 0,
            dismissed: 0,
            escalated: 1,
        });
    });
});

describe('FlaggedQuestion.deleteFlaggedQuestion', () => {
    test('deletes the matching flag and reports the deletion count', async () => {
        const db = memoryDb({
            [COLL]: [
                flag({ flagId: 'delete-me' }),
                flag({ flagId: 'keep-me' }),
            ],
        });

        await expect(FlaggedQuestion.deleteFlaggedQuestion(db, 'delete-me'))
            .resolves.toEqual({ success: true, deletedCount: 1 });
        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'delete-me')).resolves.toBeNull();
        await expect(FlaggedQuestion.getFlaggedQuestionById(db, 'keep-me'))
            .resolves.toMatchObject({ flagId: 'keep-me' });
    });

    test('returns a not-found result when no flag matches', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(FlaggedQuestion.deleteFlaggedQuestion(db, 'missing'))
            .resolves.toEqual({ success: false, error: 'Flag not found' });
    });
});
