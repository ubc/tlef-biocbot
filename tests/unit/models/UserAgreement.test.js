/**
 * Unit tests for src/models/UserAgreement.js against the in-memory Mongo double.
 * createOrUpdate exercises upsert ($set + $setOnInsert); getAgreementStats
 * exercises aggregate() ($match -> $group with $sum/$cond).
 */
const { memoryDb } = require('../helpers/memory-db');
const UserAgreement = require('../../../src/models/UserAgreement');

const COLL = 'userAgreements';

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
});
afterAll(() => {
    jest.restoreAllMocks();
});

describe('UserAgreement.getUserAgreement', () => {
    test('returns the not-agreed default when no record exists', async () => {
        const db = memoryDb({});
        expect(await UserAgreement.getUserAgreement(db, 'u1', 'student')).toEqual({
            hasAgreed: false, agreementVersion: '1.0', agreedAt: null,
        });
    });

    test('returns the stored agreement fields, matched by userId AND userType', async () => {
        const agreedAt = new Date('2026-05-01');
        const db = memoryDb({
            [COLL]: [
                { userId: 'u1', userType: 'student', hasAgreed: true, agreementVersion: '2.0', agreedAt },
                { userId: 'u1', userType: 'instructor', hasAgreed: false, agreementVersion: '1.0', agreedAt: null },
            ],
        });
        expect(await UserAgreement.getUserAgreement(db, 'u1', 'student')).toEqual({
            hasAgreed: true, agreementVersion: '2.0', agreedAt,
        });
    });

    test('throws when the db is missing', async () => {
        await expect(UserAgreement.getUserAgreement(null, 'u1', 'student')).rejects.toThrow('Database object is undefined');
    });
});

describe('UserAgreement.createOrUpdateUserAgreement', () => {
    test('creates a new record (isNew) and stamps agreedAt when hasAgreed', async () => {
        const db = memoryDb({});
        const res = await UserAgreement.createOrUpdateUserAgreement(db, 'u1', 'student', { hasAgreed: true, agreementVersion: '2.0' });

        expect(res).toMatchObject({ success: true, hasAgreed: true, agreementVersion: '2.0', isNew: true });
        expect(res.agreedAt).toBeInstanceOf(Date);

        const stored = await db.collection(COLL).findOne({ userId: 'u1', userType: 'student' });
        expect(stored).toMatchObject({ hasAgreed: true, agreementVersion: '2.0' });
        expect(stored.createdAt).toBeInstanceOf(Date);
    });

    test('defaults hasAgreed to false (agreedAt null) and version to 1.0', async () => {
        const db = memoryDb({});
        const res = await UserAgreement.createOrUpdateUserAgreement(db, 'u1', 'student', {});
        expect(res).toMatchObject({ hasAgreed: false, agreementVersion: '1.0', agreedAt: null });
    });

    test('updates an existing record in place (isNew false)', async () => {
        const db = memoryDb({});
        await UserAgreement.createOrUpdateUserAgreement(db, 'u1', 'student', { hasAgreed: false });
        const second = await UserAgreement.createOrUpdateUserAgreement(db, 'u1', 'student', { hasAgreed: true });

        expect(second.isNew).toBe(false);
        expect(second.hasAgreed).toBe(true);
        // Still exactly one record for this (userId, userType).
        expect(await db.collection(COLL).countDocuments({ userId: 'u1', userType: 'student' })).toBe(1);
    });
});

describe('UserAgreement.hasUserAgreed', () => {
    test('true only when agreed AND the version matches the current one', async () => {
        const db = memoryDb({
            [COLL]: [{ userId: 'u1', userType: 'student', hasAgreed: true, agreementVersion: '1.0' }],
        });
        expect(await UserAgreement.hasUserAgreed(db, 'u1', 'student')).toBe(true);
        expect(await UserAgreement.hasUserAgreed(db, 'u1', 'student', '2.0')).toBe(false);
    });

    test('false when the user has not agreed at all', async () => {
        const db = memoryDb({
            [COLL]: [{ userId: 'u1', userType: 'student', hasAgreed: false, agreementVersion: '1.0' }],
        });
        expect(await UserAgreement.hasUserAgreed(db, 'u1', 'student')).toBe(false);
    });
});

describe('UserAgreement.getAgreementStats', () => {
    const seed = [
        { userId: 's1', userType: 'student', hasAgreed: true },
        { userId: 's2', userType: 'student', hasAgreed: true },
        { userId: 's3', userType: 'student', hasAgreed: true },
        { userId: 's4', userType: 'student', hasAgreed: false },
        { userId: 'i1', userType: 'instructor', hasAgreed: true },
    ];

    test('returns zeros when there are no records', async () => {
        const db = memoryDb({ [COLL]: [] });
        expect(await UserAgreement.getAgreementStats(db)).toEqual({
            totalUsers: 0, agreedUsers: 0, pendingUsers: 0, agreementRate: 0,
        });
    });

    test('aggregates across everyone when no role filter is given', async () => {
        const db = memoryDb({ [COLL]: seed });
        expect(await UserAgreement.getAgreementStats(db)).toEqual({
            totalUsers: 5, agreedUsers: 4, pendingUsers: 1, agreementRate: 80,
        });
    });

    test('restricts the aggregate to the requested role', async () => {
        const db = memoryDb({ [COLL]: seed });
        expect(await UserAgreement.getAgreementStats(db, 'student')).toEqual({
            totalUsers: 4, agreedUsers: 3, pendingUsers: 1, agreementRate: 75,
        });
        expect(await UserAgreement.getAgreementStats(db, 'instructor')).toEqual({
            totalUsers: 1, agreedUsers: 1, pendingUsers: 0, agreementRate: 100,
        });
    });
});
