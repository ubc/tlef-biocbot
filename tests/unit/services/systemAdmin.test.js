/**
 * Unit tests for src/services/systemAdmin.js against the in-memory Mongo double.
 * revokeSystemAdminByEmail exercises the $unset operator added to memory-db.js.
 */
const { memoryDb } = require('../helpers/memory-db');
const systemAdmin = require('../../../src/services/systemAdmin');

const COLL = 'users';

describe('systemAdmin.listSystemAdmins', () => {
    test('returns only active system admins, sorted by email, in resolved shape', async () => {
        const db = memoryDb({
            [COLL]: [
                { userId: 'u1', email: 'bbb@x.com', role: 'instructor', isActive: true, permissions: { systemAdmin: true } },
                { userId: 'u2', email: 'aaa@x.com', role: 'instructor', isActive: true, permissions: { systemAdmin: true } },
                { userId: 'u3', email: 'ccc@x.com', role: 'student', isActive: true, permissions: {} },
                { userId: 'u4', email: 'ddd@x.com', role: 'instructor', isActive: false, permissions: { systemAdmin: true } },
            ],
        });
        const admins = await systemAdmin.listSystemAdmins(db);

        expect(admins.map(a => a.userId)).toEqual(['u2', 'u1']); // aaa before bbb; inactive + non-admin excluded
        expect(admins[0]).toMatchObject({
            userId: 'u2',
            email: 'aaa@x.com',
            role: 'instructor',
            baseRole: 'instructor',
            permissions: { systemAdmin: true },
        });
        // Defaults applied for absent timestamps.
        expect(admins[0].createdAt).toBeNull();
        expect(admins[0].lastLogin).toBeNull();
    });

    test('returns [] when there are no system admins', async () => {
        const db = memoryDb({ [COLL]: [{ userId: 'u3', email: 'x@x.com', isActive: true, permissions: {} }] });
        expect(await systemAdmin.listSystemAdmins(db)).toEqual([]);
    });
});

describe('systemAdmin.grantSystemAdminByEmail', () => {
    test('rejects an empty/invalid email before touching the db', async () => {
        const db = memoryDb({ [COLL]: [] });
        for (const bad of ['', '   ', null, undefined]) {
            expect(await systemAdmin.grantSystemAdminByEmail(db, bad)).toEqual({
                success: false, error: 'A valid email address is required.',
            });
        }
    });

    test('grants admin to an existing user (case/space-insensitive match) and stamps metadata', async () => {
        const db = memoryDb({ [COLL]: [{ userId: 'u1', email: 'foo@x.com', permissions: {} }] });
        const res = await systemAdmin.grantSystemAdminByEmail(db, '  FOO@x.com  ', { grantedBy: 'admin-9' });
        expect(res).toEqual({ success: true, email: 'foo@x.com' });

        const stored = await db.collection(COLL).findOne({ userId: 'u1' });
        expect(stored.permissions.systemAdmin).toBe(true);
        expect(stored.permissions.systemAdminGrantedBy).toBe('admin-9');
        expect(stored.permissions.systemAdminGrantedAt).toBeInstanceOf(Date);
    });

    test('fails when no user has that email', async () => {
        const db = memoryDb({ [COLL]: [] });
        expect(await systemAdmin.grantSystemAdminByEmail(db, 'nobody@x.com')).toEqual({
            success: false,
            error: 'User not found. Ask them to log in once before granting admin access.',
        });
    });
});

describe('systemAdmin.revokeSystemAdminByEmail', () => {
    test('rejects an invalid email', async () => {
        const db = memoryDb({ [COLL]: [] });
        expect(await systemAdmin.revokeSystemAdminByEmail(db, '  ')).toEqual({
            success: false, error: 'A valid email address is required.',
        });
    });

    test('fails when the email is not an active system admin', async () => {
        const db = memoryDb({ [COLL]: [{ userId: 'u1', email: 'foo@x.com', isActive: true, permissions: {} }] });
        expect(await systemAdmin.revokeSystemAdminByEmail(db, 'foo@x.com')).toEqual({
            success: false, error: 'System admin not found.',
        });
    });

    test('refuses to remove the last remaining admin', async () => {
        const db = memoryDb({
            [COLL]: [{ userId: 'u1', email: 'solo@x.com', isActive: true, permissions: { systemAdmin: true } }],
        });
        expect(await systemAdmin.revokeSystemAdminByEmail(db, 'solo@x.com')).toEqual({
            success: false, error: 'You cannot remove the last remaining system admin.',
        });
        // Still an admin afterward.
        const stored = await db.collection(COLL).findOne({ userId: 'u1' });
        expect(stored.permissions.systemAdmin).toBe(true);
    });

    test('demotes one admin when others remain, unsetting the admin flags', async () => {
        const db = memoryDb({
            [COLL]: [
                { userId: 'u1', email: 'a@x.com', isActive: true, permissions: { systemAdmin: true, systemAdminGrantedBy: 'x', systemAdminGrantedAt: new Date() } },
                { userId: 'u2', email: 'b@x.com', isActive: true, permissions: { systemAdmin: true } },
            ],
        });
        const res = await systemAdmin.revokeSystemAdminByEmail(db, 'a@x.com');
        expect(res).toEqual({ success: true, email: 'a@x.com' });

        const demoted = await db.collection(COLL).findOne({ userId: 'u1' });
        expect(demoted.permissions.systemAdmin).toBeUndefined();
        expect(demoted.permissions.systemAdminGrantedBy).toBeUndefined();
        expect(demoted.permissions.systemAdminGrantedAt).toBeUndefined();
        expect(demoted.updatedAt).toBeInstanceOf(Date);
        // The other admin is untouched.
        expect((await db.collection(COLL).findOne({ userId: 'u2' })).permissions.systemAdmin).toBe(true);
    });
});
