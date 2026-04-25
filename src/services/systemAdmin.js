const { applyAccessState, normalizeEmail } = require('./authorization');

function getUsersCollection(db) {
    return db.collection('users');
}

async function listSystemAdmins(db) {
    const users = await getUsersCollection(db)
        .find({
            isActive: true,
            'permissions.systemAdmin': true
        })
        .sort({ email: 1 })
        .toArray();

    return users.map(user => {
        const resolvedUser = applyAccessState(user);
        return {
            userId: resolvedUser.userId,
            email: resolvedUser.email,
            role: resolvedUser.role,
            baseRole: resolvedUser.baseRole,
            displayName: resolvedUser.displayName,
            authProvider: resolvedUser.authProvider,
            createdAt: resolvedUser.createdAt || null,
            lastLogin: resolvedUser.lastLogin || null,
            permissions: resolvedUser.permissions
        };
    });
}

async function grantSystemAdminByEmail(db, email, options = {}) {
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail) {
        return {
            success: false,
            error: 'A valid email address is required.'
        };
    }

    const { grantedBy = null } = options;

    const users = getUsersCollection(db);
    const now = new Date();
    const existingUser = await users.findOne({ email: normalizedEmail });

    if (existingUser) {
        await users.updateOne(
            { _id: existingUser._id },
            {
                $set: {
                    'permissions.systemAdmin': true,
                    'permissions.systemAdminGrantedAt': now,
                    'permissions.systemAdminGrantedBy': grantedBy,
                    updatedAt: now
                }
            }
        );

        return {
            success: true,
            email: normalizedEmail
        };
    }

    return {
        success: false,
        error: 'User not found. Ask them to log in once before granting admin access.'
    };
}

async function revokeSystemAdminByEmail(db, email) {
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail) {
        return {
            success: false,
            error: 'A valid email address is required.'
        };
    }

    const users = getUsersCollection(db);
    const existingUser = await users.findOne({
        email: normalizedEmail,
        isActive: true,
        'permissions.systemAdmin': true
    });

    if (!existingUser) {
        return {
            success: false,
            error: 'System admin not found.'
        };
    }

    const adminCount = await users.countDocuments({
        isActive: true,
        'permissions.systemAdmin': true
    });

    if (adminCount <= 1) {
        return {
            success: false,
            error: 'You cannot remove the last remaining system admin.'
        };
    }

    await users.updateOne(
        { _id: existingUser._id },
        {
            $unset: {
                'permissions.systemAdmin': '',
                'permissions.systemAdminGrantedAt': '',
                'permissions.systemAdminGrantedBy': ''
            },
            $set: {
                updatedAt: new Date()
            }
        }
    );

    return {
        success: true,
        email: normalizedEmail
    };
}

module.exports = {
    listSystemAdmins,
    grantSystemAdminByEmail,
    revokeSystemAdminByEmail
};
