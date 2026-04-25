function normalizeEmail(email) {
    const normalized = String(email || '').trim().toLowerCase();
    return normalized || null;
}

function hasSystemAdminAccess(user) {
    return !!(user && user.permissions && user.permissions.systemAdmin === true);
}

function getEffectiveRole(user) {
    if (!user) {
        return null;
    }

    if (hasSystemAdminAccess(user)) {
        return 'instructor';
    }

    return user.role || null;
}

function applyAccessState(user) {
    if (!user) {
        return null;
    }

    return {
        ...user,
        email: normalizeEmail(user.email),
        baseRole: user.baseRole || user.role || null,
        role: getEffectiveRole(user),
        permissions: {
            ...(user.permissions || {}),
            systemAdmin: hasSystemAdminAccess(user)
        }
    };
}

module.exports = {
    normalizeEmail,
    hasSystemAdminAccess,
    getEffectiveRole,
    applyAccessState
};
