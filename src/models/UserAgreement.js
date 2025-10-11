/**
 * UserAgreement Model for MongoDB
 * Tracks user agreement to terms of service and privacy policy
 */

/**
 * UserAgreement Schema Structure:
 * {
 *   _id: ObjectId,
 *   userId: String,              // Unique user identifier
 *   userType: String,            // "student" or "instructor"
 *   hasAgreed: Boolean,          // Whether user has agreed to terms
 *   agreementVersion: String,    // Version of agreement accepted
 *   agreedAt: Date,              // When user agreed (null if not agreed)
 *   ipAddress: String,           // IP address when agreed
 *   userAgent: String,           // User agent when agreed
 *   createdAt: Date,             // Record creation timestamp
 *   updatedAt: Date              // Last update timestamp
 * }
 */

/**
 * Get the user agreements collection from the database
 * @param {Object} db - MongoDB database instance
 * @returns {Collection} User agreements collection
 */
function getUserAgreementsCollection(db) {
    return db.collection('userAgreements');
}

/**
 * Get user agreement status
 * @param {Object} db - MongoDB database instance
 * @param {string} userId - User identifier
 * @param {string} userType - User type ("student" or "instructor")
 * @returns {Promise<Object>} Agreement status or null
 */
async function getUserAgreement(db, userId, role) {
    console.log('🔍 [USER_AGREEMENT] Getting agreement for:', { userId, role });
    console.log('🔍 [USER_AGREEMENT] Database object:', db);
    console.log('🔍 [USER_AGREEMENT] Database type:', typeof db);
    console.log('🔍 [USER_AGREEMENT] Database collections method:', typeof db?.collection);
    
    if (!db) {
        throw new Error('Database object is undefined');
    }
    
    const collection = getUserAgreementsCollection(db);
    
    const agreement = await collection.findOne({ 
        userId,
        userType: role 
    });
    
    console.log('🔍 [USER_AGREEMENT] Found agreement:', agreement);
    
    if (!agreement) {
        return {
            hasAgreed: false,
            agreementVersion: '1.0',
            agreedAt: null
        };
    }
    
    return {
        hasAgreed: agreement.hasAgreed,
        agreementVersion: agreement.agreementVersion,
        agreedAt: agreement.agreedAt
    };
}

/**
 * Create or update user agreement
 * @param {Object} db - MongoDB database instance
 * @param {string} userId - User identifier
 * @param {string} userType - User type ("student" or "instructor")
 * @param {Object} agreementData - Agreement data
 * @returns {Promise<Object>} Agreement result
 */
async function createOrUpdateUserAgreement(db, userId, role, agreementData) {
    const collection = getUserAgreementsCollection(db);
    
    const now = new Date();
    
    const agreement = {
        userId,
        userType: role,
        hasAgreed: agreementData.hasAgreed || false,
        agreementVersion: agreementData.agreementVersion || '1.0',
        agreedAt: agreementData.hasAgreed ? now : null,
        ipAddress: agreementData.ipAddress || null,
        userAgent: agreementData.userAgent || null,
        updatedAt: now
    };
    
    // Use upsert to create or update
    const result = await collection.updateOne(
        { userId, userType: role },
        { 
            $set: agreement,
            $setOnInsert: { createdAt: now }
        },
        { upsert: true }
    );
    
    console.log(`User agreement ${result.upsertedCount > 0 ? 'created' : 'updated'}: ${userId} (${role})`);
    
    return {
        success: true,
        hasAgreed: agreement.hasAgreed,
        agreementVersion: agreement.agreementVersion,
        agreedAt: agreement.agreedAt,
        isNew: result.upsertedCount > 0
    };
}

/**
 * Check if user has agreed to current terms
 * @param {Object} db - MongoDB database instance
 * @param {string} userId - User identifier
 * @param {string} userType - User type ("student" or "instructor")
 * @param {string} currentVersion - Current agreement version
 * @returns {Promise<boolean>} True if user has agreed to current version
 */
async function hasUserAgreed(db, userId, role, currentVersion = '1.0') {
    const agreement = await getUserAgreement(db, userId, role);
    
    return agreement.hasAgreed && agreement.agreementVersion === currentVersion;
}

/**
 * Get agreement statistics
 * @param {Object} db - MongoDB database instance
 * @param {string} userType - User type to filter by (optional)
 * @returns {Promise<Object>} Agreement statistics
 */
async function getAgreementStats(db, role = null) {
    const collection = getUserAgreementsCollection(db);
    
    const matchStage = role ? { userType: role } : {};
    
    const pipeline = [
        { $match: matchStage },
        {
            $group: {
                _id: null,
                totalUsers: { $sum: 1 },
                agreedUsers: { $sum: { $cond: ['$hasAgreed', 1, 0] } },
                pendingUsers: { $sum: { $cond: ['$hasAgreed', 0, 1] } }
            }
        }
    ];
    
    const result = await collection.aggregate(pipeline).toArray();
    
    if (result.length === 0) {
        return {
            totalUsers: 0,
            agreedUsers: 0,
            pendingUsers: 0,
            agreementRate: 0
        };
    }
    
    const stats = result[0];
    const agreementRate = stats.totalUsers > 0 ? (stats.agreedUsers / stats.totalUsers) * 100 : 0;
    
    return {
        totalUsers: stats.totalUsers,
        agreedUsers: stats.agreedUsers,
        pendingUsers: stats.pendingUsers,
        agreementRate: Math.round(agreementRate * 100) / 100
    };
}

module.exports = {
    getUserAgreementsCollection,
    getUserAgreement,
    createOrUpdateUserAgreement,
    hasUserAgreed,
    getAgreementStats
};
