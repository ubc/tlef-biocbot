/**
 * Flagged Question Model for MongoDB
 * Stores student flags on questions and instructor responses
 */

const { MongoClient } = require('mongodb');

/**
 * Flagged Question Schema Structure:
 * {
 *   _id: ObjectId,
 *   flagId: String,              // Unique flag identifier
 *   questionId: String,          // ID of the flagged question
 *   courseId: String,            // Course where the question was flagged
 *   unitName: String,            // Unit/lecture name where question appears
 *   studentId: String,           // ID of the student who flagged
 *   studentName: String,         // Name of the student (for display)
 *   flagReason: String,          // Reason for flagging (e.g., "unclear", "incorrect", "inappropriate")
 *   flagDescription: String,     // Detailed description of the issue
 *   botMode: String,             // Bot mode when flag was submitted ("protege" or "tutor")
 *   flagStatus: String,          // "pending", "reviewed", "resolved", "dismissed"
 *   instructorResponse: String,  // Instructor's response/explanation
 *   instructorId: String,        // ID of instructor who responded
 *   instructorName: String,      // Name of instructor who responded
 *   questionContent: {           // Snapshot of question content when flagged
 *     question: String,
 *     questionType: String,
 *     options: Object,
 *     correctAnswer: String,
 *     explanation: String
 *   },
 *   createdAt: Date,             // When the flag was created
 *   updatedAt: Date,             // Last update timestamp
 *   resolvedAt: Date,            // When the flag was resolved (if applicable)
 *   priority: String             // "low", "medium", "high" - based on flag reason and impact
 * }
 */

/**
 * Get the flagged questions collection from the database
 * @param {Object} db - MongoDB database instance
 * @returns {Collection} Flagged questions collection
 */
function getFlaggedQuestionsCollection(db) {
    return db.collection('flaggedQuestions');
}

/**
 * Create a new flagged question
 * @param {Object} db - MongoDB database instance
 * @param {Object} flagData - Flag data object
 * @returns {Promise<Object>} Created flag result
 */
async function createFlaggedQuestion(db, flagData) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const now = new Date();
    
    // Generate unique flag ID
    const flagId = `flag_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const flag = {
        flagId,
        ...flagData,
        flagStatus: 'pending',
        createdAt: now,
        updatedAt: now,
        priority: determinePriority(flagData.flagReason)
    };
    
    const result = await collection.insertOne(flag);
    
    console.log(`Flagged question created: ${flagId} for question ${flagData.questionId}`);
    
    return {
        success: true,
        flagId,
        insertedId: result.insertedId
    };
}

/**
 * Get all flagged questions for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} status - Optional status filter
 * @returns {Promise<Array>} Array of flagged questions
 */
async function getFlaggedQuestionsForCourse(db, courseId, status = null) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const filter = { courseId };
    if (status) {
        filter.flagStatus = status;
    }
    
    const flags = await collection.find(filter)
        .sort({ createdAt: -1 }) // Most recent first
        .toArray();
    
    return flags;
}

/**
 * Get flagged questions by status
 * @param {Object} db - MongoDB database instance
 * @param {string} status - Status to filter by
 * @returns {Promise<Array>} Array of flagged questions
 */
async function getFlaggedQuestionsByStatus(db, status) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const flags = await collection.find({ flagStatus: status })
        .sort({ createdAt: -1 })
        .toArray();
    
    return flags;
}

/**
 * Get a specific flagged question by ID
 * @param {Object} db - MongoDB database instance
 * @param {string} flagId - Flag identifier
 * @returns {Promise<Object>} Flagged question object
 */
async function getFlaggedQuestionById(db, flagId) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const flag = await collection.findOne({ flagId });
    return flag;
}

/**
 * Get all flagged questions for a specific student (optionally scoped to a course)
 * @param {Object} db - MongoDB database instance
 * @param {string} studentId - Student identifier
 * @param {string|null} courseId - Optional course identifier to filter
 * @returns {Promise<Array>} Array of flagged questions for the student
 */
async function getFlaggedQuestionsForStudent(db, studentId, courseId = null) {
    const collection = getFlaggedQuestionsCollection(db);
    const filter = { studentId };
    if (courseId) {
        filter.courseId = courseId;
    }
    const flags = await collection
        .find(filter)
        .sort({ createdAt: -1 })
        .toArray();
    return flags;
}

/**
 * Update instructor response to a flagged question
 * @param {Object} db - MongoDB database instance
 * @param {string} flagId - Flag identifier
 * @param {Object} responseData - Response data from instructor
 * @returns {Promise<Object>} Update result
 */
async function updateInstructorResponse(db, flagId, responseData) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const now = new Date();
    
    const finalStatus = responseData.flagStatus || 'resolved';

    const updateData = {
        instructorResponse: responseData.response,
        instructorId: responseData.instructorId,
        instructorName: responseData.instructorName,
        flagStatus: finalStatus,
        updatedAt: now
    };

    if (finalStatus === 'resolved') {
        updateData.resolvedAt = now;
    }
    
    const result = await collection.updateOne(
        { flagId },
        { $set: updateData }
    );
    
    if (result.modifiedCount > 0) {
        console.log(`Instructor response updated for flag: ${flagId}`);
        return { success: true, modifiedCount: result.modifiedCount };
    } else {
        return { success: false, error: 'Flag not found or no changes made' };
    }
}

/**
 * Update flag status
 * @param {Object} db - MongoDB database instance
 * @param {string} flagId - Flag identifier
 * @param {string} newStatus - New status to set
 * @param {string} instructorId - ID of instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updateFlagStatus(db, flagId, newStatus, instructorId) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const now = new Date();
    
    const updateData = {
        flagStatus: newStatus,
        instructorId,
        updatedAt: now
    };
    
    if (newStatus === 'resolved') {
        updateData.resolvedAt = now;
    }
    
    const result = await collection.updateOne(
        { flagId },
        { $set: updateData }
    );
    
    if (result.modifiedCount > 0) {
        console.log(`Flag status updated to ${newStatus} for flag: ${flagId}`);
        return { success: true, modifiedCount: result.modifiedCount };
    } else {
        return { success: false, error: 'Flag not found or no changes made' };
    }
}

/**
 * Get flag statistics for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object>} Flag statistics
 */
async function getFlagStatistics(db, courseId) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const pipeline = [
        { $match: { courseId } },
        {
            $group: {
                _id: '$flagStatus',
                count: { $sum: 1 }
            }
        }
    ];
    
    const stats = await collection.aggregate(pipeline).toArray();
    
    // Convert to more readable format
    const statistics = {
        total: 0,
        pending: 0,
        reviewed: 0,
        resolved: 0,
        dismissed: 0
    };
    
    stats.forEach(stat => {
        statistics[stat._id] = stat.count;
        statistics.total += stat.count;
    });
    
    return statistics;
}

/**
 * Determine priority based on flag reason
 * @param {string} flagReason - Reason for flagging
 * @returns {string} Priority level
 */
function determinePriority(flagReason) {
    const highPriorityReasons = ['incorrect', 'inappropriate', 'offensive'];
    const mediumPriorityReasons = ['unclear', 'confusing', 'typo'];
    
    if (highPriorityReasons.includes(flagReason)) {
        return 'high';
    } else if (mediumPriorityReasons.includes(flagReason)) {
        return 'medium';
    } else {
        return 'low';
    }
}

/**
 * Delete a flagged question (for cleanup purposes)
 * @param {Object} db - MongoDB database instance
 * @param {string} flagId - Flag identifier
 * @returns {Promise<Object>} Deletion result
 */
async function deleteFlaggedQuestion(db, flagId) {
    const collection = getFlaggedQuestionsCollection(db);
    
    const result = await collection.deleteOne({ flagId });
    
    if (result.deletedCount > 0) {
        console.log(`Flagged question deleted: ${flagId}`);
        return { success: true, deletedCount: result.deletedCount };
    } else {
        return { success: false, error: 'Flag not found' };
    }
}

module.exports = {
    createFlaggedQuestion,
    getFlaggedQuestionsForCourse,
    getFlaggedQuestionsByStatus,
    getFlaggedQuestionById,
    getFlaggedQuestionsForStudent,
    updateInstructorResponse,
    updateFlagStatus,
    getFlagStatistics,
    deleteFlaggedQuestion
};
