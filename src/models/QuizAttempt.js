/**
 * QuizAttempt Model
 * Tracks individual quiz practice attempts by students
 */

const { createId } = require('../services/id');
const COLLECTION_NAME = 'quizAttempts';

function getCollection(db) {
    return db.collection(COLLECTION_NAME);
}

/**
 * Generate a unique attempt ID
 * @returns {string} Prefixed collision-resistant attempt ID
 */
function generateAttemptId() {
    return createId('qa');
}

/**
 * Save a quiz attempt
 * @param {Object} db - MongoDB database instance
 * @param {Object} attemptData - Attempt data
 * @returns {Promise<Object>} Insert result
 */
async function saveAttempt(db, attemptData) {
    const collection = getCollection(db);

    const attempt = {
        attemptId: generateAttemptId(),
        studentId: attemptData.studentId,
        courseId: attemptData.courseId,
        questionId: attemptData.questionId,
        lectureName: attemptData.lectureName,
        questionType: attemptData.questionType,
        studentAnswer: attemptData.studentAnswer,
        correct: attemptData.correct,
        feedback: attemptData.feedback || '',
        attemptedAt: new Date()
    };

    await collection.insertOne(attempt);

    return {
        success: true,
        attemptId: attempt.attemptId
    };
}

/**
 * Get all attempts for a student in a course
 * @param {Object} db - MongoDB database instance
 * @param {string} studentId - Student user ID
 * @param {string} courseId - Course ID
 * @returns {Promise<Array>} Array of attempt records
 */
async function getAttemptsByStudent(db, studentId, courseId) {
    const collection = getCollection(db);

    return collection.find({
        studentId,
        courseId
    }).sort({ attemptedAt: -1 }).toArray();
}

/**
 * Get aggregated stats for a student in a course
 * @param {Object} db - MongoDB database instance
 * @param {string} studentId - Student user ID
 * @param {string} courseId - Course ID
 * @returns {Promise<Object>} Stats object
 */
async function getAttemptStats(db, studentId, courseId) {
    const collection = getCollection(db);

    const pipeline = [
        { $match: { studentId, courseId } },
        {
            $group: {
                _id: null,
                totalAttempts: { $sum: 1 },
                correctCount: { $sum: { $cond: ['$correct', 1, 0] } },
                byUnit: {
                    $push: {
                        lectureName: '$lectureName',
                        correct: '$correct'
                    }
                }
            }
        }
    ];

    const results = await collection.aggregate(pipeline).toArray();

    if (results.length === 0) {
        return {
            totalAttempts: 0,
            correctCount: 0,
            accuracy: 0,
            unitBreakdown: {}
        };
    }

    const stats = results[0];

    // Build per-unit breakdown
    const unitBreakdown = {};
    for (const entry of stats.byUnit) {
        if (!unitBreakdown[entry.lectureName]) {
            unitBreakdown[entry.lectureName] = { total: 0, correct: 0 };
        }
        unitBreakdown[entry.lectureName].total++;
        if (entry.correct) {
            unitBreakdown[entry.lectureName].correct++;
        }
    }

    return {
        totalAttempts: stats.totalAttempts,
        correctCount: stats.correctCount,
        accuracy: stats.totalAttempts > 0 ? Math.round((stats.correctCount / stats.totalAttempts) * 100) : 0,
        unitBreakdown
    };
}

module.exports = {
    saveAttempt,
    getAttemptsByStudent,
    getAttemptStats
};
