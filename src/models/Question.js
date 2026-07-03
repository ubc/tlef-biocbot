const { createId } = require('../services/id');

/**
 * Question Model for MongoDB
 * Stores assessment questions linked to courses and lectures
 */

/**
 * Question Schema Structure:
 * {
 *   _id: ObjectId,
 *   questionId: String,           // Unique question identifier
 *   courseId: String,             // Course this question belongs to
 *   lectureName: String,          // Unit/Week this question is for
 *   instructorId: String,         // ID of the instructor who created
 *   questionType: String,         // "multiple-choice", "true-false", "short-answer"
 *   question: String,             // The question text
 *   options: Object,              // For multiple choice: { "A": "option text", "B": "option text" }
 *   correctAnswer: String,        // Correct answer (option key for MC, true/false for TF, text for SA)
 *   explanation: String,          // Explanation of the correct answer
 *   difficulty: String,           // "easy", "medium", "hard"
 *   tags: [String],               // Learning objectives or topics this question covers
 *   points: Number,               // Points value for this question
 *   isActive: Boolean,            // Whether this question is active
 *   createdAt: Date,              // When the question was created
 *   updatedAt: Date,              // Last modification timestamp
 *   metadata: {                   // Additional metadata
 *     source: String,             // Where the question came from (manual, AI-generated, etc.)
 *     aiGenerated: Boolean,       // Whether this was AI-generated
 *     reviewStatus: String        // "draft", "reviewed", "approved"
 *   }
 * }
 */

/**
 * Get the questions collection from the database
 * @param {Object} db - MongoDB database instance
 * @returns {Collection} Questions collection
 */
function getQuestionsCollection(db) {
    return db.collection('questions');
}

/**
 * Create a new question
 * @param {Object} db - MongoDB database instance
 * @param {Object} questionData - Question data object
 * @returns {Promise<Object>} Created question
 */
async function createQuestion(db, questionData) {
    const collection = getQuestionsCollection(db);
    
    const now = new Date();
    const question = {
        ...questionData,
        createdAt: now,
        updatedAt: now,
        isActive: true
    };
    
    // Generate unique question ID
    question.questionId = createId('q');
    
    const result = await collection.insertOne(question);
    
    return {
        ...question,
        _id: result.insertedId
    };
}

/**
 * Get all questions for a specific lecture/unit
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @returns {Promise<Array>} Array of questions
 */
async function getQuestionsForLecture(db, courseId, lectureName) {
    const collection = getQuestionsCollection(db);
    
    const questions = await collection.find({
        courseId: courseId,
        lectureName: lectureName,
        isActive: true
    }).sort({ createdAt: 1 }).toArray();
    
    return questions;
}

/**
 * Get a specific question by ID
 * @param {Object} db - MongoDB database instance
 * @param {string} questionId - Question identifier
 * @returns {Promise<Object|null>} Question object or null
 */
async function getQuestionById(db, questionId) {
    const collection = getQuestionsCollection(db);
    
    const question = await collection.findOne({ questionId: questionId });
    return question;
}

/**
 * Update an existing question
 * @param {Object} db - MongoDB database instance
 * @param {string} questionId - Question identifier
 * @param {Object} updateData - Data to update
 * @returns {Promise<Object>} Update result
 */
async function updateQuestion(db, questionId, updateData) {
    const collection = getQuestionsCollection(db);
    
    const updateDataWithTimestamp = {
        ...updateData,
        updatedAt: new Date()
    };
    
    const result = await collection.updateOne(
        { questionId: questionId },
        { $set: updateDataWithTimestamp }
    );
    
    return result;
}

/**
 * Delete a question (soft delete by setting isActive to false)
 * @param {Object} db - MongoDB database instance
 * @param {string} questionId - Question identifier
 * @returns {Promise<Object>} Update result
 */
async function deleteQuestion(db, questionId) {
    const collection = getQuestionsCollection(db);
    
    const result = await collection.updateOne(
        { questionId: questionId },
        { 
            $set: { 
                isActive: false,
                updatedAt: new Date()
            } 
        }
    );
    
    return result;
}

/**
 * Get question statistics for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object>} Question statistics
 */
async function getQuestionStats(db, courseId) {
    const collection = getQuestionsCollection(db);
    
    const stats = await collection.aggregate([
        { $match: { courseId: courseId, isActive: true } },
        { $group: {
            _id: '$questionType',
            count: { $sum: 1 },
            totalPoints: { $sum: '$points' }
        }},
        { $group: {
            _id: null,
            totalQuestions: { $sum: '$count' },
            totalPoints: { $sum: '$totalPoints' },
            typeBreakdown: { $push: { type: '$_id', count: '$count', points: '$totalPoints' } }
        }}
    ]).toArray();
    
    return stats[0] || { totalQuestions: 0, totalPoints: 0, typeBreakdown: [] };
}

/**
 * Get questions by learning objective tags
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {Array} tags - Learning objective tags to search for
 * @returns {Promise<Array>} Array of questions matching the tags
 */
async function getQuestionsByTags(db, courseId, tags) {
    const collection = getQuestionsCollection(db);
    
    const questions = await collection.find({
        courseId: courseId,
        tags: { $in: tags },
        isActive: true
    }).sort({ createdAt: 1 }).toArray();
    
    return questions;
}

/**
 * Bulk create questions (for AI-generated questions)
 * @param {Object} db - MongoDB database instance
 * @param {Array} questionsData - Array of question data objects
 * @returns {Promise<Object>} Bulk insert result
 */
async function bulkCreateQuestions(db, questionsData) {
    const collection = getQuestionsCollection(db);
    
    const now = new Date();
    const questions = questionsData.map(q => ({
        ...q,
        createdAt: now,
        updatedAt: now,
        isActive: true,
        questionId: createId('q')
    }));
    
    const result = await collection.insertMany(questions);
    
    return {
        insertedCount: result.insertedCount,
        insertedIds: result.insertedIds
    };
}

module.exports = {
    getQuestionsCollection,
    createQuestion,
    getQuestionsForLecture,
    getQuestionById,
    updateQuestion,
    deleteQuestion,
    getQuestionStats,
    getQuestionsByTags,
    bulkCreateQuestions
};
