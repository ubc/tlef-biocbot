/**
 * PersistenceTopic Model
 * 
 * Tracks cumulative struggle counts for topics across all time.
 * Maintains a set of unique student IDs to ensure each student is counted only once per topic.
 */

const COLLECTION_NAME = 'persistenceTopics';

/**
 * Get the persistence topics collection
 * @param {Object} db - MongoDB database instance
 * @returns {Collection} MongoDB collection
 */
function getPersistenceTopicsCollection(db) {
    return db.collection(COLLECTION_NAME);
}

/**
 * Increment the student count for a topic if the user hasn't been counted yet
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} topic - Topic name
 * @param {string} userId - User identifier
 * @returns {Promise<Object>} Update result
 */
async function incrementStudentCount(db, courseId, topic, userId) {
    const collection = getPersistenceTopicsCollection(db);
    const normalizedTopic = topic.toLowerCase().trim();
    const now = new Date();

    // Try to find the document first to check if user has already been counted
    // This isn't strictly necessary with $addToSet but helpful for return value if needed
    // We use findOneAndUpdate with upsert to handle it atomically
    
    const result = await collection.findOneAndUpdate(
        { 
            courseId, 
            topic: { $regex: new RegExp(`^${normalizedTopic}$`, 'i') } // Case-insensitive match 
        },
        {
            $addToSet: { studentIds: userId },
            $setOnInsert: { 
                courseId, 
                topic: normalizedTopic, // Store normalized, or could store original casing if preferred
                createdAt: now
            },
            $set: { lastUpdated: now }
        },
        { 
            upsert: true, 
            returnDocument: 'after',
            includeResultMetadata: true 
        }
    );
    
    if (result.value) {
        const doc = result.value;
        const newCount = doc.studentIds ? doc.studentIds.length : 0;
        
        // Update the count explicitly
        await collection.updateOne(
            { _id: doc._id },
            { $set: { studentCount: newCount } }
        );
        
        return { 
            success: true, 
            topic: doc.topic, 
            count: newCount, 
            isNew: result.lastErrorObject ? !result.lastErrorObject.updatedExisting : false 
        };
    }
    
    return { success: false };
}

/**
 * Get persistence topics for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Array>} Array of persistence topics sorted by count (desc)
 */
async function getPersistenceTopics(db, courseId) {
    const collection = getPersistenceTopicsCollection(db);
    
    const topics = await collection
        .find({ courseId })
        .sort({ studentCount: -1 })
        .toArray();
        
    return topics;
}

module.exports = {
    incrementStudentCount,
    getPersistenceTopics
};
