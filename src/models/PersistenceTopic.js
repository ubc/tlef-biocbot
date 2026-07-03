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

function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
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
            topic: { $regex: new RegExp(`^${escapeRegExp(normalizedTopic)}$`, 'i') } // Case-insensitive literal match
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

    // Calculate count from array length
    // We need to update the studentCount field based on the array size
    // MongoDB doesn't support updating a field based on array size in the same operation easily without aggregation pipeline updates (avail in 4.2+)
    // But since we want to be safe, let's do a second update or use pipeline if version allows.
    // Simpler approach: 
    // Just Use $addToSet. 
    
    // Actually, to keep 'studentCount' in sync, we can use an aggregation pipeline in the update (MongoDB 4.2+)
    // [
    //   { $set: { studentIds: { $setUnion: ["$studentIds", [userId]] } } },
    //   { $set: { studentCount: { $size: "$studentIds" }, lastUpdated: now } }
    // ]
    // However, native `update` with pipeline might be complex for 'upsert'.
    
    // Alternative:
    // 1. $addToSet userId
    // 2. Then $set studentCount = studentIds.length (requires fetching)
    // OR
    // Just store studentIds and calculate count on read?
    // If studentIds array gets HUGE, this is bad. But for a class of <1000, it's fine.
    // Let's store `studentCount` for easier sorting/querying without unwinding.
    
    // Let's stick to the atomic operation.
    // If we just use $addToSet, we don't know if we modified it to increment a counter.
    // We can just inspect the result. If `updatedExisting` is true and `modifiedCount` > 0 (wait, findOneAndUpdate returns different structure).
    
    // Let's keep it simple:
    // We won't maintain a separate `studentCount` field on write if it's tricky. 
    // We can just rely on `studentIds` size. 
    // BUT, for the dashboard, we want to sort by count. 
    // Let's update the count after the upsert.
    
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
