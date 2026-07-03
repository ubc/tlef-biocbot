/**
 * Onboarding Model
 * Handles database operations for onboarding data including course setup, file uploads, and initial configuration
 */

/**
 * Get the onboarding collection
 * @param {Object} db - MongoDB database instance
 * @returns {Object} MongoDB collection
 */
function getOnboardingCollection(db) {
    return db.collection('onboarding');
}

/**
 * Create or update onboarding data for a course
 * @param {Object} db - MongoDB database instance
 * @param {Object} onboardingData - Onboarding data object
 * @returns {Promise<Object>} Operation result
 */
async function upsertOnboarding(db, onboardingData) {
    const collection = getOnboardingCollection(db);
    
    const now = new Date();
    const {
        courseId,
        courseName,
        instructorId,
        courseDescription,
        learningOutcomes,
        assessmentCriteria,
        courseMaterials,
        unitFiles,
        courseStructure,
        createdAt,
        updatedAt
    } = onboardingData;
    
    // Prepare the document
    const document = {
        courseId,
        courseName,
        instructorId,
        courseDescription: courseDescription || '',
        learningOutcomes: learningOutcomes || [],
        assessmentCriteria: assessmentCriteria || '',
        courseMaterials: courseMaterials || [],
        unitFiles: unitFiles || {},
        courseStructure: courseStructure || {},
        updatedAt: now
    };
    
    try {
        console.log('Attempting to upsert onboarding data for course:', courseId);
        console.log('Document to upsert:', document);
        
        const result = await collection.updateOne(
            { courseId },
            {
                $set: document,
                $setOnInsert: { createdAt: createdAt || now }
            },
            { upsert: true }
        );
        
        console.log(`Onboarding data ${result.upsertedCount > 0 ? 'created' : 'updated'} for course ${courseId}`);
        console.log('Upsert result:', result);
        
        return {
            success: true,
            created: result.upsertedCount > 0,
            modifiedCount: result.modifiedCount,
            courseId
        };
    } catch (error) {
        console.error('Error upserting onboarding data:', error);
        console.error('Error details:', error.message, error.stack);
        throw error;
    }
}

/**
 * Get onboarding data for a specific course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object|null>} Onboarding data or null if not found
 */
async function getOnboardingByCourseId(db, courseId) {
    const collection = getOnboardingCollection(db);
    
    try {
        const onboardingData = await collection.findOne({ courseId });
        return onboardingData;
    } catch (error) {
        console.error('Error fetching onboarding data:', error);
        throw error;
    }
}

/**
 * Get onboarding data by instructor ID
 * @param {Object} db - MongoDB database instance
 * @param {string} instructorId - Instructor identifier
 * @returns {Promise<Array>} Array of onboarding data for the instructor
 */
async function getOnboardingByInstructor(db, instructorId) {
    const collection = getOnboardingCollection(db);
    
    try {
        const onboardingData = await collection.find({ instructorId }).toArray();
        return onboardingData;
    } catch (error) {
        console.error('Error fetching onboarding data by instructor:', error);
        throw error;
    }
}

/**
 * Update specific onboarding fields
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {Object} updates - Fields to update
 * @returns {Promise<Object>} Update result
 */
async function updateOnboardingFields(db, courseId, updates) {
    const collection = getOnboardingCollection(db);
    
    const updateData = {
        ...updates,
        updatedAt: new Date()
    };
    
    try {
        const result = await collection.updateOne(
            { courseId },
            { $set: updateData }
        );
        
        return {
            success: true,
            modifiedCount: result.modifiedCount,
            courseId
        };
    } catch (error) {
        console.error('Error updating onboarding fields:', error);
        throw error;
    }
}

/**
 * Add or update unit files for a specific unit
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} unitName - Unit name (e.g., "Unit 1")
 * @param {Array} files - Array of file objects
 * @returns {Promise<Object>} Operation result
 */
async function updateUnitFiles(db, courseId, unitName, files) {
    const collection = getOnboardingCollection(db);
    
    try {
        const result = await collection.updateOne(
            { courseId },
            { 
                $set: { 
                    [`unitFiles.${unitName}`]: files,
                    updatedAt: new Date()
                }
            }
        );
        
        return {
            success: true,
            modifiedCount: result.modifiedCount,
            courseId,
            unitName
        };
    } catch (error) {
        console.error('Error updating unit files:', error);
        throw error;
    }
}

/**
 * Delete onboarding data for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object>} Deletion result
 */
async function deleteOnboarding(db, courseId) {
    const collection = getOnboardingCollection(db);
    
    try {
        const result = await collection.deleteOne({ courseId });
        
        return {
            success: true,
            deletedCount: result.deletedCount,
            courseId
        };
    } catch (error) {
        console.error('Error deleting onboarding data:', error);
        throw error;
    }
}

/**
 * Get onboarding statistics
 * @param {Object} db - MongoDB database instance
 * @returns {Promise<Object>} Statistics object
 */
async function getOnboardingStats(db) {
    const collection = getOnboardingCollection(db);
    
    try {
        const totalCourses = await collection.countDocuments();
        const totalInstructors = await collection.distinct('instructorId');
        
        return {
            totalCourses,
            totalInstructors: totalInstructors.length,
            lastUpdated: new Date().toISOString()
        };
    } catch (error) {
        console.error('Error fetching onboarding stats:', error);
        throw error;
    }
}

module.exports = {
    getOnboardingCollection,
    upsertOnboarding,
    getOnboardingByCourseId,
    getOnboardingByInstructor,
    updateOnboardingFields,
    updateUnitFiles,
    deleteOnboarding,
    getOnboardingStats
};
