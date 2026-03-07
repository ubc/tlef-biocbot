/**
 * Course Model for MongoDB
 * Stores course information and lecture publish status
 */

const { MongoClient } = require('mongodb');

/**
 * Course Schema Structure:
 * {
 *   _id: ObjectId,
 *   courseId: String,           // Unique course identifier
 *   courseName: String,         // Display name of the course
 *   instructorId: String,       // ID of the primary instructor (for backward compatibility)
 *   instructors: [String],      // Array of instructor IDs (primary instructor + additional instructors)
 *   tas: [String],              // Array of TA IDs
 *   taPermissions: {            // TA permission settings
 *     [taId]: {                 // Permission object for each TA
 *       canAccessCourses: Boolean,  // Can access My Courses page
 *       canAccessFlags: Boolean    // Can access Flag page
 *     }
 *   },
 *   studentEnrollment: {        // Per-student enrollment overrides (optional)
 *     [studentId]: {
 *       enrolled: Boolean,      // If false, student is blocked from course features
 *       updatedAt: Date
 *     }
// ... (existing code)
 *   },
 *   studentIdleTimeout: Number, // Idle timeout for students in seconds (default: 300)
 *   lectures: [                 // Array of lectures/units
// ... (rest of the file)
 *     {
 *       name: String,           // e.g., "Unit 1", "Week 1"
 *       displayName: String,    // Custom title e.g., "Biology" (optional)
 *       isPublished: Boolean,   // Publish status
 *       createdAt: Date,        // When the lecture was created
 *       updatedAt: Date,        // Last update timestamp
 *       documents: [            // Array of uploaded documents
 *         {
 *           filename: String,
 *           originalName: String,
 *           size: Number,
 *           mimeType: String,
 *           uploadDate: Date,
 *           status: String      // "parsed", "needs-verify", "error"
 *         }
 *       ]
 *     }
 *   ],
 *   createdAt: Date,            // Course creation timestamp
 *   updatedAt: Date             // Last course update timestamp
 * }
 */

/**
 * Generate a random 6-character alphanumeric course code
 * @returns {string} Course code
 */
function generateCourseCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Excludes I, O, 1, 0 to avoid confusion
    let code = '';
    for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

/**
 * Normalize a topic label for storage/display consistency
 * @param {string} topic - Raw topic text
 * @returns {string} Normalized topic text
 */
function normalizeTopicLabel(topic) {
    if (typeof topic !== 'string') return '';
    return topic.replace(/\s+/g, ' ').trim();
}

/**
 * Normalize + deduplicate topic list (case-insensitive)
 * @param {Array<string>} topics - Raw topic list
 * @returns {Array<string>} Cleaned topic list
 */
function normalizeTopicList(topics = []) {
    if (!Array.isArray(topics)) return [];
    const seen = new Set();
    const output = [];

    for (const rawTopic of topics) {
        const normalized = normalizeTopicLabel(rawTopic);
        if (!normalized) continue;

        const key = normalized.toLowerCase();
        if (seen.has(key)) continue;

        seen.add(key);
        output.push(normalized);
    }

    return output;
}

/**
 * Get the courses collection from the database
 * @param {Object} db - MongoDB database instance
 * @returns {Collection} Courses collection
 */
function getCoursesCollection(db) {
    return db.collection('courses');
}

/**
 * Ensure all courses have a course code (Migration)
 * @param {Object} db - MongoDB database instance
 */
async function ensureCourseCodes(db) {
    const collection = getCoursesCollection(db);
    const courses = await collection.find({ courseCode: { $exists: false } }).toArray();
    
    if (courses.length > 0) {
        console.log(`Migrating ${courses.length} courses to have course codes...`);
        for (const course of courses) {
            const code = generateCourseCode();
            await collection.updateOne(
                { _id: course._id },
                { $set: { courseCode: code } }
            );
            console.log(`Assigned code ${code} to course ${course.courseId}`);
        }
    }
}

/**
 * Create or update a course with lecture publish status
 * @param {Object} db - MongoDB database instance
 * @param {Object} courseData - Course data object
 * @returns {Promise<Object>} Created/updated course
 */
async function upsertCourse(db, courseData) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    const course = {
        ...courseData,
        updatedAt: now
    };
    
    if (!course.createdAt) {
        course.createdAt = now;
    }

    // Ensure course code exists
    if (!course.courseCode) {
        course.courseCode = generateCourseCode();
    }
    
    const result = await collection.updateOne(
        { courseId: courseData.courseId },
        { $set: course },
        { upsert: true }
    );
    
    return result;
}

/**
 * Update the publish status of a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @param {boolean} isPublished - New publish status
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updateLecturePublishStatus(db, courseId, lectureName, isPublished, updatedById) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for publish status update`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the lecture already exists
    const existingLecture = course.lectures ? course.lectures.find(l => l.name === lectureName) : null;
    
    if (existingLecture) {
        // Update existing lecture with publish status
        const result = await collection.updateOne(
            { 
                courseId,
                'lectures.name': lectureName 
            },
            {
                $set: {
                    'lectures.$.isPublished': isPublished,
                    'lectures.$.updatedAt': now,
                    updatedAt: now,
                    lastUpdatedById: updatedById
                }
            }
        );
        
        console.log(`Updated existing lecture ${lectureName} publish status to ${isPublished}`);
        return { success: true, created: false, modifiedCount: result.modifiedCount };
    } else {
        console.error(`Lecture ${lectureName} not found in course ${courseId}`);
        return { success: false, error: 'Lecture not found' };
    }
}

/**
 * Get the publish status of all lectures for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object>} Publish status for each lecture
 */
async function getLecturePublishStatus(db, courseId) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne(
        { courseId },
        { projection: { lectures: 1 } }
    );
    
    if (!course || !course.lectures) {
        return {};
    }
    
    // Convert to a simple object mapping lecture names to publish status
    const publishStatus = {};
    course.lectures.forEach(lecture => {
        publishStatus[lecture.name] = lecture.isPublished;
    });
    
    return publishStatus;
}

/**
 * Get all published lectures for student access
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Array>} Array of published lecture names
 */
async function getPublishedLectures(db, courseId) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne(
        { courseId },
        { projection: { lectures: 1 } }
    );
    
    if (!course || !course.lectures) {
        return [];
    }
    
    return course.lectures
        .filter(lecture => lecture.isPublished)
        .map(lecture => lecture.name);
}

/**
 * Update learning objectives for a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @param {Array} objectives - Array of learning objectives
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updateLearningObjectives(db, courseId, lectureName, objectives, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for learning objectives update`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the lecture already exists
    const existingLecture = course.lectures ? course.lectures.find(l => l.name === lectureName) : null;
    
    if (existingLecture) {
        // Update existing lecture with learning objectives
        const result = await collection.updateOne(
            { 
                courseId,
                'lectures.name': lectureName 
            },
            {
                $set: {
                    'lectures.$.learningObjectives': objectives,
                    'lectures.$.updatedAt': now,
                    updatedAt: now,
                    lastUpdatedById: instructorId
                }
            }
        );
        
        console.log(`Updated existing lecture ${lectureName} with learning objectives`);
        return { success: true, created: false, modifiedCount: result.modifiedCount };
    } else {
        console.error(`Lecture ${lectureName} not found in course ${courseId}`);
        return { success: false, error: 'Lecture not found' };
    }
}

/**
 * Add or update assessment questions for a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @param {Object} questionData - Question data to add/update
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updateAssessmentQuestions(db, courseId, lectureName, questionData, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for assessment questions update`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the lecture already exists
    const existingLecture = course.lectures ? course.lectures.find(l => l.name === lectureName) : null;
    
    if (existingLecture) {
        // Generate unique question ID if not provided
        if (!questionData.questionId) {
            questionData.questionId = `q_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }
        
        // Add timestamp if not present
        if (!questionData.createdAt) {
            questionData.createdAt = now;
        }
        questionData.updatedAt = now;
        
        // Check if question already exists (for updates)
        const existingQuestionIndex = existingLecture.assessmentQuestions ? 
            existingLecture.assessmentQuestions.findIndex(q => q.questionId === questionData.questionId) : -1;
        
        if (existingQuestionIndex >= 0) {
            // Update existing question
            const result = await collection.updateOne(
                { 
                    courseId,
                    'lectures.name': lectureName,
                    'lectures.assessmentQuestions.questionId': questionData.questionId
                },
                {
                    $set: {
                        'lectures.$.assessmentQuestions.$': questionData,
                        'lectures.$.updatedAt': now,
                        updatedAt: now,
                        lastUpdatedById: instructorId
                    }
                }
            );
            
            console.log(`Updated existing assessment question in ${lectureName}`);
            return { success: true, created: false, modifiedCount: result.modifiedCount, questionId: questionData.questionId };
        } else {
            // Add new question
            const result = await collection.updateOne(
                { 
                    courseId,
                    'lectures.name': lectureName 
                },
                {
                    $push: {
                        'lectures.$.assessmentQuestions': questionData
                    },
                    $set: {
                        'lectures.$.updatedAt': now,
                        updatedAt: now,
                        lastUpdatedById: instructorId
                    }
                }
            );
            
            console.log(`Added new assessment question to ${lectureName}`);
            return { success: true, created: true, modifiedCount: result.modifiedCount, questionId: questionData.questionId };
        }
    } else {
        console.error(`Lecture ${lectureName} not found in course ${courseId}`);
        return { success: false, error: 'Lecture not found' };
    }
}

/**
 * Get assessment questions for a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @returns {Promise<Array>} Array of assessment questions
 */
async function getAssessmentQuestions(db, courseId, lectureName) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne(
        { courseId },
        { projection: { lectures: 1 } }
    );
    
    if (!course || !course.lectures) {
        return [];
    }
    
    // Find the specific lecture and return its assessment questions
    const lecture = course.lectures.find(l => l.name === lectureName);
    return lecture ? (lecture.assessmentQuestions || []) : [];
}

/**
 * Delete an assessment question from a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @param {string} questionId - ID of the question to delete
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Deletion result
 */
async function deleteAssessmentQuestion(db, courseId, lectureName, questionId, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for assessment question deletion`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the lecture already exists
    const existingLecture = course.lectures ? course.lectures.find(l => l.name === lectureName) : null;
    
    if (existingLecture) {
        // Remove the question from the assessmentQuestions array
        const result = await collection.updateOne(
            { 
                courseId,
                'lectures.name': lectureName 
            },
            {
                $pull: { 
                    'lectures.$.assessmentQuestions': { questionId: questionId } 
                },
                $set: {
                    'lectures.$.updatedAt': now,
                    updatedAt: now,
                    lastUpdatedById: instructorId
                }
            }
        );
        
        console.log(`Deleted assessment question from ${lectureName}`);
        return { success: true, deletedCount: result.modifiedCount, questionId };
    } else {
        console.error(`Lecture ${lectureName} not found in course ${courseId}`);
        return { success: false, error: 'Lecture not found' };
    }
}

/**
 * Update pass threshold for a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @param {number} passThreshold - Number of questions required to pass
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updatePassThreshold(db, courseId, lectureName, passThreshold, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for pass threshold update`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the lecture already exists
    const existingLecture = course.lectures ? course.lectures.find(l => l.name === lectureName) : null;
    
    if (existingLecture) {
        // Update existing lecture with pass threshold
        const result = await collection.updateOne(
            { 
                courseId,
                'lectures.name': lectureName 
            },
            {
                $set: {
                    'lectures.$.passThreshold': passThreshold,
                    'lectures.$.updatedAt': now,
                    updatedAt: now,
                    lastUpdatedById: instructorId
                }
            }
        );
        
        console.log(`Updated existing lecture ${lectureName} with pass threshold ${passThreshold}`);
        return { success: true, created: false, modifiedCount: result.modifiedCount };
    } else {
        console.error(`Lecture ${lectureName} not found in course ${courseId}`);
        return { success: false, error: 'Lecture not found' };
    }
}

/**
 * Get pass threshold for a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @returns {Promise<number>} Pass threshold value
 */
async function getPassThreshold(db, courseId, lectureName) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne(
        { courseId },
        { projection: { lectures: 1 } }
    );
    
    if (!course || !course.lectures) {
        return 0; // Default threshold when no threshold is set
    }
    
    // Find the specific lecture and return its pass threshold
    const lecture = course.lectures.find(l => l.name === lectureName);
    // Return 0 if no threshold is set (null, undefined, or not found)
    if (!lecture) {
        return 0;
    }
    return lecture.passThreshold !== undefined && lecture.passThreshold !== null ? lecture.passThreshold : 0;
}



/**
 * Get learning objectives for a specific lecture
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @returns {Promise<Array>} Array of learning objectives
 */
async function getLearningObjectives(db, courseId, lectureName) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne(
        { courseId },
        { projection: { lectures: 1 } }
    );
    
    if (!course || !course.lectures) {
        return [];
    }
    
    // Find the specific lecture and return its learning objectives
    const lecture = course.lectures.find(l => l.name === lectureName);
    return lecture ? (lecture.learningObjectives || []) : [];
}

/**
 * Create or update a course with onboarding data and generate units
 * @param {Object} db - MongoDB database instance
 * @param {Object} onboardingData - Onboarding data including course structure
 * @returns {Promise<Object>} Created/updated course with units
 */
async function createCourseFromOnboarding(db, onboardingData) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    const {
        courseId,
        courseName,
        instructorId,
        courseDescription,
        learningOutcomes,
        assessmentCriteria,
        courseMaterials,
        courseStructure
    } = onboardingData;
    
    try {
        // Check if course already exists for this instructor
        const existingCourse = await collection.findOne({ 
            $or: [
                { courseId: onboardingData.courseId },
                { instructorId: onboardingData.instructorId }
            ]
        });
        
        if (existingCourse) {
            console.log(`Course already exists for instructor ${instructorId}: ${existingCourse.courseId}`);
            return {
                success: true,
                created: false,
                modifiedCount: 0,
                courseId: existingCourse.courseId,
                totalUnits: existingCourse.courseStructure?.totalUnits || 0,
                message: 'Course already exists'
            };
        }
        
        // Calculate total units from weeks and lectures per week
        const totalUnits = courseStructure.weeks * courseStructure.lecturesPerWeek;
        
        // Generate units array
        const units = [];
        for (let i = 1; i <= totalUnits; i++) {
            const unitName = `Unit ${i}`;
            
            // Check if we have existing data for this unit from onboarding
            // Note: Documents are now handled separately through the documents array
            
            // For Unit 1, use learning outcomes from onboarding if available
            let learningObjectives = [];
            if (i === 1 && learningOutcomes && learningOutcomes.length > 0) {
                learningObjectives = learningOutcomes;
                console.log(`Setting Unit 1 learning objectives:`, learningObjectives);
            }
            
            // Debug: Log what we're setting for each unit
            console.log(`Unit ${i} (${unitName}): learningObjectives =`, learningObjectives);
            
            units.push({
                name: unitName,
                isPublished: false,
                learningObjectives: learningObjectives, // This should now work correctly
                passThreshold: 2, // Default threshold
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [] // Initialize empty assessment questions array
            });
        }
        
        // Prepare the course document
        const course = {
            courseId,
            courseName,
            courseCode: generateCourseCode(), // Generate course code
            instructorId,
            instructors: [instructorId], // Initialize with primary instructor
            tas: [], // Initialize empty TA array
            courseDescription: courseDescription || '',
            assessmentCriteria: assessmentCriteria || '',
            courseMaterials: courseMaterials || [],
            approvedStruggleTopics: [],
            // Retrieval behavior setting will be inherited from global settings if not set
            // isAdditiveRetrieval: false,
            courseStructure: {
                weeks: courseStructure.weeks,
                lecturesPerWeek: courseStructure.lecturesPerWeek,
                totalUnits: totalUnits
            },
            isOnboardingComplete: false, // Flag to track onboarding completion - set to true only after Unit 1 setup is complete
            lectures: units, // Use the existing lectures field for units
            createdAt: now,
            updatedAt: now
        };
        
        console.log(`Creating course from onboarding: ${courseId} with ${totalUnits} units`);
        
        const result = await collection.insertOne(course);
        
        console.log(`Course created with ${totalUnits} units`);
        
        return {
            success: true,
            created: true,
            modifiedCount: 1,
            courseId,
            totalUnits
        };
    } catch (error) {
        console.error('Error creating course from onboarding:', error);
        throw error;
    }
}

/**
 * Get course with onboarding data
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object|null>} Course data or null if not found
 */
async function getCourseWithOnboarding(db, courseId) {
    const collection = getCoursesCollection(db);
    
    try {
        const course = await collection.findOne({ courseId });
        return course;
    } catch (error) {
        console.error('Error fetching course with onboarding data:', error);
        throw error;
    }
}

/**
 * Update onboarding completion status
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {boolean} isComplete - Whether onboarding is complete
 * @returns {Promise<Object>} Update result
 */
async function updateOnboardingStatus(db, courseId, isComplete) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    try {
        const result = await collection.updateOne(
            { courseId },
            {
                $set: {
                    isOnboardingComplete: isComplete,
                    updatedAt: now
                }
            }
        );
        
        return {
            success: true,
            modifiedCount: result.modifiedCount,
            courseId
        };
    } catch (error) {
        console.error('Error updating onboarding status:', error);
        throw error;
    }
}

/**
 * Delete a unit from a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} unitName - Name of the unit to delete
 * @returns {Promise<Object>} Deletion result
 */
async function deleteUnit(db, courseId, unitName) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    try {
        const result = await collection.updateOne(
            { courseId },
            {
                $pull: { lectures: { name: unitName } },
                $set: { updatedAt: now }
            }
        );
        
        return {
            success: true,
            deletedCount: result.modifiedCount,
            courseId,
            unitName
        };
    } catch (error) {
        console.error('Error deleting unit:', error);
        throw error;
    }
}

/**
 * Update the display name of a unit (for custom unit titles)
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} unitName - Internal name of the unit (e.g., "Unit 1")
 * @param {string} displayName - Custom display name (e.g., "Biology") or null to clear
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updateUnitDisplayName(db, courseId, unitName, displayName, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists and find the unit
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for display name update`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the unit exists
    const existingUnit = course.lectures ? course.lectures.find(l => l.name === unitName) : null;
    if (!existingUnit) {
        console.error(`Unit ${unitName} not found in course ${courseId}`);
        return { success: false, error: 'Unit not found' };
    }
    
    // Build the update - set displayName or unset if empty/null
    const updateFields = {
        'lectures.$.updatedAt': now,
        updatedAt: now,
        lastUpdatedById: instructorId
    };
    
    // If displayName is empty or null, remove the field; otherwise set it
    if (displayName && displayName.trim()) {
        updateFields['lectures.$.displayName'] = displayName.trim();
    }
    
    const updateOp = {
        $set: updateFields
    };
    
    // If displayName is empty, also unset the field
    if (!displayName || !displayName.trim()) {
        updateOp.$unset = { 'lectures.$.displayName': '' };
    }
    
    const result = await collection.updateOne(
        { 
            courseId,
            'lectures.name': unitName 
        },
        updateOp
    );
    
    console.log(`Updated display name for ${unitName} to "${displayName || '(cleared)'}" in course ${courseId}`);
    
    return { 
        success: true, 
        modifiedCount: result.modifiedCount,
        unitName,
        displayName: displayName && displayName.trim() ? displayName.trim() : null
    };
}

/**
 * Add or update a document reference within a specific unit
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} unitName - Name of the unit
 * @param {Object} documentData - Document data to store
 * @param {string} instructorId - ID of the instructor
 * @returns {Promise<Object>} Update result
 */
async function addDocumentToUnit(db, courseId, unitName, documentData, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for document addition`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the unit already exists
    const existingUnit = course.lectures ? course.lectures.find(l => l.name === unitName) : null;
    
    if (existingUnit) {
        // Check if document already exists (for updates)
        const existingDocIndex = existingUnit.documents ? 
            existingUnit.documents.findIndex(d => d.documentId === documentData.documentId) : -1;
        
        if (existingDocIndex >= 0) {
            // Update existing document
            const result = await collection.updateOne(
                { 
                    courseId,
                    'lectures.name': unitName,
                    'lectures.documents.documentId': documentData.documentId
                },
                {
                    $set: {
                        'lectures.$.documents.$': {
                            ...documentData,
                            updatedAt: now
                        },
                        'lectures.$.updatedAt': now,
                        updatedAt: now,
                        instructorId
                    }
                }
            );
            
            console.log(`Updated existing document in ${unitName}`);
            return { success: true, created: false, modifiedCount: result.modifiedCount };
        } else {
            // Add new document
            const result = await collection.updateOne(
                { 
                    courseId,
                    'lectures.name': unitName 
                },
                {
                    $push: {
                        'lectures.$.documents': {
                            ...documentData,
                            createdAt: now,
                            updatedAt: now
                        }
                    },
                    $set: {
                        'lectures.$.updatedAt': now,
                        updatedAt: now,
                        instructorId
                    }
                }
            );
            
            console.log(`Added new document to ${unitName}`);
            return { success: true, created: true, modifiedCount: result.modifiedCount };
        }
    } else {
        console.error(`Unit ${unitName} not found in course ${courseId}`);
        return { success: false, error: 'Unit not found' };
    }
}

/**
 * Get documents for a specific unit from the course structure
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} unitName - Name of the unit
 * @returns {Promise<Array>} Array of documents
 */
async function getDocumentsForUnit(db, courseId, unitName) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne(
        { courseId },
        { projection: { lectures: 1 } }
    );
    
    if (!course || !course.lectures) {
        return [];
    }
    
    // Find the specific unit and return its documents
    const unit = course.lectures.find(l => l.name === unitName);
    return unit ? (unit.documents || []) : [];
}

/**
 * Remove a document from a specific unit
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} unitName - Name of the unit
 * @param {string} documentId - ID of the document to remove
 * @param {string} instructorId - ID of the instructor
 * @returns {Promise<Object>} Removal result
 */
async function removeDocumentFromUnit(db, courseId, unitName, documentId, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        console.error(`Course ${courseId} not found for document removal`);
        return { success: false, error: 'Course not found' };
    }
    
    // Check if the unit already exists
    const existingUnit = course.lectures ? course.lectures.find(l => l.name === unitName) : null;
    
    if (existingUnit) {
        console.log(`Found unit ${unitName} with ${existingUnit.documents?.length || 0} documents`);
        console.log(`Looking for document with ID: ${documentId}`);
        
        // Check if the document actually exists in this unit
        const documentExists = existingUnit.documents && existingUnit.documents.some(doc => doc.documentId === documentId);
        console.log(`Document exists in unit: ${documentExists}`);
        
        if (!documentExists) {
            console.log(`Document ${documentId} not found in unit ${unitName}`);
            return { success: false, error: 'Document not found in unit' };
        }
        
        // Remove the document from the documents array using a direct approach
        // First, get the current course to modify it directly
        const currentCourse = await collection.findOne({ courseId });
        if (!currentCourse) {
            return { success: false, error: 'Course not found during update' };
        }
        
        // Find the unit and remove the document
        let documentRemoved = false;
        if (currentCourse.lectures) {
            for (let i = 0; i < currentCourse.lectures.length; i++) {
                const unit = currentCourse.lectures[i];
                if (unit.name === unitName && unit.documents) {
                    const initialLength = unit.documents.length;
                    unit.documents = unit.documents.filter(doc => doc.documentId !== documentId);
                    if (unit.documents.length < initialLength) {
                        documentRemoved = true;
                        unit.updatedAt = now;
                    }
                }
            }
        }
        
        if (!documentRemoved) {
            console.log(`Document ${documentId} not found in unit ${unitName}`);
            return { success: false, error: 'Document not found in unit' };
        }
        
        // Update the course with the modified data
        const result = await collection.updateOne(
            { courseId },
            {
                $set: {
                    lectures: currentCourse.lectures,
                    updatedAt: now,
                    lastUpdatedById: instructorId
                }
            }
        );
        
        console.log(`MongoDB update result:`, result);
        console.log(`Removed document from ${unitName}`);
        return { success: true, removedCount: result.modifiedCount, documentId };
    } else {
        console.error(`Unit ${unitName} not found in course ${courseId}`);
        return { success: false, error: 'Unit not found' };
    }
}

/**
 * Remove a document from any unit in a course (fallback method)
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} documentId - ID of the document to remove
 * @param {string} instructorId - ID of the instructor
 * @returns {Promise<Object>} Removal result
 */
async function removeDocumentFromAnyUnit(db, courseId, documentId, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // Remove the document from any unit that contains it using a direct approach
    // First, get the current course to modify it directly
    const currentCourse = await collection.findOne({ courseId });
    if (!currentCourse) {
        return { success: false, error: 'Course not found during update' };
    }
    
    // Find and remove the document from any unit
    let documentRemoved = false;
    let removedCount = 0;
    if (currentCourse.lectures) {
        for (let i = 0; i < currentCourse.lectures.length; i++) {
            const unit = currentCourse.lectures[i];
            if (unit.documents) {
                const initialLength = unit.documents.length;
                unit.documents = unit.documents.filter(doc => doc.documentId !== documentId);
                if (unit.documents.length < initialLength) {
                    documentRemoved = true;
                    removedCount += (initialLength - unit.documents.length);
                    unit.updatedAt = now;
                }
            }
        }
    }
    
    if (!documentRemoved) {
        console.log(`Document ${documentId} not found in any unit`);
        return { success: false, error: 'Document not found in any unit' };
    }
    
    // Update the course with the modified data
    const result = await collection.updateOne(
        { courseId },
        {
            $set: {
                lectures: currentCourse.lectures,
                updatedAt: now,
                lastUpdatedById: instructorId
            }
        }
    );
    
    console.log(`Removed document ${documentId} from any unit in course ${courseId}`);
    return { success: true, removedCount: result.modifiedCount, documentId };
}

/**
 * Add an instructor to a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} instructorId - ID of the instructor to add
 * @returns {Promise<Object>} Update result
 */
async function addInstructorToCourse(db, courseId, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        return { success: false, error: 'Course not found' };
    }
    
    // Initialize arrays if they don't exist
    const updateData = {
        $addToSet: { instructors: instructorId },
        $set: { updatedAt: now }
    };
    
    // If this is the first instructor, also set instructorId for backward compatibility
    if (!course.instructorId) {
        updateData.$set.instructorId = instructorId;
    }
    
    const result = await collection.updateOne(
        { courseId },
        updateData
    );
    
    console.log(`Added instructor ${instructorId} to course ${courseId}`);
    return { success: true, modifiedCount: result.modifiedCount };
}

/**
 * Add a TA to a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} taId - ID of the TA to add
 * @returns {Promise<Object>} Update result
 */
async function addTAToCourse(db, courseId, taId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        return { success: false, error: 'Course not found' };
    }
    
    const result = await collection.updateOne(
        { courseId },
        {
            $addToSet: { tas: taId },
            $set: { updatedAt: now }
        }
    );
    
    console.log(`Added TA ${taId} to course ${courseId}`);
    return { success: true, modifiedCount: result.modifiedCount };
}

/**
 * Remove an instructor from a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} instructorId - ID of the instructor to remove
 * @returns {Promise<Object>} Update result
 */
async function removeInstructorFromCourse(db, courseId, instructorId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    const result = await collection.updateOne(
        { courseId },
        {
            $pull: { instructors: instructorId },
            $set: { updatedAt: now }
        }
    );
    
    console.log(`Removed instructor ${instructorId} from course ${courseId}`);
    return { success: true, modifiedCount: result.modifiedCount };
}

/**
 * Remove a TA from a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} taId - ID of the TA to remove
 * @returns {Promise<Object>} Update result
 */
async function removeTAFromCourse(db, courseId, taId) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    const result = await collection.updateOne(
        { courseId },
        {
            $pull: { tas: taId },
            $set: { updatedAt: now }
        }
    );
    
    console.log(`Removed TA ${taId} from course ${courseId}`);
    return { success: true, modifiedCount: result.modifiedCount };
}

/**
 * Get all courses for a user (instructor or TA)
 * @param {Object} db - MongoDB database instance
 * @param {string} userId - User identifier
 * @param {string} role - User role ('instructor' or 'ta')
 * @returns {Promise<Array>} Array of courses
 */
async function getCoursesForUser(db, userId, role) {
    const collection = getCoursesCollection(db);
    
    let query = {};
    if (role === 'instructor') {
        query = {
            $or: [
                { instructorId: userId },
                { instructors: userId }
            ]
        };
    } else if (role === 'ta') {
        query = { tas: userId };
    }
    
    const courses = await collection.find(query)
        .project({
            courseId: 1,
            courseName: 1,
            instructorId: 1,
            instructors: 1,
            tas: 1,
            courseStructure: 1,
            createdAt: 1,
            updatedAt: 1
        })
        .sort({ updatedAt: -1 })
        .toArray();
    
    return courses;
}

/**
 * Check if a user has access to a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} userId - User identifier
 * @param {string} role - User role
 * @returns {Promise<boolean>} True if user has access
 */
async function userHasCourseAccess(db, courseId, userId, role) {
    const collection = getCoursesCollection(db);
    
    let query = { courseId };
    if (role === 'instructor') {
        query.$or = [
            { instructorId: userId },
            { instructors: userId }
        ];
    } else if (role === 'ta') {
        query.tas = userId;
    } else if (role === 'student') {
        // Students can access published courses (this might need to be more specific)
        query.isPublished = true;
    }
    
    const course = await collection.findOne(query);
    return !!course;
}

/**
 * Get a course by its ID
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course ID to find
 * @returns {Promise<Object|null>} Course object or null if not found
 */
async function getCourseById(db, courseId) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne({ courseId });
    return course;
}

/**
 * Update TA permissions for a specific course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} taId - TA identifier
 * @param {Object} permissions - Permission object
 * @param {boolean} permissions.canAccessCourses - Can access My Courses page
 * @param {boolean} permissions.canAccessFlags - Can access Flag page
 * @returns {Promise<Object>} Update result
 */
async function updateTAPermissions(db, courseId, taId, permissions) {
    const collection = getCoursesCollection(db);
    
    const now = new Date();
    
    // First, ensure the course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        return { success: false, error: 'Course not found' };
    }
    
    // Check if TA is assigned to this course
    if (!course.tas || !course.tas.includes(taId)) {
        return { success: false, error: 'TA is not assigned to this course' };
    }
    
    // Update TA permissions
    const result = await collection.updateOne(
        { courseId },
        {
            $set: {
                [`taPermissions.${taId}`]: {
                    canAccessCourses: permissions.canAccessCourses,
                    canAccessFlags: permissions.canAccessFlags,
                    updatedAt: now
                },
                updatedAt: now
            }
        }
    );
    
    if (result.modifiedCount > 0) {
        console.log(`Updated TA permissions for ${taId} in course ${courseId}`);
        return { success: true, modifiedCount: result.modifiedCount };
    } else {
        return { success: false, error: 'Failed to update TA permissions' };
    }
}

/**
 * Get TA permissions for a specific course and TA
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} taId - TA identifier
 * @returns {Promise<Object>} TA permissions or default permissions
 */
async function getTAPermissions(db, courseId, taId) {
    const collection = getCoursesCollection(db);
    
    const course = await collection.findOne({ courseId });
    if (!course) {
        return { success: false, error: 'Course not found' };
    }
    
    // Check if TA is assigned to this course
    if (!course.tas || !course.tas.includes(taId)) {
        return { success: false, error: 'TA is not assigned to this course' };
    }
    
    // Get TA permissions or return default permissions
    const permissions = course.taPermissions && course.taPermissions[taId] 
        ? course.taPermissions[taId]
        : { canAccessCourses: true, canAccessFlags: true }; // Default to allowing access
    
    return { success: true, permissions };
}

/**
 * Check if a TA has permission to access a specific feature
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} taId - TA identifier
 * @param {string} feature - Feature to check ('courses' or 'flags')
 * @returns {Promise<boolean>} True if TA has permission
 */
async function checkTAPermission(db, courseId, taId, feature) {
    const result = await getTAPermissions(db, courseId, taId);
    
    if (!result.success) {
        return false;
    }
    
    const permissions = result.permissions;
    
    switch (feature) {
        case 'courses':
            return permissions.canAccessCourses;
        case 'flags':
            return permissions.canAccessFlags;
        default:
            return false;
    }
}

/**
 * Update student enrollment override for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} studentId - Student identifier
 * @param {boolean} enrolled - Whether the student is enrolled (true) or blocked (false)
 * @returns {Promise<Object>} Update result
 */
async function updateStudentEnrollment(db, courseId, studentId, enrolled) {
    const collection = getCoursesCollection(db);

    const now = new Date();

    // Ensure course exists
    const course = await collection.findOne({ courseId });
    if (!course) {
        return { success: false, error: 'Course not found' };
    }

    const result = await collection.updateOne(
        { courseId },
        {
            $set: {
                [`studentEnrollment.${studentId}`]: {
                    enrolled: !!enrolled,
                    updatedAt: now
                },
                updatedAt: now
            }
        }
    );

    if (result.modifiedCount > 0) {
        return { success: true, modifiedCount: result.modifiedCount };
    }
    return { success: false, error: 'Failed to update student enrollment' };
}

/**
 * Get student enrollment override for a course (defaults to enrolled=false)
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} studentId - Student identifier
 * @returns {Promise<{ success: boolean, enrolled?: boolean, status?: string, error?: string }>} Result
 */
async function getStudentEnrollment(db, courseId, studentId) {
    const collection = getCoursesCollection(db);

    const course = await collection.findOne(
        { courseId },
        { projection: { studentEnrollment: 1 } }
    );

    if (!course) {
        return { success: false, error: 'Course not found' };
    }

    const enrollment = course.studentEnrollment && course.studentEnrollment[studentId];
    
    let status = 'none'; // Default: Not Joined
    let enrolled = false;

    if (enrollment) {
        if (enrollment.enrolled) {
            status = 'enrolled';
            enrolled = true;
        } else {
            status = 'banned'; // Explicitly false means banned
            enrolled = false;
        }
    }

    return { success: true, enrolled, status };
}

/**
 * Join a course using a course code
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} studentId - Student identifier
 * @param {string} code - Course code provided by student
 * @returns {Promise<{ success: boolean, enrolled?: boolean, error?: string, message?: string }>} Result
 */
async function joinCourse(db, courseId, studentId, code) {
    const collection = getCoursesCollection(db);
    const now = new Date();

    const course = await collection.findOne({ courseId });
    if (!course) {
        return { success: false, error: 'Course not found' };
    }

    // Check if currently blocked
    const currentEnrollment = course.studentEnrollment && course.studentEnrollment[studentId];
    if (currentEnrollment && currentEnrollment.enrolled === false) {
        return { success: false, error: 'Access revoked by instructor' };
    }

    // Verify code (case-insensitive)
    if (!course.courseCode || course.courseCode.toUpperCase() !== code.toUpperCase()) {
        return { success: false, error: 'Invalid course code' };
    }

    // Enroll the student
    await collection.updateOne(
        { courseId },
        {
            $set: {
                [`studentEnrollment.${studentId}`]: {
                    enrolled: true,
                    joinedAt: now,
                    updatedAt: now
                },
                updatedAt: now
            }
        }
    );

    return { success: true, enrolled: true, message: 'Successfully joined course' };
}

/**
 * Get approved struggle topics for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Array<string>>} Approved topic list
 */
async function getApprovedStruggleTopics(db, courseId) {
    const collection = getCoursesCollection(db);
    const course = await collection.findOne(
        { courseId },
        { projection: { approvedStruggleTopics: 1 } }
    );

    if (!course || !Array.isArray(course.approvedStruggleTopics)) {
        return [];
    }

    return normalizeTopicList(course.approvedStruggleTopics);
}

/**
 * Replace approved struggle topics for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {Array<string>} topics - Topic list
 * @param {string} updatedById - User making update
 * @returns {Promise<Object>} Update result
 */
async function setApprovedStruggleTopics(db, courseId, topics, updatedById) {
    const collection = getCoursesCollection(db);
    const normalizedTopics = normalizeTopicList(topics);
    const now = new Date();

    const result = await collection.updateOne(
        { courseId },
        {
            $set: {
                approvedStruggleTopics: normalizedTopics,
                updatedAt: now,
                lastUpdatedById: updatedById
            }
        }
    );

    return {
        success: result.matchedCount > 0,
        modifiedCount: result.modifiedCount,
        topics: normalizedTopics,
        error: result.matchedCount > 0 ? null : 'Course not found'
    };
}

/**
 * Get quiz practice settings for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object>} Quiz settings with defaults
 */
async function getQuizSettings(db, courseId) {
    const collection = getCoursesCollection(db);
    const course = await collection.findOne(
        { courseId },
        { projection: { quizSettings: 1 } }
    );

    const defaults = {
        enabled: false,
        testableUnits: 'all',
        allowLectureMaterialAccess: true,
        allowSourceAttributionDownloads: false
    };

    if (!course) {
        return defaults;
    }

    const settings = course.quizSettings || {};

    return {
        enabled: settings.enabled !== undefined ? settings.enabled : defaults.enabled,
        testableUnits: settings.testableUnits !== undefined ? settings.testableUnits : defaults.testableUnits,
        allowLectureMaterialAccess: settings.allowLectureMaterialAccess !== undefined ? settings.allowLectureMaterialAccess : defaults.allowLectureMaterialAccess,
        allowSourceAttributionDownloads: settings.allowSourceAttributionDownloads !== undefined
            ? settings.allowSourceAttributionDownloads
            : defaults.allowSourceAttributionDownloads
    };
}

/**
 * Update quiz practice settings for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {Object} settings - { enabled, testableUnits, allowLectureMaterialAccess, allowSourceAttributionDownloads }
 * @param {string} instructorId - ID of the instructor making the change
 * @returns {Promise<Object>} Update result
 */
async function updateQuizSettings(db, courseId, settings, instructorId) {
    const collection = getCoursesCollection(db);
    const now = new Date();

    const quizSettings = {
        enabled: settings.enabled !== undefined ? settings.enabled : false,
        testableUnits: settings.testableUnits !== undefined ? settings.testableUnits : 'all',
        allowLectureMaterialAccess: settings.allowLectureMaterialAccess !== undefined ? settings.allowLectureMaterialAccess : true,
        allowSourceAttributionDownloads: settings.allowSourceAttributionDownloads !== undefined
            ? settings.allowSourceAttributionDownloads
            : false
    };

    const result = await collection.updateOne(
        { courseId },
        {
            $set: {
                quizSettings,
                updatedAt: now,
                lastUpdatedById: instructorId
            }
        }
    );

    return {
        success: result.matchedCount > 0,
        modifiedCount: result.modifiedCount,
        error: result.matchedCount > 0 ? null : 'Course not found'
    };
}

module.exports = {
    getCoursesCollection,
    ensureCourseCodes,
    upsertCourse,
    updateLecturePublishStatus,
    getLecturePublishStatus,
    getPublishedLectures,
    updateLearningObjectives,
    getLearningObjectives,
    updatePassThreshold,
    getPassThreshold,
    createCourseFromOnboarding,
    getCourseWithOnboarding,
    updateOnboardingStatus,
    deleteUnit,
    updateAssessmentQuestions,
    getAssessmentQuestions,
    deleteAssessmentQuestion,
    addDocumentToUnit,
    getDocumentsForUnit,
    removeDocumentFromUnit,
    removeDocumentFromAnyUnit,
    addInstructorToCourse,
    addTAToCourse,
    removeInstructorFromCourse,
    removeTAFromCourse,
    getCoursesForUser,
    userHasCourseAccess,
    getCourseById,
    updateTAPermissions,
    getTAPermissions,
    checkTAPermission,
    updateStudentEnrollment,
    getStudentEnrollment,
    joinCourse,
    updateUnitDisplayName,
    getApprovedStruggleTopics,
    setApprovedStruggleTopics,
    normalizeTopicList,
    getQuizSettings,
    updateQuizSettings
};
