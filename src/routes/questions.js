const express = require('express');
const router = express.Router();

// Import the Course model instead of Question model
const CourseModel = require('../models/Course');

// Middleware for JSON parsing
router.use(express.json());

/**
 * POST /api/questions
 * Create a new assessment question
 */
router.post('/', async (req, res) => {
    try {
        const { 
            courseId, 
            lectureName, 
            instructorId, 
            questionType, 
            question, 
            options, 
            correctAnswer, 
            explanation,
            difficulty,
            tags,
            points,
            metadata
        } = req.body;
        
        // Validate required fields
        if (!courseId || !lectureName || !instructorId || !questionType || !question || !correctAnswer) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, instructorId, questionType, question, correctAnswer'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Prepare question data
        const questionData = {
            questionType,
            question,
            options: options || {},
            correctAnswer,
            explanation: explanation || '',
            difficulty: difficulty || 'medium',
            tags: tags || [],
            points: points || 1,
            metadata: {
                source: 'manual',
                aiGenerated: false,
                reviewStatus: 'draft',
                ...metadata
            }
        };
        
        // Create question in the course structure using Course model
        const result = await CourseModel.updateAssessmentQuestions(
            db, 
            courseId, 
            lectureName, 
            questionData, 
            instructorId
        );
        
        if (!result.success) {
            return res.status(400).json({
                success: false,
                message: result.error || 'Failed to create question'
            });
        }
        
        console.log(`Question created for ${lectureName} by instructor ${instructorId}`);
        
        res.json({
            success: true,
            message: 'Question created successfully!',
            data: {
                questionId: result.questionId,
                question: questionData.question,
                questionType: questionData.questionType,
                createdAt: new Date().toISOString(),
                created: result.created
            }
        });
        
    } catch (error) {
        console.error('Error creating question:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while creating question',
            error: error.message
        });
    }
});

/**
 * GET /api/questions/lecture
 * Get all questions for a specific lecture/unit
 */
router.get('/lecture', async (req, res) => {
    try {
        const { courseId, lectureName } = req.query;
        
        if (!courseId || !lectureName) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameters: courseId, lectureName'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Fetch questions from the course structure using Course model
        const questions = await CourseModel.getAssessmentQuestions(db, courseId, lectureName);
        
        res.json({
            success: true,
            data: {
                courseId,
                lectureName,
                questions: questions,
                count: questions.length
            }
        });
        
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching questions'
        });
    }
});

/**
 * GET /api/questions/:questionId
 * Get a specific question by ID (search across all courses)
 */
router.get('/:questionId', async (req, res) => {
    try {
        const { questionId } = req.params;
        
        if (!questionId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: questionId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Search for the question across all courses
        const collection = db.collection('courses');
        const course = await collection.findOne({
            'lectures.assessmentQuestions.questionId': questionId
        });
        
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }
        
        // Find the specific question
        let foundQuestion = null;
        for (const lecture of course.lectures || []) {
            if (lecture.assessmentQuestions) {
                foundQuestion = lecture.assessmentQuestions.find(q => q.questionId === questionId);
                if (foundQuestion) break;
            }
        }
        
        if (!foundQuestion) {
            return res.status(404).json({
                success: false,
                message: 'Question not found'
            });
        }
        
        res.json({
            success: true,
            data: foundQuestion
        });
        
    } catch (error) {
        console.error('Error fetching question:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching question'
        });
    }
});

/**
 * PUT /api/questions/:questionId
 * Update an existing question
 */
router.put('/:questionId', async (req, res) => {
    try {
        const { questionId } = req.params;
        const updateData = req.body;
        const { courseId, lectureName, instructorId } = req.body;
        
        if (!questionId || !courseId || !lectureName || !instructorId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: questionId, courseId, lectureName, instructorId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Prepare the updated question data
        const questionData = {
            ...updateData,
            questionId: questionId
        };
        
        // Update question in the course structure using Course model
        const result = await CourseModel.updateAssessmentQuestions(
            db, 
            courseId, 
            lectureName, 
            questionData, 
            instructorId
        );
        
        if (!result.success) {
            return res.status(400).json({
                success: false,
                message: result.error || 'Failed to update question'
            });
        }
        
        console.log(`Question updated: ${questionId}`);
        
        res.json({
            success: true,
            message: 'Question updated successfully!',
            data: {
                questionId,
                updatedCount: result.modifiedCount
            }
        });
        
    } catch (error) {
        console.error('Error updating question:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while updating question',
            error: error.message
        });
    }
});

/**
 * DELETE /api/questions/:questionId
 * Delete a question (remove from course structure)
 */
router.delete('/:questionId', async (req, res) => {
    try {
        const { questionId } = req.params;
        const { instructorId, courseId, lectureName } = req.body;
        
        if (!questionId || !instructorId || !courseId || !lectureName) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: questionId, instructorId, courseId, lectureName'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Delete the question from the course structure using Course model
        const result = await CourseModel.deleteAssessmentQuestion(
            db, 
            courseId, 
            lectureName, 
            questionId, 
            instructorId
        );
        
        if (!result.success) {
            return res.status(400).json({
                success: false,
                message: result.error || 'Failed to delete question'
            });
        }
        
        console.log(`Question deleted: ${questionId} by instructor ${instructorId}`);
        
        res.json({
            success: true,
            message: 'Question deleted successfully!',
            data: {
                questionId,
                deletedCount: result.deletedCount
            }
        });
        
    } catch (error) {
        console.error('Error deleting question:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while deleting question'
        });
    }
});

/**
 * GET /api/questions/stats
 * Get question statistics for a course
 */
router.get('/stats', async (req, res) => {
    try {
        const { courseId } = req.query;
        
        if (!courseId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: courseId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Get course data to calculate statistics
        const collection = db.collection('courses');
        const course = await collection.findOne({ courseId });
        
        if (!course || !course.lectures) {
            return res.json({
                success: true,
                data: {
                    courseId,
                    totalQuestions: 0,
                    totalPoints: 0,
                    typeBreakdown: []
                }
            });
        }
        
        // Calculate statistics from the course structure
        let totalQuestions = 0;
        let totalPoints = 0;
        const typeBreakdown = {};
        
        for (const lecture of course.lectures) {
            if (lecture.assessmentQuestions) {
                for (const question of lecture.assessmentQuestions) {
                    totalQuestions++;
                    totalPoints += question.points || 1;
                    
                    const type = question.questionType;
                    if (!typeBreakdown[type]) {
                        typeBreakdown[type] = { count: 0, points: 0 };
                    }
                    typeBreakdown[type].count++;
                    typeBreakdown[type].points += question.points || 1;
                }
            }
        }
        
        const stats = {
            totalQuestions,
            totalPoints,
            typeBreakdown: Object.entries(typeBreakdown).map(([type, data]) => ({
                type,
                count: data.count,
                points: data.points
            }))
        };
        
        res.json({
            success: true,
            data: {
                courseId,
                stats
            }
        });
        
    } catch (error) {
        console.error('Error fetching question stats:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching question stats'
        });
    }
});

/**
 * POST /api/questions/bulk
 * Bulk create questions (for AI-generated questions)
 */
router.post('/bulk', async (req, res) => {
    try {
        const { courseId, lectureName, instructorId, questions } = req.body;
        
        if (!courseId || !lectureName || !instructorId || !questions || !Array.isArray(questions)) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, instructorId, questions (array)'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        let insertedCount = 0;
        const insertedIds = [];
        
        // Create each question individually using the Course model
        for (const question of questions) {
            const questionData = {
                ...question,
                metadata: {
                    source: 'ai-generated',
                    aiGenerated: true,
                    reviewStatus: 'draft',
                    ...question.metadata
                }
            };
            
            const result = await CourseModel.updateAssessmentQuestions(
                db, 
                courseId, 
                lectureName, 
                questionData, 
                instructorId
            );
            
            if (result.success) {
                insertedCount++;
                insertedIds.push(result.questionId);
            }
        }
        
        console.log(`Bulk created ${insertedCount} questions for ${lectureName}`);
        
        res.json({
            success: true,
            message: `${insertedCount} questions created successfully!`,
            data: {
                courseId,
                lectureName,
                insertedCount,
                insertedIds
            }
        });
        
    } catch (error) {
        console.error('Error bulk creating questions:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while bulk creating questions',
            error: error.message
        });
    }
});

/**
 * GET /api/questions/course-material
 * Get course material content for AI question generation
 */
router.get('/course-material', async (req, res) => {
    try {
        const { courseId, lectureName, instructorId } = req.query;
        
        // Validate required fields
        if (!courseId || !lectureName || !instructorId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, instructorId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Get course data to find documents for the specific lecture/unit
        const course = await CourseModel.getCourseWithOnboarding(db, courseId);
        
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found'
            });
        }
        
        // Check if the instructor has access to this course
        if (course.instructorId !== instructorId) {
            return res.status(403).json({
                success: false,
                message: 'Access denied: You do not have permission to access this course'
            });
        }
        
        // Find the specific lecture/unit
        const unit = course.lectures?.find(l => l.name === lectureName);
        
        if (!unit) {
            return res.status(404).json({
                success: false,
                message: `Unit ${lectureName} not found in course`
            });
        }
        
        // Get documents for this unit
        const documents = unit.documents || [];
        
        if (documents.length === 0) {
            return res.status(404).json({
                success: false,
                message: `No course materials found for ${lectureName}`,
                data: {
                    hasMaterials: false,
                    content: null
                }
            });
        }
        
        // Combine content from all documents (prioritize lecture notes and practice questions)
        let combinedContent = '';
        let hasRequiredMaterials = false;
        
        // First, look for lecture notes and practice questions
        const priorityDocuments = documents.filter(doc => 
            doc.type === 'lecture_notes' || 
            doc.type === 'practice_q_tutorials' ||
            doc.documentType === 'lecture-notes' ||
            doc.documentType === 'practice-quiz'
        );
        
        if (priorityDocuments.length > 0) {
            hasRequiredMaterials = true;
            // Combine content from priority documents
            priorityDocuments.forEach(doc => {
                if (doc.content && doc.content.trim()) {
                    combinedContent += `\n\n--- ${doc.originalName || 'Document'} ---\n${doc.content}`;
                }
            });
        } else {
            // Fallback to any document with content
            documents.forEach(doc => {
                if (doc.content && doc.content.trim()) {
                    combinedContent += `\n\n--- ${doc.originalName || 'Document'} ---\n${doc.content}`;
                }
            });
        }
        
        if (!combinedContent.trim()) {
            return res.status(404).json({
                success: false,
                message: `No content found in documents for ${lectureName}`,
                data: {
                    hasMaterials: false,
                    content: null
                }
            });
        }
        
        // Handle content length intelligently
        const maxContentLength = 16000; // Increased limit for better context
        
        if (combinedContent.length > maxContentLength) {
            console.log(`📚 [CONTENT] Original content length: ${combinedContent.length} chars`);
            
            // Split content into sections
            const sections = combinedContent.split('---').filter(s => s.trim());
            console.log(`📚 [CONTENT] Found ${sections.length} sections`);
            
            // Sort sections: Priority docs first, then additional materials
            const prioritizedSections = sections.sort((a, b) => {
                const aIsPriority = a.includes('Lecture Notes') || a.includes('Practice Questions');
                const bIsPriority = b.includes('Lecture Notes') || b.includes('Practice Questions');
                if (aIsPriority && !bIsPriority) return -1;
                if (!aIsPriority && bIsPriority) return 1;
                return 0; // Keep original order for additional materials
            });
            
            console.log('📚 [CONTENT] Section types:', prioritizedSections.map(s => {
                if (s.includes('Lecture Notes')) return 'Lecture Notes';
                if (s.includes('Practice Questions')) return 'Practice Questions';
                return 'Additional Material';
            }));
            
            // Rebuild content with prioritized sections up to limit
            let newContent = '';
            let sectionsIncluded = 0;
            
            for (const section of prioritizedSections) {
                if ((newContent + section).length <= maxContentLength) {
                    newContent += '---' + section;
                    sectionsIncluded++;
                } else {
                    break;
                }
            }
            
            combinedContent = newContent.trim() + `\n\n[Content truncated: ${sectionsIncluded}/${sections.length} sections included]`;
            console.log(`📚 [CONTENT] Truncated to ${combinedContent.length} chars, included ${sectionsIncluded} sections`);
        }
        
        console.log(`📚 Retrieved course material content for ${lectureName}: ${combinedContent.length} characters`);
        
        res.json({
            success: true,
            message: 'Course material content retrieved successfully',
            data: {
                hasMaterials: true,
                content: combinedContent,
                documentCount: documents.length,
                unitName: lectureName,
                courseId: courseId
            }
        });
        
    } catch (error) {
        console.error('Error retrieving course material content:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while retrieving course material content',
            error: error.message
        });
    }
});

/**
 * POST /api/questions/check-answer
 * Check a student's answer using LLM
 */
router.post('/check-answer', async (req, res) => {
    try {
        const { question, studentAnswer, expectedAnswer, questionType, studentName } = req.body;

        if (!question || !studentAnswer || !expectedAnswer) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: question, studentAnswer, expectedAnswer'
            });
        }

        const llmService = req.app.locals.llm;
        if (!llmService) {
            return res.status(503).json({
                success: false,
                message: 'LLM service not available'
            });
        }

        const result = await llmService.evaluateStudentAnswer(
            question,
            studentAnswer,
            expectedAnswer,
            questionType,
            studentName || 'Student'
        );

        res.json({
            success: true,
            data: result
        });

    } catch (error) {
        console.error('Error checking answer:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while checking answer'
        });
    }
});

/**
 * POST /api/questions/generate-ai
 * Generate an assessment question using AI based on course material
 */
router.post('/generate-ai', async (req, res) => {
    try {
        const { 
            courseId, 
            lectureName, 
            instructorId, 
            questionType, 
            learningObjectives,
            regenerate,
            feedback,
            previousQuestion
        } = req.body;
        
        // Validate required fields
        if (!courseId || !lectureName || !instructorId || !questionType) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, instructorId, questionType'
            });
        }
        
        // Additional validation for regeneration requests
        if (regenerate && !feedback) {
            return res.status(400).json({
                success: false,
                message: 'Feedback is required for regeneration requests'
            });
        }
        
        console.log('🎯 [GENERATE] Learning objectives:', learningObjectives);
        
        // Validate question type
        const validQuestionTypes = ['true-false', 'multiple-choice', 'short-answer'];
        if (!validQuestionTypes.includes(questionType)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid question type. Must be one of: true-false, multiple-choice, short-answer'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        const DocumentModel = require('../models/Document');
        
        // First, get the course material content
        const course = await CourseModel.getCourseWithOnboarding(db, courseId);
        
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found'
            });
        }
        
        // Check if the user has access to this course
        // Uses session user (req.user) for reliable authentication
        // Also allows TAs who are assigned to this course
        const user = req.user;
        const hasAccess = user && (
            course.instructorId === user.userId ||
            course.instructorId === user.email ||
            course.instructors?.includes(user.userId) ||
            course.instructors?.includes(user.email) ||
            course.tas?.some(ta => ta.email === user.email || ta.userId === user.userId) ||
            user.role === 'admin'
        );
        
        if (!hasAccess) {
            console.log(`🚫 [PERMISSION] Access denied for user ${user?.userId || 'unknown'} to course ${courseId}`);
            console.log(`🔍 [PERMISSION] Course instructorId: ${course.instructorId}, User: ${user?.userId}, Email: ${user?.email}`);
            console.log(`🔍 [PERMISSION] Course instructors array: ${JSON.stringify(course.instructors)}`);
            return res.status(403).json({
                success: false,
                message: 'Access denied: You do not have permission to access this course'
            });
        }
        const unit = course.lectures?.find(l => l.name === lectureName);
        
        if (!unit) {
            return res.status(404).json({
                success: false,
                message: `Unit ${lectureName} not found in course`
            });
        }
        
        // Format unit name for prompts - use displayName if available
        const unitNum = lectureName.match(/\d+/)?.[0] || '';
        const formattedUnitName = unit.displayName 
            ? `${unitNum}. ${unit.displayName}` 
            : lectureName;
        
        const documents = unit.documents || [];
        
        if (documents.length === 0) {
            return res.status(400).json({
                success: false,
                message: `No course materials found for ${lectureName}`,
                data: {
                    hasMaterials: false,
                    content: null
                }
            });
        }
        
        // Combine content from all documents, including additional materials
        let combinedContent = '';
        
        // First process priority documents (lecture notes and practice quizzes)
        const priorityDocumentTypes = ['lecture-notes', 'practice-quiz'];
        const priorityDocuments = documents.filter(doc => priorityDocumentTypes.includes(doc.documentType));
        
        // Then process additional materials
        const additionalDocuments = documents.filter(doc => !priorityDocumentTypes.includes(doc.documentType));
        
        // Process all documents, starting with priority ones
        const docsToProcess = [...priorityDocuments, ...additionalDocuments];
        console.log(`📚 [CONTENT] Processing ${priorityDocuments.length} priority docs and ${additionalDocuments.length} additional docs`);

        for (const docRef of docsToProcess) {
            if (docRef.documentId) {
                const fullDoc = await DocumentModel.getDocumentById(db, docRef.documentId);
                if (fullDoc && fullDoc.content && fullDoc.content.trim()) {
                    combinedContent += `\n\n--- ${fullDoc.originalName || 'Document'} ---\n${fullDoc.content}`;
                }
            }
        }
        
        if (!combinedContent.trim()) {
            return res.status(400).json({
                success: false,
                message: `No content found in documents for ${lectureName}`,
                data: {
                    hasMaterials: false,
                    content: null
                }
            });
        }
        
        // Handle content length intelligently
        const maxContentLength = 6000; // Optimized limit for better performance
        
        if (combinedContent.length > maxContentLength) {
            console.log(`📚 [CONTENT] Original content length: ${combinedContent.length} chars`);
            
            // Split content into sections
            const sections = combinedContent.split('---').filter(s => s.trim());
            console.log(`📚 [CONTENT] Found ${sections.length} sections`);
            
            // Sort sections: Priority docs first, then additional materials
            const prioritizedSections = sections.sort((a, b) => {
                const aIsPriority = a.includes('Lecture Notes') || a.includes('Practice Questions');
                const bIsPriority = b.includes('Lecture Notes') || b.includes('Practice Questions');
                if (aIsPriority && !bIsPriority) return -1;
                if (!aIsPriority && bIsPriority) return 1;
                return 0; // Keep original order for additional materials
            });
            
            console.log('📚 [CONTENT] Section types:', prioritizedSections.map(s => {
                if (s.includes('Lecture Notes')) return 'Lecture Notes';
                if (s.includes('Practice Questions')) return 'Practice Questions';
                return 'Additional Material';
            }));
            
            // Rebuild content with prioritized sections up to limit
            let newContent = '';
            let sectionsIncluded = 0;
            
            for (const section of prioritizedSections) {
                if ((newContent + section).length <= maxContentLength) {
                    newContent += '---' + section;
                    sectionsIncluded++;
                } else {
                    break;
                }
            }
            
            combinedContent = newContent.trim() + `\n\n[Content truncated: ${sectionsIncluded}/${sections.length} included]`;
            console.log(`📚 [CONTENT] Truncated to ${combinedContent.length} chars, included ${sectionsIncluded} sections`);
        }
        
        // Get the initialized LLM service from app.locals
        const llmService = req.app.locals.llm;
        if (!llmService) {
            return res.status(503).json({
                success: false,
                message: 'LLM service not available'
            });
        }
        
        try {
            // Format learning objectives for the prompt
            // For normal generation: randomly select ONE objective to ensure question variety.
            // Sending all objectives every time causes the LLM to gravitate toward the same one,
            // producing near-identical questions on repeat clicks.
            // For regeneration: pass all objectives so feedback-based improvements have full context.
            let formattedLearningObjectives = '';
            if (learningObjectives && learningObjectives.length > 0) {
                if (regenerate) {
                    formattedLearningObjectives = learningObjectives.map((obj, i) => `${i + 1}. ${obj}`).join('\n');
                } else {
                    const randomIndex = Math.floor(Math.random() * learningObjectives.length);
                    const selectedObjective = learningObjectives[randomIndex];
                    formattedLearningObjectives = `Focus on this learning objective:\n1. ${selectedObjective}`;
                    console.log(`[GENERATE] Randomly selected objective ${randomIndex + 1}/${learningObjectives.length}: "${selectedObjective}"`);
                }
            }

            console.log('🎯 [GENERATE] Learning objectives available:', formattedLearningObjectives ? 'Yes' : 'No');
            
            // Check for course-specific question prompts
            let customPrompts = null;
            if (course.questionPrompts) {
                console.log('📝 [GENERATE] Using course-specific question prompts');
                customPrompts = course.questionPrompts;
            }
            
            let generatedQuestion;
            
            if (regenerate) {
                console.log('🔄 [REGENERATE] Processing regeneration request with feedback:', feedback);
                
                // Call regenerate method with lower temperature and feedback
                generatedQuestion = await llmService.regenerateAssessmentQuestion(
                    questionType,
                    combinedContent,
                    lectureName,
                    formattedLearningObjectives,
                    previousQuestion,
                    feedback
                );
                
                console.log(`🔄 AI question regenerated successfully for ${lectureName}: ${questionType}`);
            } else {
                // Normal generation - pass custom prompts if available
                generatedQuestion = await llmService.generateAssessmentQuestion(
                    questionType, 
                    combinedContent, 
                    lectureName,
                    formattedLearningObjectives,
                    customPrompts  // Pass course-specific prompts (will be null if none set)
                );
                
                console.log(`🤖 AI question generated successfully for ${lectureName}: ${questionType}`);
            }
            
            res.json({
                success: true,
                message: 'AI question generated successfully',
                data: {
                    question: generatedQuestion.question,
                    answer: generatedQuestion.answer,
                    options: generatedQuestion.options || {},
                    questionType: questionType,
                    unitName: lectureName,
                    courseId: courseId,
                    aiGenerated: true,
                    timestamp: new Date().toISOString()
                }
            });
            
        } catch (llmError) {
            console.error('LLM service error:', llmError);
            
            // Provide specific error messages based on the type of error
            let errorMessage = 'Failed to generate AI question. Please try again.';
            let statusCode = 500;
            
            if (llmError.message.includes('timed out')) {
                errorMessage = 'AI question generation is taking longer than expected. This may be due to high server load. Please try again with a shorter document or try again later.';
                statusCode = 408; // Request Timeout
            } else if (llmError.message.includes('JSON')) {
                errorMessage = 'AI generated an invalid response format. Please try again.';
                statusCode = 422; // Unprocessable Entity
            } else if (llmError.message.includes('not initialized')) {
                errorMessage = 'AI service is not available. Please contact support.';
                statusCode = 503; // Service Unavailable
            }
            
            return res.status(statusCode).json({
                success: false,
                message: errorMessage,
                error: llmError.message,
                troubleshooting: {
                    suggestions: [
                        'Try again in a few moments',
                        'Ensure your course materials are not too lengthy',
                        'Check that all required services are running'
                    ]
                }
            });
        }
        
    } catch (error) {
        console.error('Error generating AI question:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while generating AI question',
            error: error.message
        });
    }
});

/**
 * POST /api/questions/bulk
 * Save multiple assessment questions at once (from LLM extraction)
 */
router.post('/bulk', async (req, res) => {
    try {
        const { courseId, lectureName, instructorId, questions } = req.body;

        if (!courseId || !lectureName || !instructorId || !Array.isArray(questions) || questions.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, instructorId, questions (array)'
            });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const results = [];
        let successCount = 0;

        for (const q of questions) {
            if (!q.question || !q.questionType || !q.correctAnswer) continue;

            const questionData = {
                questionType: q.questionType,
                question: q.question,
                options: q.options || {},
                correctAnswer: q.correctAnswer,
                explanation: q.explanation || '',
                difficulty: q.difficulty || 'medium',
                tags: q.tags || [],
                points: q.points || 1,
                metadata: {
                    source: 'ai-extracted',
                    aiGenerated: true,
                    reviewStatus: 'approved',
                    extractedFrom: q.extractedFrom || null
                }
            };

            const result = await CourseModel.updateAssessmentQuestions(
                db, courseId, lectureName, questionData, instructorId
            );

            if (result.success) {
                successCount++;
                results.push({ questionId: result.questionId, question: q.question });
            }
        }

        res.json({
            success: true,
            message: `${successCount} question${successCount === 1 ? '' : 's'} added to assessments`,
            data: { addedCount: successCount, questions: results }
        });

    } catch (error) {
        console.error('Error bulk saving questions:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while saving questions',
            error: error.message
        });
    }
});

module.exports = router;
