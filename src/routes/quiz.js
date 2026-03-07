/**
 * Quiz Practice Routes
 * Student-facing API for the self-paced quiz practice page
 */

const express = require('express');
const path = require('path');
const router = express.Router();
const CourseModel = require('../models/Course');
const QuizAttempt = require('../models/QuizAttempt');
const DocumentModel = require('../models/Document');
const QdrantService = require('../services/qdrantService');
const prompts = require('../services/prompts');
const profanityCleaner = require('profanity-cleaner');

router.use(express.json());

function inferExtensionFromMimeType(mimeType) {
    switch ((mimeType || '').toLowerCase()) {
        case 'application/pdf':
            return '.pdf';
        case 'text/markdown':
            return '.md';
        case 'application/msword':
            return '.doc';
        case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            return '.docx';
        case 'application/rtf':
            return '.rtf';
        case 'text/plain':
            return '.txt';
        default:
            return '';
    }
}

function resolveDownloadFilename(document) {
    const fallbackName = `quiz-material-${document.documentId || Date.now()}`;
    const rawOriginal = (document.originalName || '').trim();
    const rawFile = (document.filename || '').trim();
    const preferredName = rawOriginal || rawFile || fallbackName;
    let safeName = path.basename(preferredName).replace(/[\r\n]/g, '');

    if (!path.extname(safeName)) {
        if (rawFile && path.extname(rawFile)) {
            safeName = path.basename(rawFile).replace(/[\r\n]/g, '');
        } else {
            safeName += inferExtensionFromMimeType(document.mimeType);
        }
    }

    return safeName || `${fallbackName}.txt`;
}

function setAttachmentHeaders(res, filename) {
    const encodedName = encodeURIComponent(filename);
    const asciiFallback = filename.replace(/[^\x20-\x7E]/g, '_').replace(/"/g, '');
    res.setHeader(
        'Content-Disposition',
        `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encodedName}`
    );
}

/**
 * GET /api/quiz/status
 * Lightweight check: is the quiz page enabled for this course?
 */
router.get('/status', async (req, res) => {
    try {
        const { courseId } = req.query;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const settings = await CourseModel.getQuizSettings(db, courseId);
        res.json({ success: true, enabled: settings.enabled });
    } catch (error) {
        console.error('Error checking quiz status:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * GET /api/quiz/questions
 * Get all quiz-eligible questions for the student's course
 */
router.get('/questions', async (req, res) => {
    try {
        const { courseId } = req.query;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check quiz settings
        const settings = await CourseModel.getQuizSettings(db, courseId);
        if (!settings.enabled) {
            return res.status(403).json({ success: false, message: 'Quiz practice is not enabled for this course' });
        }

        // getPublishedLectures returns an array of lecture name strings
        const publishedNames = await CourseModel.getPublishedLectures(db, courseId);
        if (!publishedNames || publishedNames.length === 0) {
            return res.json({ success: true, questions: [], units: [], allowLectureMaterialAccess: settings.allowLectureMaterialAccess });
        }

        // Get full course for display names
        const course = await CourseModel.getCourseWithOnboarding(db, courseId);
        const lecturesMap = {};
        if (course && course.lectures) {
            for (const lec of course.lectures) {
                lecturesMap[lec.name] = lec;
            }
        }

        // Filter to testable units only
        let testableNames;
        if (settings.testableUnits === 'all') {
            testableNames = publishedNames;
        } else {
            testableNames = publishedNames.filter(name => settings.testableUnits.includes(name));
        }

        // Gather questions from each testable unit
        const allQuestions = [];
        for (const unitName of testableNames) {
            const questions = await CourseModel.getAssessmentQuestions(db, courseId, unitName);
            if (questions && questions.length > 0) {
                for (const q of questions) {
                    if (q.isActive === false) continue; // skip soft-deleted

                    const sanitized = {
                        questionId: q.questionId,
                        lectureName: unitName,
                        questionType: q.questionType,
                        question: q.question,
                        options: q.options || {},
                        difficulty: q.difficulty || 'medium',
                        tags: q.tags || [],
                        points: q.points || 1
                    };

                    // MC/TF: include correctAnswer for client-side checking
                    if (q.questionType === 'multiple-choice' || q.questionType === 'true-false') {
                        sanitized.correctAnswer = q.correctAnswer;
                    }
                    // Short-answer: no correctAnswer sent (AI evaluates server-side)

                    allQuestions.push(sanitized);
                }
            }
        }

        // Build unit list with display names
        const units = testableNames.map(name => {
            const lecture = lecturesMap[name];
            return {
                name,
                displayName: lecture?.displayName || name
            };
        });

        res.json({
            success: true,
            questions: allQuestions,
            units,
            allowLectureMaterialAccess: settings.allowLectureMaterialAccess
        });
    } catch (error) {
        console.error('Error fetching quiz questions:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * POST /api/quiz/check-answer
 * AI evaluation for short-answer questions
 * Looks up the correct answer server-side so it's never exposed to the client
 */
router.post('/check-answer', async (req, res) => {
    try {
        const { courseId, questionId, lectureName, studentAnswer, studentName } = req.body;

        if (!courseId || !questionId || !lectureName || !studentAnswer) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, questionId, lectureName, studentAnswer'
            });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Look up the question to get the correct answer server-side
        const questions = await CourseModel.getAssessmentQuestions(db, courseId, lectureName);
        const question = questions.find(q => q.questionId === questionId);
        if (!question) {
            return res.status(404).json({ success: false, message: 'Question not found' });
        }

        const llmService = req.app.locals.llm;
        if (!llmService) {
            return res.status(503).json({ success: false, message: 'LLM service not available' });
        }

        const result = await llmService.evaluateStudentAnswer(
            question.question,
            studentAnswer,
            question.correctAnswer,
            question.questionType,
            studentName || 'Student'
        );

        res.json({ success: true, data: result });
    } catch (error) {
        console.error('Error checking quiz answer:', error);
        res.status(500).json({ success: false, message: 'Internal server error while checking answer' });
    }
});

/**
 * POST /api/quiz/attempt
 * Record a quiz attempt
 */
router.post('/attempt', async (req, res) => {
    try {
        const { courseId, questionId, lectureName, questionType, studentAnswer, correct, feedback } = req.body;

        if (!courseId || !questionId || !lectureName || !questionType || studentAnswer === undefined || correct === undefined) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const studentId = req.user ? req.user.userId : null;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        const result = await QuizAttempt.saveAttempt(db, {
            studentId,
            courseId,
            questionId,
            lectureName,
            questionType,
            studentAnswer: String(studentAnswer),
            correct: Boolean(correct),
            feedback: feedback || ''
        });

        res.json({ success: true, attemptId: result.attemptId });
    } catch (error) {
        console.error('Error recording quiz attempt:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * GET /api/quiz/history
 * Get student's quiz attempt stats
 */
router.get('/history', async (req, res) => {
    try {
        const { courseId } = req.query;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const studentId = req.user ? req.user.userId : null;
        if (!studentId) {
            return res.status(401).json({ success: false, message: 'User not authenticated' });
        }

        const stats = await QuizAttempt.getAttemptStats(db, studentId, courseId);
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Error fetching quiz history:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * GET /api/quiz/materials
 * Get documents for a unit (when student answers incorrectly)
 */
router.get('/materials', async (req, res) => {
    try {
        const { courseId, lectureName } = req.query;
        if (!courseId || !lectureName) {
            return res.status(400).json({ success: false, message: 'Missing courseId or lectureName' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check if material access is allowed
        const settings = await CourseModel.getQuizSettings(db, courseId);
        if (!settings.allowLectureMaterialAccess) {
            return res.status(403).json({ success: false, message: 'Lecture material access is not enabled' });
        }

        const documents = await DocumentModel.getDocumentsForLecture(db, courseId, lectureName);

        const materials = (documents || []).map(doc => ({
            documentId: doc.documentId,
            originalName: doc.originalName || doc.filename,
            mimeType: doc.mimeType,
            size: doc.size,
            documentType: doc.documentType
        }));

        res.json({ success: true, materials });
    } catch (error) {
        console.error('Error fetching quiz materials:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * GET /api/quiz/materials/:documentId/download
 * Download a specific document
 */
router.get('/materials/:documentId/download', async (req, res) => {
    try {
        const { documentId } = req.params;
        const { courseId } = req.query;

        if (!documentId || !courseId) {
            return res.status(400).json({ success: false, message: 'Missing documentId or courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        // Check if material access is allowed
        const settings = await CourseModel.getQuizSettings(db, courseId);
        if (!settings.allowLectureMaterialAccess) {
            return res.status(403).json({ success: false, message: 'Lecture material access is not enabled' });
        }

        const document = await DocumentModel.getDocumentById(db, documentId);
        if (!document || document.courseId !== courseId) {
            return res.status(404).json({ success: false, message: 'Document not found' });
        }

        const downloadFilename = resolveDownloadFilename(document);
        setAttachmentHeaders(res, downloadFilename);

        if (document.contentType === 'file' && document.fileData) {
            const payload = Buffer.isBuffer(document.fileData)
                ? document.fileData
                : (document.fileData.buffer ? Buffer.from(document.fileData.buffer) : null);

            if (!payload) {
                return res.status(500).json({ success: false, message: 'Stored file data is invalid' });
            }

            res.setHeader('Content-Type', document.mimeType || 'application/octet-stream');
            return res.send(payload);
        }

        const textContent = typeof document.content === 'string' ? document.content : '';
        res.setHeader('Content-Type', `${document.mimeType || 'text/plain'}; charset=utf-8`);
        return res.send(textContent);
    } catch (error) {
        console.error('Error downloading quiz material:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

/**
 * POST /api/quiz/chat
 * Quiz-specific help chat - scoped to a single question and its lecture unit
 */
router.post('/chat', async (req, res) => {
    try {
        const {
            message,
            courseId,
            lectureName,
            questionText,
            questionType,
            correctAnswer,
            studentAnswer,
            conversationHistory
        } = req.body;

        // Validation
        if (!message || !courseId || !lectureName || !questionText) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: message, courseId, lectureName, questionText'
            });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const llmService = req.app.locals.llm;
        if (!llmService) {
            return res.status(503).json({ success: false, message: 'LLM service not available' });
        }

        // Profanity filter
        const cleanedMessage = profanityCleaner && typeof profanityCleaner.clean === 'function'
            ? profanityCleaner.clean(message)
            : message;

        if (cleanedMessage !== message) {
            return res.json({
                success: true,
                message: 'Please keep the language appropriate. This is an educational tool.',
                source: 'system'
            });
        }

        // Safety check
        const safetyKeywords = ['suicide', 'kill myself', 'want to die', 'end my life', 'ending it all'];
        if (safetyKeywords.some(kw => message.toLowerCase().includes(kw))) {
            return res.json({
                success: true,
                message: "I'm sorry you're feeling this way. Please reach out to the UBC Wellness Centre: http://students.ubc.ca/health/wellness-centre/",
                source: 'system'
            });
        }

        // For short-answer questions, look up the correct answer server-side
        let actualCorrectAnswer = correctAnswer || '';
        if (questionType === 'short-answer' && (!correctAnswer || correctAnswer.includes('[evaluated by AI'))) {
            try {
                const course = await db.collection('courses').findOne({ courseId });
                if (course && course.lectures) {
                    for (const lecture of course.lectures) {
                        if (lecture.name === lectureName && lecture.assessmentQuestions) {
                            const matchedQ = lecture.assessmentQuestions.find(q => q.question === questionText);
                            if (matchedQ && matchedQ.correctAnswer) {
                                actualCorrectAnswer = matchedQ.correctAnswer;
                            }
                            break;
                        }
                    }
                }
            } catch (e) {
                console.error('Could not look up short-answer correct answer:', e);
            }
        }

        // RAG Retrieval (single unit only)
        let contextText = '';
        try {
            const qdrant = new QdrantService();
            await qdrant.initialize();

            const searchResults = await qdrant.searchDocuments(
                message,
                { courseId, lectureNames: [lectureName] },
                6
            );

            if (searchResults && searchResults.length > 0) {
                contextText = searchResults
                    .map(r => `From ${r.lectureName} (${r.fileName}):\n${r.chunkText}`)
                    .join('\n\n---\n\n');
            }
        } catch (qdrantError) {
            console.error('Quiz chat RAG error:', qdrantError.message);
        }

        // Build the question context block
        const questionContext = `QUIZ QUESTION CONTEXT:
Question: ${questionText}
Question Type: ${questionType}
Correct Answer: ${actualCorrectAnswer}
Student's Answer: ${studentAnswer}
Lecture Unit: ${lectureName}`;

        // Build conversation history block
        let conversationBlock = '';
        if (conversationHistory && conversationHistory.length > 0) {
            conversationBlock = '\nPrevious conversation:\n';
            conversationHistory.forEach(msg => {
                const speaker = msg.role === 'user' ? 'Student' : 'BiocBot';
                conversationBlock += `${speaker}: ${msg.content}\n\n`;
            });
        }

        const messageToSend = `${questionContext}

Course context (from ${lectureName}):
${contextText || 'No specific course materials retrieved for this query.'}
${conversationBlock}
Student's new message: ${message}`;

        // Load course-specific or default prompts
        const course = await db.collection('courses').findOne({ courseId });
        let basePrompt = prompts.DEFAULT_PROMPTS.base;
        let quizHelpPrompt = prompts.DEFAULT_PROMPTS.quizHelp;

        if (course && course.prompts) {
            if (course.prompts.base) basePrompt = course.prompts.base;
            if (course.prompts.quizHelp) quizHelpPrompt = course.prompts.quizHelp;
        }

        // Call LLM
        const response = await llmService.sendMessage(messageToSend, {
            temperature: 0.5,
            maxTokens: 1024,
            systemPrompt: basePrompt + '\n\n' + quizHelpPrompt
        });

        const responseText = response && response.content
            ? response.content
            : 'Sorry, I could not generate a response. Please try again.';

        res.json({
            success: true,
            message: responseText,
            source: 'quiz-help'
        });

    } catch (error) {
        console.error('Error in quiz chat endpoint:', error);
        res.status(500).json({
            success: false,
            message: 'Sorry, I encountered an error. Please try again.'
        });
    }
});

module.exports = router;
