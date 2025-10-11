/**
 * Students API Routes
 * Handles student data and saved chat sessions for instructors
 */

const express = require('express');
const router = express.Router();

// Middleware to parse JSON bodies
router.use(express.json());

/**
 * GET /api/students/:courseId
 * Get all students who have saved chat sessions for a specific course
 */
router.get('/:courseId', async (req, res) => {
    try {
        const { courseId } = req.params;
        
        // Get authenticated user information
        const user = req.user;
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        // Only instructors can access student data
        if (user.role !== 'instructor') {
            return res.status(403).json({
                success: false,
                message: 'Only instructors can access student data'
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
        
        // Verify the instructor has access to this course
        const coursesCollection = db.collection('courses');
        const course = await coursesCollection.findOne({ 
            courseId: courseId, 
            instructorId: user.userId 
        });
        
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found or access denied'
            });
        }
        
        // Get saved chat sessions for this course (excluding soft deleted)
        const chatSessionsCollection = db.collection('chat_sessions');
        const chatSessions = await chatSessionsCollection.find({ 
            courseId: courseId,
            $or: [
                { isDeleted: { $exists: false } }, // Legacy sessions without isDeleted field
                { isDeleted: false } // Non-deleted sessions
            ]
        }).sort({ savedAt: -1 }).toArray();
        
        // Group chat sessions by student
        const studentsMap = new Map();
        
        chatSessions.forEach(session => {
            
            const studentId = session.studentId;
            let studentName = session.studentName || 'Unknown Student';
            
            // If studentName is an object, try to extract the actual name
            if (typeof studentName === 'object' && studentName !== null) {
                studentName = studentName.displayName || 
                             studentName.name || 
                             studentName.studentName || 
                             'Unknown Student';
            }
            
            // Ensure studentName is a string
            if (typeof studentName !== 'string') {
                studentName = 'Unknown Student';
            }
            
            if (!studentsMap.has(studentId)) {
                studentsMap.set(studentId, {
                    studentId: studentId,
                    studentName: studentName,
                    courseId: courseId,
                    courseName: course.courseName,
                    totalSessions: 0,
                    lastActivity: null,
                    sessions: []
                });
            }
            
            const student = studentsMap.get(studentId);
            student.totalSessions++;
            student.sessions.push({
                sessionId: session.sessionId,
                title: session.title || `Chat Session ${student.totalSessions}`,
                unitName: session.unitName,
                savedAt: session.savedAt,
                messageCount: session.messageCount || 0,
                duration: session.duration || 'Unknown'
            });
            
            // Update last activity
            if (!student.lastActivity || new Date(session.savedAt) > new Date(student.lastActivity)) {
                student.lastActivity = session.savedAt;
            }
        });
        
        // Convert map to array and sort by last activity
        const students = Array.from(studentsMap.values()).sort((a, b) => 
            new Date(b.lastActivity) - new Date(a.lastActivity)
        );
        
        console.log(`Retrieved ${students.length} students with saved chats for course ${courseId}`);
        
        res.json({
            success: true,
            data: {
                courseId: courseId,
                courseName: course.courseName,
                students: students,
                totalStudents: students.length,
                totalSessions: chatSessions.length
            }
        });
        
    } catch (error) {
        console.error('Error fetching students:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching students'
        });
    }
});

/**
 * GET /api/students/:courseId/:studentId/sessions
 * Get all saved chat sessions for a specific student in a course
 */
router.get('/:courseId/:studentId/sessions', async (req, res) => {
    try {
        const { courseId, studentId } = req.params;
        
        // Get authenticated user information
        const user = req.user;
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        // Only instructors can access student data
        if (user.role !== 'instructor') {
            return res.status(403).json({
                success: false,
                message: 'Only instructors can access student data'
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
        
        // Verify the instructor has access to this course
        const coursesCollection = db.collection('courses');
        const course = await coursesCollection.findOne({ 
            courseId: courseId, 
            instructorId: user.userId 
        });
        
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found or access denied'
            });
        }
        
        // Get all chat sessions for this student in this course (excluding soft deleted)
        const chatSessionsCollection = db.collection('chat_sessions');
        const sessions = await chatSessionsCollection.find({ 
            courseId: courseId,
            studentId: studentId,
            $or: [
                { isDeleted: { $exists: false } }, // Legacy sessions without isDeleted field
                { isDeleted: false } // Non-deleted sessions
            ]
        }).sort({ savedAt: -1 }).toArray();
        
        console.log(`Retrieved ${sessions.length} sessions for student ${studentId} in course ${courseId}`);
        
        res.json({
            success: true,
            data: {
                courseId: courseId,
                studentId: studentId,
                studentName: sessions[0]?.studentName || 'Unknown Student',
                sessions: sessions
            }
        });
        
    } catch (error) {
        console.error('Error fetching student sessions:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching student sessions'
        });
    }
});

/**
 * GET /api/students/:courseId/:studentId/sessions/:sessionId
 * Get a specific chat session data for download
 */
router.get('/:courseId/:studentId/sessions/:sessionId', async (req, res) => {
    try {
        const { courseId, studentId, sessionId } = req.params;
        
        // Get authenticated user information
        const user = req.user;
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }
        
        // Only instructors can access student data
        if (user.role !== 'instructor') {
            return res.status(403).json({
                success: false,
                message: 'Only instructors can access student data'
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
        
        // Verify the instructor has access to this course
        const coursesCollection = db.collection('courses');
        const course = await coursesCollection.findOne({ 
            courseId: courseId, 
            instructorId: user.userId 
        });
        
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found or access denied'
            });
        }
        
        // Get the specific chat session (excluding soft deleted)
        const chatSessionsCollection = db.collection('chat_sessions');
        const session = await chatSessionsCollection.findOne({ 
            courseId: courseId,
            studentId: studentId,
            sessionId: sessionId,
            $or: [
                { isDeleted: { $exists: false } }, // Legacy sessions without isDeleted field
                { isDeleted: false } // Non-deleted sessions
            ]
        });
        
        if (!session) {
            return res.status(404).json({
                success: false,
                message: 'Chat session not found'
            });
        }
        
        console.log(`Retrieved chat session ${sessionId} for student ${studentId}`);
        
        res.json({
            success: true,
            data: session
        });
        
    } catch (error) {
        console.error('Error fetching chat session:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching chat session'
        });
    }
});

/**
 * DELETE /api/students/:courseId/:studentId/sessions/:sessionId
 * Delete a specific chat session for a student
 */
router.delete('/:courseId/:studentId/sessions/:sessionId', async (req, res) => {
    try {
        const { courseId, studentId, sessionId } = req.params;
        
        if (!courseId || !studentId || !sessionId) {
            return res.status(400).json({
                success: false,
                error: 'Course ID, Student ID, and Session ID are required'
            });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(500).json({
                success: false,
                error: 'Database connection not available'
            });
        }

        const chatSessionsCollection = db.collection('chat_sessions');
        
        // Find the session to ensure it belongs to the student and is not already deleted
        const session = await chatSessionsCollection.findOne({
            sessionId: sessionId,
            courseId: courseId,
            studentId: studentId,
            $or: [
                { isDeleted: { $exists: false } }, // Legacy sessions without isDeleted field
                { isDeleted: false } // Non-deleted sessions
            ]
        });

        if (!session) {
            return res.status(404).json({
                success: false,
                error: 'Chat session not found or does not belong to this student'
            });
        }

        // Soft delete the session by setting isDeleted to true
        const result = await chatSessionsCollection.updateOne({
            sessionId: sessionId,
            courseId: courseId,
            studentId: studentId
        }, {
            $set: {
                isDeleted: true,
                deletedAt: new Date()
            }
        });

        if (result.matchedCount === 0) {
            return res.status(404).json({
                success: false,
                error: 'Chat session not found'
            });
        }

        console.log(`Soft deleted chat session ${sessionId} for student ${studentId} in course ${courseId}`);

        res.json({
            success: true,
            message: 'Chat session deleted successfully',
            data: { sessionId, courseId, studentId }
        });

    } catch (error) {
        console.error('Error deleting chat session:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete chat session'
        });
    }
});

module.exports = router;
