/**
 * Authentication Middleware
 * Handles session management and route protection
 */

const AuthService = require('../services/authService');
const { hasSystemAdminAccess } = require('../services/authorization');

/**
 * Initialize authentication middleware
 * @param {Object} db - MongoDB database instance
 * @returns {Object} Middleware functions
 */
function createAuthMiddleware(db) {
    const authService = new AuthService(db);

    /**
     * Middleware to check if user is authenticated
     * Works with Passport.js (checks req.user) and falls back to session-based auth
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    async function requireAuth(req, res, next) {
        console.log('🔐 [AUTH] Checking authentication for:', req.path);
        console.log('🔐 [AUTH] Passport user:', !!req.user);
        console.log('🔐 [AUTH] Session exists:', !!req.session);
        console.log('🔐 [AUTH] User ID:', req.user?.userId || req.session?.userId);
        
        // Check if user is authenticated via Passport (preferred method)
        if (req.user) {
            console.log('🔐 [AUTH] Authentication successful via Passport');
            // User is authenticated via Passport, continue
            next();
            return;
        }
        
        // Fallback: Check if user is in session (backward compatibility)
        if (req.session && req.session.userId) {
            console.log('🔐 [AUTH] Authentication successful via session (fallback)');

            try {
                const user = await authService.getUserById(req.session.userId);

                if (!user) {
                    req.session.destroy(() => {});

                    if (req.path.startsWith('/api/')) {
                        return res.status(401).json({
                            success: false,
                            error: 'User not found',
                            redirect: '/login'
                        });
                    }

                    return res.redirect('/login');
                }

                req.user = user;
                next();
                return;
            } catch (error) {
                console.error('Error hydrating session user:', error);

                if (req.path.startsWith('/api/')) {
                    return res.status(500).json({
                        success: false,
                        error: 'Authentication error'
                    });
                }

                return res.redirect('/login');
            }
        }
        
        // No authentication found
        console.log('🔐 [AUTH] Authentication failed - no user or session');
        
        // If it's an API request, return JSON error
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({
                success: false,
                error: 'Authentication required',
                redirect: '/login'
            });
        }
        
        // For page requests, redirect to login
        return res.redirect('/login');
    }

    /**
     * Middleware to check if user has specific role
     * Works with Passport.js (uses req.user) and falls back to session-based auth
     * @param {string} requiredRole - Required role ('instructor', 'student', or 'ta')
     * @returns {Function} Middleware function
     */
    function requireRole(requiredRole) {
        return async (req, res, next) => {
            try {
                let user = req.user;
                
                // If Passport hasn't populated req.user, try to get from session
                if (!user) {
                    if (!req.session || !req.session.userId) {
                        if (req.path.startsWith('/api/')) {
                            return res.status(401).json({
                                success: false,
                                error: 'Authentication required',
                                redirect: '/login'
                            });
                        }
                        return res.redirect('/login');
                    }

                    // Get user details from database
                    user = await authService.getUserById(req.session.userId);
                    if (!user) {
                        // User not found, clear session
                        req.session.destroy();
                        if (req.path.startsWith('/api/')) {
                            return res.status(401).json({
                                success: false,
                                error: 'User not found',
                                redirect: '/login'
                            });
                        }
                        return res.redirect('/login');
                    }
                    
                    // Set user in request for future use
                    req.user = user;
                }

                // Check role
                if (user.role !== requiredRole) {
                    if (req.path.startsWith('/api/')) {
                        return res.status(403).json({
                            success: false,
                            error: `Access denied. ${requiredRole} role required.`,
                            userRole: user.role
                        });
                    }
                    
                    // Redirect based on user's actual role
                    if (user.role === 'instructor') {
                        return res.redirect('/instructor');
                    } else if (user.role === 'student') {
                        return res.redirect('/student');
                    } else if (user.role === 'ta') {
                        return res.redirect('/ta');
                    } else {
                        return res.redirect('/login');
                    }
                }

                // User has required role, continue
                next();

            } catch (error) {
                console.error('Error in requireRole middleware:', error);
                if (req.path.startsWith('/api/')) {
                    return res.status(500).json({
                        success: false,
                        error: 'Authentication error'
                    });
                }
                return res.redirect('/login');
            }
        };
    }

    /**
     * Middleware to require instructor role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    async function requireInstructor(req, res, next) {
        return requireRole('instructor')(req, res, next);
    }

    /**
     * Middleware to require student role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    function requireStudent(req, res, next) {
        return requireRole('student')(req, res, next);
    }

    /**
     * Middleware to require TA role
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    function requireTA(req, res, next) {
        return requireRole('ta')(req, res, next);
    }

    /**
     * Middleware to require instructor or TA role (for shared instructor/TA pages)
     * Works with Passport.js (uses req.user) and falls back to session-based auth
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    async function requireInstructorOrTA(req, res, next) {
        try {
            let user = req.user;
            
            // If Passport hasn't populated req.user, try to get from session
            if (!user) {
                if (!req.session || !req.session.userId) {
                    if (req.path.startsWith('/api/')) {
                        return res.status(401).json({
                            success: false,
                            error: 'Authentication required',
                            redirect: '/login'
                        });
                    }
                    return res.redirect('/login');
                }

                // Get user details from database
                user = await authService.getUserById(req.session.userId);
                if (!user) {
                    // User not found, clear session
                    req.session.destroy();
                    if (req.path.startsWith('/api/')) {
                        return res.status(401).json({
                            success: false,
                            error: 'User not found',
                            redirect: '/login'
                        });
                    }
                    return res.redirect('/login');
                }
                
                // Set user in request for future use
                req.user = user;
            }

            // Check role - allow both instructor and TA
            if (user.role !== 'instructor' && user.role !== 'ta') {
                if (req.path.startsWith('/api/')) {
                    return res.status(403).json({
                        success: false,
                        error: 'Access denied. Instructor or TA role required.',
                        userRole: user.role
                    });
                }
                
                // Redirect based on user's actual role
                if (user.role === 'instructor') {
                    return res.redirect('/instructor');
                } else if (user.role === 'student') {
                    return res.redirect('/student');
                } else if (user.role === 'ta') {
                    return res.redirect('/ta');
                } else {
                    return res.redirect('/login');
                }
            }

            // User has required role, continue
            next();

        } catch (error) {
            console.error('Error in requireInstructorOrTA middleware:', error);
            if (req.path.startsWith('/api/')) {
                return res.status(500).json({
                    success: false,
                    error: 'Authentication error'
                });
            }
            return res.redirect('/login');
        }
    }

    /**
     * Middleware to require platform system admin access.
     */
    async function requireSystemAdmin(req, res, next) {
        try {
            let user = req.user;

            if (!user) {
                if (!req.session || !req.session.userId) {
                    if (req.path.startsWith('/api/')) {
                        return res.status(401).json({
                            success: false,
                            error: 'Authentication required',
                            redirect: '/login'
                        });
                    }
                    return res.redirect('/login');
                }

                user = await authService.getUserById(req.session.userId);
                if (!user) {
                    req.session.destroy();
                    if (req.path.startsWith('/api/')) {
                        return res.status(401).json({
                            success: false,
                            error: 'User not found',
                            redirect: '/login'
                        });
                    }
                    return res.redirect('/login');
                }

                req.user = user;
            }

            if (!hasSystemAdminAccess(user)) {
                if (req.path.startsWith('/api/')) {
                    return res.status(403).json({
                        success: false,
                        error: 'Access denied. System admin access required.'
                    });
                }

                return res.redirect('/instructor/home');
            }

            next();
        } catch (error) {
            console.error('Error in requireSystemAdmin middleware:', error);
            if (req.path.startsWith('/api/')) {
                return res.status(500).json({
                    success: false,
                    error: 'Authentication error'
                });
            }
            return res.redirect('/login');
        }
    }

    /**
     * Middleware to populate user data in request
     * Works with Passport.js (req.user is already populated) and falls back to session
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    async function populateUser(req, res, next) {
        try {
            // If Passport has already populated req.user, use it
            if (req.user) {
                next();
                return;
            }
            
            // Fallback: Populate from session if available
            if (req.session && req.session.userId) {
                const user = await authService.getUserById(req.session.userId);
                if (user) {
                    req.user = user;
                } else {
                    // User not found, clear session
                    req.session.destroy();
                }
            }
            next();
        } catch (error) {
            console.error('Error in populateUser middleware:', error);
            next();
        }
    }

    /**
     * Middleware to check if user is already authenticated
     * Redirects authenticated users away from login page
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    function redirectIfAuthenticated(req, res, next) {
        if (req.session && req.session.userId) {
            // User is already authenticated, redirect to appropriate dashboard
            const userRole = req.session.userRole;
            if (userRole === 'instructor') {
                return res.redirect('/instructor');
            } else if (userRole === 'student') {
                return res.redirect('/student');
            } else if (userRole === 'ta') {
                return res.redirect('/ta');
            }
        }
        next();
    }

    /**
     * Middleware to ensure user has a course context (for instructors)
     * @param {Object} req - Express request object
     * @param {Object} res - Express response object
     * @param {Function} next - Express next function
     */
    async function requireCourseContext(req, res, next) {
        try {
            if (!req.user) {
                return res.redirect('/login');
            }

            // Only apply to instructor routes that need course context
            if (req.user.role === 'instructor') {
                const courseId = authService.getCurrentCourseId(req.user);
                if (!courseId) {
                    // No course context, redirect to onboarding or course selection
                    return res.redirect('/instructor/onboarding');
                }
                
                // Add course context to request
                req.courseId = courseId;
            }

            next();
        } catch (error) {
            console.error('Error in requireCourseContext middleware:', error);
            next();
        }
    }

    /**
     * Middleware to check TA permissions for specific features
     * @param {string} feature - Feature to check ('courses' or 'flags')
     */
    function requireTAPermission(feature) {
        return async (req, res, next) => {
            try {
                // Only apply to TAs
                if (req.user.role !== 'ta') {
                    return next();
                }

                const taId = req.user.userId;
                let courseId = req.query.courseId ||
                    (req.body && req.body.courseId) ||
                    (req.params && req.params.courseId) ||
                    req.user.preferences?.courseId;

                if (!courseId) {
                    const CourseModel = require('../models/Course');
                    const courses = await CourseModel.getCoursesForUser(db, taId, 'ta');

                    if (courses.length === 1) {
                        courseId = courses[0].courseId;
                    }
                }

                if (!courseId) {
                    if (!req.path.startsWith('/api/')) {
                        return res.redirect('/ta');
                    }

                    return res.status(400).json({
                        success: false,
                        message: 'Course ID is required to check TA permissions'
                    });
                }

                // Import CourseModel here to avoid circular dependency
                const CourseModel = require('../models/Course');

                // Check if TA has permission for this feature
                const hasPermission = await CourseModel.checkTAPermission(db, courseId, taId, feature);
                
                if (!hasPermission) {
                    const featureName = feature === 'courses' ? 'My Courses' : 'Flagged Content';
                    return res.status(403).json({
                        success: false,
                        message: `Access denied. You do not have permission to access ${featureName}. Contact your instructor.`
                    });
                }

                next();
            } catch (error) {
                console.error('Error checking TA permission:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Error checking permissions'
                });
            }
        };
    }

    /**
     * Middleware to require that a student is enrolled in the course
     * If the user is not a student, this is a no-op.
     * Attempts to infer courseId from body, query, or params.
     */
    async function requireStudentEnrolled(req, res, next) {
        try {
            // Only enforce for students
            if (!req.user || req.user.role !== 'student') {
                return next();
            }

            // Try to infer courseId
            const courseId = (req.body && req.body.courseId) || req.query.courseId || req.params.courseId;
            if (!courseId) {
                // If we cannot determine course context, allow through
                // (endpoints without course context shouldn't be blocked here)
                return next();
            }

            // Import CourseModel lazily
            const CourseModel = require('../models/Course');

            // Default behavior: enrolled unless explicitly disabled in course settings
            const result = await CourseModel.getStudentEnrollment(db, courseId, req.user.userId);

            if (!result.success) {
                return res.status(404).json({
                    success: false,
                    message: 'Course not found'
                });
            }

            if (result.enrolled === false) {
                const isCourseInactive = result.reason === 'course_inactive';
                return res.status(403).json({
                    success: false,
                    message: isCourseInactive
                        ? 'This course is currently deactivated by the instructor.'
                        : 'Your access to this course is disabled by the instructor.'
                });
            }

            next();
        } catch (error) {
            console.error('Error in requireStudentEnrolled middleware:', error);
            return res.status(500).json({
                success: false,
                message: 'Enrollment check failed'
            });
        }
    }

    /**
     * Middleware to block students from using inactive courses.
     * Instructors and TAs can still access inactive courses so they can manage/reactivate them.
     * Attempts to infer courseId from body, query, or params.
     */
    async function requireActiveCourseForNonInstructors(req, res, next) {
        try {
            if (!req.user || req.user.role === 'instructor' || req.user.role === 'ta') {
                return next();
            }

            // Allow students to inspect enrollment status for a stale/deactivated course
            if (req.user.role === 'student' && req.method === 'GET' && req.path.endsWith('/student-enrollment')) {
                return next();
            }

            const courseId = (req.body && req.body.courseId) || req.query.courseId || req.params.courseId;
            if (!courseId) {
                return next();
            }

            const CourseModel = require('../models/Course');
            const course = await CourseModel.getCourseById(db, courseId);

            if (!course) {
                return next();
            }

            if (course.status === 'inactive' || course.status === 'deleted') {
                return res.status(403).json({
                    success: false,
                    message: 'This course is currently deactivated by the instructor.'
                });
            }

            next();
        } catch (error) {
            console.error('Error in requireActiveCourseForNonInstructors middleware:', error);
            return res.status(500).json({
                success: false,
                message: 'Course access check failed'
            });
        }
    }

    return {
        requireAuth,
        requireRole,
        requireInstructor,
        requireStudent,
        requireTA,
        requireInstructorOrTA,
        requireSystemAdmin,
        populateUser,
        redirectIfAuthenticated,
        requireCourseContext,
        requireTAPermission,
        requireStudentEnrolled,
        requireActiveCourseForNonInstructors,
        authService
    };
}

module.exports = createAuthMiddleware;
