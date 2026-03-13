/**
 * Authentication Service
 * Handles user authentication, session management, and role-based access control
 * Supports both basic authentication and future SAML integration
 */

const User = require('../models/User');

/**
 * Authentication Service Class
 * Provides methods for user authentication and session management
 */
class AuthService {
    constructor(db) {
        this.db = db;
    }

    /**
     * Create a new user account
     * @param {Object} userData - User registration data
     * @returns {Promise<Object>} Registration result
     */
    async registerUser(userData) {
        try {
            // Validate required fields
            if (!userData.username || !userData.password || !userData.role) {
                return {
                    success: false,
                    error: 'Username, password, and role are required'
                };
            }

            // Validate role
            if (!['instructor', 'student', 'ta'].includes(userData.role)) {
                return {
                    success: false,
                    error: 'Role must be "instructor", "student", or "ta"'
                };
            }

            // Validate email format if provided
            if (userData.email && !this.isValidEmail(userData.email)) {
                return {
                    success: false,
                    error: 'Invalid email format'
                };
            }

            const result = await User.createUser(this.db, userData);
            return result;

        } catch (error) {
            console.error('Error in registerUser:', error);
            return {
                success: false,
                error: 'Registration failed. Please try again.'
            };
        }
    }

    /**
     * Get user by ID
     * @param {string} userId - User identifier
     * @returns {Promise<Object>} User object or null
     */
    async getUserById(userId) {
        try {
            if (!userId) {
                return null;
            }

            return await User.getUserById(this.db, userId);

        } catch (error) {
            console.error('Error in getUserById:', error);
            return null;
        }
    }

    /**
     * Update user preferences
     * @param {string} userId - User identifier
     * @param {Object} preferences - New preferences
     * @returns {Promise<Object>} Update result
     */
    async updateUserPreferences(userId, preferences) {
        try {
            if (!userId) {
                return {
                    success: false,
                    error: 'User ID is required'
                };
            }

            return await User.updateUserPreferences(this.db, userId, preferences);

        } catch (error) {
            console.error('Error in updateUserPreferences:', error);
            return {
                success: false,
                error: 'Failed to update preferences'
            };
        }
    }

    /**
     * Validate email format
     * @param {string} email - Email address to validate
     * @returns {boolean} True if valid email format
     */
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Check if user has required role
     * @param {Object} user - User object
     * @param {string} requiredRole - Required role
     * @returns {boolean} True if user has required role
     */
    hasRole(user, requiredRole) {
        if (!user || !user.role) {
            return false;
        }
        return user.role === requiredRole;
    }

    /**
     * Check if user is instructor
     * @param {Object} user - User object
     * @returns {boolean} True if user is instructor
     */
    isInstructor(user) {
        return this.hasRole(user, 'instructor');
    }

    /**
     * Check if user is student
     * @param {Object} user - User object
     * @returns {boolean} True if user is student
     */
    isStudent(user) {
        return this.hasRole(user, 'student');
    }

    /**
     * Get user's current course context
     * @param {Object} user - User object
     * @returns {string|null} Current course ID or null
     */
    getCurrentCourseId(user) {
        if (!user || !user.preferences) {
            return null;
        }
        return user.preferences.courseId || null;
    }

    /**
     * Set user's current course context
     * @param {string} userId - User identifier
     * @param {string} courseId - Course identifier
     * @returns {Promise<Object>} Update result
     */
    async setCurrentCourseId(userId, courseId) {
        try {
            const user = await this.getUserById(userId);
            if (!user) {
                return {
                    success: false,
                    error: 'User not found'
                };
            }

            const preferences = {
                ...user.preferences,
                courseId: courseId
            };

            return await this.updateUserPreferences(userId, preferences);

        } catch (error) {
            console.error('Error in setCurrentCourseId:', error);
            return {
                success: false,
                error: 'Failed to update course context'
            };
        }
    }

    /**
     * Create a session-safe user object (removes sensitive data)
     * @param {Object} user - Full user object
     * @returns {Object} Session-safe user object
     */
    createSessionUser(user) {
        if (!user) {
            return null;
        }

        return {
            userId: user.userId,
            username: user.username,
            email: user.email,
            role: user.role,
            displayName: user.displayName,
            authProvider: user.authProvider,
            preferences: user.preferences
        };
    }

    /**
     * Initialize default users for development/testing
     * @returns {Promise<Object>} Initialization result
     */
    async initializeDefaultUsers() {
        try {
            console.log('🔐 Initializing default users...');

            // Check if users already exist
            const existingUsers = await User.getUsersByRole(this.db, 'instructor');
            if (existingUsers.length > 0) {
                console.log('✅ Default users already exist');
                return { success: true, message: 'Default users already exist' };
            }

            // Create default instructor
            const instructorResult = await this.registerUser({
                username: 'instructor',
                password: 'password123',
                email: 'instructor@ubc.ca',
                role: 'instructor',
                displayName: 'Default Instructor'
            });

            if (!instructorResult.success) {
                console.error('Failed to create default instructor:', instructorResult.error);
                return { success: false, error: 'Failed to create default instructor' };
            }

            // Create default student
            const studentResult = await this.registerUser({
                username: 'student',
                password: 'password123',
                email: 'student@ubc.ca',
                role: 'student',
                displayName: 'Default Student'
            });

            if (!studentResult.success) {
                console.error('Failed to create default student:', studentResult.error);
                return { success: false, error: 'Failed to create default student' };
            }

            console.log('✅ Default users created successfully');
            console.log('   Instructor: instructor / password123');
            console.log('   Student: student / password123');

            return {
                success: true,
                message: 'Default users created successfully',
                users: {
                    instructor: instructorResult.userId,
                    student: studentResult.userId
                }
            };

        } catch (error) {
            console.error('Error initializing default users:', error);
            return {
                success: false,
                error: 'Failed to initialize default users'
            };
        }
    }
}

module.exports = AuthService;
