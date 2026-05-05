/**
 * Common Authentication Script
 * Handles user authentication state and logout functionality
 */

let currentUser = null;

/**
 * Initialize authentication for the page
 */
async function initAuth() {
    try {
        // Get current user information
        const response = await fetch('/api/auth/me');
        const result = await response.json();
        
        if (result.success && result.user) {
            currentUser = result.user;
            updateUserDisplay();
            adjustNavigationForRole();
            setupLogoutHandler();
            // Notify listeners that auth/user state is ready
            try {
                document.dispatchEvent(new CustomEvent('auth:ready', { detail: currentUser }));
            } catch (e) {
                console.warn('auth:ready event dispatch failed', e);
            }
        } else {
            // User not authenticated, redirect to login
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Error checking authentication:', error);
        // On error, redirect to login
        window.location.href = '/login';
    }
}

/**
 * Hide/show navigation items based on role
 */
function adjustNavigationForRole() {
    try {
        if (!currentUser) return;
        const downloadsNav = document.getElementById('instructor-downloads-nav') ||
            document.getElementById('nav-downloads')?.closest('li');

        if (downloadsNav) {
            downloadsNav.style.display = isSystemAdmin() ? '' : 'none';
        }

        // Hide Student Hub link from TAs
        if (currentUser.role === 'ta') {
            const studentHubNav = document.getElementById('nav-student-hub-li');
            if (studentHubNav && studentHubNav.style) {
                studentHubNav.style.display = 'none';
            }
        }
        // Check quiz visibility for students
        if (currentUser.role === 'student') {
            checkQuizNavVisibility();
        }
    } catch (e) {
        console.warn('adjustNavigationForRole failed:', e);
    }
}

/**
 * Check if quiz page is enabled and show/hide nav item accordingly
 */
async function checkQuizNavVisibility() {
    const quizNavItem = document.getElementById('quiz-nav-item');
    if (!quizNavItem) return;
    try {
        // getCurrentCourseId may be sync (auth.js) or async (student.js override)
        let courseId = getCurrentCourseId();
        if (courseId && typeof courseId.then === 'function') {
            courseId = await courseId;
        }
        if (!courseId) {
            quizNavItem.style.display = 'none';
            return;
        }
        const response = await fetch(`/api/quiz/status?courseId=${courseId}`);
        const data = await response.json();
        if (data.success && data.enabled) {
            quizNavItem.style.display = '';
        } else {
            quizNavItem.style.display = 'none';
        }
    } catch (e) {
        // On error, hide quiz nav
        quizNavItem.style.display = 'none';
    }
}

/**
 * Update user display information
 */
function updateUserDisplay() {
    if (!currentUser) return;
    
    // Update user display name
    const displayNameElement = document.getElementById('user-display-name');
    if (displayNameElement) {
        displayNameElement.textContent = currentUser.displayName || currentUser.username;
    }
    
    // Update user avatar with first letter of display name
    const avatarElement = document.querySelector('.user-avatar');
    if (avatarElement) {
        avatarElement.textContent = getCurrentUserInitial();
    }

    const roleElement = document.querySelector('.user-role');
    if (roleElement) {
        roleElement.textContent = getCurrentUserRoleLabel();
    }

    // Update settings link based on role
    const settingsLink = document.querySelector('a[href="/instructor/settings"]');
    if (settingsLink && currentUser.role === 'ta') {
        settingsLink.href = '/ta/settings';
    }
}

/**
 * Setup logout button handler
 */
function setupLogoutHandler() {
    const logoutBtns = ['logout-btn', 'mobile-logout-btn'];
    
    logoutBtns.forEach(id => {
        const btn = document.getElementById(id);
        if (btn) {
            btn.addEventListener('click', async (e) => {
                e.preventDefault();
                await logout();
            });
        }
    });
}

/**
 * Logout user
 */
async function logout() {
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Log debug info for troubleshooting
            if (result.debug) {
                console.log('Logout Debug Info:', result.debug);
                if (result.debug.isCWL) {
                    console.log('CWL Logout Status:', result.debug.samlLogoutUrl ? 'SUCCESS' : 'FAILED/SKIPPED');
                }
            }
            
            // Clear local user data
            currentUser = null;
            
            // Redirect to login page
            // Use redirect URL from server if available (important for SAML logout)
            window.location.href = result.redirect || '/login';
        } else {
            console.error('Logout failed:', result.error);
            if (result.debug) console.log('Debug Info:', result.debug);
            // Still redirect to login even if logout failed
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Error during logout:', error);
        // Still redirect to login even if logout failed
        window.location.href = '/login';
    }
}

/**
 * Get current user information
 * @returns {Object|null} Current user object or null
 */
function getCurrentUser() {
    return currentUser;
}

/**
 * Check if current user has system administrator access
 * @returns {boolean} True if user is a system admin
 */
function isSystemAdmin() {
    return !!(currentUser && currentUser.permissions && currentUser.permissions.systemAdmin === true);
}

/**
 * Get user's display initial
 * @returns {string} Uppercase initial for the current user
 */
function getCurrentUserInitial() {
    if (!currentUser) return 'U';

    const displayValue = currentUser.displayName || currentUser.username || currentUser.email || currentUser.userId || 'User';
    return displayValue.charAt(0).toUpperCase();
}

/**
 * Get user's role label for display
 * @returns {string} Display-ready role label
 */
function getCurrentUserRoleLabel() {
    if (!currentUser) return 'User';

    if (currentUser.role === 'instructor') {
        return isSystemAdmin() ? 'Instructor (Admin)' : 'Instructor';
    }

    if (currentUser.role === 'ta') {
        return 'Teaching Assistant';
    }

    if (currentUser.role === 'student') {
        return 'Student';
    }

    return currentUser.role || 'User';
}

/**
 * Check if current user has specific role
 * @param {string} role - Role to check for
 * @returns {boolean} True if user has the role
 */
function hasRole(role) {
    return currentUser && currentUser.role === role;
}

/**
 * Check if current user is instructor
 * @returns {boolean} True if user is instructor
 */
function isInstructor() {
    return hasRole('instructor');
}

/**
 * Check if current user is student
 * @returns {boolean} True if user is student
 */
function isStudent() {
    return hasRole('student');
}

/**
 * Check if current user is TA
 * @returns {boolean} True if user is TA
 */
function isTA() {
    return hasRole('ta');
}

/**
 * Get user's current course context
 * @returns {string|null} Current course ID or null
 */
function getCurrentCourseId() {
    // First check URL parameters (highest priority)
    const urlParams = new URLSearchParams(window.location.search);
    const courseIdFromUrl = urlParams.get('courseId');
    if (courseIdFromUrl) {
        return courseIdFromUrl;
    }
    
    // Then check localStorage (for instructor pages)
    const courseIdFromStorage = localStorage.getItem('selectedCourseId');
    if (courseIdFromStorage) {
        return courseIdFromStorage;
    }
    
    // Finally check user preferences
    return currentUser && currentUser.preferences ? currentUser.preferences.courseId : null;
}

/**
 * Get current instructor ID (for backward compatibility)
 * @returns {string|null} Current user ID or null
 */
function getCurrentInstructorId() {
    return currentUser ? currentUser.userId : null;
}

/**
 * Set user's current course context
 * @param {string} courseId - Course ID to set
 * @returns {Promise<boolean>} True if successful
 */
async function setCurrentCourseId(courseId) {
    try {
        const response = await fetch('/api/auth/set-course', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ courseId })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Update local user data
            if (currentUser && currentUser.preferences) {
                currentUser.preferences.courseId = courseId;
            }
            return true;
        } else {
            console.error('Failed to set course context:', result.error);
            return false;
        }
    } catch (error) {
        console.error('Error setting course context:', error);
        return false;
    }
}

/**
 * Authenticated fetch helper that automatically includes credentials
 * @param {string} url - URL to fetch
 * @param {Object} options - Fetch options
 * @returns {Promise<Response>} Fetch response
 */
function authenticatedFetch(url, options = {}) {
    console.log('🔍 [AUTH_FETCH] Making request to:', url);
    console.log('🔍 [AUTH_FETCH] Full URL would be:', window.location.origin + url);
    return fetch(url, {
        ...options,
        credentials: 'include'
    });
}

// Initialize authentication when DOM is loaded
document.addEventListener('DOMContentLoaded', initAuth);
