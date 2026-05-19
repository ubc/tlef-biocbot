/**
 * Common Authentication Script
 * Handles user authentication state and logout functionality
 */

let currentUser = null;
let currentLLMTagClasses = [];

const LLM_TAG_CLASS_PATTERN = /^(llm|reasoning)-\d+$/;
const LLM_TAG_TARGET_SELECTOR = 'body, .chat-container, #chat-messages, .quiz-chat-container, #quiz-chat-messages';
const LLM_TAG_COMMENT_PREFIX = 'LLM tag map:';
const LLM_TAG_COMMENT_TEXT = 'LLM tag map: llm-1 = gpt-4.1-mini; llm-2 = gpt-5-nano; llm-3 = gpt-5.4-nano; reasoning-* applies to GPT-5 models only; reasoning-1 = minimal; reasoning-2 = low; reasoning-3 = medium; reasoning-4 = high';

function stripLLMTagClasses(element) {
    if (!element || !element.classList) return;

    Array.from(element.classList)
        .filter(className => LLM_TAG_CLASS_PATTERN.test(className))
        .forEach(className => element.classList.remove(className));
}

function applyLLMTagClassesToElement(element, tagClasses = currentLLMTagClasses) {
    if (!element || !element.classList) return;

    stripLLMTagClasses(element);
    tagClasses.forEach(className => element.classList.add(className));
    if (tagClasses.length > 0) {
        ensureLLMTagComment(element);
    }
}

function applyLLMTagClasses(tagClasses = currentLLMTagClasses) {
    document
        .querySelectorAll(LLM_TAG_TARGET_SELECTOR)
        .forEach(element => applyLLMTagClassesToElement(element, tagClasses));
}

function getCurrentLLMTagClasses() {
    return currentLLMTagClasses.slice();
}

function ensureLLMTagComment(element) {
    const parent = element.parentNode;
    if (!parent) return;

    const previousNode = element.previousSibling;
    if (
        previousNode &&
        previousNode.nodeType === Node.COMMENT_NODE &&
        previousNode.nodeValue.trim().startsWith(LLM_TAG_COMMENT_PREFIX)
    ) {
        previousNode.nodeValue = ` ${LLM_TAG_COMMENT_TEXT} `;
        return;
    }

    parent.insertBefore(document.createComment(` ${LLM_TAG_COMMENT_TEXT} `), element);
}

/**
 * Tag the chat DOM with obfuscated classes (e.g. "llm-2 reasoning-1") and a
 * nearby HTML comment mapping those classes for anyone inspecting DevTools.
 */
async function applyLLMBodyTag() {
    try {
        const response = await fetch('/api/settings/llm-tag');
        const result = await response.json();
        if (!result || !result.success) return;
        const { llmIndex, reasoningIndex } = result;
        currentLLMTagClasses = [
            llmIndex ? `llm-${llmIndex}` : null,
            reasoningIndex ? `reasoning-${reasoningIndex}` : null
        ].filter(Boolean);
        applyLLMTagClasses();
    } catch (e) {
        // Non-critical: tag is for internal debugging only
        console.warn('applyLLMBodyTag failed', e);
    }
}

window.applyLLMBodyTag = applyLLMBodyTag;
window.applyLLMTagClassesToElement = applyLLMTagClassesToElement;
window.getCurrentLLMTagClasses = getCurrentLLMTagClasses;

async function initAuth() {
    try {
        // Apply the hidden LLM debug tag in parallel with auth check
        applyLLMBodyTag();

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
    // If a page-level Auth controller is in place (e.g. dashboard.js exposes
    // window.Auth with its own logout, or a test installs a shim), defer to
    // it instead of double-attaching. Without this guard, two handlers fire
    // on the same click — one navigates and one calls the page controller —
    // and the navigation races the page logic. See Redundancies R1d.
    if (typeof window.Auth === 'object' && window.Auth && typeof window.Auth.logout === 'function') {
        return;
    }

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
