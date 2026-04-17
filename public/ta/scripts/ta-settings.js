/**
 * TA Settings Page JavaScript
 * Handles the Teaching Assistant settings functionality
 */

let taCourses = [];
let taPermissions = {};

function isCourseDeactive(course = {}) {
    return (course.status || 'active') === 'inactive';
}

function getCourseDisplayName(course = {}) {
    const courseName = course.courseName || course.courseId || 'Untitled Course';
    return isCourseDeactive(course) ? `${courseName} (deactive)` : courseName;
}

document.addEventListener('DOMContentLoaded', async function() {
    console.log('🚀 [TA SETTINGS] Page loaded');
    
    // Wait for authentication to be ready
    await waitForAuth();
    
    // Load TA data
    await loadTAData();
    
    // Setup navigation handlers
    setupTANavigationHandlers();
    
    // Update navigation based on permissions
    await updateTANavigationBasedOnPermissions();
    
    console.log('✅ [TA SETTINGS] Page initialized');
});

/**
 * Load TA data (courses and permissions)
 */
async function loadTAData() {
    try {
        // Load TA courses
        await loadTACourses();
        
        // Load TA permissions
        await loadTAPermissions();
        
        // Update UI with loaded data
        updateAccountInfo();
        updateCourseAssignments();
        updatePermissionsStatus();
        
    } catch (error) {
        console.error('Error loading TA data:', error);
        showNotification('Error loading your data. Please refresh the page.', 'error');
    }
}

/**
 * Load TA courses
 */
async function loadTACourses() {
    try {
        const taId = getCurrentInstructorId();
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return;
        }
        
        console.log(`Loading courses for TA: ${taId}`);
        
        const response = await authenticatedFetch(`/api/courses/ta/${taId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch TA courses');
        }
        
        taCourses = result.data || [];
        console.log('TA courses loaded:', taCourses);
        
    } catch (error) {
        console.error('Error loading TA courses:', error);
        taCourses = [];
    }
}

/**
 * Load TA permissions for all courses
 */
async function loadTAPermissions() {
    try {
        const taId = getCurrentInstructorId();
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return;
        }
        
        console.log(`Loading permissions for TA: ${taId}`);
        
        // Load permissions for each course
        const permissions = {};
        for (const course of taCourses) {
            const response = await authenticatedFetch(`/api/courses/${course.courseId}/ta-permissions/${taId}`);
            
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    permissions[course.courseId] = result.data.permissions;
                }
            }
        }
        
        console.log('TA permissions loaded:', permissions);
        taPermissions = permissions;
        
    } catch (error) {
        console.error('Error loading TA permissions:', error);
        taPermissions = {};
    }
}

/**
 * Update account information display
 */
function updateAccountInfo() {
    const taId = getCurrentInstructorId();
    const currentUser = getCurrentUser();
    
    // Update TA ID
    const taIdInput = document.getElementById('ta-id');
    if (taIdInput) {
        taIdInput.value = taId || 'Not available';
    }
    
    // Update email (this would come from user data)
    const emailInput = document.getElementById('ta-email');
    
    if (emailInput) {
        emailInput.value = currentUser?.email || 'Not available';
    }
}

/**
 * Update course assignments display
 */
function updateCourseAssignments() {
    const container = document.getElementById('course-assignments');
    if (!container) return;
    
    if (taCourses.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No Course Assignments</h3>
                <p>You haven't been assigned to any courses yet. Contact your instructor to be added to a course.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = taCourses.map(course => {
        const isInactive = isCourseDeactive(course);

        return `
        <div class="course-assignment">
            <div class="course-info">
                <h4>${getCourseDisplayName(course)}</h4>
                <p>Course ID: ${course.courseId}</p>
            </div>
            <div class="course-status ${isInactive ? 'inactive' : 'active'}">${isInactive ? 'Deactive' : 'Active'}</div>
        </div>
    `;
    }).join('');
}

/**
 * Update permissions status display
 */
function updatePermissionsStatus() {
    const container = document.getElementById('permissions-status');
    if (!container) return;
    
    if (Object.keys(taPermissions).length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <h3>No Permission Data</h3>
                <p>Permission information is not available. Contact your instructor for details.</p>
            </div>
        `;
        return;
    }
    
    // Check overall permissions across all courses
    const canAccessCourses = hasPermissionForFeature('courses');
    const canAccessFlags = hasPermissionForFeature('flags');
    
    container.innerHTML = `
        <div class="permission-item">
            <span class="permission-name">Course Access</span>
            <span class="permission-status ${canAccessCourses ? 'allowed' : 'denied'}">
                ${canAccessCourses ? 'Allowed' : 'Denied'}
            </span>
        </div>
        <div class="permission-item">
            <span class="permission-name">Student Support</span>
            <span class="permission-status ${canAccessFlags ? 'allowed' : 'denied'}">
                ${canAccessFlags ? 'Allowed' : 'Denied'}
            </span>
        </div>
    `;
}

/**
 * Check if TA has permission for a specific feature in any course
 */
function hasPermissionForFeature(feature) {
    if (!taPermissions || Object.keys(taPermissions).length === 0) {
        return false;
    }
    
    for (const courseId in taPermissions) {
        const permissions = taPermissions[courseId];
        if (permissions) {
            if (feature === 'courses' && permissions.canAccessCourses) {
                return true;
            }
            if (feature === 'flags' && permissions.canAccessFlags) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Setup TA navigation handlers
 */
function setupTANavigationHandlers() {
    console.log('🔍 [TA SETTINGS] Setting up navigation handlers');
    
    // TA My Courses link
    const taMyCoursesLink = document.getElementById('ta-my-courses-link');
    if (taMyCoursesLink) {
        taMyCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('🔍 [TA SETTINGS] My Courses clicked');
            
            // Get courseId from URL or use first course
            const urlParams = new URLSearchParams(window.location.search);
            const courseId = urlParams.get('courseId');
            
            if (courseId) {
                window.location.href = `/instructor/documents?courseId=${courseId}`;
            } else if (taCourses.length > 0) {
                window.location.href = `/instructor/documents?courseId=${taCourses[0].courseId}`;
            } else {
                showNotification('No courses available. Contact your instructor.', 'warning');
            }
        });
    }
    
    // TA Student Support link
    const taStudentSupportLink = document.getElementById('ta-student-support-link');
    if (taStudentSupportLink) {
        taStudentSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('🔍 [TA SETTINGS] Student Support clicked');
            
            // Get courseId from URL or use first course
            const urlParams = new URLSearchParams(window.location.search);
            const courseId = urlParams.get('courseId');
            
            if (courseId) {
                window.location.href = `/instructor/flagged?courseId=${courseId}`;
            } else if (taCourses.length > 0) {
                window.location.href = `/instructor/flagged?courseId=${taCourses[0].courseId}`;
            } else {
                showNotification('No courses available. Contact your instructor.', 'warning');
            }
        });
    }
}

/**
 * Update TA navigation based on permissions
 */
async function updateTANavigationBasedOnPermissions() {
    console.log('🔍 [TA SETTINGS] Updating navigation based on permissions');
    
    // Hide/show My Courses link
    const taMyCoursesLink = document.getElementById('ta-my-courses-link');
    if (taMyCoursesLink) {
        if (hasPermissionForFeature('courses')) {
            taMyCoursesLink.style.display = 'block';
        } else {
            taMyCoursesLink.style.display = 'none';
        }
    }
    
    // Hide/show Student Support link
    const taStudentSupportLink = document.getElementById('ta-student-support-link');
    if (taStudentSupportLink) {
        if (hasPermissionForFeature('flags')) {
            taStudentSupportLink.style.display = 'block';
        } else {
            taStudentSupportLink.style.display = 'none';
        }
    }
}

/**
 * Contact instructor function
 */
function contactInstructor() {
    showNotification('Contact instructor functionality coming soon!', 'info');
}

/**
 * View help function
 */
function viewHelp() {
    showNotification('Help guide coming soon!', 'info');
}

/**
 * Wait for authentication to be initialized
 */
async function waitForAuth() {
    let attempts = 0;
    const maxAttempts = 50;
    
    while (attempts < maxAttempts) {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) {
            console.log('✅ [AUTH] TA Authentication ready');
            return;
        }
        
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }
    
    console.warn('⚠️ [AUTH] TA Authentication not ready after 5 seconds, proceeding anyway');
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Style the notification
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 4px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        max-width: 400px;
        word-wrap: break-word;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transform: translateX(100%);
        transition: transform 0.3s ease-in-out;
    `;
    
    // Set background color based on type
    const colors = {
        info: '#2196F3',
        success: '#4CAF50',
        warning: '#FF9800',
        error: '#F44336'
    };
    notification.style.backgroundColor = colors[type] || colors.info;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, 5000);
}
