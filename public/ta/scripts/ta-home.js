/**
 * TA Home Page JavaScript
 * Handles the TA dashboard functionality
 */

let taCourses = [];
let taPermissions = {}; // Store TA permissions for each course

function isCourseDeactive(course = {}) {
    return (course.status || 'active') === 'inactive';
}

function getCourseDisplayName(course = {}) {
    const courseName = course.courseName || course.courseId || 'Untitled Course';
    return isCourseDeactive(course) ? `${courseName} (deactive)` : courseName;
}

document.addEventListener('DOMContentLoaded', async function() {
    // Wait for authentication to be ready
    await waitForAuth();
    
    // Load TA courses
    await loadTACourses();
    
    // Load TA permissions
    await loadTAPermissions();
    
    // Re-display courses with permission data
    displayTACourses();
    
    // Initialize dashboard
    initializeDashboard();
});

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
        
        // Load permissions for each course
        for (const course of taCourses) {
            const response = await authenticatedFetch(`/api/courses/${course.courseId}/ta-permissions/${taId}`);
            
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    taPermissions[course.courseId] = result.data.permissions;
                }
            }
        }
        
        console.log('TA permissions loaded:', taPermissions);
    } catch (error) {
        console.error('Error loading TA permissions:', error);
    }
}

/**
 * Check if TA has permission for a specific feature in any course
 */
function hasPermissionForFeature(feature) {
    // If no courses, deny access
    if (taCourses.length === 0) {
        return false;
    }
    
    // Check permissions for all courses - if any course allows access, grant it
    for (const course of taCourses) {
        const permissions = taPermissions[course.courseId];
        if (permissions) {
            if (feature === 'courses' && permissions.canAccessCourses) {
                return true;
            }
            if (feature === 'flags' && permissions.canAccessFlags) {
                return true;
            }
        } else {
            // Default permissions if not set
            return true;
        }
    }
    
    return false;
}

/**
 * Initialize dashboard functionality
 */
function initializeDashboard() {
    // Set up My Courses link handler
    setupMyCoursesLink();
    // Set up Student Support link handler
    setupStudentSupportLink();
    // Set up Quick Actions link handlers
    setupQuickActionsLinks();
    // Update navigation based on permissions
    updateNavigationBasedOnPermissions();
    console.log('TA Dashboard initialized');
}

/**
 * Update navigation based on TA permissions
 */
function updateNavigationBasedOnPermissions() {
    // Hide/show My Courses link
    const myCoursesLink = document.getElementById('my-courses-link');
    if (myCoursesLink) {
        if (hasPermissionForFeature('courses')) {
            myCoursesLink.style.display = 'block';
        } else {
            myCoursesLink.style.display = 'none';
        }
    }
    
    // Hide/show Student Support link
    const studentSupportLink = document.getElementById('student-support-link');
    if (studentSupportLink) {
        if (hasPermissionForFeature('flags')) {
            studentSupportLink.style.display = 'block';
        } else {
            studentSupportLink.style.display = 'none';
        }
    }
    
    // Hide/show Quick Actions links
    const quickCoursesLink = document.getElementById('quick-courses-link');
    if (quickCoursesLink) {
        if (hasPermissionForFeature('courses')) {
            quickCoursesLink.style.display = 'block';
        } else {
            quickCoursesLink.style.display = 'none';
        }
    }
    
    const quickSupportLink = document.getElementById('quick-support-link');
    if (quickSupportLink) {
        if (hasPermissionForFeature('flags')) {
            quickSupportLink.style.display = 'block';
        } else {
            quickSupportLink.style.display = 'none';
        }
    }
}

/**
 * Setup My Courses link to navigate to the first assigned course
 */
function setupMyCoursesLink() {
    const myCoursesLink = document.getElementById('my-courses-link');
    if (myCoursesLink) {
        myCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            
            if (taCourses.length === 0) {
                showNotification('No courses assigned. Contact an instructor to be added to a course.', 'warning');
                return;
            }
            
            // Check permissions
            if (!hasPermissionForFeature('courses')) {
                showNotification('You do not have permission to access My Courses. Contact your instructor.', 'error');
                return;
            }
            
            // Navigate to the first assigned course
            const firstCourse = taCourses[0];
            window.location.href = `/instructor/documents?courseId=${firstCourse.courseId}`;
        });
    }
}

/**
 * Setup Student Support link to navigate to the first assigned course's flagged content
 */
function setupStudentSupportLink() {
    const studentSupportLink = document.getElementById('student-support-link');
    if (studentSupportLink) {
        studentSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            
            if (taCourses.length === 0) {
                showNotification('No courses assigned. Contact an instructor to be added to a course.', 'warning');
                return;
            }
            
            // Check permissions
            if (!hasPermissionForFeature('flags')) {
                showNotification('You do not have permission to access Student Support. Contact your instructor.', 'error');
                return;
            }
            
            // Navigate to the first assigned course's flagged content
            const firstCourse = taCourses[0];
            window.location.href = `/instructor/flagged?courseId=${firstCourse.courseId}`;
        });
    }
}

/**
 * Setup Quick Actions links to navigate with proper course context
 */
function setupQuickActionsLinks() {
    // Quick Courses link
    const quickCoursesLink = document.getElementById('quick-courses-link');
    if (quickCoursesLink) {
        quickCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            
            if (taCourses.length === 0) {
                showNotification('No courses assigned. Contact an instructor to be added to a course.', 'warning');
                return;
            }
            
            // Check permissions
            if (!hasPermissionForFeature('courses')) {
                showNotification('You do not have permission to access My Courses. Contact your instructor.', 'error');
                return;
            }
            
            // Navigate to the first assigned course
            const firstCourse = taCourses[0];
            window.location.href = `/instructor/documents?courseId=${firstCourse.courseId}`;
        });
    }
    
    // Quick Support link
    const quickSupportLink = document.getElementById('quick-support-link');
    if (quickSupportLink) {
        quickSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            
            if (taCourses.length === 0) {
                showNotification('No courses assigned. Contact an instructor to be added to a course.', 'warning');
                return;
            }
            
            // Check permissions
            if (!hasPermissionForFeature('flags')) {
                showNotification('You do not have permission to access Student Support. Contact your instructor.', 'error');
                return;
            }
            
            // Navigate to the first assigned course's flagged content
            const firstCourse = taCourses[0];
            window.location.href = `/instructor/flagged?courseId=${firstCourse.courseId}`;
        });
    }
}

/**
 * Load courses for the TA
 */
async function loadTACourses() {
    try {
        const taId = getCurrentInstructorId(); // Using same function for user ID
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return;
        }
        
        console.log(`Loading courses for TA: ${taId}`);
        
        // Fetch courses for this TA
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
        
        // Display courses
        displayTACourses();
        
    } catch (error) {
        console.error('Error loading TA courses:', error);
        showNotification('Error loading courses. Please try again.', 'error');
    }
}

/**
 * Display TA courses on the dashboard
 */
function displayTACourses() {
    const coursesContainer = document.getElementById('courses-container');
    
    if (!coursesContainer) {
        console.error('Courses container not found');
        return;
    }
    
    if (taCourses.length === 0) {
        coursesContainer.innerHTML = `
            <div class="no-courses-message">
                <h3>No courses assigned</h3>
                <p>You haven't been assigned to any courses yet. Contact an instructor to be added to a course.</p>
                <a href="/ta/onboarding" class="btn-primary">Join a Course</a>
            </div>
        `;
        return;
    }
    
    // Create course cards
    coursesContainer.innerHTML = taCourses.map(course => {
        const coursePermissions = taPermissions[course.courseId] || {};
        const canAccessCourses = coursePermissions.canAccessCourses !== false; // Default to true
        const canAccessFlags = coursePermissions.canAccessFlags !== false; // Default to true
        const isInactive = isCourseDeactive(course);
        const statusLabel = isInactive ? 'Deactive' : 'Active';
        
        return `
        <div class="course-card">
            <div class="course-header">
                <h3>${getCourseDisplayName(course)}</h3>
                <span class="course-status ${isInactive ? 'inactive' : 'active'}">${statusLabel}</span>
            </div>
            <div class="course-info">
                <p><strong>Course ID:</strong> ${course.courseId}</p>
                <p><strong>Instructor:</strong> ${course.instructorId}</p>
                <p><strong>Units:</strong> ${course.totalUnits || 0}</p>
            </div>
        </div>
        `;
    }).join('');
}

/**
 * Wait for authentication to be initialized
 * @returns {Promise<void>}
 */
async function waitForAuth() {
    // Wait for auth.js to initialize
    let attempts = 0;
    const maxAttempts = 50; // 5 seconds max wait
    
    while (attempts < maxAttempts) {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) {
            console.log('✅ [AUTH] TA Authentication ready');
            return;
        }
        
        // Wait 100ms before next attempt
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }
    
    console.warn('⚠️ [AUTH] TA Authentication not ready after 5 seconds, proceeding anyway');
}

/**
 * Show notification to user
 */
function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close">×</button>
    `;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 6px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: 10px;
        max-width: 400px;
        ${type === 'success' ? 'background-color: #28a745;' : 'background-color: #dc3545;'}
    `;
    
    // Add event listener for close button
    const closeButton = notification.querySelector('.notification-close');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            notification.remove();
        });
    }
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}
