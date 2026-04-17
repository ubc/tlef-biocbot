/**
 * TA Onboarding Page JavaScript
 * Handles course joining flow for Teaching Assistants
 */

// Global state for TA onboarding
let taOnboardingState = {
    currentStep: 1,
    totalSteps: 1,
    selectedCourse: null,
    isSubmitting: false
};

function isCourseDeactive(course = {}) {
    return (course.status || 'active') === 'inactive';
}

function getCourseDisplayName(course = {}) {
    const courseName = course.courseName || course.courseId || 'Untitled Course';
    return isCourseDeactive(course) ? `${courseName} (deactive)` : courseName;
}

function dedupeCourses(courses = []) {
    return courses.filter((course, index, self) =>
        index === self.findIndex(candidate => candidate.courseId === course.courseId)
    );
}

function appendCourseGroup(selectElement, label, courses) {
    if (!courses.length) {
        return;
    }

    const optgroup = document.createElement('optgroup');
    optgroup.label = label;

    courses.forEach(course => {
        const option = document.createElement('option');
        option.value = course.courseId;
        option.textContent = getCourseDisplayName(course);
        option.dataset.status = course.status || 'active';
        optgroup.appendChild(option);
    });

    selectElement.appendChild(optgroup);
}

function populateAvailableCourses(selectElement, courses, placeholderText) {
    selectElement.innerHTML = `<option value="">${placeholderText}</option>`;

    const uniqueCourses = dedupeCourses(courses);
    const activeCourses = uniqueCourses.filter(course => !isCourseDeactive(course));
    const inactiveCourses = uniqueCourses.filter(isCourseDeactive);

    appendCourseGroup(selectElement, 'Active Courses', activeCourses);
    appendCourseGroup(selectElement, 'Deactive Courses', inactiveCourses);
}

document.addEventListener('DOMContentLoaded', async function() {
    // Initialize TA onboarding functionality
    initializeTAOnboarding();
    
    // Wait for authentication to be ready
    await waitForAuth();
    
    // Load available courses for course selection
    loadAvailableCourses();
});

/**
 * Initialize TA onboarding functionality
 */
function initializeTAOnboarding() {
    // Initialize form handlers
    initializeFormHandlers();
    
    // Show first step
    showStep(1);
}

/**
 * Initialize form event handlers
 */
function initializeFormHandlers() {
    // Course selection form handler
    const courseSelectionForm = document.getElementById('ta-course-selection-form');
    if (courseSelectionForm) {
        courseSelectionForm.addEventListener('submit', handleCourseSelection);
    }
}

/**
 * Handle course selection form submission
 */
async function handleCourseSelection(event) {
    event.preventDefault();
    
    // Prevent multiple submissions
    if (taOnboardingState.isSubmitting) {
        return;
    }
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const courseSelect = document.getElementById('ta-course-select');
    
    // Validate form
    if (!courseSelect.value) {
        showNotification('Please select a course to join.', 'error');
        return;
    }
    
    // Set submitting flag and disable submit button
    taOnboardingState.isSubmitting = true;
    submitButton.disabled = true;
    submitButton.textContent = 'Joining course...';
    
    try {
        // Join the selected course
        const result = await joinCourse(courseSelect.value);
        
        if (result.success) {
            taOnboardingState.selectedCourse = result.course;
            showTAOnboardingComplete();
        } else {
            showNotification(result.message || 'Failed to join course. Please try again.', 'error');
        }
        
    } catch (error) {
        console.error('Error joining course:', error);
        showNotification('Error joining course. Please try again.', 'error');
    } finally {
        // Reset submitting flag and re-enable submit button
        taOnboardingState.isSubmitting = false;
        submitButton.disabled = false;
        submitButton.textContent = 'Join Course';
    }
}

/**
 * Join a course as a TA
 */
async function joinCourse(courseId) {
    try {
        console.log('🚀 [TA_ONBOARDING] Starting course joining process...');
        console.log('📋 [TA_ONBOARDING] Course ID:', courseId);
        
        const taId = getCurrentInstructorId(); // Using same function for user ID
        if (!taId) {
            throw new Error('No TA ID found. User not authenticated.');
        }
        
        console.log(`👤 [TA_ONBOARDING] Using TA ID: ${taId}`);
        
        // Join course as TA
        const response = await authenticatedFetch(`/api/courses/${courseId}/join`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to join course: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Successfully joined course:', result);
        
        // Get course details for display
        const courseDetails = await getCourseDetails(courseId);
        
        return {
            success: true,
            course: courseDetails || { courseId, courseName: 'Unknown Course' }
        };
        
    } catch (error) {
        console.error('❌ [TA_ONBOARDING] Error joining course:', error);
        throw error;
    }
}

/**
 * Get detailed course information
 */
async function getCourseDetails(courseId) {
    try {
        const response = await authenticatedFetch(`/api/onboarding/${courseId}`);
        if (response.ok) {
            const result = await response.json();
            return result.data;
        }
        return null;
    } catch (error) {
        console.error('Error getting course details:', error);
        return null;
    }
}

/**
 * Show TA onboarding complete message
 */
function showTAOnboardingComplete() {
    // Hide all onboarding steps
    document.querySelectorAll('.onboarding-step').forEach(step => {
        step.style.display = 'none';
    });
    
    // Show completion message
    document.getElementById('ta-onboarding-complete').style.display = 'block';
    
    // Auto-redirect after 5 seconds to prevent users from staying on onboarding
    setTimeout(() => {
        window.location.href = '/ta';
    }, 5000);
}

/**
 * Show specific step
 */
function showStep(stepNumber) {
    // Hide all steps
    const steps = document.querySelectorAll('.onboarding-step');
    steps.forEach(step => step.classList.remove('active'));
    
    // Show current step
    const currentStep = document.getElementById(`ta-step-${stepNumber}`);
    if (currentStep) {
        currentStep.classList.add('active');
    }
}

/**
 * Load available courses for the TA
 */
async function loadAvailableCourses() {
    try {
        const courseSelect = document.getElementById('ta-course-select');
        
        if (!courseSelect) return;
        
        // Fetch courses from the API
        const response = await authenticatedFetch('/api/courses/available/all');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch courses');
        }
        
        const courses = result.data || [];
        
        console.log('Available courses for TA:', courses);

        populateAvailableCourses(courseSelect, courses, 'Choose a course to join...');
        
        console.log('Available courses loaded for TA:', dedupeCourses(courses).length);
        
    } catch (error) {
        console.error('Error loading available courses:', error);
        // Keep the placeholder option if API fails
        const courseSelect = document.getElementById('ta-course-select');
        if (courseSelect) {
            courseSelect.innerHTML = '<option value="">No courses available</option>';
        }
    }
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
