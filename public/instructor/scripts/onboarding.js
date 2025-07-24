/**
 * Onboarding Page JavaScript
 * Handles course selection and setup functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize onboarding functionality
    initializeOnboarding();
});

/**
 * Initialize all onboarding functionality
 */
function initializeOnboarding() {
    const form = document.getElementById('course-setup-form');
    const courseSelect = document.getElementById('course-select');
    const unitsSelect = document.getElementById('units-count');
    
    // Add event listeners
    if (form) {
        form.addEventListener('submit', handleFormSubmission);
    }
    
    if (courseSelect) {
        courseSelect.addEventListener('change', handleCourseSelection);
    }
    
    if (unitsSelect) {
        unitsSelect.addEventListener('change', handleUnitsSelection);
    }
    
    // Initialize form validation
    initializeFormValidation();
}

/**
 * Handle form submission
 * @param {Event} event - Form submit event
 */
async function handleFormSubmission(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    const courseSelect = document.getElementById('course-select');
    const unitsSelect = document.getElementById('units-count');
    
    // Validate form
    if (!validateForm()) {
        return;
    }
    
    // Disable submit button and show loading state
    submitButton.disabled = true;
    submitButton.textContent = 'Creating Course...';
    
    try {
        // Prepare form data
        const formData = {
            course: courseSelect.value,
            units: parseInt(unitsSelect.value),
            instructorId: getCurrentInstructorId() // This would come from auth
        };
        
        // Send request to backend
        const response = await createCourse(formData);
        
        if (response.success) {
            showSuccessMessage('Course created successfully!');
            
            // Redirect to documents page after a short delay
            setTimeout(() => {
                window.location.href = '/instructor';
            }, 1500);
        } else {
            showErrorMessage(response.message || 'Failed to create course');
        }
        
    } catch (error) {
        console.error('Error creating course:', error);
        showErrorMessage('An error occurred while creating the course');
    } finally {
        // Re-enable submit button
        submitButton.disabled = false;
        submitButton.textContent = 'Create Course';
    }
}

/**
 * Handle course selection change
 * @param {Event} event - Select change event
 */
function handleCourseSelection(event) {
    const courseSelect = event.target;
    const formGroup = courseSelect.closest('.form-group');
    
    // Remove any existing error states
    formGroup.classList.remove('error');
    const existingError = formGroup.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Add success state if course is selected
    if (courseSelect.value) {
        formGroup.classList.add('success');
    } else {
        formGroup.classList.remove('success');
    }
}

/**
 * Handle units selection change
 * @param {Event} event - Select change event
 */
function handleUnitsSelection(event) {
    const unitsSelect = event.target;
    const formGroup = unitsSelect.closest('.form-group');
    
    // Remove any existing error states
    formGroup.classList.remove('error');
    const existingError = formGroup.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Add success state if units is selected
    if (unitsSelect.value) {
        formGroup.classList.add('success');
    } else {
        formGroup.classList.remove('success');
    }
}

/**
 * Initialize form validation
 */
function initializeFormValidation() {
    const courseSelect = document.getElementById('course-select');
    const unitsSelect = document.getElementById('units-count');
    
    // Add required validation attributes
    if (courseSelect) {
        courseSelect.setAttribute('required', 'required');
    }
    
    if (unitsSelect) {
        unitsSelect.setAttribute('required', 'required');
    }
}

/**
 * Validate the form
 * @returns {boolean} True if form is valid, false otherwise
 */
function validateForm() {
    const courseSelect = document.getElementById('course-select');
    const unitsSelect = document.getElementById('units-count');
    let isValid = true;
    
    // Validate course selection
    if (!courseSelect.value) {
        showFieldError(courseSelect, 'Please select a course');
        isValid = false;
    }
    
    // Validate units selection
    if (!unitsSelect.value) {
        showFieldError(unitsSelect, 'Please select the number of units');
        isValid = false;
    }
    
    return isValid;
}

/**
 * Show field error
 * @param {HTMLElement} field - The form field
 * @param {string} message - Error message
 */
function showFieldError(field, message) {
    const formGroup = field.closest('.form-group');
    
    // Remove existing error
    formGroup.classList.remove('success');
    const existingError = formGroup.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Add error state
    formGroup.classList.add('error');
    
    // Create error message element
    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = message;
    
    // Insert error message after the field
    field.parentNode.insertBefore(errorElement, field.nextSibling);
}

/**
 * Create course via API
 * @param {Object} courseData - Course data
 * @returns {Promise<Object>} API response
 */
async function createCourse(courseData) {
    try {
        const response = await fetch('/api/courses', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${getAuthToken()}`
            },
            body: JSON.stringify(courseData)
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
        
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Get current instructor ID (placeholder)
 * @returns {string} Instructor ID
 */
function getCurrentInstructorId() {
    // This would typically come from JWT token or session
    // For now, return a placeholder
    return 'instructor-123';
}

/**
 * Get auth token (placeholder)
 * @returns {string} Auth token
 */
function getAuthToken() {
    // This would typically come from localStorage or sessionStorage
    // For now, return a placeholder
    return 'placeholder-token';
}

/**
 * Show success message
 * @param {string} message - Success message
 */
function showSuccessMessage(message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification success';
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showErrorMessage(message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification error';
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
} 