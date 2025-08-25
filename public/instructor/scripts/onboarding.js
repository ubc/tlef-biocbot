/**
 * Onboarding Page JavaScript
 * Handles guided multi-step onboarding flow for instructors
 * Focuses on course setup and initialization, not detailed document management
 */

// Script loaded successfully
console.log('🔥 [ONBOARDING] Script file loaded successfully');

// Global state for onboarding
const onboardingState = {
    currentStep: 1,
    totalSteps: 3,
    currentSubstep: 'objectives',
    substeps: ['objectives', 'materials', 'questions'],
    courseData: {},
    isSubmitting: false, // Prevent multiple submissions
    existingCourseId: null, // Store existing course ID if found
    statusChecked: false, // Prevent multiple status checks
    initialized: false, // Prevent multiple initializations
    createdCourseId: null,
    assessmentQuestions: {},
    // Add upload status tracking
    uploadStatus: {
        'lecture-notes': false,
        'practice-quiz': false,
        'additional': false
    }
};

// Make onboardingState accessible globally for instructor.js
window.onboardingState = onboardingState;

/**
 * Navigate to next step
 */
function nextStep() {
    console.log(`🔄 [ONBOARDING] nextStep called. Current step: ${onboardingState.currentStep}, Total steps: ${onboardingState.totalSteps}`);
    
    if (onboardingState.currentStep < onboardingState.totalSteps) {
        onboardingState.currentStep++;
        console.log(`✅ [ONBOARDING] Moving to step ${onboardingState.currentStep}`);
        showStep(onboardingState.currentStep);
        updateProgressBar();
    } else {
        console.log(`ℹ️ [ONBOARDING] Already at last step (${onboardingState.currentStep})`);
    }
}

/**
 * Navigate to previous step
 */
function previousStep() {
    console.log(`🔄 [ONBOARDING] previousStep called. Current step: ${onboardingState.currentStep}`);
    
    if (onboardingState.currentStep > 1) {
        onboardingState.currentStep--;
        console.log(`✅ [ONBOARDING] Moving to step ${onboardingState.currentStep}`);
        showStep(onboardingState.currentStep);
        updateProgressBar();
    } else {
        console.log(`ℹ️ [ONBOARDING] Already at first step (${onboardingState.currentStep})`);
    }
}

/**
 * Show specific step
 */
function showStep(stepNumber) {
    console.log(`🔄 [ONBOARDING] showStep called with stepNumber: ${stepNumber}`);
    
    // Hide all steps
    const steps = document.querySelectorAll('.onboarding-step');
    console.log(`🔍 [ONBOARDING] Found ${steps.length} steps:`, Array.from(steps).map(s => s.id));
    
    steps.forEach(step => {
        step.classList.remove('active');
        console.log(`🔍 [ONBOARDING] Removed 'active' class from ${step.id}`);
    });
    
    // Show current step
    const currentStep = document.getElementById(`step-${stepNumber}`);
    if (currentStep) {
        currentStep.classList.add('active');
        console.log(`✅ [ONBOARDING] Added 'active' class to ${currentStep.id}`);
    } else {
        console.error(`❌ [ONBOARDING] Step ${stepNumber} not found!`);
    }
    
    // Update step indicators
    const indicators = document.querySelectorAll('.step-indicator');
    console.log(`🔍 [ONBOARDING] Found ${indicators.length} step indicators`);
    
    indicators.forEach((indicator, index) => {
        indicator.classList.remove('active', 'completed');
        if (index + 1 < stepNumber) {
            indicator.classList.add('completed');
            console.log(`✅ [ONBOARDING] Marked indicator ${index + 1} as completed`);
        } else if (index + 1 === stepNumber) {
            indicator.classList.add('active');
            console.log(`✅ [ONBOARDING] Marked indicator ${index + 1} as active`);
        }
    });
    
    // If we're on step 3, show the first substep
    if (stepNumber === 3) {
        console.log(`🔄 [ONBOARDING] Step 3 detected, showing first substep`);
        showSubstep('objectives');
    }
    
    console.log(`✅ [ONBOARDING] showStep completed for step ${stepNumber}`);
}

// Functions will be made globally accessible after DOM loads

document.addEventListener('DOMContentLoaded', async function() {
    // CRITICAL: Prevent multiple initializations
    if (onboardingState.initialized) {
        return;
    }
    
    onboardingState.initialized = true;
    
    // Make functions globally accessible for onclick handlers
    window.nextStep = nextStep;
    window.previousStep = previousStep;
    window.nextSubstep = nextSubstep;
    window.previousSubstep = previousSubstep;
    window.addObjectiveForUnit = addObjectiveForUnit;
    
    // Don't override global function names - just use the instructor.js functions directly
    // The HTML onclick handlers will call these functions
    
    // Remove global function overrides to prevent circular references
    // window.openQuestionModal = openQuestionModalFromInstructor;
    // window.closeQuestionModal = closeQuestionModalFromInstructor;
    // window.saveQuestion = saveQuestionFromInstructor;
    window.saveAssessment = saveAssessment;
    window.completeUnit1Setup = completeUnit1Setup;
    window.removeObjective = removeObjective;
    // window.updateQuestionForm = updateQuestionFormFromInstructor;
    window.deleteOnboardingQuestion = deleteOnboardingQuestion;
    
    // Initialize onboarding functionality (this will check status ONCE)
    await initializeOnboarding();
    
    // Show the first step by default
    console.log('🔄 [ONBOARDING] Showing first step by default');
    showStep(1);
    
    // Only initialize other components if onboarding is NOT complete
    if (!onboardingState.existingCourseId) {
        // Initialize guided substep functionality
        initializeGuidedSubsteps();
        
        // Initialize modal click-outside functionality
        initializeModalFunctionality().then(() => {
            console.log('✅ [ONBOARDING] Modal functionality initialized successfully');
        }).catch(error => {
            console.error('❌ [ONBOARDING] Error initializing modal functionality:', error);
        });
        
        // Load existing assessment questions if any
        await loadExistingAssessmentQuestions();
        
        // Add test function for debugging
        window.testAssessmentQuestions = testAssessmentQuestions;
        console.log('🧪 [ONBOARDING] Test function added: testAssessmentQuestions()');

        // Add test function for step navigation
        window.testStepNavigation = function() {
            console.log('🧪 [ONBOARDING] Testing step navigation...');
            console.log('📊 [ONBOARDING] Current state:', {
                currentStep: onboardingState.currentStep,
                totalSteps: onboardingState.totalSteps,
                currentSubstep: onboardingState.currentSubstep
            });
            
            // Test showing each step
            for (let i = 1; i <= onboardingState.totalSteps; i++) {
                console.log(`🧪 [ONBOARDING] Testing step ${i}`);
                showStep(i);
            }
            
            // Return to first step
            showStep(1);
            console.log('🧪 [ONBOARDING] Step navigation test complete');
        };
        console.log('🧪 [ONBOARDING] Test function added: testStepNavigation()');

        // Add test function for question modal
        window.testQuestionModal = function() {
            console.log('🧪 [ONBOARDING] Testing question modal...');
            
            const questionModal = document.getElementById('question-modal');
            if (questionModal) {
                console.log('🔍 [ONBOARDING] Question modal found:', questionModal);
                console.log('🔍 [ONBOARDING] Current display style:', questionModal.style.display);
                console.log('🔍 [ONBOARDING] Current visibility:', questionModal.style.visibility);
                console.log('🔍 [ONBOARDING] Current opacity:', questionModal.style.opacity);
                
                // Try to show the modal
                questionModal.style.display = 'block';
                questionModal.style.visibility = 'visible';
                questionModal.style.opacity = '1';
                
                console.log('✅ [ONBOARDING] Attempted to show question modal');
                console.log('🔍 [ONBOARDING] New display style:', questionModal.style.display);
            } else {
                console.error('❌ [ONBOARDING] Question modal not found!');
            }
        };
        console.log('🧪 [ONBOARDING] Test function added: testQuestionModal()');
    }
});

/**
 * Check if onboarding is already complete for this instructor
 * This function runs EXACTLY ONCE and never loops
 */
async function checkOnboardingStatus() {
    // CRITICAL: Prevent multiple status checks
    if (onboardingState.statusChecked) {
        return;
    }
    
    // Mark as checked immediately to prevent any possibility of loops
    onboardingState.statusChecked = true;
    
    try {
        // Check if there's a courseId in URL params (from redirect)
        const urlParams = new URLSearchParams(window.location.search);
        const courseId = urlParams.get('courseId');
        
        if (courseId) {
            // Skip API call for now
        }
        
        // Only check instructor courses if we don't have a courseId from URL
        if (!courseId) {
            // Skip API call for now
        }
        
        // If we get here, onboarding is NOT complete
        showOnboardingFlow();
        
    } catch (error) {
        console.error('Error during status check:', error);
        // Even on error, don't loop - just show normal flow
        showOnboardingFlow();
    }
}

// GLOBAL GUARD: Prevent any other code from calling this function after it's been called once
const originalCheckOnboardingStatus = checkOnboardingStatus;
checkOnboardingStatus = function() {
    if (onboardingState.statusChecked) {
        console.log('🚫 [ONBOARDING] BLOCKED: Status check called after already completed!');
        return Promise.resolve();
    }
    return originalCheckOnboardingStatus.apply(this, arguments);
};

/**
 * Show onboarding complete message
 */
function showOnboardingComplete() {
    // Prevent multiple calls
    if (document.getElementById('onboarding-complete').style.display === 'block') {
        return;
    }
    
    // Hide all onboarding steps
    document.querySelectorAll('.onboarding-step').forEach(step => {
        step.style.display = 'none';
    });
    
    // Hide progress bar
    document.querySelector('.onboarding-progress').style.display = 'none';
    
    // Show completion message
    document.getElementById('onboarding-complete').style.display = 'block';
    
    // Update the course upload link to include the existing course ID
    if (onboardingState.existingCourseId) {
        const courseUploadLink = document.querySelector('#onboarding-complete .btn-primary');
        if (courseUploadLink) {
            courseUploadLink.href = `/instructor/documents?courseId=${onboardingState.existingCourseId}`;
        }
    }
    
    // Auto-redirect after 5 seconds to prevent users from staying on onboarding
    setTimeout(() => {
        if (onboardingState.existingCourseId) {
            window.location.href = `/instructor/documents?courseId=${onboardingState.existingCourseId}`;
        } else {
            window.location.href = '/instructor/documents';
        }
    }, 5000);
}

/**
 * Show normal onboarding flow
 */
function showOnboardingFlow() {
    // Prevent multiple calls
    if (document.getElementById('onboarding-complete').style.display === 'none' && 
        document.querySelector('.onboarding-progress').style.display === 'block') {
        return;
    }
    
    // Hide completion message
    document.getElementById('onboarding-complete').style.display = 'none';
    
    // Show progress bar
    document.querySelector('.onboarding-progress').style.display = 'block';
    
    // Show first step
    showStep(1);
}

/**
 * Initialize all onboarding functionality
 */
async function initializeOnboarding() {
    // First, check if onboarding is already complete
    await checkOnboardingStatus();
    
    // Only continue with initialization if onboarding is not complete
    if (onboardingState.existingCourseId) {
        return; // Onboarding is complete, don't initialize further
    }
    
    // Initialize form handlers
    initializeFormHandlers();
    
    // Initialize file upload handlers
    // initializeFileUpload(); // Removed as per edit hint
    
    // Initialize progress bar
    updateProgressBar();
    
    // Show first step (this will be overridden if onboarding is complete)
    showStep(1);
    
    // Add debugging for learning objectives
    setTimeout(() => {
        const addButton = document.querySelector('.add-objective-btn');
        if (addButton) {
            // Remove any existing onclick to avoid conflicts
            addButton.removeAttribute('onclick');
            
            addButton.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                addObjective();
            });
        }
    }, 1000); // Wait a bit for DOM to be ready
}

/**
 * Initialize guided substep functionality
 */
function initializeGuidedSubsteps() {
    // Initialize progress card click handlers
    const progressCards = document.querySelectorAll('.progress-card');
    progressCards.forEach(card => {
        card.addEventListener('click', () => {
            const substep = card.dataset.substep;
            if (substep) {
                showSubstep(substep);
            }
        });
    });
}

/**
 * Wait for instructor.js functions to be available
 */
function waitForInstructorFunctions() {
    return new Promise((resolve) => {
        const checkFunctions = () => {
            const requiredFunctions = [
                'openUploadModal',
                'closeUploadModal',
                'triggerFileInput',
                'handleFileUpload',
                'handleUpload',
                'addContentToWeek'
            ];
            
            const availableFunctions = requiredFunctions.filter(func => typeof window[func] === 'function');
            
            if (availableFunctions.length === requiredFunctions.length) {
                console.log('✅ [ONBOARDING] All required instructor.js functions are available');
                resolve(true);
            } else {
                console.log('⏳ [ONBOARDING] Waiting for instructor.js functions...', {
                    available: availableFunctions,
                    missing: requiredFunctions.filter(func => typeof window[func] !== 'function')
                });
                setTimeout(checkFunctions, 100);
            }
        };
        
        checkFunctions();
    });
}

/**
 * Initialize modal click-outside functionality
 */
async function initializeModalFunctionality() {
    // Wait for instructor.js functions to be available
    await waitForInstructorFunctions();
    
    const questionModal = document.getElementById('question-modal');
    if (questionModal) {
        questionModal.addEventListener('click', (event) => {
            if (event.target === questionModal) {
                closeQuestionModalFromInstructor();
            }
        });
    }

    const uploadModal = document.getElementById('upload-modal');
    if (uploadModal) {
        uploadModal.addEventListener('click', (event) => {
            if (event.target === uploadModal) {
                closeUploadModalFromInstructor();
            }
        });
    }
    
    // Override the instructor.js addContentToWeek function for onboarding
    overrideInstructorFunctions();
    
    // Set up upload completion monitoring as a fallback
    monitorUploadCompletion();
}

/**
 * Override instructor.js functions to work with onboarding page structure
 */
function overrideInstructorFunctions() {
    // Don't override functions - just ensure they exist
    console.log('🔧 [ONBOARDING] Checking instructor.js function availability...');
    
    const requiredFunctions = [
        'openUploadModal',
        'closeUploadModal', 
        'triggerFileInput',
        'handleFileUpload',
        'handleUpload',
        'openQuestionModal',
        'closeQuestionModal',
        'updateQuestionForm',
        'saveQuestion',
        'addContentToWeek'
    ];
    
    const availableFunctions = requiredFunctions.filter(func => typeof window[func] === 'function');
    const missingFunctions = requiredFunctions.filter(func => typeof window[func] !== 'function');
    
    if (missingFunctions.length > 0) {
        console.warn('⚠️ [ONBOARDING] Missing instructor.js functions:', missingFunctions);
    } else {
        console.log('✅ [ONBOARDING] All required instructor.js functions are available');
    }
    
    // Override only addContentToWeek to work with onboarding structure
    if (typeof window.addContentToWeek === 'function') {
        const originalAddContentToWeek = window.addContentToWeek;
        window.addContentToWeek = function(week, fileName, description, documentId) {
            console.log('🔧 [ONBOARDING] Overriding addContentToWeek for onboarding structure');
            
            // Check if we're on the onboarding page
            if (window.location.pathname.includes('/onboarding')) {
                addContentToWeekOnboarding(week, fileName, description, documentId);
            } else {
                // Use original function for main instructor page
                originalAddContentToWeek(week, fileName, description, documentId);
            }
        };
        console.log('✅ [ONBOARDING] Successfully overrode addContentToWeek function');
    } else {
        console.warn('⚠️ [ONBOARDING] addContentToWeek function not found in instructor.js');
    }
}

/**
 * Custom addContentToWeek function for onboarding page structure
 */
function addContentToWeekOnboarding(week, fileName, description, documentId) {
    console.log('🔧 [ONBOARDING] addContentToWeekOnboarding called:', { week, fileName, description, documentId });
    
    // Get the current content type from the global variable
    const contentType = window.currentContentType || 'additional';
    console.log('🔧 [ONBOARDING] Content type:', contentType);
    
    // Also try to determine content type from the function call context
    let detectedContentType = contentType;
    if (fileName && fileName.toLowerCase().includes('lecture')) {
        detectedContentType = 'lecture-notes';
    } else if (fileName && fileName.toLowerCase().includes('practice') || fileName && fileName.toLowerCase().includes('quiz')) {
        detectedContentType = 'practice-quiz';
    } else if (contentType === 'additional') {
        detectedContentType = 'additional';
    }
    
    console.log('🔧 [ONBOARDING] Detected content type:', detectedContentType);
    
    // Find the appropriate status badge based on content type
    let statusBadge = null;
    let statusText = 'Uploaded';
    
    switch (detectedContentType) {
        case 'lecture-notes':
            statusBadge = document.getElementById('lecture-status');
            statusText = 'Uploaded';
            // Update state
            onboardingState.uploadStatus['lecture-notes'] = true;
            console.log('✅ [ONBOARDING] Set lecture-notes upload status to true');
            break;
        case 'practice-quiz':
            statusBadge = document.getElementById('practice-status');
            statusText = 'Uploaded';
            // Update state
            onboardingState.uploadStatus['practice-quiz'] = true;
            console.log('✅ [ONBOARDING] Set practice-quiz upload status to true');
            break;
        case 'additional':
            statusBadge = document.getElementById('additional-status');
            statusText = 'Added';
            // Update state
            onboardingState.uploadStatus['additional'] = true;
            console.log('✅ [ONBOARDING] Set additional upload status to true');
            break;
        default:
            statusBadge = document.getElementById('additional-status');
            statusText = 'Uploaded';
            // Update state for additional
            onboardingState.uploadStatus['additional'] = true;
            console.log('✅ [ONBOARDING] Set default upload status to true');
    }
    
    if (statusBadge) {
        // Update the status badge
        statusBadge.textContent = statusText;
        statusBadge.style.background = 'rgba(40, 167, 69, 0.1)';
        statusBadge.style.color = '#28a745';
        
        console.log('✅ [ONBOARDING] Updated status badge for', detectedContentType, 'to:', statusText);
        console.log('📊 [ONBOARDING] Updated upload status:', onboardingState.uploadStatus);
        
        // Store the document ID in the status badge for future reference
        if (documentId) {
            statusBadge.dataset.documentId = documentId;
        }
        
        // Show success notification
        showNotification(`${detectedContentType.replace('-', ' ')} uploaded successfully!`, 'success');
    } else {
        console.error('❌ [ONBOARDING] Could not find status badge for content type:', detectedContentType);
        showNotification('Content uploaded but status could not be updated.', 'warning');
    }
}

/**
 * Check and display current upload status
 */
function checkAndDisplayUploadStatus() {
    console.log('🔍 [ONBOARDING] Checking current upload status...');
    
    // Check if status badges exist and update them based on state
    const lectureStatus = document.getElementById('lecture-status');
    const practiceStatus = document.getElementById('practice-status');
    const additionalStatus = document.getElementById('additional-status');
    
    if (lectureStatus) {
        if (onboardingState.uploadStatus['lecture-notes']) {
            lectureStatus.textContent = 'Uploaded';
            lectureStatus.style.background = 'rgba(40, 167, 69, 0.1)';
            lectureStatus.style.color = '#28a745';
        } else {
            lectureStatus.textContent = 'Not Uploaded';
            lectureStatus.style.background = 'rgba(220, 53, 69, 0.1)';
            lectureStatus.style.color = '#dc3545';
        }
    }
    
    if (practiceStatus) {
        if (onboardingState.uploadStatus['practice-quiz']) {
            practiceStatus.textContent = 'Uploaded';
            practiceStatus.style.background = 'rgba(40, 167, 69, 0.1)';
            practiceStatus.style.color = '#28a745';
        } else {
            practiceStatus.textContent = 'Not Uploaded';
            practiceStatus.style.background = 'rgba(220, 53, 69, 0.1)';
            practiceStatus.style.color = '#dc3545';
        }
    }
    
    if (additionalStatus) {
        if (onboardingState.uploadStatus['additional']) {
            additionalStatus.textContent = 'Added';
            additionalStatus.style.background = 'rgba(40, 167, 69, 0.1)';
            additionalStatus.style.color = '#28a745';
        } else {
            additionalStatus.textContent = 'Optional';
            additionalStatus.style.background = 'rgba(108, 117, 125, 0.1)';
            additionalStatus.style.color = '#6c757d';
        }
    }
    
    console.log('📊 [ONBOARDING] Current upload status:', onboardingState.uploadStatus);
}

/**
 * Check if required DOM elements exist for upload functionality
 */
function checkUploadRequirements() {
    console.log('🔍 [ONBOARDING] Checking upload requirements...');
    
    const requiredElements = {
        'upload-modal': document.getElementById('upload-modal'),
        'file-input': document.getElementById('file-input'),
        'url-input': document.getElementById('url-input'),
        'text-input': document.getElementById('text-input'),
        'upload-btn': document.getElementById('upload-btn'),
        'lecture-status': document.getElementById('lecture-status'),
        'practice-status': document.getElementById('practice-status'),
        'additional-status': document.getElementById('additional-status')
    };
    
    console.log('🔍 [ONBOARDING] Required elements status:', requiredElements);
    
    const missingElements = Object.entries(requiredElements)
        .filter(([name, element]) => !element)
        .map(([name]) => name);
    
    if (missingElements.length > 0) {
        console.error('❌ [ONBOARDING] Missing required elements:', missingElements);
        return false;
    }
    
    console.log('✅ [ONBOARDING] All required elements found');
    return true;
}

/**
 * Initialize form event handlers
 */
function initializeFormHandlers() {
    // Course selection handler
    const courseSelect = document.getElementById('course-select');
    if (courseSelect) {
        courseSelect.addEventListener('change', handleCourseSelection);
    }
    
    // Custom course name handler
    const customCourseSection = document.getElementById('custom-course-section');
    const customCourseName = document.getElementById('custom-course-name');
    if (customCourseName) {
        customCourseName.addEventListener('input', handleCustomCourseInput);
    }
    
    // Course setup form handler
    const courseSetupForm = document.getElementById('course-setup-form');
    if (courseSetupForm) {
        courseSetupForm.addEventListener('submit', handleCourseSetup);
    }
}

/**
 * Handle course selection change
 */
function handleCourseSelection(event) {
    const courseSelect = event.target;
    const customCourseSection = document.getElementById('custom-course-section');
    
    if (courseSelect.value === 'custom') {
        customCourseSection.style.display = 'block';
    } else {
        customCourseSection.style.display = 'none';
        // Store course data
        onboardingState.courseData.course = courseSelect.value;
    }
}

/**
 * Handle custom course name input
 */
function handleCustomCourseInput(event) {
    onboardingState.courseData.course = event.target.value;
}

/**
 * Handle course setup form submission
 */
async function handleCourseSetup(event) {
    event.preventDefault();
    
    // Prevent multiple submissions
    if (onboardingState.isSubmitting) {
        return;
    }
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    
    // Validate form
    if (!validateCourseSetup()) {
        return;
    }
    
    // Collect form data
    const formData = new FormData(form);
    const weeks = parseInt(formData.get('weeks'));
    const lecturesPerWeek = parseInt(formData.get('lecturesPerWeek'));
    
    onboardingState.courseData = {
        course: formData.get('course') === 'custom' ? 
            document.getElementById('custom-course-name').value : 
            formData.get('course'),
        weeks: weeks,
        lecturesPerWeek: lecturesPerWeek,
        totalUnits: weeks * lecturesPerWeek // Calculate total units
    };
    
    // Set submitting flag and disable submit button
    onboardingState.isSubmitting = true;
    submitButton.disabled = true;
    submitButton.textContent = 'Creating course...';
    
    try {
        // Check if course already exists for this instructor
        const existingCourse = await checkExistingCourse();
        if (existingCourse) {
            showNotification('You already have a course set up. Redirecting to course page...', 'info');
            setTimeout(() => {
                window.location.href = `/instructor/documents?courseId=${existingCourse.courseId}`;
            }, 2000);
            return;
        }
        
        // Create course and save to database
        const response = await createCourse(onboardingState.courseData);
        onboardingState.createdCourseId = response.courseId;
        
        // Update the courseData with the created course ID and instructor ID
        onboardingState.courseData.courseId = response.courseId;
        onboardingState.courseData.instructorId = 'instructor-123'; // This should match what's used in createCourse
        
        // Set global course ID for instructor.js functions
        if (typeof window.currentCourseId !== 'undefined') {
            window.currentCourseId = response.courseId;
        }
        if (typeof window.getCurrentCourseId === 'function') {
            // Override the getCurrentCourseId function to return our course ID
            window.getCurrentCourseId = async function() {
                return onboardingState.createdCourseId;
            };
        }
        
        // Set global instructor ID for instructor.js functions
        ensureInstructorIdAvailable();
        
        console.log('✅ [ONBOARDING] Updated onboarding state:', {
            createdCourseId: onboardingState.createdCourseId,
            courseData: onboardingState.courseData
        });
        
        // Verify the course was created by checking the database
        await verifyCourseCreation(response.courseId);
        
        // Move to next step (guided unit setup)
        nextStep();
        
    } catch (error) {
        console.error('Error creating course:', error);
        showNotification('Error creating course. Please try again.', 'error');
    } finally {
        // Reset submitting flag and re-enable submit button
        onboardingState.isSubmitting = false;
        submitButton.disabled = false;
        submitButton.textContent = 'Continue to Unit Setup';
    }
}

/**
 * Check if instructor already has a course
 */
async function checkExistingCourse() {
    try {
        const instructorId = 'instructor-123'; // This would come from authentication
        const response = await fetch(`/api/onboarding/instructor/${instructorId}`);
        
        if (response.ok) {
            const result = await response.json();
            if (result.data && result.data.courses && result.data.courses.length > 0) {
                // Return the first course found
                return result.data.courses[0];
            }
        }
        
        return null;
    } catch (error) {
        console.error('Error checking existing course:', error);
        return null;
    }
}

/**
 * Create course and save onboarding data to database
 */
async function createCourse(courseData) {
    try {
        console.log('🚀 [ONBOARDING] Starting course creation process...');
        console.log('📋 [ONBOARDING] Course data:', courseData);
        
        // Generate a course ID based on the course name
        let courseId = courseData.course.replace(/\s+/g, '-').toUpperCase();
        
        // Ensure the course ID is valid (no special characters, reasonable length)
        courseId = courseId.replace(/[^A-Z0-9-]/g, '');
        if (courseId.length > 20) {
            courseId = courseId.substring(0, 20);
        }
        
        // Add timestamp to ensure uniqueness
        courseId = `${courseId}-${Date.now()}`;
        console.log(`🆔 [ONBOARDING] Generated course ID: ${courseId}`);
        
        const instructorId = 'instructor-123'; // This would come from authentication in real app
        console.log(`👤 [ONBOARDING] Using instructor ID: ${instructorId}`);
        
        // Get learning objectives from the UI
        const learningObjectives = getLearningObjectivesFromUI();
        console.log('📚 [ONBOARDING] Learning objectives from UI:', learningObjectives);
        
        // Prepare onboarding data with unit structure
        const onboardingData = {
            courseId: courseId,
            courseName: courseData.course,
            instructorId: instructorId,
            courseDescription: '',
            learningOutcomes: learningObjectives,
            assessmentCriteria: '',
            courseMaterials: [],
            unitFiles: {},
            courseStructure: {
                weeks: courseData.weeks,
                lecturesPerWeek: courseData.lecturesPerWeek,
                totalUnits: courseData.totalUnits
            }
        };
        
        console.log('📋 [ONBOARDING] Prepared onboarding data:', onboardingData);
        
        // Initialize unit structure
        for (let i = 1; i <= courseData.totalUnits; i++) {
            const unitName = `Unit ${i}`;
            onboardingData.unitFiles[unitName] = [];
            
            // Add learning objectives to Unit 1
            if (i === 1 && learningObjectives.length > 0) {
                onboardingData.lectures = [{
                    name: unitName,
                    learningObjectives: learningObjectives,
                    isPublished: false,
                    passThreshold: 2,
                    createdAt: new Date(),
                    updatedAt: new Date()
                }];
            }
        }
        
        console.log('📋 [ONBOARDING] Final onboarding data with unit structure:', onboardingData);
        console.log(`📡 [MONGODB] Making API request to /api/onboarding (POST)`);
        
        const response = await fetch('/api/onboarding', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(onboardingData)
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to create course: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Course created successfully:', result);
        
        return {
            courseId: courseId,
            name: courseData.course,
            weeks: courseData.weeks,
            lecturesPerWeek: courseData.lecturesPerWeek,
            createdAt: new Date().toISOString(),
            status: 'active'
        };
        
    } catch (error) {
        console.error('❌ [ONBOARDING] Error creating course:', error);
        throw error;
    }
}

/**
 * Get learning objectives from the UI
 * @returns {Array} Array of learning objectives
 */
function getLearningObjectivesFromUI() {
    const objectivesList = document.getElementById('objectives-list');
    if (!objectivesList) {
        return [];
    }
    
    const objectives = [];
    const objectiveItems = objectivesList.querySelectorAll('.objective-display-item');    
    objectiveItems.forEach((item, index) => {
        const objectiveText = item.querySelector('.objective-text');
        if (objectiveText && objectiveText.textContent.trim()) {
            const text = objectiveText.textContent.trim();
            objectives.push(text);
            console.log(`Objective ${index + 1}:`, text);
        }
    });
    return objectives;
}

/**
 * Add a new learning objective
 */
function addObjective() {
    const inputField = document.getElementById('objective-input');
    const objectivesList = document.getElementById('objectives-list');
    
    if (!inputField || !objectivesList) {
        console.error('Could not find objective input or list elements');
        showNotification('Error: Could not find objective elements', 'error');
        return;
    }
    
    const objectiveText = inputField.value.trim();
    
    if (!objectiveText) {
        showNotification('Please enter a learning objective.', 'error');
        return;
    }
    
    // Create new objective display item
    const objectiveItem = document.createElement('div');
    objectiveItem.className = 'objective-display-item';
    objectiveItem.innerHTML = `
        <span class="objective-text">${objectiveText}</span>
        <button class="remove-objective" onclick="removeObjective(this)">×</button>
    `;
    
    // Add to the list
    objectivesList.appendChild(objectiveItem);
    
    // Clear the input field
    inputField.value = '';
    inputField.focus();
    
    showNotification('Learning objective added successfully!', 'success');
}

/**
 * Remove a learning objective
 * @param {HTMLElement} button - The remove button element
 */
function removeObjective(button) {
    const objectiveItem = button.closest('.objective-display-item');
    objectiveItem.remove();
    showNotification('Learning objective removed.', 'info');
}

/**
 * Validate course setup form
 */
function validateCourseSetup() {
    const courseSelect = document.getElementById('course-select');
    const weeksInput = document.getElementById('weeks-count');
    const lecturesInput = document.getElementById('lectures-per-week');
    
    let isValid = true;
    
    // Validate course selection
    if (!courseSelect.value) {
        showFieldError(courseSelect, 'Please select a course');
        isValid = false;
    }
    
    // Validate custom course name if selected
    if (courseSelect.value === 'custom') {
        const customName = document.getElementById('custom-course-name').value.trim();
        if (!customName) {
            showFieldError(document.getElementById('custom-course-name'), 'Please enter a course name');
            isValid = false;
        }
    }
    
    // Validate weeks input
    const weeks = parseInt(weeksInput.value);
    if (!weeks || weeks < 1 || weeks > 20) {
        showFieldError(weeksInput, 'Please enter a valid number of weeks (1-20)');
        isValid = false;
    }
    
    // Validate lectures per week input
    const lectures = parseInt(lecturesInput.value);
    if (!lectures || lectures < 1 || lectures > 5) {
        showFieldError(lecturesInput, 'Please enter a valid number of lectures per week (1-5)');
        isValid = false;
    }
    
    return isValid;
}

/**
 * Show a specific substep
 * @param {string} substepName - Name of the substep to show
 */
function showSubstep(substepName) {
    console.log(`🔄 [ONBOARDING] Showing substep: ${substepName}`);
    
    // Hide all substeps
    document.querySelectorAll('.guided-substep').forEach(substep => {
        substep.style.display = 'none';
    });
    
    // Show the selected substep
    const targetSubstep = document.getElementById(`substep-${substepName}`);
    if (targetSubstep) {
        targetSubstep.style.display = 'block';
        onboardingState.currentSubstep = substepName;
        
        // Special handling for specific substeps
        if (substepName === 'questions') {
            // Load existing assessment questions when showing questions substep
            loadExistingAssessmentQuestions();
        } else if (substepName === 'materials') {
            // Check and display current upload status when showing materials substep
            checkAndDisplayUploadStatus();
        }
        
        console.log(`✅ [ONBOARDING] Substep ${substepName} displayed successfully`);
    } else {
        console.error(`❌ [ONBOARDING] Substep ${substepName} not found`);
    }
}

/**
 * Navigate to next substep
 */
function nextSubstep(substepName) {
    showSubstep(substepName);
}

/**
 * Navigate to previous substep
 */
function previousSubstep(substepName) {
    showSubstep(substepName);
}

/**
 * Update progress bar
 */
function updateProgressBar() {
    const progressFill = document.getElementById('progress-fill');
    if (progressFill) {
        const progress = (onboardingState.currentStep / onboardingState.totalSteps) * 100;
        progressFill.style.width = `${progress}%`;
    }
}

/**
 * Complete onboarding and redirect to course management
 */
async function completeOnboarding() {
    try {
        // Validate that required content has been set up
        const objectivesList = document.getElementById('objectives-list');
        const objectives = objectivesList.querySelectorAll('.objective-display-item');
        
        if (objectives.length === 0) {
            showNotification('Please add at least one learning objective before continuing.', 'error');
            return;
        }
        
        // Check if required materials are uploaded using state instead of DOM text
        console.log('🔍 [ONBOARDING] Checking upload status:', onboardingState.uploadStatus);
        
        if (!onboardingState.uploadStatus['lecture-notes'] || !onboardingState.uploadStatus['practice-quiz']) {
            const missingMaterials = [];
            if (!onboardingState.uploadStatus['lecture-notes']) missingMaterials.push('Lecture Notes');
            if (!onboardingState.uploadStatus['practice-quiz']) missingMaterials.push('Practice Questions');
            
            showNotification(`Please upload required materials (${missingMaterials.join(' and ')}) before continuing.`, 'error');
            return;
        }
        
        // Show success message and redirect
        showNotification('Course setup completed successfully! Redirecting to course management...', 'success');
        
        // Wait a moment for the notification to be seen, then redirect with course ID
        setTimeout(() => {
            window.location.href = `/instructor/index.html?courseId=${onboardingState.createdCourseId}`;
        }, 1500);
        
    } catch (error) {
        console.error('Error completing onboarding:', error);
        showNotification('Error completing onboarding. Please try again.', 'error');
    }
}

/**
 * Ensure course ID is available to instructor.js functions
 */
function ensureCourseIdAvailable() {
    if (onboardingState.createdCourseId) {
        // Set global course ID for instructor.js functions
        if (typeof window.currentCourseId !== 'undefined') {
            window.currentCourseId = onboardingState.createdCourseId;
        }
        if (typeof window.getCurrentCourseId === 'function') {
            // Override the getCurrentCourseId function to return our course ID
            window.getCurrentCourseId = async function() {
                return onboardingState.createdCourseId;
            };
        }
        return true;
    }
    return false;
}

/**
 * Ensure instructor ID is available to instructor.js functions
 */
function ensureInstructorIdAvailable() {
    const instructorId = 'instructor-123'; // This would come from authentication in real app
    
    // Set global instructor ID for instructor.js functions
    if (typeof window.currentInstructorId !== 'undefined') {
        window.currentInstructorId = instructorId;
    }
    if (typeof window.getCurrentInstructorId === 'function') {
        // Override the getCurrentInstructorId function to return our instructor ID
        window.getCurrentInstructorId = function() {
            return instructorId;
        };
    }
    return instructorId;
}

/**
 * Open upload modal for a specific week and content type (local implementation)
 * @param {string} week - The week identifier (e.g., 'Unit 1')
 * @param {string} contentType - The content type ('lecture-notes', 'practice-quiz', 'additional', etc.)
 */
function openUploadModalFromInstructor(week, contentType = '') {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] openUploadModalFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    console.log(`🔓 [ONBOARDING] openUploadModalFromInstructor called: week=${week}, contentType=${contentType}`);
    
    // Check upload requirements first
    if (!checkUploadRequirements()) {
        showNotification('Upload functionality not properly initialized. Please refresh the page.', 'error');
        this.called = false;
        return;
    }
    
    // Ensure course ID and instructor ID are available
    if (!ensureCourseIdAvailable()) {
        showNotification('Please complete course setup before uploading materials.', 'error');
        this.called = false;
        return;
    }
    ensureInstructorIdAvailable();
    
    // Set global variables that instructor.js functions expect
    if (typeof window.currentWeek !== 'undefined') {
        window.currentWeek = week;
        console.log('✅ [ONBOARDING] Set currentWeek to:', week);
    }
    if (typeof window.currentContentType !== 'undefined') {
        window.currentContentType = contentType;
        console.log('✅ [ONBOARDING] Set currentContentType to:', contentType);
    }
    
    console.log('🔍 [ONBOARDING] Global variables set:', {
        currentWeek: window.currentWeek,
        currentContentType: window.currentContentType,
        currentCourseId: window.currentCourseId,
        currentInstructorId: window.currentInstructorId
    });
    
    // Call the function from instructor.js directly
    if (typeof window.openUploadModal === 'function') {
        console.log('📞 [ONBOARDING] Calling instructor.js openUploadModal function');
        try {
            window.openUploadModal(week, contentType);
        } catch (error) {
            console.error('❌ [ONBOARDING] Error calling instructor.js openUploadModal:', error);
            showNotification('Error opening upload modal. Please refresh the page.', 'error');
        }
    } else {
        console.error('❌ [ONBOARDING] openUploadModal function not found in instructor.js');
        showNotification('Upload functionality not available. Please refresh the page.', 'error');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Close the upload modal
 */
function closeUploadModalFromInstructor() {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] closeUploadModalFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    // Call the function from instructor.js directly
    if (typeof window.closeUploadModal === 'function') {
        console.log('📞 [ONBOARDING] Calling instructor.js closeUploadModal function');
        try {
            window.closeUploadModal();
        } catch (error) {
            console.error('❌ [ONBOARDING] Error calling instructor.js closeUploadModal:', error);
        }
    } else {
        console.error('❌ [ONBOARDING] closeUploadModal function not found in instructor.js');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Trigger file input click
 */
function triggerFileInputFromInstructor() {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] triggerFileInputFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    // Call the function from instructor.js directly
    if (typeof window.triggerFileInput === 'function') {
        console.log('📞 [ONBOARDING] Calling instructor.js triggerFileInput function');
        try {
            window.triggerFileInput();
        } catch (error) {
            console.error('❌ [ONBOARDING] Error calling instructor.js triggerFileInput:', error);
        }
    } else {
        console.error('❌ [ONBOARDING] triggerFileInput function not found in instructor.js');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Handle file upload (local implementation)
 * @param {File} file - The uploaded file
 */
function handleFileUploadFromInstructor(file) {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] handleFileUploadFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    console.log('📁 [ONBOARDING] handleFileUploadFromInstructor called with file:', file);
    
    // Call the function from instructor.js directly
    if (typeof window.handleFileUpload === 'function') {
        console.log('📞 [ONBOARDING] Calling instructor.js handleFileUpload function');
        try {
            window.handleFileUpload(file);
        } catch (error) {
            console.error('❌ [ONBOARDING] Error calling instructor.js handleFileUpload:', error);
            showNotification('File upload functionality not available. Please refresh the page.', 'error');
        }
    } else {
        console.error('❌ [ONBOARDING] handleFileUpload function not found in instructor.js');
        showNotification('File upload functionality not available. Please refresh the page.', 'error');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Handle the main upload action (local implementation)
 */
async function handleUploadFromInstructor() {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] handleUploadFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    console.log('🚀 [ONBOARDING] handleUploadFromInstructor called');
    
    // Call the function from instructor.js directly
    if (typeof window.handleUpload === 'function') {
        console.log('📞 [ONBOARDING] Calling instructor.js handleUpload function');
        try {
            await window.handleUpload();
            console.log('✅ [ONBOARDING] Upload completed successfully');
            
            // Force update upload status after successful upload
            setTimeout(() => {
                forceUpdateUploadStatus();
            }, 500);
            
        } catch (error) {
            console.error('❌ [ONBOARDING] Error during upload:', error);
            showNotification(`Upload failed: ${error.message}`, 'error');
        }
    } else {
        console.error('❌ [ONBOARDING] handleUpload function not found in instructor.js');
        showNotification('Upload functionality not available. Please refresh the page.', 'error');
    }
    
    // Reset the recursion guard
    this.called = false;
}


/**
 * Utility functions
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

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
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
        ${type === 'success' ? 'background-color: #28a745;' : 
          type === 'error' ? 'background-color: #dc3545;' : 
          type === 'warning' ? 'background-color: #ffc107;' : 
          'background-color: #17a2b8;'}
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
 * Add a new learning objective for a unit (used in onboarding)
 * @param {string} unitName - The unit name (e.g., 'Unit 1')
 */
function addObjectiveForUnit(unitName) {
    addObjective(); // Reuse the existing addObjective function
}

/**
 * Open question modal for adding assessment questions
 */
function openQuestionModalFromInstructor(week) {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] openQuestionModalFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    console.log(`🔓 [ONBOARDING] openQuestionModalFromInstructor called: week=${week}`);
    
    // Ensure course ID and instructor ID are available
    if (!ensureCourseIdAvailable()) {
        showNotification('Please complete course setup before creating questions.', 'error');
        this.called = false;
        return;
    }
    ensureInstructorIdAvailable();
    
    // Set global variables that instructor.js functions expect
    if (typeof window.currentWeek !== 'undefined') {
        window.currentWeek = week;
    }
    
    // Find and show the question modal
    const questionModal = document.getElementById('question-modal');
    if (questionModal) {
        console.log('🔍 [ONBOARDING] Found question modal, displaying it');
        questionModal.classList.add('show');
        
        // Reset the form
        const questionTypeSelect = document.getElementById('question-type');
        if (questionTypeSelect) {
            questionTypeSelect.value = '';
            console.log('🔧 [ONBOARDING] Reset question type select');
        }
        
        // Hide all answer sections initially
        const answerSections = ['tf-answer-section', 'mcq-answer-section', 'sa-answer-section'];
        answerSections.forEach(sectionId => {
            const section = document.getElementById(sectionId);
            if (section) {
                section.style.display = 'none';
                console.log(`🔍 [ONBOARDING] Hidden section: ${sectionId}`);
            }
        });
        
        console.log('✅ [ONBOARDING] Question modal opened and form reset');
    } else {
        console.error('❌ [ONBOARDING] Question modal not found!');
        showNotification('Question modal not found. Please refresh the page.', 'error');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Close the question creation modal
 */
function closeQuestionModalFromInstructor() {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] closeQuestionModalFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    console.log('🔓 [ONBOARDING] closeQuestionModalFromInstructor called');
    
    // Find and hide the question modal
    const questionModal = document.getElementById('question-modal');
    if (questionModal) {
        questionModal.classList.remove('show');
        console.log('✅ [ONBOARDING] Question modal hidden');
    } else {
        console.error('❌ [ONBOARDING] Question modal not found for closing');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Update question form based on selected question type
 */
function updateQuestionFormFromInstructor() {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] updateQuestionFormFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    console.log('🔄 [ONBOARDING] updateQuestionFormFromInstructor called');
    
    // Get the question type
    const questionTypeSelect = document.getElementById('question-type');
    if (!questionTypeSelect) {
        console.error('❌ [ONBOARDING] Question type select not found');
        this.called = false;
        return;
    }
    
    const questionType = questionTypeSelect.value;
    console.log('🔍 [ONBOARDING] Question type selected:', questionType);
    
    // Hide all answer sections first
    const answerSections = [
        'tf-answer-section',      // True/False
        'mcq-answer-section',     // Multiple Choice
        'sa-answer-section'       // Short Answer
    ];
    
    answerSections.forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section) {
            section.style.display = 'none';
            console.log(`🔍 [ONBOARDING] Hidden section: ${sectionId}`);
        }
    });
    
    // Show the appropriate section based on question type
    if (questionType === 'multiple-choice') {
        const mcqSection = document.getElementById('mcq-answer-section');
        if (mcqSection) {
            mcqSection.style.display = 'block';
            console.log('✅ [ONBOARDING] Showed multiple choice section');
        }
        
    } else if (questionType === 'true-false') {
        const tfSection = document.getElementById('tf-answer-section');
        if (tfSection) {
            tfSection.style.display = 'block';
            console.log('✅ [ONBOARDING] Showed true/false section');
        }
        
    } else if (questionType === 'short-answer') {
        const saSection = document.getElementById('sa-answer-section');
        if (saSection) {
            saSection.style.display = 'block';
            console.log('✅ [ONBOARDING] Showed short answer section');
        }
    }
    
    console.log('✅ [ONBOARDING] Question form updated for type:', questionType);
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Save the question from the modal
 */
async function saveQuestionFromInstructor() {
    // Safety check to prevent recursion
    if (this.called) {
        console.error('❌ [ONBOARDING] saveQuestionFromInstructor called recursively!');
        return;
    }
    this.called = true;
    
    // Call the function from instructor.js directly
    if (typeof window.saveQuestion === 'function') {
        console.log('📞 [ONBOARDING] Calling instructor.js saveQuestion function');
        try {
            await window.saveQuestion();
            
            // After saving, reload the questions for this unit
            if (onboardingState.createdCourseId) {
                await loadExistingAssessmentQuestions();
            }
        } catch (error) {
            console.error('❌ [ONBOARDING] Error calling instructor.js saveQuestion:', error);
            showNotification('Question saving functionality not available. Please refresh the page.', 'error');
        }
    } else {
        console.error('❌ [ONBOARDING] saveQuestion function not found in instructor.js');
        showNotification('Question saving functionality not available. Please refresh the page.', 'error');
    }
    
    // Reset the recursion guard
    this.called = false;
}

/**
 * Update the questions display for onboarding
 * @param {string} lectureName - Name of the lecture/unit
 */
function updateOnboardingQuestionsDisplay(lectureName) {
    const containerId = 'assessment-questions-onboarding';
    const questionsContainer = document.getElementById(containerId);
    
    if (!questionsContainer) {
        console.error(`Container not found for onboarding questions: ${containerId}`);
        return;
    }
    
    // Clear existing content
    questionsContainer.innerHTML = '';
    
    // Get questions for this lecture
    const questions = onboardingState.assessmentQuestions?.[lectureName] || [];
    
    if (questions.length === 0) {
        // Show no questions message
        questionsContainer.innerHTML = `
            <div class="no-questions-message">
                <p>No assessment questions created yet. Click "Add Question" to get started.</p>
            </div>
        `;
        return;
    }
    
    // Create questions list
    const questionsList = document.createElement('div');
    questionsList.className = 'questions-list';
    
    questions.forEach((question, index) => {
        const questionItem = document.createElement('div');
        questionItem.className = 'question-item';
        questionItem.innerHTML = `
            <div class="question-content">
                <div class="question-header">
                    <span class="question-number">Q${index + 1}</span>
                    <span class="question-type">${question.type}</span>
                </div>
                <div class="question-text">${question.question}</div>
                ${question.type === 'multiple-choice' && question.options ? `
                    <div class="question-options">
                        ${Object.entries(question.options).map(([key, value]) => `
                            <div class="option ${key === question.answer ? 'correct' : ''}">
                                <span class="option-label">${key}:</span>
                                <span class="option-text">${value}</span>
                                ${key === question.answer ? '<span class="correct-badge">✓</span>' : ''}
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
                ${question.type === 'true-false' ? `
                    <div class="question-answer">
                        <span class="answer-label">Correct Answer:</span>
                        <span class="answer-text">${question.answer}</span>
                    </div>
                ` : ''}
                ${question.type === 'short-answer' ? `
                    <div class="question-answer">
                        <span class="answer-label">Expected Answer:</span>
                        <span class="answer-text">${question.answer}</span>
                    </div>
                ` : ''}
            </div>
            <div class="question-actions">
                <button class="btn-secondary btn-sm" onclick="deleteOnboardingQuestion('${question.questionId}', '${lectureName}')">Delete</button>
            </div>
        `;
        questionsList.appendChild(questionItem);
    });
    
    questionsContainer.appendChild(questionsList);
}

/**
 * Delete an assessment question from onboarding
 * @param {string} questionId - Question identifier
 * @param {string} lectureName - Lecture/unit name
 */
async function deleteOnboardingQuestion(questionId, lectureName) {
    try {
        const courseId = onboardingState.createdCourseId;
        const instructorId = 'instructor-123'; // This would come from authentication in real app
        
        if (!courseId) {
            throw new Error('No course ID available.');
        }
        
        const response = await fetch(`/api/questions/${questionId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: lectureName,
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Delete failed: ${response.status} ${errorText}`);
        }
        
        // Remove from local state
        if (onboardingState.assessmentQuestions?.[lectureName]) {
            onboardingState.assessmentQuestions[lectureName] = onboardingState.assessmentQuestions[lectureName].filter(
                q => q.questionId !== questionId
            );
        }
        
        // Update the display
        updateOnboardingQuestionsDisplay(lectureName);
        
        showNotification('Question deleted successfully!', 'success');
        
    } catch (error) {
        console.error('Error deleting question:', error);
        showNotification(`Error deleting question: ${error.message}`, 'error');
    }
}

/**
 * Save assessment for the current week
 */
async function saveAssessment(week) {
    try {
        // For now, just show a success message
        // In a full implementation, this would save to the database
        showNotification(`Assessment saved for ${week}!`, 'success');
    } catch (error) {
        console.error('Error saving assessment:', error);
        showNotification(`Failed to save assessment: ${error.message}`, 'error');
    }
}

/**
 * Complete Unit 1 setup (alias for completeOnboarding)
 */
async function completeUnit1Setup() {
    await completeOnboarding();
}

/**
 * Load existing assessment questions from the database
 */
async function loadExistingAssessmentQuestions() {
    try {
        const courseId = onboardingState.createdCourseId;
        const instructorId = 'instructor-123'; // This would come from authentication in real app

        if (!courseId) {
            console.warn('❌ [ONBOARDING] No course ID available to load assessment questions.');
            return;
        }

        console.log('🚀 [ONBOARDING] Loading existing assessment questions for course:', courseId);

        // Use the existing lecture endpoint to get questions for Unit 1
        const response = await fetch(`/api/questions/lecture?courseId=${courseId}&lectureName=Unit 1`);
        console.log('📡 [ONBOARDING] Questions API response status:', response.status, response.statusText);
        
        if (response.ok) {
            const result = await response.json();
            console.log('📡 [ONBOARDING] Questions API response data:', result);
            
            if (result.data && result.data.questions) {
                onboardingState.assessmentQuestions = {};
                onboardingState.assessmentQuestions['Unit 1'] = result.data.questions.map(q => ({
                    id: q.questionId,
                    questionId: q.questionId,
                    type: q.questionType,
                    question: q.question,
                    answer: q.correctAnswer,
                    options: q.options || {}
                }));
                console.log('✅ [ONBOARDING] Loaded', result.data.questions.length, 'assessment questions for Unit 1.');
                console.log('📋 [ONBOARDING] Questions data:', onboardingState.assessmentQuestions['Unit 1']);
                
                // Update the display
                updateOnboardingQuestionsDisplay('Unit 1');
            } else {
                console.warn('⚠️ [ONBOARDING] No assessment questions found for Unit 1.');
                console.log('📋 [ONBOARDING] Response data structure:', result);
            }
        } else {
            const errorText = await response.text();
            console.error(`❌ [ONBOARDING] Failed to load assessment questions: ${response.status} ${errorText}`);
        }
    } catch (error) {
        console.error('❌ [ONBOARDING] Error loading assessment questions:', error);
    }
}

/**
 * Verify course creation by fetching it from the database
 */
async function verifyCourseCreation(courseId) {
    try {
        console.log('🔍 [ONBOARDING] Verifying course creation with ID:', courseId);
        const response = await fetch(`/api/courses/${courseId}`);
        if (response.ok) {
            const result = await response.json();
            console.log('✅ [ONBOARDING] Course verified successfully:', result);
            // Course exists, continue with onboarding flow
            return true;
        } else {
            const errorText = await response.text();
            console.error(`❌ [ONBOARDING] Course verification failed: ${response.status} ${errorText}`);
            return false;
        }
    } catch (error) {
        console.error('❌ [ONBOARDING] Error verifying course creation:', error);
        return false;
    }
}

/**
 * Test function to verify assessment questions are working
 */
function testAssessmentQuestions() {
    console.log('🧪 [ONBOARDING] Testing assessment questions functionality...');
    
    // Test learning objectives functionality
    const objectivesList = document.getElementById('objectives-list');
    if (objectivesList) {
        const objectives = getLearningObjectivesFromUI();
        console.log('📚 [ONBOARDING] Learning objectives:', objectives);
        if (objectives.length > 0) {
            addObjective(); // Add a new objective
            console.log('✅ [ONBOARDING] Added a new objective.');
            const objectivesAfterAdd = getLearningObjectivesFromUI();
            console.log('📚 [ONBOARDING] Learning objectives after add:', objectivesAfterAdd);
            if (objectivesAfterAdd.length > objectives.length) {
                console.log('✅ [ONBOARDING] Objective add functionality works.');
            } else {
                console.error('❌ [ONBOARDING] Objective add functionality failed.');
            }
        } else {
            console.warn('⚠️ [ONBOARDING] No objectives to test add functionality.');
        }
    } else {
        console.error('❌ [ONBOARDING] Objectives list not found for testing.');
    }

    // Test course setup functionality
    const courseSetupForm = document.getElementById('course-setup-form');
    if (courseSetupForm) {
        const courseSelect = document.getElementById('course-select');
        const customCourseName = document.getElementById('custom-course-name');
        const weeksInput = document.getElementById('weeks-count');
        const lecturesInput = document.getElementById('lectures-per-week');

        if (courseSelect && customCourseName && weeksInput && lecturesInput) {
            // Simulate form submission
            courseSelect.value = 'custom';
            customCourseName.value = 'Test Course';
            weeksInput.value = '4';
            lecturesInput.value = '3';
            console.log('📋 [ONBOARDING] Simulating form submission with test data.');
            handleCourseSetup({ preventDefault: () => {} }); // Mock event
            console.log('✅ [ONBOARDING] Simulated form submission.');
        } else {
            console.warn('⚠️ [ONBOARDING] Form elements not found for testing.');
        }
    } else {
        console.error('❌ [ONBOARDING] Course setup form not found for testing.');
    }

    // Test assessment questions functionality
    if (onboardingState.createdCourseId) {
        console.log('🧪 [ONBOARDING] Testing assessment questions with course ID:', onboardingState.createdCourseId);
        
        // Test opening question modal
        openQuestionModalFromInstructor('Unit 1');
        console.log('🔓 [ONBOARDING] Opened question modal for Unit 1.');
        
        // Test loading existing questions
        loadExistingAssessmentQuestions();
        console.log('✅ [ONBOARDING] Tested loading existing questions.');
        
        // Close question modal
        closeQuestionModalFromInstructor();
        console.log('🔒 [ONBOARDING] Closed question modal.');
    } else {
        console.warn('⚠️ [ONBOARDING] No course ID available to test assessment questions.');
    }

    console.log('🧪 [ONBOARDING] Assessment questions test complete.');
}

/**
 * Debug function to check upload status and help troubleshoot issues
 */
function debugUploadStatus() {
    console.log('🔍 [ONBOARDING] === UPLOAD STATUS DEBUG ===');
    console.log('📊 [ONBOARDING] onboardingState.uploadStatus:', onboardingState.uploadStatus);
    
    // Check DOM elements
    const lectureStatus = document.getElementById('lecture-status');
    const practiceStatus = document.getElementById('practice-status');
    const additionalStatus = document.getElementById('additional-status');
    
    console.log('🔍 [ONBOARDING] DOM Elements:');
    console.log('  - lecture-status:', lectureStatus);
    console.log('  - practice-status:', practiceStatus);
    console.log('  - additional-status:', additionalStatus);
    
    if (lectureStatus) {
        console.log('  - lecture-status text:', lectureStatus.textContent);
        console.log('  - lecture-status style:', lectureStatus.style.background, lectureStatus.style.color);
    }
    
    if (practiceStatus) {
        console.log('  - practice-status text:', practiceStatus.textContent);
        console.log('  - practice-status style:', practiceStatus.style.background, practiceStatus.style.color);
    }
    
    if (additionalStatus) {
        console.log('  - additional-status text:', additionalStatus.textContent);
        console.log('  - additional-status style:', additionalStatus.style.background, additionalStatus.style.color);
    }
    
    // Check global variables
    console.log('🔍 [ONBOARDING] Global Variables:');
    console.log('  - window.currentWeek:', window.currentWeek);
    console.log('  - window.currentContentType:', window.currentContentType);
    console.log('  - window.currentCourseId:', window.currentCourseId);
    console.log('  - window.currentInstructorId:', window.currentInstructorId);
    
    console.log('🔍 [ONBOARDING] === END DEBUG ===');
}

/**
 * Manually set upload status for testing purposes
 * @param {string} contentType - The content type ('lecture-notes', 'practice-quiz', 'additional')
 * @param {boolean} isUploaded - Whether the content is uploaded
 */
function setUploadStatus(contentType, isUploaded) {
    console.log(`🔧 [ONBOARDING] Setting upload status for ${contentType} to ${isUploaded}`);
    
    if (onboardingState.uploadStatus.hasOwnProperty(contentType)) {
        onboardingState.uploadStatus[contentType] = isUploaded;
        console.log(`✅ [ONBOARDING] Updated upload status:`, onboardingState.uploadStatus);
        
        // Update the UI to reflect the new status
        checkAndDisplayUploadStatus();
        
        showNotification(`${contentType.replace('-', ' ')} status set to ${isUploaded ? 'uploaded' : 'not uploaded'}`, 'success');
    } else {
        console.error(`❌ [ONBOARDING] Invalid content type: ${contentType}`);
        showNotification(`Invalid content type: ${contentType}`, 'error');
    }
}

/**
 * Monitor upload completion and update status
 * This is a fallback mechanism in case addContentToWeek is not called
 */
function monitorUploadCompletion() {
    console.log('🔍 [ONBOARDING] Setting up upload completion monitoring...');
    
    // Monitor the upload button for successful uploads
    const uploadBtn = document.getElementById('upload-btn');
    if (uploadBtn) {
        // Create a mutation observer to watch for changes in the upload button
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.type === 'attributes' && mutation.attributeName === 'disabled') {
                    // Upload button was disabled, which usually means upload completed
                    if (uploadBtn.disabled === false) {
                        console.log('🔍 [ONBOARDING] Upload button re-enabled, upload may have completed');
                        // Small delay to ensure the upload process is complete
                        setTimeout(() => {
                            updateUploadStatusFromUI();
                        }, 1000);
                    }
                }
            });
        });
        
        observer.observe(uploadBtn, { attributes: true });
        console.log('✅ [ONBOARDING] Upload completion monitoring set up');
    }
}

/**
 * Update upload status based on UI state
 * This is a fallback method to detect uploads
 */
function updateUploadStatusFromUI() {
    console.log('🔍 [ONBOARDING] Checking UI state for upload status...');
    
    // Check if any status badges show "Uploaded" or "Added"
    const lectureStatus = document.getElementById('lecture-status');
    const practiceStatus = document.getElementById('practice-status');
    const additionalStatus = document.getElementById('additional-status');
    
    if (lectureStatus && lectureStatus.textContent.includes('Uploaded')) {
        onboardingState.uploadStatus['lecture-notes'] = true;
        console.log('✅ [ONBOARDING] Detected lecture notes as uploaded from UI');
    }
    
    if (practiceStatus && practiceStatus.textContent.includes('Uploaded')) {
        onboardingState.uploadStatus['practice-quiz'] = true;
        console.log('✅ [ONBOARDING] Detected practice quiz as uploaded from UI');
    }
    
    if (additionalStatus && (additionalStatus.textContent.includes('Added') || additionalStatus.textContent.includes('Uploaded'))) {
        onboardingState.uploadStatus['additional'] = true;
        console.log('✅ [ONBOARDING] Detected additional materials as uploaded from UI');
    }
    
    console.log('📊 [ONBOARDING] Current upload status after UI check:', onboardingState.uploadStatus);
}

/**
 * Force update upload status based on current content type
 * This can be called after successful uploads to ensure status is updated
 */
function forceUpdateUploadStatus() {
    console.log('🔧 [ONBOARDING] Force updating upload status...');
    
    const contentType = window.currentContentType;
    if (contentType) {
        console.log('🔧 [ONBOARDING] Current content type:', contentType);
        
        // Update the appropriate status
        switch (contentType) {
            case 'lecture-notes':
                onboardingState.uploadStatus['lecture-notes'] = true;
                console.log('✅ [ONBOARDING] Force updated lecture-notes status to true');
                break;
            case 'practice-quiz':
                onboardingState.uploadStatus['practice-quiz'] = true;
                console.log('✅ [ONBOARDING] Force updated practice-quiz status to true');
                break;
            case 'additional':
                onboardingState.uploadStatus['additional'] = true;
                console.log('✅ [ONBOARDING] Force updated additional status to true');
                break;
        }
        
        // Update the UI to reflect the new status
        checkAndDisplayUploadStatus();
        
        console.log('📊 [ONBOARDING] Updated upload status:', onboardingState.uploadStatus);
    } else {
        console.warn('⚠️ [ONBOARDING] No current content type available for force update');
    }
}

// Add debug function to window for easy access
window.debugUploadStatus = debugUploadStatus;
// Add manual upload status functions to window for easy access
window.setLectureNotesUploaded = () => setUploadStatus('lecture-notes', true);
window.setPracticeQuizUploaded = () => setUploadStatus('practice-quiz', true);
window.setAdditionalUploaded = () => setUploadStatus('additional', true);
window.resetUploadStatus = () => {
    onboardingState.uploadStatus['lecture-notes'] = false;
    onboardingState.uploadStatus['practice-quiz'] = false;
    onboardingState.uploadStatus['additional'] = false;
    checkAndDisplayUploadStatus();
    showNotification('Upload status reset', 'info');
};

// Add function to manually check and update upload status from UI
window.checkUploadStatusFromUI = updateUploadStatusFromUI;