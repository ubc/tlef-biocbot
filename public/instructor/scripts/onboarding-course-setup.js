/**
 * Onboarding: course selection, join-by-code, creation, and validation.
 * Part of the instructor onboarding page. Loads after onboarding-state.js.
 */

async function checkCourseCodeBypassPermission() {
    try {
        const response = await fetch('/api/settings/can-delete-all', {
            credentials: 'include'
        });

        const result = await response.json();
        return !!(result.success && result.canDeleteAll);
    } catch (error) {
        console.error('Error checking onboarding instructor-code bypass permission:', error);
        return false;
    }
}

function applyJoinCourseCodePermission() {
    const codeHelp = document.getElementById('instructor-course-code-help');
    const codeGroup = document.getElementById('instructor-course-code-group');

    if (codeHelp) {
        codeHelp.textContent = canBypassOnboardingInstructorCourseCodes
            ? 'You have admin access, so no instructor code is required for you to join this course.'
            : 'Ask the course owner for the instructor course code.';
    }

    if (codeGroup && onboardingState.existingCourseId) {
        codeGroup.style.display = canBypassOnboardingInstructorCourseCodes ? 'none' : 'block';
    }

    if (canBypassOnboardingInstructorCourseCodes) {
        clearOnboardingJoinCourseCodeFeedback();
    }
}

/**
 * Handle course selection change
 */
function handleCourseSelection(event) {
    const courseSelect = event.target;
    const customCourseSection = document.getElementById('custom-course-section');
    const courseStructureSection = document.getElementById('course-structure-section');
    const joinCourseSection = document.getElementById('join-course-section');
    const continueBtn = document.getElementById('continue-btn');
    const joinCourseBtn = document.getElementById('join-course-btn');
    const codeGroup = document.getElementById('instructor-course-code-group');
    const codeInput = document.getElementById('instructor-course-code');
    clearOnboardingJoinCourseCodeFeedback();
    
    if (courseSelect.value === 'custom') {
        // Show custom course input and course structure
        customCourseSection.style.display = 'block';
        courseStructureSection.style.display = 'block';
        joinCourseSection.style.display = 'none';
        continueBtn.style.display = 'inline-block';
        joinCourseBtn.style.display = 'none';
        
        // Clear course data
        onboardingState.courseData.course = null;
        onboardingState.existingCourseId = null;
        if (codeGroup) codeGroup.style.display = 'none';
        if (codeInput) codeInput.value = '';
    } else if (courseSelect.value === '') {
        // No course selected
        customCourseSection.style.display = 'none';
        courseStructureSection.style.display = 'block';
        joinCourseSection.style.display = 'none';
        continueBtn.style.display = 'inline-block';
        joinCourseBtn.style.display = 'none';
        
        // Clear course data
        onboardingState.courseData.course = null;
        onboardingState.existingCourseId = null;
        if (codeGroup) codeGroup.style.display = 'none';
        if (codeInput) codeInput.value = '';
    } else {
        // Existing course selected
        customCourseSection.style.display = 'none';
        courseStructureSection.style.display = 'none';
        joinCourseSection.style.display = 'block';
        continueBtn.style.display = 'none';
        joinCourseBtn.style.display = 'inline-block';
        if (codeGroup) {
            codeGroup.style.display = canBypassOnboardingInstructorCourseCodes ? 'none' : 'block';
        }
        if (codeInput) codeInput.value = '';
        
        // Store course data and populate course details
        onboardingState.courseData.course = courseSelect.value;
        populateSelectedCourseDetails(courseSelect.value);
    }
}

/**
 * Handle custom course name input
 */
function handleCustomCourseInput(event) {
    onboardingState.courseData.course = event.target.value;
}

/**
 * Populate selected course details for joining
 */
function populateSelectedCourseDetails(courseId) {
    const courseDetailsContainer = document.getElementById('selected-course-details');
    
    // Find the course data from the available courses
    const courseSelect = document.getElementById('course-select');
    const selectedOption = courseSelect.querySelector(`option[value="${courseId}"]`);
    
    if (selectedOption) {
        const courseName = selectedOption.textContent;
        courseDetailsContainer.innerHTML = `
            <div class="course-info">
                <h4>${courseName}</h4>
                <p><strong>Course ID:</strong> ${courseId}</p>
                <p>${canBypassOnboardingInstructorCourseCodes
                    ? 'You have admin access, so you can join this course without entering an instructor code.'
                    : 'Enter the instructor course code to join this course.'}</p>
            </div>
        `;
        
        // Store the course ID for joining
        onboardingState.existingCourseId = courseId;
    }
}

function animateOnboardingJoinCourseCodeError(field) {
    if (!field) {
        return;
    }

    field.classList.remove('field-error-shake');
    void field.offsetWidth;
    field.classList.add('field-error-shake');
}

function setOnboardingJoinCourseCodeFeedback(message) {
    const codeInput = document.getElementById('instructor-course-code');
    const errorElement = document.getElementById('instructor-course-code-error');

    if (codeInput) {
        codeInput.classList.add('input-error');
        codeInput.setAttribute('aria-invalid', 'true');
        animateOnboardingJoinCourseCodeError(codeInput);
        codeInput.focus();
    }

    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
}

function clearOnboardingJoinCourseCodeFeedback() {
    const codeInput = document.getElementById('instructor-course-code');
    const errorElement = document.getElementById('instructor-course-code-error');

    if (codeInput) {
        codeInput.classList.remove('input-error', 'field-error-shake');
        codeInput.removeAttribute('aria-invalid');
    }

    if (errorElement) {
        errorElement.textContent = '';
        errorElement.style.display = 'none';
    }
}

/**
 * Join an existing course
 */
async function joinExistingCourse() {
    if (!onboardingState.existingCourseId) {
        showNotification('No course selected to join.', 'error');
        return;
    }

    const codeInput = document.getElementById('instructor-course-code');
    const code = codeInput ? codeInput.value.trim().toUpperCase() : '';
    if (!canBypassOnboardingInstructorCourseCodes && !code) {
        setOnboardingJoinCourseCodeFeedback('Instructor course code is required to join this course.');
        return;
    }

    clearOnboardingJoinCourseCodeFeedback();
    
    try {
        console.log(`🚀 [ONBOARDING] Joining existing course: ${onboardingState.existingCourseId}`);
        
        // Show loading state
        const joinBtn = document.getElementById('join-course-btn');
        const originalText = joinBtn.textContent;
        joinBtn.textContent = 'Joining Course...';
        joinBtn.disabled = true;
        
        // Call the join course API
        const response = await fetch(`/api/courses/${onboardingState.existingCourseId}/instructors`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                instructorId: getCurrentInstructorId(),
                code
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to join course');
        }
        
        const result = await response.json();
        console.log('✅ [ONBOARDING] Successfully joined course:', result);
        
        // Mark instructor's onboarding as complete since they joined an existing course
        await markInstructorOnboardingComplete(onboardingState.existingCourseId);
        
        // Show success message
        showNotification('Successfully joined the course!', 'success');
        
        // Redirect to the course page after a short delay
        setTimeout(() => {
            window.location.href = `/instructor/documents?courseId=${onboardingState.existingCourseId}`;
        }, 2000);
        
    } catch (error) {
        console.error('❌ [ONBOARDING] Error joining course:', error);
        if (codeInput && /course code|required|invalid/i.test(error.message)) {
            setOnboardingJoinCourseCodeFeedback(error.message);
        } else {
            showNotification(`Error joining course: ${error.message}`, 'error');
        }
        
        // Reset button state
        const joinBtn = document.getElementById('join-course-btn');
        joinBtn.textContent = 'Join Course';
        joinBtn.disabled = false;
    }
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
        // Only check for existing courses if not creating a custom course
        const courseSelect = document.getElementById('course-select');
        const isCustomCourse = courseSelect && courseSelect.value === 'custom';
        
        if (!isCustomCourse) {
            // Check if course already exists (either for this instructor or globally)
            const existingCourse = await checkExistingCourse();
            if (existingCourse) {
                // If course exists, set the existing course ID and join it
                onboardingState.existingCourseId = existingCourse.courseId;
                onboardingState.createdCourseId = existingCourse.courseId;
                await joinExistingCourse();
                return;
            }
        } else {
            // For custom courses, check if instructor already has an incomplete course
            // If so, use that course instead of creating a new one
            const instructorId = getCurrentInstructorId();
            if (instructorId) {
                const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);
                if (response.ok) {
                    const result = await response.json();
                    if (result.data && result.data.courses && result.data.courses.length > 0) {
                        // Check for incomplete course (isOnboardingComplete is false)
                        const incompleteCourse = result.data.courses.find(course => 
                            !course.isOnboardingComplete || course.isOnboardingComplete === false
                        );
                        if (incompleteCourse) {
                            // Use the existing incomplete course
                            onboardingState.createdCourseId = incompleteCourse.courseId;
                            onboardingState.existingCourseId = incompleteCourse.courseId;
                            console.log('Using existing incomplete course:', incompleteCourse.courseId);
                            // Continue to next step with existing course
                            nextStep();
                            return;
                        }
                    }
                }
            }
        }
        
        // Create course and save to database
        const response = await createCourse(onboardingState.courseData);
        onboardingState.createdCourseId = response.courseId;
        
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
 * Check if course already exists (either for this instructor or globally by name)
 */
async function checkExistingCourse() {
    try {
        const courseSelect = document.getElementById('course-select');
        const selectedCourseId = courseSelect ? courseSelect.value : '';
        if (selectedCourseId && selectedCourseId !== 'custom') {
            const selectedOption = courseSelect.options[courseSelect.selectedIndex];
            return {
                courseId: selectedCourseId,
                courseName: selectedOption ? selectedOption.textContent : selectedCourseId
            };
        }

        const courseName = onboardingState.courseData.course;
        if (!courseName) {
            return null;
        }

        const instructorId = getCurrentInstructorId();
        if (instructorId) {
            const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);

            if (response.ok) {
                const result = await response.json();
                if (result.data && result.data.courses) {
                    const existingInstructorCourse = result.data.courses.find(course =>
                        course.courseName && course.courseName.toLowerCase() === courseName.toLowerCase()
                    );

                    if (existingInstructorCourse) {
                        return existingInstructorCourse;
                    }
                }
            }
        }

        const joinableCoursesResponse = await authenticatedFetch('/api/courses/available/joinable');
        if (joinableCoursesResponse.ok) {
            const joinableCoursesResult = await joinableCoursesResponse.json();
            if (joinableCoursesResult.success && joinableCoursesResult.data) {
                const existingCourse = joinableCoursesResult.data.find(course =>
                    course.courseName.toLowerCase() === courseName.toLowerCase()
                );
                if (existingCourse) {
                    return existingCourse;
                }
            }
        }
        
        return null;
    } catch (error) {
        console.error('Error checking existing course:', error);
        return null;
    }
}

/**
 * Mark instructor's onboarding as complete
 */
async function markInstructorOnboardingComplete(courseId) {
    try {
        console.log(`🔧 [ONBOARDING] Marking instructor onboarding as complete for course: ${courseId}`);
        
        const response = await authenticatedFetch('/api/onboarding/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                instructorId: getCurrentInstructorId()
            })
        });
        
        if (response.ok) {
            console.log('✅ [ONBOARDING] Successfully marked onboarding as complete');
        } else {
            console.warn('⚠️ [ONBOARDING] Failed to mark onboarding as complete, but continuing...');
        }
    } catch (error) {
        console.error('❌ [ONBOARDING] Error marking onboarding as complete:', error);
        // Don't throw error here as it's not critical for the join process
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
        
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        console.log(`👤 [ONBOARDING] Using instructor ID: ${instructorId}`);
        
        // Get learning objectives from the UI
        const learningObjectives = getLearningObjectivesFromUI();
        console.log('📚 [ONBOARDING] Learning objectives from UI:', learningObjectives);
        
        // If no objectives found, show error
        if (learningObjectives.length === 0) {            
            console.warn('⚠️ [ONBOARDING] No learning objectives found in UI');
            // Try to find objectives manually
            const objectivesList = document.getElementById('objectives-list');
            if (objectivesList) {
                const items = objectivesList.querySelectorAll('.objective-display-item');
                items.forEach((item, index) => {
                    const text = item.querySelector('.objective-text')?.textContent;
                });
            }
        }
        
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
        
        // Initialize unit structure with Unit 1 learning objectives
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
        console.log(`📡 [MONGODB] Request body size: ${JSON.stringify(onboardingData).length} characters`);
        
        const response = await authenticatedFetch('/api/onboarding', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(onboardingData)
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to create course: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Course created successfully:', result);
        
        // After successfully creating the course, save Unit 1 data using the same APIs
        // that the course upload functionality expects
        // Note: Learning objectives will be saved together when onboarding is completed
        // to avoid overwriting issues
        
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
    
    // Only validate course structure fields if creating a new course (custom or no existing course)
    if (courseSelect.value === 'custom' || courseSelect.value === '') {
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
    }
    
    return isValid;
}

function isCourseInactive(course = {}) {
    return (course.status || 'active') === 'inactive';
}

function getCourseDisplayName(course = {}) {
    const courseName = course.courseName || course.courseId || 'Untitled Course';
    return isCourseInactive(course) ? `${courseName} (Inactive)` : courseName;
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

function populateAvailableCourses(selectElement, courses) {
    selectElement.innerHTML = '<option value="">Choose a course...</option>';

    const uniqueCourses = dedupeCourses(courses);
    const activeCourses = uniqueCourses.filter(course => !isCourseInactive(course));
    const inactiveCourses = uniqueCourses.filter(isCourseInactive);

    appendCourseGroup(selectElement, 'Active Courses', activeCourses);
    appendCourseGroup(selectElement, 'Inactive Courses', inactiveCourses);
}

/**
 * Load available courses for the instructor
 */
async function loadAvailableCourses() {
    try {
        const courseSelect = document.getElementById('course-select');
        
        if (!courseSelect) return;
        
        // Fetch courses from the API
        const response = await fetch('/api/courses/available/joinable');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch courses');
        }
        
        const courses = result.data || [];
        
        console.log('All available courses from API:', courses);

        populateAvailableCourses(courseSelect, courses);
        
        // Add custom course option
        const customOption = document.createElement('option');
        customOption.value = 'custom';
        customOption.textContent = 'Enter custom course name...';
        courseSelect.appendChild(customOption);
        
        console.log('Available courses loaded and deduplicated:', dedupeCourses(courses));
        
    } catch (error) {
        console.error('Error loading available courses:', error);
        // Keep the placeholder option if API fails
        const courseSelect = document.getElementById('course-select');
        if (courseSelect) {
            courseSelect.innerHTML = '<option value="">Choose a course...</option>';
            // Add custom course option even if API fails
            const customOption = document.createElement('option');
            customOption.value = 'custom';
            customOption.textContent = 'Enter custom course name...';
            courseSelect.appendChild(customOption);
        }
    }
}
