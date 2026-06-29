/**
 * Student chat: course selection/display and student identity helpers.
 */

async function renderStandaloneCourseSelectorBelowHeader(container) {
    try {
        const resp = await fetch('/api/courses/available/all');
        if (!resp.ok) return;
        const data = await resp.json();
        const courses = (data && data.data) || [];
        if (!Array.isArray(courses) || courses.length === 0) return;

        const wrapper = document.createElement('div');
        wrapper.style.margin = '16px 0 0 0';
        wrapper.innerHTML = `
            <div class="course-selection-container" style="margin: 16px 0; padding: 15px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid var(--primary-color);">
                <h3 style="margin: 0 0 10px 0; color: #333;">Select Your Course</h3>
                <select id="revoked-course-select" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                    <option value="">Choose a course...</option>
                    ${courses.map(c => `<option value="${c.courseId}">${c.courseName}</option>`).join('')}
                </select>
            </div>
        `;
        container.appendChild(wrapper);
        const sel = wrapper.querySelector('#revoked-course-select');
        if (sel) {
            sel.addEventListener('change', async function() {
                const selectedCourseId = this.value;
                if (selectedCourseId) {
                    await loadCourseData(selectedCourseId);
                    // after switching, reload page to reinit chat area
                    window.location.reload();
                }
            });
        }
    } catch (e) {
        console.warn('Failed to render standalone course selector:', e);
    }
}

/**
 * Load current course information and update the UI
 */
async function loadCurrentCourseInfo() {
    try {


        // Get student name first
        const studentName = await getCurrentStudentName();


        // Update student name display
        const userNameElement = document.getElementById('user-display-name');
        if (userNameElement && studentName) {
            userNameElement.textContent = studentName;
        }

        // Load available courses and show course selection
        await loadAvailableCourses();

    } catch (error) {
        console.error('Error loading course information:', error);
        // Keep default display if course loading fails
    }
}

/**
 * Load available courses and show course selection
 */
async function loadAvailableCourses() {
    try {


        // Check if there's already a selected course in localStorage
        const storedCourseId = localStorage.getItem('selectedCourseId');
        const storedCourseName = localStorage.getItem('selectedCourseName');
        
        if (storedCourseId) {

            
            // Check if this stored courseId has actual chat data (messages) for the current user
            // If not, it's likely leftover from a previous user session and should be cleared
            const studentId = getCurrentStudentId();
            let hasUserChatData = false;
            
            if (studentId) {
                // Check if there's actual chat data with messages for this user with this course
                const chatDataKey = `biocbot_current_chat_${studentId}`;
                const chatDataStr = localStorage.getItem(chatDataKey);
                
                if (chatDataStr) {
                    try {
                        const chatData = JSON.parse(chatDataStr);
                        const hasMessages = chatData.messages && chatData.messages.length > 0;
                        const hasAssessment = (chatData.practiceTests && chatData.practiceTests.questions && chatData.practiceTests.questions.length > 0) || 
                                             (chatData.studentAnswers && chatData.studentAnswers.answers && chatData.studentAnswers.answers.length > 0);
                        
                        // Also check if metadata alone is valid (course/unit selected) to allow resuming "empty" sessions
                        // This fixes the issue where refreshing on a "no questions available" screen kicks the user out
                        const hasValidMetadata = chatData.metadata && 
                                               chatData.metadata.courseId === storedCourseId &&
                                               chatData.metadata.studentId === studentId &&
                                               chatData.metadata.unitName;

                        // Check if chat data exists and matches the stored courseId
                        if (chatData && 
                            chatData.metadata && 
                            chatData.metadata.courseId === storedCourseId &&
                            chatData.metadata.studentId === studentId &&
                            (hasMessages || hasAssessment || hasValidMetadata)) {
                            hasUserChatData = true;

                        } else {

                        }
                    } catch (e) {

                    }
                } else {

                }
            }
            
            // First, verify the course exists and the current user has access to it
            try {
                // Check if user has access to this course
                const enrollmentResponse = await fetch(`/api/courses/${storedCourseId}/student-enrollment`, { 
                    credentials: 'include' 
                });
                
                if (enrollmentResponse.ok) {
                    const enrollmentData = await enrollmentResponse.json();
                    // If user is not enrolled or access is revoked, clear the stored course
                    if (!enrollmentData.success || !enrollmentData.data || enrollmentData.data.enrolled === false) {
                        console.log('User does not have access to stored course, clearing localStorage');
                        localStorage.removeItem('selectedCourseId');
                        localStorage.removeItem('selectedCourseName');
                        // Clear any session data for this course
                        if (studentId) {
                            Object.keys(localStorage).forEach(key => {
                                if (key.startsWith(`biocbot_session_${studentId}_${storedCourseId}_`)) {
                                    localStorage.removeItem(key);
                                }
                            });
                        }
                        // Continue to fetch fresh courses below
                    } else if (!hasUserChatData) {
                        // User has access but no actual chat messages - this is a first-time user
                        // or the courseId is from a different user's session
                        console.log('User has access but no chat messages - treating as first-time user, clearing stored course');
                        localStorage.removeItem('selectedCourseId');
                        localStorage.removeItem('selectedCourseName');
                        // Clear any session keys for this course to prevent future false positives
                        if (studentId) {
                            Object.keys(localStorage).forEach(key => {
                                if (key.startsWith(`biocbot_session_${studentId}_${storedCourseId}_`)) {
                                    localStorage.removeItem(key);
                                }
                            });
                        }
                        // Continue to fetch fresh courses below
                    } else {
                        // User has access and has actual chat messages - verify course still exists
                        const courseResponse = await fetch(`/api/courses/${storedCourseId}`);
                        if (courseResponse.ok) {
                            const courseData = await courseResponse.json();
                            if (courseData.success && courseData.data) {
                                // Course exists, user has access, and has chat messages - load it
                                console.log('Stored course is valid, user has access and chat messages, loading it');
                                await loadCourseData(storedCourseId);
                                return;
                            } else {
                                console.log('Stored course does not exist, clearing localStorage');
                                localStorage.removeItem('selectedCourseId');
                                localStorage.removeItem('selectedCourseName');
                            }
                        } else {
                            console.log('Failed to verify stored course, clearing localStorage');
                            localStorage.removeItem('selectedCourseId');
                            localStorage.removeItem('selectedCourseName');
                        }
                    }
                } else {
                    console.log('Failed to check enrollment, clearing localStorage');
                    localStorage.removeItem('selectedCourseId');
                    localStorage.removeItem('selectedCourseName');
                }
            } catch (error) {
                console.warn('Error verifying stored course, clearing localStorage:', error);
                localStorage.removeItem('selectedCourseId');
                localStorage.removeItem('selectedCourseName');
                // Continue to fetch fresh courses below
            }
        }

        // Fetch available courses
        const response = await fetch('/api/courses/available/all');
        if (!response.ok) {
            throw new Error(`Failed to fetch courses: ${response.status}`);
        }

        const result = await response.json();
        if (!result.success || !result.data) {
            throw new Error('Invalid courses data received');
        }

        const courses = result.data;
        console.log('Available courses loaded:', courses);
        console.log('Course names in dropdown:', courses.map(c => c.courseName));

        if (courses.length === 0) {
            console.log('No courses available');
            showNoCoursesMessage();
            return;
        }

        // Always show course selection dropdown if no course is stored (first time user)
        // This ensures users can choose their course even if only one is available
        const hasStoredCourse = !!localStorage.getItem('selectedCourseId');
        
        if (!hasStoredCourse) {
            // First time user - always show selection dropdown
            console.log('First time user - showing course selection dropdown');
            showCourseSelection(courses);
        } else if (courses.length === 1) {
            // Returning user with stored course, but only one course available - use it directly
            console.log('Only one course available and user has stored course, using it directly');
            await loadCourseData(courses[0].courseId);
        } else {
            // Multiple courses available, show selection dropdown
            console.log('Multiple courses available, showing selection');
            showCourseSelection(courses);
        }

    } catch (error) {
        console.error('Error loading available courses:', error);
        showNoCoursesMessage();
    }
}

/**
 * Show course selection dropdown
 * @param {Array} courses - Array of available courses
 */
function showCourseSelection(courses) {
    console.log('Showing course selection for courses:', courses);

    // Update header to show "Select Course"
    const courseNameElement = document.querySelector('.course-name');
    if (courseNameElement) {
        courseNameElement.textContent = 'Select Course';
    }
    const userRoleElement = document.querySelector('.user-role');
    if (userRoleElement) {
        userRoleElement.textContent = 'Student';
    }

    // Create course selection dropdown
    const courseSelectionHTML = `
        <div class="course-selection-container" style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid var(--primary-color);">
            <h3 style="margin: 0 0 10px 0; color: #333;">Select Your Course</h3>
            <p style="margin: 0 0 15px 0; color: #666;">Choose the course you want to access:</p>
            <select id="course-select" aria-label="Select your course" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                <option value="">Choose a course...</option>
                ${courses.map(course => `<option value="${course.courseId}">${course.courseName}</option>`).join('')}
            </select>
        </div>
    `;

    const chatMessages = document.getElementById('chat-messages');
    
    // Clear any existing messages (including default welcome message) to prevents showing content from other courses
    if (chatMessages) {
        chatMessages.innerHTML = '';
        
        // Create a container for the course selection
        const courseSelectionDiv = document.createElement('div');
        courseSelectionDiv.innerHTML = courseSelectionHTML;
        courseSelectionDiv.id = 'course-selection-wrapper';
        
        chatMessages.appendChild(courseSelectionDiv);
    }

    // Add event listener for course selection
    const courseSelect = document.getElementById('course-select');
    if (courseSelect) {
        courseSelect.addEventListener('change', async function() {
            const selectedCourseId = this.value;

            if (selectedCourseId) {
                console.log('Course selected:', selectedCourseId);

                // The selector only lists courses the student is enrolled in
                // (enrollment comes from the academic roster sync), so we can
                // load directly without any join/enrollment-code step.
                await loadCourseData(selectedCourseId, true);

                // Hide the course selection after selection
                const courseSelectionWrapper = document.getElementById('course-selection-wrapper');
                if (courseSelectionWrapper) {
                    courseSelectionWrapper.style.display = 'none';
                }
            }
        });
    }
}

/**
 * Load course data and update display
 * @param {string} courseId - Course ID to load
 * @param {boolean} isCourseChange - Whether this is a course change (vs initial load)
 */
async function loadCourseData(courseId, isCourseChange = false) {
    try {


        // Check if this is actually a course change by comparing with stored courseId
        const previousCourseId = localStorage.getItem('selectedCourseId');
        const actualCourseChange = isCourseChange || (previousCourseId && previousCourseId !== courseId);
        
        // Store the selected course in localStorage
        localStorage.setItem('selectedCourseId', courseId);

        // Fetch course details
        const response = await fetch(`/api/courses/${courseId}`);
        if (!response.ok) {
            throw new Error(`Failed to fetch course data: ${response.status}`);
        }

        const courseData = await response.json();
        if (!courseData.success || !courseData.data) {
            throw new Error('Invalid course data received');
        }

        const course = courseData.data;


        // Use name property if courseName is not available (API compatibility)
        const courseName = course.courseName || course.name;


        // Store course name in localStorage for persistence
        if (courseName) {
            localStorage.setItem('selectedCourseName', courseName);

        }

        // Update UI elements with actual course information

        updateCourseDisplay(course);

        // Force a small delay and try again to ensure DOM is updated
        setTimeout(() => {

            updateCourseDisplay(course);
        }, 100);

        // Add change course functionality
        addChangeCourseButton();

        // If this is a course change (not initial load), create a new clean session
        if (actualCourseChange) {

            
            // Clear any existing session data for the old course
            clearCurrentChatData();

            // Clear the selected unit name so the unit dropdown will show up
            localStorage.removeItem('selectedUnitName');


            // Generate a new session ID for the new course
            const studentId = getCurrentStudentId();
            const unitName = localStorage.getItem('selectedUnitName') || 'this unit';

            if (studentId && courseId) {
                const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
                const newSessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                localStorage.setItem(sessionKey, newSessionId);

            }

            // Clear the chat interface to start fresh
            const chatMessages = document.getElementById('chat-messages');
            if (chatMessages) {
            chatMessages.innerHTML = ''; // Start empty, let checkPublishedUnitsAndLoadQuestions handle the welcome message
            }

            // Reset flags
            window.autoContinued = false;
            window.loadingFromHistory = false;

            // Load questions and proper prompts for the new course
            // Use a small delay to ensure DOM is fully updated
            setTimeout(() => {

                checkPublishedUnitsAndLoadQuestions();
            }, 200);
        } else {
            // On initial load, ensure session exists and questions are loaded

            
            // Ensure session ID exists (but don't create a new one if one already exists)
            const studentId = getCurrentStudentId();
            const unitName = localStorage.getItem('selectedUnitName') || 'this unit';
            if (studentId && courseId) {
                const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
                let sessionId = localStorage.getItem(sessionKey);
                if (!sessionId) {
                    // Only create session if one doesn't exist
                    sessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                    localStorage.setItem(sessionKey, sessionId);

                }
            }

            // Ensure questions are loaded after a delay to allow DOM to be ready
            // This handles the case where loadCourseData is called before checkPublishedUnitsAndLoadQuestions
            setTimeout(() => {

                checkPublishedUnitsAndLoadQuestions();
            }, 300);
        }

    } catch (error) {
        console.error('Error loading course data:', error);

        // If this was a 404 error, clear localStorage and try to load available courses
        if (error.message.includes('404')) {

            localStorage.removeItem('selectedCourseId');
            await loadAvailableCourses();
            return;
        }

        showCourseLoadError();
    }
}

/**
 * Show message when no courses are available
 */
function showNoCoursesMessage() {
    const noCoursesMessage = document.createElement('div');
    noCoursesMessage.classList.add('message', 'bot-message');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const messageText = document.createElement('p');
    messageText.innerHTML = `<strong>No Courses Available</strong><br>
    There are no courses available at this time. Please contact your instructor or administrator.`;

    contentDiv.appendChild(messageText);

    // Add timestamp
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = 'Just now';
    contentDiv.appendChild(timestamp);

    noCoursesMessage.appendChild(avatarDiv);
    noCoursesMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(noCoursesMessage);
}

/**
 * Show error message when course loading fails
 */
function showCourseLoadError() {
    const errorMessage = document.createElement('div');
    errorMessage.classList.add('message', 'bot-message');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const messageText = document.createElement('p');
    messageText.innerHTML = `<strong>Error Loading Course</strong><br>
    There was an error loading the course information. Please try refreshing the page or contact support.`;

    contentDiv.appendChild(messageText);

    // Add timestamp
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = 'Just now';
    contentDiv.appendChild(timestamp);

    errorMessage.appendChild(avatarDiv);
    errorMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(errorMessage);
}

/**
 * Update the UI with current course information
 * @param {Object} course - Course object with course details
 * @param {string} studentName - Student's display name (optional)
 */
function updateCourseDisplay(course, studentName) {


    // Use name property if courseName is not available (API compatibility)
    const courseName = course.courseName || course.name;


    // Update course name in header - try multiple selectors
    let courseNameElement = document.querySelector('.course-name');


    // If not found, try alternative selectors
    if (!courseNameElement) {
        courseNameElement = document.querySelector('span.course-name');

    }

    if (!courseNameElement) {
        courseNameElement = document.querySelector('.current-course .course-name');

    }



    if (courseNameElement && courseName) {
        const oldText = courseNameElement.textContent;
        courseNameElement.textContent = courseName;


        // Verify the update worked
        const newText = courseNameElement.textContent;

    } else {
        console.warn('Could not update course name - element or courseName missing');
        console.warn('Element found:', !!courseNameElement);
        console.warn('Course name provided:', courseName);

        // Try the more aggressive approach
        if (courseName) {

            const forceUpdated = forceUpdateCourseName(courseName);
            if (forceUpdated) {

            } else {
                console.error('Force update failed!');
            }
        }
    }

    // Update user role display
    const userRoleElement = document.querySelector('.user-role');
    if (userRoleElement && courseName) {
        userRoleElement.textContent = `Student - ${courseName}`;

    }

    // Update student name display if provided
    if (studentName) {
        const userNameElement = document.getElementById('user-display-name');
        if (userNameElement) {
            userNameElement.textContent = studentName;
        }
    }

    // Update welcome message
    const welcomeMessage = document.querySelector('.message.bot-message p');
    if (welcomeMessage && courseName) {
        welcomeMessage.textContent = `Hello! I'm BiocBot, your AI study assistant for ${courseName}. How can I help you today?`;
    }


}

/**
 * Force update course name in the header - more aggressive approach
 * @param {string} courseName - The course name to display
 */
function forceUpdateCourseName(courseName) {


    // Try multiple approaches to find and update the course name
    const selectors = [
        '.course-name',
        'span.course-name',
        '.current-course .course-name',
        '.chat-header .course-name',
        'header .course-name'
    ];

    let updated = false;
    for (const selector of selectors) {
        const elements = document.querySelectorAll(selector);


        elements.forEach((element, index) => {

            updated = true;
        });
    }

    if (!updated) {
        console.error('Could not find any course name elements to update!');
        // List all elements that might be relevant
        const allSpans = document.querySelectorAll('span');

        allSpans.forEach((span, index) => {
            if (span.textContent.includes('BIOC') || span.textContent.includes('Course')) {

            }
        });
    }

    return updated;
}

/**
 * Add a change course button to allow users to switch courses
 */
function addChangeCourseButton() {
    // Check if button already exists
    if (document.getElementById('change-course-btn')) {
        return;
    }

    // Create change course button
    const changeCourseBtn = document.createElement('button');
    changeCourseBtn.id = 'change-course-btn';
    changeCourseBtn.textContent = 'Change Course';
    changeCourseBtn.style.cssText = `
        background: #6c757d;
        color: white;
        border: none;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        cursor: pointer;
        margin-left: 10px;
    `;

    // Add click handler
    changeCourseBtn.addEventListener('click', async () => {
        if (confirm('Are you sure you want to change your course? This will clear your current selection.')) {
            // Clear localStorage
            localStorage.removeItem('selectedCourseId');
            localStorage.removeItem('selectedCourseName');

            // Remove the button
            changeCourseBtn.remove();

            // Reload available courses to show selection
            // When a course is selected, it will be treated as a course change
            await loadAvailableCourses();
        }
    });

    // Add button to the course display area
    const courseDisplay = document.querySelector('.current-course');
    if (courseDisplay) {
        courseDisplay.appendChild(changeCourseBtn);
    }
}

/**
 * Get current student ID from authentication system
 * @returns {string} Student ID
 */
function getCurrentStudentId() {
    try {
        // Get the current user from the auth system
        const currentUser = getCurrentUser();


        if (currentUser && currentUser.userId) {

            return currentUser.userId;
        }

        // Fallback: try to get from localStorage or sessionStorage
        const storedUserId = localStorage.getItem('userId') || sessionStorage.getItem('userId');
        if (storedUserId) {

            return storedUserId;
        }

        // Last resort: generate a unique ID for this session
        let sessionId = sessionStorage.getItem('sessionId');
        if (!sessionId) {
            sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('sessionId', sessionId);

        }
        return sessionId;

    } catch (error) {
        console.error('Error getting student ID:', error);
        // Fallback to a unique session-based ID
        let sessionId = sessionStorage.getItem('sessionId');
        if (!sessionId) {
            sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('sessionId', sessionId);

        }
        return sessionId;
    }
}

/**
 * Get current student name from user session
 * @returns {Promise<string>} Student name
 */
async function getCurrentStudentName() {
    try {
        const response = await fetch('/api/auth/me');
        if (response.ok) {
            const userData = await response.json();
            if (userData.success && userData.user && userData.user.displayName) {
                return userData.user.displayName;
            }
        }
    } catch (error) {
        console.error('Error fetching student name:', error);
    }

    // Fallback to placeholder
    return 'Student Name';
}

/**
 * Get current course ID from user's session, preferences, or localStorage
 * @returns {Promise<string>} Course ID
 */
async function getCurrentCourseId() {
    try {
        // First, try to get the user's current course context from their session
        const userResponse = await fetch('/api/auth/me');
        if (userResponse.ok) {
            const userData = await userResponse.json();
            if (userData.success && userData.user && userData.user.preferences && userData.user.preferences.courseId) {

                return userData.user.preferences.courseId;
            }
        }

        // Check localStorage for previously selected course
        const storedCourseId = localStorage.getItem('selectedCourseId');
        if (storedCourseId) {

            return storedCourseId;
        }

        // If no course context, fetch available courses
        const response = await fetch('/api/courses/available/all');

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();

        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch courses');
        }

        const courses = result.data;

        // Only auto-select if there's exactly one course
        if (courses.length === 1) {

            // Store it in localStorage for future use
            localStorage.setItem('selectedCourseId', courses[0].courseId);
            return courses[0].courseId;
        } else if (courses.length > 1) {
            // Multiple courses available - don't auto-select, let user choose
            return null;
        }

        // No courses available
        return null;

    } catch (error) {
        console.error('Error fetching course ID:', error);
        return null;
    }
}

/**
 * Get current unit name (placeholder)
 * @returns {string} Unit name
 */
function getCurrentUnitName() {
    // This would typically come from current session or course context
    // For now, return a placeholder
    return 'Unit 1';
}

/**
 * Generate a unique question ID for flagged bot responses
 * @param {string} messageText - The message text to generate ID from
 * @returns {string} Unique question ID
 */
function generateQuestionId(messageText) {
    const timestamp = Date.now();
    // Use encodeURIComponent to safely encode any characters, then create a hash
    const encodedText = encodeURIComponent(messageText.substring(0, 20));
    const hash = encodedText.replace(/[^a-zA-Z0-9]/g, '').substring(0, 10);
    return `bot_response_${timestamp}_${hash}`;
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
