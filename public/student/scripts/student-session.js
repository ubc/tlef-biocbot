/**
 * Student chat: auto-save, session lifecycle, chat history storage, and
 * chat-data collection/serialization.
 */

/**
 * Initialize auto-save system for chat
 * Creates an empty chat data structure that will be updated with each message
 */
async function initializeAutoSave() {
    try {


        // Get current student info using the same functions as the rest of the code
        const studentId = getCurrentStudentId();
        // Get student name synchronously from currentUser to avoid Promise issues
        const currentUser = getCurrentUser();
        const studentName = currentUser?.displayName || 'Anonymous Student';
        const courseId = localStorage.getItem('selectedCourseId') || 'unknown';
        const courseName = document.querySelector('.course-name')?.textContent || 'Unknown Course';
        const unitName = localStorage.getItem('selectedUnitName') || 'this unit';
        const currentMode = localStorage.getItem('studentMode') || 'tutor';



        // Check if there's already existing chat data
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        const existingChatData = localStorage.getItem(autoSaveKey);

        if (existingChatData) {
            const parsedData = JSON.parse(existingChatData);
            const hasMessages = parsedData.messages && parsedData.messages.length > 0;
            const hasAssessment = (parsedData.practiceTests && parsedData.practiceTests.questions && parsedData.practiceTests.questions.length > 0) || 
                                 (parsedData.studentAnswers && parsedData.studentAnswers.answers && parsedData.studentAnswers.answers.length > 0);

            if (hasMessages || hasAssessment) {


                // Ensure the session ID is properly restored if it exists in localStorage
                const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
                const existingSessionId = localStorage.getItem(sessionKey);

                // If localStorage has a session ID but chat data doesn't, restore it
                if (existingSessionId && (!parsedData.sessionInfo || !parsedData.sessionInfo.sessionId)) {
                    if (!parsedData.sessionInfo) {
                        parsedData.sessionInfo = {};
                    }
                    parsedData.sessionInfo.sessionId = existingSessionId;
                    localStorage.setItem(autoSaveKey, JSON.stringify(parsedData));

                }
                // If chat data has a session ID but localStorage doesn't, restore it
                else if (parsedData.sessionInfo && parsedData.sessionInfo.sessionId && !existingSessionId) {
                    localStorage.setItem(sessionKey, parsedData.sessionInfo.sessionId);

                }

                return; // Don't overwrite existing chat data
            }
        }

        // Create initial empty chat data structure only if no existing data
        const initialChatData = {
            metadata: {
                exportDate: new Date().toISOString(),
                courseId: courseId,
                courseName: courseName,
                studentId: studentId,
                studentName: studentName,
                unitName: unitName,
                currentMode: currentMode,
                totalMessages: 0,
                version: '1.0'
            },
            messages: [],
            practiceTests: null,
            studentAnswers: {
                answers: []
            },
            sessionInfo: {
                startTime: new Date().toISOString(),
                endTime: null,
                duration: '0 minutes'
            }
        };

        // Store in localStorage for auto-save updates
        localStorage.setItem(autoSaveKey, JSON.stringify(initialChatData));



    } catch (error) {
        console.error('Error initializing auto-save:', error);
    }
}

/**
 * Auto-save a new message to the current chat data
 * @param {string} content - The message content
 * @param {string} sender - 'user' or 'bot'
 * @param {boolean} withSource - Whether the message has source citation
 * @param {Object} sourceAttribution - Source attribution information
 */
function autoSaveMessage(content, sender, withSource = false, sourceAttribution = null, isHtml = false, activeStruggleTopic = null, messageId = null, feedbackRating = null) {
    try {


        // Get current student ID using the same function as the rest of the code
        const studentId = getCurrentStudentId();
        const autoSaveKey = `biocbot_current_chat_${studentId}`;


        // Get current chat data
        let currentChatData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');


        // If no current chat data exists, initialize it
        if (!currentChatData.messages) {

            // Initialize the data structure directly instead of calling initializeAutoSave()
            const studentId = getCurrentStudentId();
            // Get student name synchronously from currentUser to avoid Promise issues
            const currentUser = getCurrentUser();
            const studentName = currentUser?.displayName || 'Anonymous Student';
            const courseId = localStorage.getItem('selectedCourseId') || 'unknown';
            const courseName = document.querySelector('.course-name')?.textContent || 'Unknown Course';
            const unitName = localStorage.getItem('selectedUnitName') || 'this unit';
            const currentMode = localStorage.getItem('studentMode') || 'tutor';

            currentChatData = {
                metadata: {
                    exportDate: new Date().toISOString(),
                    courseId: courseId,
                    courseName: courseName,
                    studentId: studentId,
                    studentName: studentName,
                    unitName: unitName,
                    currentMode: currentMode,
                    totalMessages: 0,
                    version: '1.0'
                },
                messages: [],
                practiceTests: {
                    questions: [],
                    passThreshold: 70
                },
                studentAnswers: {
                    answers: []
                },
                sessionInfo: {
                    startTime: new Date().toISOString(),
                    endTime: null,
                    duration: '0 minutes'
                },
                lastActivityTimestamp: new Date().toISOString()
            };

            // Ensure session ID is set when creating new chat data
            // This prevents new sessions from being created on page refresh
            const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
            let sessionId = localStorage.getItem(sessionKey);
            if (!sessionId) {
                sessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                localStorage.setItem(sessionKey, sessionId);

            } else {

            }
            currentChatData.sessionInfo.sessionId = sessionId;


        }

        // Create new message object
        const newMessage = {
            type: sender,
            content: content,
            timestamp: new Date().toISOString(),
            hasFlagButton: sender === 'bot' && withSource,
            messageType: 'regular-chat',
            messageType: 'regular-chat',
            sourceAttribution: sourceAttribution || null,  // Save source attribution for restoration
            isHtml: isHtml, // Save whether message was rendered as HTML
            activeStruggleTopic: activeStruggleTopic || null, // Save active struggle topic
            messageId: messageId || null,
            feedbackRating: feedbackRating || null
        };

        // Add message to messages array
        currentChatData.messages.push(newMessage);

        // Update metadata - only count actual chat messages (not assessment messages)
        currentChatData.metadata.totalMessages = currentChatData.messages.length;
        currentChatData.metadata.exportDate = new Date().toISOString();
        currentChatData.metadata.currentMode = localStorage.getItem('studentMode') || 'tutor'; // Update current mode
        currentChatData.sessionInfo.endTime = new Date().toISOString();
        currentChatData.sessionInfo.duration = calculateSessionDuration(currentChatData);

        // Update last activity timestamp to ensure auto-continue works
        currentChatData.lastActivityTimestamp = new Date().toISOString();

        // Update assessment data if available
        updateAssessmentDataInAutoSave(currentChatData);

        // Save to localStorage
        localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));


        // Debug: Log the current auto-save data structure


        // Verify the save worked
        const verifyData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');


        // Sync with server after every message to ensure nothing is lost

        syncAutoSaveWithServer(currentChatData);

    } catch (error) {
        console.error('Error auto-saving message:', error);
    }
}

/**
 * Get or create a consistent session ID for the current chat session
 * @param {Object} chatData - The chat data
 * @returns {string} Session ID
 */
function getCurrentSessionId(chatData) {
    const studentId = chatData.metadata.studentId;
    const courseId = chatData.metadata.courseId;
    const unitName = chatData.metadata.unitName;

    // First, check if the chat data already has a session ID (from loaded history)
    if (chatData.sessionInfo && chatData.sessionInfo.sessionId) {

        return chatData.sessionInfo.sessionId;
    }

    // Check if we have a stored session ID for this chat
    const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
    let sessionId = localStorage.getItem(sessionKey);

    if (!sessionId) {
        // Create a new session ID
        sessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        localStorage.setItem(sessionKey, sessionId);

    } else {

    }

    // Ensure the session ID is stored in chatData.sessionInfo for consistency
    // This prevents the session ID from being lost on page refresh
    if (chatData && (!chatData.sessionInfo || !chatData.sessionInfo.sessionId || chatData.sessionInfo.sessionId !== sessionId)) {
        if (!chatData.sessionInfo) {
            chatData.sessionInfo = {};
        }
        chatData.sessionInfo.sessionId = sessionId;

        // Also update localStorage to keep it in sync
        const studentIdFromData = chatData.metadata.studentId;
        const autoSaveKey = `biocbot_current_chat_${studentIdFromData}`;
        try {
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));

        } catch (error) {
            console.warn('🔄 [SESSION] Could not update session ID in chat data:', error);
        }
    }

    return sessionId;
}

/**
 * Check if we should create a new session (if assessment is currently being taken)
 * @param {Object} chatData - The chat data
 * @returns {boolean} True if should create new session
 */
function shouldCreateNewSession(chatData) {
    // Check if assessment is currently being taken (chat input disabled)
    const chatInputContainer = document.querySelector('.chat-input-container');
    if (!chatInputContainer) {
        return false;
    }

    // If chat input is disabled, assessment is being taken - create new session
    if (chatInputContainer.style.display === 'none') {

        return true;
    }

    // If chat input is enabled, assessment is completed - use existing session

    return false;
}

/**
 * Update assessment data in auto-save
 * @param {Object} chatData - The chat data to update
 */
function updateAssessmentDataInAutoSave(chatData) {
    try {
        // Get current assessment questions and answers from the correct variables
        const questions = window.currentCalibrationQuestions || [];
        const studentAnswers = window.studentAnswers || [];

        // Update practice test data
        // Initialize practiceTests if it doesn't exist
        if (!chatData.practiceTests) {
            chatData.practiceTests = {
                questions: [],
                passThreshold: null
            };
        }

        if (questions.length > 0) {
            chatData.practiceTests.questions = questions.map((q, index) => {
                const studentAnswerIndex = studentAnswers[index];
                let studentAnswerText = null;
                let isCorrect = null;

                if (studentAnswerIndex !== undefined && studentAnswerIndex !== null) {
                    // Convert student answer index to actual answer text
                    if (q.type === 'true-false') {
                        studentAnswerText = studentAnswerIndex === 0 ? 'True' : 'False';
                    } else if (q.type === 'multiple-choice' && q.options) {
                        const optionKeys = Object.keys(q.options);
                        if (optionKeys[studentAnswerIndex]) {
                            studentAnswerText = q.options[optionKeys[studentAnswerIndex]];
                        } else {
                            studentAnswerText = `Option ${studentAnswerIndex}`;
                        }
                    } else {
                        studentAnswerText = studentAnswerIndex;
                    }

                    // Check if answer is correct
                    if (q.type === 'true-false') {
                        const expectedAnswer = q.correctAnswer === true || q.correctAnswer === 'true';
                        isCorrect = (studentAnswerIndex === 0) === expectedAnswer;
                    } else if (q.type === 'multiple-choice') {
                        let expectedIndex = q.correctAnswer;
                        if (typeof expectedIndex === 'string') {
                            const optionKeys = Object.keys(q.options);
                            expectedIndex = optionKeys.indexOf(expectedIndex);
                            if (expectedIndex === -1) expectedIndex = 0;
                        }
                        isCorrect = (studentAnswerIndex === expectedIndex);
                    } else {
                        isCorrect = (studentAnswerIndex === q.correctAnswer ||
                                   studentAnswerIndex === q.correctAnswer.toString());
                    }
                }

                return {
                    questionId: q.id || index,
                    question: q.question,
                    questionType: q.type || q.questionType,
                    options: q.options || {},
                    correctAnswer: q.correctAnswer,
                    explanation: q.explanation || '',
                    unitName: q.unitName || chatData.metadata.unitName,
                    studentAnswer: studentAnswerText,
                    isCorrect: isCorrect
                };
            });
        }

        // Update student answers
        chatData.studentAnswers.answers = studentAnswers.map((answer, index) => ({
            questionIndex: index,
            answer: answer,
            timestamp: new Date().toISOString()
        }));

        // Update pass threshold to use the actual calculated threshold
        if (window.currentPassThreshold !== undefined && questions.length > 0) {
            chatData.practiceTests.passThreshold = window.currentPassThreshold;
        } else if (questions.length === 0) {
            // If no questions, set practiceTests to null
            chatData.practiceTests = null;
        }



    } catch (error) {
        console.error('Error updating assessment data in auto-save:', error);
    }
}

/**
 * Sync auto-saved data with server
 * @param {Object} chatData - The chat data to sync
 */
async function syncAutoSaveWithServer(chatData) {
    try {


        // Check if we should create a new session
        const shouldCreateNew = shouldCreateNewSession(chatData);
        let sessionId;

        if (shouldCreateNew) {
            // Create new session ID and clear the old one
            const studentId = chatData.metadata.studentId;
            const courseId = chatData.metadata.courseId;
            const unitName = chatData.metadata.unitName;
            const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
            localStorage.removeItem(sessionKey);

        }

        sessionId = getCurrentSessionId(chatData);

        // Update last sync time
        const studentId = chatData.metadata.studentId;
        const courseId = chatData.metadata.courseId;
        const unitName = chatData.metadata.unitName;
        const lastSyncKey = `biocbot_last_sync_${studentId}_${courseId}_${unitName}`;
        localStorage.setItem(lastSyncKey, Date.now().toString());

        // Prepare data for server
        const serverData = {
            sessionId: sessionId,
            courseId: chatData.metadata.courseId,
            studentId: chatData.metadata.studentId,
            studentName: chatData.metadata.studentName,
            unitName: chatData.metadata.unitName,
            title: `Auto-saved Chat - ${new Date().toLocaleDateString()}`,
            messageCount: chatData.metadata.totalMessages,
            duration: chatData.sessionInfo.duration,
            savedAt: chatData.metadata.exportDate,
            chatData: chatData
        };



        // Debug: Check if studentName is valid
        if (!serverData.studentName || typeof serverData.studentName !== 'string') {
            console.warn('🔄 [SERVER-SYNC] ⚠️ Invalid studentName:', serverData.studentName);
        }

        // Use a simple fetch without await to avoid blocking the UI
        // This ensures the student's message is saved even if the server is slow
        fetch('/api/chat/save', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify(serverData)
        }).then(response => {
            if (response.ok) {
                return response.json();
            } else {
                throw new Error(`Server sync failed: ${response.status} ${response.statusText}`);
            }
        }).then(result => {
            if (result.success) {

            } else {
                console.warn('🔄 [SERVER-SYNC] ⚠️ Server returned error:', result.message);
            }
        }).catch(error => {
            console.warn('🔄 [SERVER-SYNC] ⚠️ Server sync failed:', error.message);
        });

    } catch (error) {
        console.error('🔄 [SERVER-SYNC] ❌ Error syncing with server:', error);
    }
}

/**
 * Get current chat data from auto-save storage
 * @returns {Object} Current chat data or null if not found
 */
function getCurrentChatData() {
    try {
        const studentId = getCurrentStudentId();
        if (!studentId) {
            console.warn('⚠️ [GET_CHAT_DATA] No student ID available');
            return null;
        }
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        const chatData = localStorage.getItem(autoSaveKey);

        if (chatData) {
            const parsed = JSON.parse(chatData);
            // Validate that we have the required structure
            if (!parsed.messages) {
                console.warn('⚠️ [GET_CHAT_DATA] Chat data missing messages array');
                parsed.messages = [];
            }
            return parsed;
        }

        return null;
    } catch (error) {
        console.error('Error getting current chat data:', error);
        return null;
    }
}

/**
 * Update the last activity timestamp in the current chat data
 * This tracks when the last message was sent or received
 */
function updateLastActivityTimestamp() {
    try {
        const chatData = getCurrentChatData();
        if (chatData) {
            chatData.lastActivityTimestamp = new Date().toISOString();

            // Save the updated data back to localStorage
            const studentId = getCurrentStudentId();
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));


        }
    } catch (error) {
        console.error('Error updating last activity timestamp:', error);
    }
}

/**
 * Load the current session data into the chat interface
 * This is used for auto-continue to restore the session without creating a new one
 */
async function loadCurrentSessionIntoInterface() {
    try {
        // Fetch current struggle state first
        if (typeof fetchCurrentStruggleState === 'function') {
            window.currentStruggleState = await fetchCurrentStruggleState();
            // Update UI indicator immediately
            if (typeof updateStruggleUI === 'function') {
                updateStruggleUI(window.currentStruggleState);
            }
        }



        const chatData = getCurrentChatData();
        if (!chatData || !chatData.messages || chatData.messages.length === 0) {

            return;
        }



        // Set flags for continuing chat BEFORE loading data
        // This ensures getConversationContext() can access the data
        sessionStorage.setItem('isContinuingChat', 'true');
        sessionStorage.setItem('loadedChatData', JSON.stringify(chatData));


        // Load the chat data using the existing function
        loadChatData(chatData);



    } catch (error) {
        console.error('Error loading current session into interface:', error);
    }
}

/**
 * Show a notification that the chat was auto-continued
 */
function showAutoContinueNotification() {
    try {
        // Find or create notification container
        let container = document.querySelector('.notification-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'notification-container';
            document.body.appendChild(container); // Append to body to ensure it's visible
        }

        // Create notification element
        const notification = document.createElement('div');
        notification.className = 'notification success'; // Green for success
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 16px;">🔄</span>
                <span>Chat continued from where you left off</span>
            </div>
            <button class="notification-close" aria-label="Close notification">&times;</button>
        `;

        // Add close functionality
        const closeBtn = notification.querySelector('.notification-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                notification.remove();
            });
        }

        // Add to container
        container.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                // Add fade out effect if desired, or just remove
                notification.style.opacity = '0';
                notification.style.transition = 'opacity 0.3s ease-out';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.remove();
                    }
                }, 300);
            }
        }, 3000);

    } catch (error) {
        console.error('Error showing auto-continue notification:', error);
    }
}

/**
 * Check if we should auto-continue the chat based on 30-minute window
 * This function checks if the last activity was within 30 minutes and auto-loads the chat
 * @returns {boolean} True if chat was auto-continued, false otherwise
 */
function checkForAutoContinue() {
    try {


        const chatData = getCurrentChatData();


        if (!chatData || ((!chatData.messages || chatData.messages.length === 0) && 
            (!chatData.practiceTests || !chatData.practiceTests.questions || chatData.practiceTests.questions.length === 0))) {

            return false;
        }

        // Check if we have a last activity timestamp
        if (!chatData.lastActivityTimestamp) {

            return false;
        }

        // Calculate time difference
        const lastActivity = new Date(chatData.lastActivityTimestamp);
        const now = new Date();
        const diffMs = now - lastActivity;
        const diffMinutes = Math.floor(diffMs / (1000 * 60));



        // Check if within 30 minutes
        if (diffMinutes <= 30) {


            // For auto-continue, we don't load the chat data into the interface
            // Instead, we just restore the session state by updating the current chat data
            // This maintains the session continuity without creating a new session

            // Validate metadata exists before accessing it
            if (!chatData.metadata) {
                console.error('🔄 [AUTO-CONTINUE] ❌ Chat data missing metadata, cannot auto-continue');
                return false;
            }

            // Restore the session ID from localStorage to ensure continuity
            const studentId = chatData.metadata.studentId || getCurrentStudentId();
            const courseId = chatData.metadata.courseId || localStorage.getItem('selectedCourseId') || 'unknown';
            const unitName = chatData.metadata.unitName || localStorage.getItem('selectedUnitName') || 'this unit';
            const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
            const existingSessionId = localStorage.getItem(sessionKey);

            // If we have a stored session ID, ensure it's in the chat data
            if (existingSessionId) {
                if (!chatData.sessionInfo) {
                    chatData.sessionInfo = {};
                }
                chatData.sessionInfo.sessionId = existingSessionId;

            } else if (chatData.sessionInfo && chatData.sessionInfo.sessionId) {
                // If chat data has a session ID but localStorage doesn't, restore it
                localStorage.setItem(sessionKey, chatData.sessionInfo.sessionId);

            } else {
                // If neither has a session ID, get/create one and store it in both places
                const sessionId = getCurrentSessionId(chatData);
                if (!chatData.sessionInfo) {
                    chatData.sessionInfo = {};
                }
                chatData.sessionInfo.sessionId = sessionId;

            }

            // Update the current chat data with the restored data (including session ID)
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));



            // Show a brief notification to the user
            showAutoContinueNotification();

            return true;
        } else {

            return false;
        }

    } catch (error) {
        console.error('Error checking for auto-continue:', error);
        return false;
    }
}

/**
 * Clear current chat data from auto-save storage
 * Used when starting a new chat session
 */
function clearCurrentChatData() {
    try {
        const studentId = getCurrentStudentId();
        if (studentId) {
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            localStorage.removeItem(autoSaveKey);
        }
    } catch (error) {
        console.error('Error clearing chat data:', error);
    }
}

/**
 * Initialize the new session button functionality
 */
function initializeNewSessionButton() {
    try {
        const newSessionBtn = document.getElementById('new-session-btn');
        if (!newSessionBtn) {

            return;
        }

        newSessionBtn.addEventListener('click', handleNewSession);


    } catch (error) {
        console.error('Error initializing new session button:', error);
    }
}

/**
 * Handle new session button click
 */
async function handleNewSession() {
    try {


        // Clear any existing session data
        clearCurrentChatData();

        const courseId = localStorage.getItem('selectedCourseId');

        // If no course is selected, reload available courses to show dropdown
        if (!courseId) {

            
            const chatMessages = document.getElementById('chat-messages');
            if (chatMessages) {
                chatMessages.innerHTML = `
                    <div class="message bot-message">
                        <div class="message-avatar">B</div>
                        <div class="message-content">
                            <p>Hello! Please select a course to get started.</p>
                            <div class="message-footer">
                                <div class="message-footer-right">
                                    <span class="timestamp">Just now</span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            
            await loadAvailableCourses();
            return;
        }

        // Generate a new session ID for the new session
        const studentId = getCurrentStudentId();
        const unitName = localStorage.getItem('selectedUnitName') || 'this unit';

        if (studentId && courseId) {
            const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
            const newSessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            localStorage.setItem(sessionKey, newSessionId);

        }

        // Get the current course name from localStorage or fetch it
        const storedCourseName = localStorage.getItem('selectedCourseName');
        let courseName = storedCourseName || 'BIOC 202'; // Fallback to default if not found

        // If course name not in localStorage, try to fetch it
        if (!storedCourseName && courseId) {
            try {
                const response = await fetch(`/api/courses/${courseId}`);
                if (response.ok) {
                    const courseData = await response.json();
                    if (courseData.success && courseData.data) {
                        courseName = courseData.data.courseName || courseData.data.name || courseName;
                        // Store it for future use
                        localStorage.setItem('selectedCourseName', courseName);
                    }
                }
            } catch (error) {
                console.warn('Could not fetch course name, using stored or default:', error);
            }
        }

        // Clear the chat interface
        const chatMessages = document.getElementById('chat-messages');
        if (chatMessages) {
            chatMessages.innerHTML = ''; // Start empty, let checkPublishedUnitsAndLoadQuestions handle the welcome message
        }

        // Reset flags
        window.autoContinued = false;
        window.loadingFromHistory = false;

        // Update course display to ensure header and other elements are synced
        if (courseName) {
            // Update the course name in the header
            const courseNameElement = document.querySelector('.course-name');
            if (courseNameElement) {
                courseNameElement.textContent = courseName;
            }
            // Update the user role display
            const userRoleElement = document.querySelector('.user-role');
            if (userRoleElement) {
                userRoleElement.textContent = `Student - ${courseName}`;
            }
        }

        // Show notification
        showNewSessionNotification();

        // Trigger the full initialization process including assessment questions

        checkPublishedUnitsAndLoadQuestions();



    } catch (error) {
        console.error('Error starting new session:', error);
    }
}

/**
 * Show a notification that a new session was started
 */
function showNewSessionNotification() {
    try {
        // Find or create notification container
        let container = document.querySelector('.notification-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'notification-container';
            document.body.appendChild(container); // Append to body to ensure it's visible
        }

        // Create notification element
        const notification = document.createElement('div');
        notification.className = 'notification info'; // Info color (teal)
        
        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 16px;">✨</span>
                <span>New chat session started</span>
            </div>
            <button class="notification-close" aria-label="Close notification">&times;</button>
        `;

        // Add close functionality
        const closeBtn = notification.querySelector('.notification-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                notification.remove();
            });
        }

        // Add to container
        container.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                 // Add fade out effect if desired, or just remove
                notification.style.opacity = '0';
                notification.style.transition = 'opacity 0.3s ease-out';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.remove();
                    }
                }, 300);
            }
        }, 3000);

    } catch (error) {
        console.error('Error showing new session notification:', error);
    }
}

/**
 * Collect all chat data including messages, practice tests, and responses
 * @returns {Promise<Object>} Complete chat data object
 */
async function collectAllChatData() {
    const chatMessages = document.getElementById('chat-messages');
    const messages = [];

    // Get current course and student information
    const courseId = localStorage.getItem('selectedCourseId');
    if (!courseId) {
        throw new Error('No course selected. Please select a course first.');
    }
    const studentName = await getCurrentStudentName();
    const studentId = getCurrentStudentId();
    const unitName = localStorage.getItem('selectedUnitName') || getCurrentUnitName();
    const currentMode = localStorage.getItem('studentMode') || 'tutor';

    // Process all message elements
    const messageElements = chatMessages.querySelectorAll('.message');
    messageElements.forEach((messageElement, index) => {
        const messageData = extractMessageData(messageElement, index);
        if (messageData) {
            messages.push(messageData);
        }
    });

    // Collect practice test data
    const practiceTestData = collectPracticeTestData();

    // Collect student answers
    const studentAnswersData = collectStudentAnswersData();

    // Create comprehensive chat data object
    const chatData = {
        metadata: {
            exportDate: new Date().toISOString(),
            courseId: courseId,
            courseName: document.querySelector('.course-name')?.textContent || 'Unknown Course',
            studentId: studentId,
            studentName: studentName,
            unitName: unitName,
            currentMode: currentMode,
            totalMessages: messages.length,
            version: '1.0'
        },
        messages: messages,
        practiceTests: practiceTestData,
        studentAnswers: studentAnswersData,
        sessionInfo: {
            startTime: getSessionStartTime(messages),
            endTime: new Date().toISOString(),
            duration: calculateSessionDuration({ metadata: { totalMessages: messages.length }, messages: messages })
        }
    };

    return chatData;
}

/**
 * Extract data from a single message element
 * @param {HTMLElement} messageElement - The message DOM element
 * @param {number} index - Message index
 * @returns {Object|null} Extracted message data or null if invalid
 */
function extractMessageData(messageElement, index) {
    try {
        const isBotMessage = messageElement.classList.contains('bot-message');
        const isUserMessage = messageElement.classList.contains('user-message');
        const isCalibrationQuestion = messageElement.classList.contains('calibration-question');
        const isModeResult = messageElement.classList.contains('mode-result');
        const isAssessmentStart = messageElement.classList.contains('assessment-start');
        const isTypingIndicator = messageElement.classList.contains('typing-indicator');

        // Skip typing indicators
        if (isTypingIndicator) {
            return null;
        }

        const avatarElement = messageElement.querySelector('.message-avatar');
        const contentElement = messageElement.querySelector('.message-content');
        const timestampElement = messageElement.querySelector('.timestamp');

        if (!contentElement) {
            return null;
        }

        // Extract basic message data
        const messageData = {
            index: index,
            type: isBotMessage ? 'bot' : 'user',
            timestamp: messageElement.dataset.timestamp ? new Date(parseInt(messageElement.dataset.timestamp)).toISOString() : new Date().toISOString(),
            displayTimestamp: timestampElement?.textContent || 'Unknown',
            content: extractMessageContent(contentElement),
            messageType: getMessageType(messageElement),
            isCalibrationQuestion: isCalibrationQuestion,
            isModeResult: isModeResult,
            isModeToggleResult: messageElement.classList.contains('mode-toggle-result'),
            isAssessmentStart: isAssessmentStart
        };

        if (messageElement.dataset.messageId) {
            messageData.messageId = messageElement.dataset.messageId;
        }
        if (messageElement.dataset.feedbackRating) {
            messageData.feedbackRating = messageElement.dataset.feedbackRating;
        }

        // Extract additional data for specific message types
        if (isCalibrationQuestion) {
            messageData.questionData = extractQuestionData(messageElement);
        }

        if (isModeResult || messageData.isModeToggleResult) {
            // For mode results, we want to save the HTML content to preserve formatting
            // But we need to be careful not to save the timestamp or avatar which are re-added on restore
            const contentClone = contentElement.cloneNode(true);
            const timestamp = contentClone.querySelector('.timestamp');
            if (timestamp) timestamp.remove();
            
            messageData.htmlContent = contentClone.innerHTML;
            messageData.modeData = extractModeData(messageElement);
        }

        // Extract flag information if present
        const flagContainer = messageElement.querySelector('.message-flag-container');
        if (flagContainer) {
            messageData.hasFlagButton = true;
        }

        return messageData;

    } catch (error) {
        console.error('Error extracting message data:', error);
        return null;
    }
}

/**
 * Extract content from message content element
 * @param {HTMLElement} contentElement - The message content element
 * @returns {string} Extracted content text
 */
function extractMessageContent(contentElement) {
    const paragraph = contentElement.querySelector('p');
    if (paragraph) {
        return paragraph.textContent || paragraph.innerText || '';
    }

    // Fallback to all text content
    return contentElement.textContent || contentElement.innerText || '';
}

/**
 * Get the type of message based on classes
 * @param {HTMLElement} messageElement - The message element
 * @returns {string} Message type
 */
function getMessageType(messageElement) {
    if (messageElement.classList.contains('calibration-question')) {
        return 'practice-test-question';
    }
    if (messageElement.classList.contains('mode-result')) {
        return 'mode-result';
    }
    if (messageElement.classList.contains('assessment-start')) {
        return 'assessment-start';
    }
    if (messageElement.classList.contains('mode-toggle-result')) {
        return 'mode-toggle-result';
    }
    if (messageElement.classList.contains('unit-selection-welcome')) {
        return 'unit-selection';
    }
    return 'regular-chat';
}

/**
 * Extract question data from calibration question elements
 * @param {HTMLElement} messageElement - The message element
 * @returns {Object|null} Question data or null
 */
function extractQuestionData(messageElement) {
    try {
        const contentElement = messageElement.querySelector('.message-content');
        if (!contentElement) return null;

        const questionText = contentElement.querySelector('p')?.textContent || '';
        const optionsContainer = contentElement.querySelector('.calibration-options');
        const options = [];

        if (optionsContainer) {
            const optionButtons = optionsContainer.querySelectorAll('.calibration-option');
            optionButtons.forEach((button, index) => {
                options.push({
                    index: index,
                    text: button.textContent || '',
                    isSelected: button.classList.contains('selected') || button.style.backgroundColor.includes('var(--primary-color)')
                });
            });
        }

        // Check for short answer input
        const answerInput = contentElement.querySelector('.calibration-answer-input');
        let studentAnswer = null;
        if (answerInput) {
            studentAnswer = answerInput.value;
        }

        // Check for feedback
        const feedbackElement = contentElement.querySelector('.calibration-feedback');
        let feedback = null;
        if (feedbackElement) {
            feedback = feedbackElement.innerHTML;
        }

        return {
            questionText: questionText,
            options: options,
            studentAnswer: studentAnswer,
            feedback: feedback,
            questionIndex: currentQuestionIndex
        };

    } catch (error) {
        console.error('Error extracting question data:', error);
        return null;
    }
}

/**
 * Extract mode data from mode result elements
 * @param {HTMLElement} messageElement - The message element
 * @returns {Object|null} Mode data or null
 */
function extractModeData(messageElement) {
    try {
        const contentElement = messageElement.querySelector('.message-content');
        if (!contentElement) return null;

        const modeExplanation = contentElement.querySelector('.mode-explanation');
        const modeText = modeExplanation?.textContent || contentElement.querySelector('p')?.textContent || '';

        return {
            modeText: modeText,
            determinedMode: localStorage.getItem('studentMode') || 'tutor'
        };

    } catch (error) {
        console.error('Error extracting mode data:', error);
        return null;
    }
}

/**
 * Collect practice test data
 * @returns {Object} Practice test data
 */
function collectPracticeTestData() {
    // If there are no practice questions, return null instead of an empty object
    if (!currentCalibrationQuestions || currentCalibrationQuestions.length === 0) {
        return null;
    }

    return {
        questions: currentCalibrationQuestions.map((question, index) => ({
            questionId: question.id,
            questionIndex: index,
            questionType: question.type,
            question: question.question,
            options: question.options,
            correctAnswer: question.correctAnswer,
            explanation: question.explanation,
            unitName: question.unitName,
            passThreshold: question.passThreshold
        })),
        totalQuestions: currentCalibrationQuestions.length,
        passThreshold: currentPassThreshold,
        currentQuestionIndex: currentQuestionIndex
    };
}

/**
 * Collect student answers data
 * @returns {Object} Student answers data
 */
function collectStudentAnswersData() {
    return {
        answers: studentAnswers.map((answer, index) => ({
            questionIndex: index,
            answer: answer,
            question: currentCalibrationQuestions[index] ? {
                id: currentCalibrationQuestions[index].id,
                question: currentCalibrationQuestions[index].question,
                type: currentCalibrationQuestions[index].type
            } : null
        })),
        totalAnswers: studentAnswers.length,
        answersProvided: studentAnswers.filter(answer => answer !== undefined && answer !== null).length
    };
}

/**
 * Get session start time (approximate)
 * @param {Array} messages - Optional messages array
 * @returns {string} Session start time ISO string
 */
function getSessionStartTime(messages) {
    // Try to get the timestamp from the provided messages
    if (messages && messages.length > 0) {
        // Find the first user message (student message)
        const firstUserMessage = messages.find(msg => msg.type === 'user');
        if (firstUserMessage && firstUserMessage.timestamp) {
            return firstUserMessage.timestamp;
        }

        // If no user message found, use the first message
        const firstMessage = messages[0];
        if (firstMessage && firstMessage.timestamp) {
            return firstMessage.timestamp;
        }
    }

    // Try to get from DOM as fallback
    const firstMessage = document.querySelector('.message');
    if (firstMessage && firstMessage.dataset.timestamp) {
        return new Date(parseInt(firstMessage.dataset.timestamp)).toISOString();
    }

    // Last resort fallback to current time minus estimated duration
    return new Date(Date.now() - 3600000).toISOString(); // 1 hour ago as fallback
}

/**
 * Calculate session duration from first user message to last bot response
 * @param {Object} chatData - The chat data object to calculate duration from
 * @returns {string} Duration in human readable format
 */
function calculateSessionDuration(chatData) {
    if (!chatData || !chatData.messages || chatData.messages.length === 0) {
        return '0s';
    }

    // Find the first user message (student message)
    const firstUserMessage = chatData.messages.find(msg => msg.type === 'user');
    if (!firstUserMessage || !firstUserMessage.timestamp) {
        return '0s';
    }

    // Find the last bot message
    const lastBotMessage = chatData.messages.slice().reverse().find(msg => msg.type === 'bot');
    if (!lastBotMessage || !lastBotMessage.timestamp) {
        // If no bot message found, use the last message
        const lastMessage = chatData.messages[chatData.messages.length - 1];
        if (!lastMessage || !lastMessage.timestamp) {
            return '0s';
        }
        const start = new Date(firstUserMessage.timestamp);
        const end = new Date(lastMessage.timestamp);
        const diffMs = end - start;

        const hours = Math.floor(diffMs / (1000 * 60 * 60));
        const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diffMs % (1000 * 60)) / 1000);

        if (hours > 0) {
            return `${hours}h ${minutes}m ${seconds}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds}s`;
        } else {
            return `${seconds}s`;
        }
    }

    const start = new Date(firstUserMessage.timestamp);
    const end = new Date(lastBotMessage.timestamp);
    const diffMs = end - start;

    const hours = Math.floor(diffMs / (1000 * 60 * 60));
    const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((diffMs % (1000 * 60)) / 1000);

    if (hours > 0) {
        return `${hours}h ${minutes}m ${seconds}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds}s`;
    } else {
        return `${seconds}s`;
    }
}

/**
 * Initialize chat history storage system
 */
function initializeChatHistoryStorage() {
    // Chat history is automatically saved via auto-save functionality after each message
    // No manual save button is needed

}

/**
 * Initialize user agreement modal
 * This will show the agreement modal for first-time users
 */
function initializeUserAgreement() {
    // The agreement modal is automatically initialized by the agreement-modal.js script
    // This function is here for consistency with other initialize functions


    // Listen for agreement acceptance event
    document.addEventListener('userAgreementAccepted', (event) => {

        // You can add any additional logic here after agreement is accepted
    });
}

/**
 * Save chat data to history storage
 * @param {Object} chatData - The chat data to save
 */
function saveChatToHistory(chatData) {
    try {


        // Use student-specific localStorage key for security
        const studentId = chatData.metadata.studentId;
        const historyKey = `biocbot_chat_history_${studentId}`;
        let history = JSON.parse(localStorage.getItem(historyKey) || '[]');


        // Create a unique ID for this chat session
        const chatId = `chat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;


        // Create history entry
        const historyEntry = {
            id: chatId,
            title: generateChatTitle(chatData),
            preview: generateChatPreview(chatData),
            date: chatData.metadata.exportDate,
            courseName: chatData.metadata.courseName,
            unitName: chatData.metadata.unitName,
            studentName: chatData.metadata.studentName,
            totalMessages: chatData.metadata.totalMessages,
            duration: chatData.sessionInfo.duration,
            chatData: chatData
        };



        // Add to beginning of history (most recent first)
        history.unshift(historyEntry);


        // Keep only last 50 chat sessions to prevent storage bloat
        if (history.length > 50) {
            history = history.slice(0, 50);

        }

        // Save back to localStorage
        localStorage.setItem(historyKey, JSON.stringify(history));


        // Verify it was saved
        const savedData = localStorage.getItem(historyKey);




        // Also save to server for instructor access
        saveChatToServer(chatData, chatId);

    } catch (error) {
        console.error('Error saving chat to history:', error);
    }
}

/**
 * Save chat data to server for instructor access
 * @param {Object} chatData - The chat data to save
 * @param {string} chatId - The chat session ID
 */
async function saveChatToServer(chatData, chatId) {
    try {


        // Prepare server data
        const serverData = {
            sessionId: chatId,
            courseId: chatData.metadata.courseId,
            studentId: chatData.metadata.studentId,
            studentName: chatData.metadata.studentName,
            unitName: chatData.metadata.unitName,
            title: generateChatTitle(chatData),
            messageCount: chatData.metadata.totalMessages,
            duration: chatData.sessionInfo.duration,
            savedAt: chatData.metadata.exportDate,
            chatData: chatData
        };



        // Send to server
        const response = await fetch('/api/chat/save', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(serverData)
        });

        if (!response.ok) {
            throw new Error(`Server responded with ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();


    } catch (error) {
        console.error('Error saving chat to server:', error);
        // Don't show error to user as this is background saving
        // The chat is already saved locally
    }
}

/**
 * Generate a title for the chat based on its content
 * @param {Object} chatData - The chat data
 * @returns {string} Generated title
 */
function generateChatTitle(chatData) {
    const courseName = chatData.metadata.courseName;
    const unitName = chatData.metadata.unitName;
    const messageCount = chatData.metadata.totalMessages;

    // Try to find the first user question
    const firstUserMessage = chatData.messages.find(msg => msg.type === 'user');
    if (firstUserMessage) {
        const question = firstUserMessage.content.substring(0, 50);
        return `${courseName} - ${question}${question.length >= 50 ? '...' : ''}`;
    }

    // Fallback titles based on content
    if (chatData.practiceTests && chatData.practiceTests.questions && chatData.practiceTests.questions.length > 0) {
        return `${courseName} - ${unitName} Assessment (${messageCount} messages)`;
    }

    return `${courseName} - Chat Session (${messageCount} messages)`;
}

/**
 * Generate a preview for the chat
 * @param {Object} chatData - The chat data
 * @returns {string} Generated preview
 */
function generateChatPreview(chatData) {
    // Find the first user message
    const firstUserMessage = chatData.messages.find(msg => msg.type === 'user');
    if (firstUserMessage) {
        return firstUserMessage.content.substring(0, 100) + (firstUserMessage.content.length > 100 ? '...' : '');
    }

    // Find the first bot message
    const firstBotMessage = chatData.messages.find(msg => msg.type === 'bot');
    if (firstBotMessage) {
        return firstBotMessage.content.substring(0, 100) + (firstBotMessage.content.length > 100 ? '...' : '');
    }

    return 'Chat session with BiocBot';
}

/**
 * Get all chat history entries for the current student
 * @returns {Array} Array of chat history entries
 */
function getChatHistory() {
    try {
        // Get current student ID for security
        const studentId = getCurrentStudentId();
        if (!studentId) {
            console.error('No student ID found - cannot load chat history');
            return [];
        }

        const historyKey = `biocbot_chat_history_${studentId}`;
        return JSON.parse(localStorage.getItem(historyKey) || '[]');
    } catch (error) {
        console.error('Error getting chat history:', error);
        return [];
    }
}

/**
 * Get a specific chat by ID
 * @param {string} chatId - The chat ID
 * @returns {Object|null} Chat data or null if not found
 */
function getChatById(chatId) {
    try {
        const history = getChatHistory();
        return history.find(chat => chat.id === chatId) || null;
    } catch (error) {
        console.error('Error getting chat by ID:', error);
        return null;
    }
}

/**
 * Delete a chat from history
 * @param {string} chatId - The chat ID to delete
 * @returns {boolean} True if successful
 */
function deleteChatFromHistory(chatId) {
    try {
        const studentId = getCurrentStudentId();
        if (!studentId) {
            console.error('No student ID found - cannot delete chat history entry');
            return false;
        }
        const history = getChatHistory();
        const filteredHistory = history.filter(chat => chat.id !== chatId);
        // Must write to the same per-student namespaced key that
        // saveChatToHistory and getChatHistory use, otherwise the entry
        // stays in the student's actual history and the UI deletes nothing.
        const historyKey = `biocbot_chat_history_${studentId}`;
        localStorage.setItem(historyKey, JSON.stringify(filteredHistory));
        return true;
    } catch (error) {
        console.error('Error deleting chat from history:', error);
        return false;
    }
}
