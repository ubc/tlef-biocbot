document.addEventListener('DOMContentLoaded', async () => {
    try {
        const courseId = localStorage.getItem('selectedCourseId');
        if (courseId) {
            const resp = await fetch(`/api/courses/${courseId}/student-enrollment`, { credentials: 'include' });
            if (resp.ok) {
                const data = await resp.json();
                // Only show revoked UI if explicitly banned
                if (data && data.success && data.data && data.data.status === 'banned') {
                    renderRevokedAccessUI();
                    return; // stop further chat init
                }
            }
        }
    } catch (e) { console.warn('Enrollment check failed, proceeding:', e); }
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatMessages = document.getElementById('chat-messages');
    let currentController = null; // Controller for aborting in-flight requests
    let lastActiveStruggleTopic = null; // Track active struggle topic for the session

    // Guard: Only allow students on this page; redirect others immediately
    const handleRoleGuard = (user) => {
        if (!user) return; // auth.js will handle redirect if unauthenticated
        if (user.role === 'student') return;
        if (user.role === 'instructor') {
            window.location.href = '/instructor';
            return;
        }
        if (user.role === 'ta') {
            window.location.href = '/ta';
            return;
        }
        window.location.href = '/login';
    };

    // Perform role check as early as possible
    try {
        const existingUser = typeof getCurrentUser === 'function' ? getCurrentUser() : null;
        if (existingUser) {
            handleRoleGuard(existingUser);
        } else {
            document.addEventListener('auth:ready', (e) => handleRoleGuard(e.detail));
        }
    } catch (e) {
        // If anything goes wrong, rely on server-side protection
        console.warn('Student role guard failed softly:', e);
    }

    // Initialize chat


    // Wait for authentication to be ready before initializing auto-save
    const initializeAutoSaveWhenReady = async () => {

        await initializeAutoSave();

        // Check for auto-continue after authentication is ready
        // Add a small delay to ensure auto-save data is fully loaded
        setTimeout(() => {
            // Only check for auto-continue if we're NOT loading from history
            const isLoadingFromHistory = sessionStorage.getItem('loadChatData');
            const isAlreadyLoadingFromHistory = window.loadingFromHistory;

            if (!isLoadingFromHistory && !isAlreadyLoadingFromHistory) {

                const wasAutoContinued = checkForAutoContinue();

        if (wasAutoContinued) {

            // Set a flag to prevent assessment questions from loading
            window.autoContinued = true;

            // Load the current session data into the interface
            // Add a small delay to ensure DOM is fully ready
            setTimeout(() => {
                try {

                    loadCurrentSessionIntoInterface();
                } catch (error) {
                    console.error('🔄 [AUTO-CONTINUE] Error loading session into interface:', error);
                }
            }, 200);
        }
            } else {
                // console logs removed
            }
        }, 100);
    };

    // Check if auth is already ready
    if (getCurrentUser()) {

        await initializeAutoSaveWhenReady();
    } else {
        // Wait for auth:ready event
        document.addEventListener('auth:ready', initializeAutoSaveWhenReady);
    }

    // Add beforeunload event to ensure auto-save data is preserved and synced
    window.addEventListener('beforeunload', async () => {

        const chatData = getCurrentChatData();
        if (chatData && chatData.messages.length > 0) {
            await syncAutoSaveWithServer(chatData);
        }
    });

    // Load current course information and update UI
    loadCurrentCourseInfo();

    // Check if we're loading from history first
    const isLoadingFromHistory = sessionStorage.getItem('loadChatData');

    if (isLoadingFromHistory) {
        // console log removed
    }

    // Initialize mode toggle functionality
    initializeModeToggle();

    // Ensure mode toggle is properly set after a short delay (fallback for timing issues)
    setTimeout(() => {
        const currentMode = localStorage.getItem('studentMode') || 'tutor';

        updateModeToggleUI(currentMode);
    }, 200);

    // Set up periodic timestamp updates
    setInterval(updateTimestamps, 20000); // Update every 20 seconds

    // Initialize chat history storage
    initializeChatHistoryStorage();

    // Check for chat data to load from history (after DOM is ready)
    setTimeout(() => {
        checkForChatDataToLoad();
    }, 100);
    
    // Initialize Idle Timer
    initializeIdleTimer();

    // Initialize user agreement modal
    initializeUserAgreement();

    // Initialize new session button
    initializeNewSessionButton();

    // Initialize "View General Rules" link
    const viewRulesLink = document.getElementById('view-rules-link');
    if (viewRulesLink) {
        viewRulesLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (window.agreementModal) {
                window.agreementModal.show(true); // true = read-only mode
            }
        });
    }

    /**
     * Format timestamp for display
     * @param {Date} timestamp - The timestamp to format
     * @returns {string} Formatted timestamp string
     */
    function formatTimestamp(timestamp) {
        const now = new Date();
        const diffMs = now - timestamp;
        const diffSeconds = Math.floor(diffMs / 1000);
        const diffMinutes = Math.floor(diffSeconds / 60);
        const diffHours = Math.floor(diffMinutes / 60);
        const diffDays = Math.floor(diffHours / 24);

        // Format based on how long ago
        if (diffSeconds < 60) {
            return 'Just now';
        } else if (diffMinutes < 60) {
            return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`;
        } else if (diffHours < 24) {
            return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
            return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
        } else {
            // For older messages, show actual date
            return timestamp.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
        }
    }

    /**
     * Update all timestamps to show relative time
     */
    function updateTimestamps() {
        const timestamps = document.querySelectorAll('.timestamp');
        timestamps.forEach(timestamp => {
            const messageDiv = timestamp.closest('.message');
            if (messageDiv && messageDiv.dataset.timestamp) {
                const messageTime = new Date(parseInt(messageDiv.dataset.timestamp));
                timestamp.textContent = formatTimestamp(messageTime);
            }
        });
    }

    /**
     * Update UI based on Struggle State
     * @param {Object} state - The struggle state object
     */
    function updateStruggleUI(state) {
        if (!state || !state.topics) return;

        const activeTopics = state.topics.filter(t => t.isActive);
        const modeToggleContainer = document.querySelector('.mode-toggle-container');
        let indicator = document.getElementById('directive-mode-indicator');

        if (activeTopics.length > 0) {
            if (!indicator) {
                indicator = document.createElement('div');
                indicator.id = 'directive-mode-indicator';
                indicator.className = 'directive-mode-badge';
                indicator.innerHTML = `
                    <span class="icon">⚠️</span>
                    <span>Directive Mode Active</span>
                `;
                indicator.title = `Directive Mode is active for: ${activeTopics.map(t => t.topic).join(', ')}`;
                
                // Add click handler to go to dashboard
                indicator.style.cursor = 'pointer';
                indicator.addEventListener('click', () => {
                    window.location.href = '/student/dashboard.html';
                });

                // Insert before mode toggle
                if (modeToggleContainer) {
                    modeToggleContainer.parentNode.insertBefore(indicator, modeToggleContainer);
                }
            }
        } else {
            if (indicator) {
                indicator.remove();
            }
        }
    }

    /**
     * Send message to LLM service
     * @param {string} message - The message to send
     * @param {boolean} checkSummaryAttempt - Whether to check for summary attempt
     * @param {AbortSignal} signal - Optional abort signal
     * @returns {Promise<Object>} Response from LLM service
     */
    async function sendMessageToLLM(message, checkSummaryAttempt = false, signal = null, isExplanationRequest = false) {
        try {
            // Get current student mode for context
            const currentMode = localStorage.getItem('studentMode') || 'tutor';

            // Get course ID from localStorage (should be set after course selection)
            const courseId = localStorage.getItem('selectedCourseId');
            if (!courseId) {
                throw new Error('No course selected. Please select a course first.');
            }

            const unitName = localStorage.getItem('selectedUnitName') || getCurrentUnitName();

            // Check if we're continuing a chat and need to include conversation context
            const conversationContext = getConversationContext();

            // conversationContext retrieved or new conversation started


            const requestBody = {
                message: message,
                mode: currentMode,
                courseId: courseId,
                unitName: unitName,
                conversationContext: conversationContext,
                checkSummaryAttempt: checkSummaryAttempt,
                isExplanationRequest: isExplanationRequest,
                topic: isExplanationRequest && typeof isExplanationRequest === 'object' ? isExplanationRequest.topic : null
            };




            const fetchOptions = {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestBody)
            };

            if (signal) {
                fetchOptions.signal = signal;
            }

            const response = await fetch('/api/chat', fetchOptions);



            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            if (!data.success) {
                throw new Error(data.message || 'Failed to get response from LLM');
            }

            // Don't clear the continuing chat flags - we need them for the entire conversation
            // The flags will be cleared when starting a new chat session or explicitly clearing chat
            // This ensures the conversation context is maintained throughout the chat session

            return data;

        } catch (error) {
            console.error('Error sending message to LLM:', error);
            throw error;
        }
    }

    // Maximum number of regular-chat messages (user + bot combined) before session is capped
    const MAX_MESSAGES = 40;

    /**
     * Check if the 15-message warning has already been shown
     * @returns {boolean} True if warning was already shown
     */
    function hasWarningBeenShown() {
        try {
            const chatData = getCurrentChatData();
            if (!chatData || !chatData.messages || chatData.messages.length === 0) {
                return false;
            }

            // Check if any bot message contains the warning text
            const warningText = 'Please be aware that after 15 messages, the quality of the responses might be degraded.';
            return chatData.messages.some(msg =>
                msg.type === 'bot' &&
                msg.content &&
                msg.content.includes(warningText.substring(0, 50)) // Check first 50 chars to avoid exact match issues
            );
        } catch (error) {
            console.error('Error checking if warning was shown:', error);
            return false;
        }
    }

    /**
     * Check if the 25-message warning has already been shown
     * @returns {boolean} True if warning was already shown
     */
    function hasWarning25BeenShown() {
        try {
            const chatData = getCurrentChatData();
            if (!chatData || !chatData.messages || chatData.messages.length === 0) {
                return false;
            }
            const warningText = 'You\'ve reached 25 messages. We recommend starting a new session';
            return chatData.messages.some(msg =>
                msg.type === 'bot' &&
                msg.content &&
                msg.content.includes(warningText.substring(0, 50))
            );
        } catch (error) {
            console.error('Error checking if 25-message warning was shown:', error);
            return false;
        }
    }

    /**
     * Check if the 35-message warning has already been shown
     * @returns {boolean} True if warning was already shown
     */
    function hasWarning35BeenShown() {
        try {
            const chatData = getCurrentChatData();
            if (!chatData || !chatData.messages || chatData.messages.length === 0) {
                return false;
            }
            const warningText = 'In 5 messages, this session will automatically close';
            return chatData.messages.some(msg =>
                msg.type === 'bot' &&
                msg.content &&
                msg.content.includes(warningText.substring(0, 50))
            );
        } catch (error) {
            console.error('Error checking if 35-message warning was shown:', error);
            return false;
        }
    }

    /**
     * Check if the session has been capped (40 messages reached)
     * @returns {boolean} True if session is capped
     */
    function isSessionCapped() {
        const count = countMessagesFromFirstStudent();
        return count >= MAX_MESSAGES;
    }

    /**
     * Disable chat input because the session has reached the message cap
     */
    function disableChatInputForCap() {
        const chatInput = document.getElementById('chat-input');
        if (chatInput) {
            chatInput.disabled = true;
            chatInput.placeholder = 'This session has reached the 40-message limit. Please start a new session.';
            chatInput.classList.add('disabled-input');
            chatInput.style.cursor = 'not-allowed';
        }
        const sendButton = document.getElementById('send-button');
        if (sendButton) {
            sendButton.disabled = true;
            sendButton.classList.add('disabled-button');
            sendButton.style.cursor = 'not-allowed';
            sendButton.style.opacity = '0.5';
        }
    }

    /**
     * Check if the Protege Effect prompt has already been shown
     * @returns {boolean} True if prompt was already shown
     */
    function hasProtegePromptShown() {
        try {
            const chatData = getCurrentChatData();
            if (!chatData || !chatData.messages || chatData.messages.length === 0) {
                return false;
            }

            // Check if any bot message contains the prompt text
            const promptText = 'Do you want to try and explain our chat above to me?';
            return chatData.messages.some(msg =>
                msg.type === 'bot' &&
                msg.content &&
                msg.content.includes(promptText)
            );
        } catch (error) {
            console.error('Error checking if protege prompt was shown:', error);
            return false;
        }
    }

    /**
     * Count messages starting from the first student message
     * Only counts regular-chat messages (user and bot)
     * @returns {number} Count of messages from first student message
     */
    function countMessagesFromFirstStudent() {
        try {
            const chatData = getCurrentChatData();
            if (!chatData || !chatData.messages || chatData.messages.length === 0) {

                return 0;
            }



            // Find the index of the first user message
            const firstUserMessageIndex = chatData.messages.findIndex(msg =>
                msg.type === 'user' && msg.messageType === 'regular-chat'
            );

            // If no user message found, return 0
            if (firstUserMessageIndex === -1) {

                return 0;
            }



            // Count all regular-chat messages (user and bot) from the first user message onwards
            const messagesFromFirstStudent = chatData.messages.slice(firstUserMessageIndex).filter(msg =>
                (msg.type === 'user' || msg.type === 'bot') && msg.messageType === 'regular-chat'
            );



            return messagesFromFirstStudent.length;
        } catch (error) {
            console.error('Error counting messages from first student:', error);
            return 0;
        }
    }

    /**
     * Get conversation context for continuing a chat
     * @returns {Object|null} Conversation context or null if not continuing a chat
     */
    function getConversationContext() {


        // Check if we're continuing a chat (this flag is set when loading chat data)
        const isContinuingChat = sessionStorage.getItem('isContinuingChat') === 'true';


        // Always get the latest chat data from localStorage to ensure we have the most recent messages
        // The sessionStorage might be stale if messages were added after loading
        const currentChatData = getCurrentChatData();
        let loadedChatData = null;

        if (currentChatData && currentChatData.messages && currentChatData.messages.length > 0) {

            // Always use the latest data from localStorage
            loadedChatData = JSON.stringify(currentChatData);
            // Update sessionStorage with the latest data
            sessionStorage.setItem('isContinuingChat', 'true');
            sessionStorage.setItem('loadedChatData', loadedChatData);
        } else {
            // Fallback: try sessionStorage if localStorage is empty
            loadedChatData = sessionStorage.getItem('loadedChatData');
            if (!loadedChatData) {
                // No chat data found
            }
        }

        if (!loadedChatData) {

            return null;
        }



        try {
            const chatData = JSON.parse(loadedChatData);

            // Verify session ID matches - only use context if we're in the same session
            const currentChatData = getCurrentChatData();
            let currentSessionId = null;
            if (currentChatData && currentChatData.sessionInfo && currentChatData.sessionInfo.sessionId) {
                currentSessionId = currentChatData.sessionInfo.sessionId;
            }

            const loadedSessionId = chatData.sessionInfo && chatData.sessionInfo.sessionId
                ? chatData.sessionInfo.sessionId
                : null;



            // If we have a current session ID, verify it matches the loaded session ID
            if (currentSessionId && loadedSessionId && currentSessionId !== loadedSessionId) {
                // This is a new session - clearing old context and returning null
                // Clear the old context flags since they're from a different session
                sessionStorage.removeItem('isContinuingChat');
                sessionStorage.removeItem('loadedChatData');
                return null;
            }

            // If current session has no ID but loaded does, it means we're starting fresh
            // Don't use old session context - new sessions should not reference old conversations
            if (!currentSessionId && loadedSessionId) {
                sessionStorage.removeItem('isContinuingChat');
                sessionStorage.removeItem('loadedChatData');
                return null;
            }



            const currentMode = localStorage.getItem('studentMode') || 'tutor';
            const unitName = localStorage.getItem('selectedUnitName') || 'this unit';

            // Build structured conversation context
            const conversationMessages = [];

            // 1) System prompt (handled by the API)

            // 2) Hardcoded assistant response with learning objectives and test questions
            let assistantResponse = `I'm BiocBot in ${currentMode === 'protege' ? 'Protégé' : 'Tutor'} Mode. We're discussing ${unitName} this week.`;

            if (chatData.practiceTests && chatData.practiceTests.questions.length > 0) {
                assistantResponse += ` How did you get on with the test questions?`;
            } else {
                assistantResponse += ` How can I help you today?`;
            }

            conversationMessages.push({
                role: 'assistant',
                content: assistantResponse
            });

            // 3) Hardcoded student response with test answers (if practice test exists)
            if (chatData.practiceTests && chatData.practiceTests.questions.length > 0 &&
                chatData.studentAnswers && chatData.studentAnswers.answers.length > 0) {

                let studentResponse = `Here's my responses to those:\n\n`;
                chatData.studentAnswers.answers.forEach((answer, index) => {
                    const question = chatData.practiceTests.questions[index];
                    if (question) {
                        studentResponse += `${index + 1}. ${question.question}\n`;
                        studentResponse += `   My Answer: ${answer.answer}\n`;
                        studentResponse += `   Correct: ${question.correctAnswer}\n`;
                        studentResponse += `   Result: ${answer.isCorrect ? 'Correct' : 'Incorrect'}\n\n`;
                    }
                });

                conversationMessages.push({
                    role: 'user',
                    content: studentResponse
                });

                // 4) Hardcoded assistant response acknowledging the test
                // Calculate overall performance
                const correctAnswers = chatData.studentAnswers.answers.filter(a => a.isCorrect).length;
                const totalAnswers = chatData.studentAnswers.answers.length;
                const performance = correctAnswers / totalAnswers;
                const passThreshold = chatData.practiceTests.passThreshold / 100;

                conversationMessages.push({
                    role: 'assistant',
                    content: `Thank you for that. Based on your responses, I can see you ${performance >= passThreshold ? 'demonstrated good understanding' : 'need some additional support'}. So how can I help you today?`
                });
            }

            // 5) Add the actual conversation history from the previous chat
            if (chatData.messages && chatData.messages.length > 0) {
                // Filter out system messages and only include actual conversation
                const regularChatMessages = chatData.messages.filter(msg =>
                    msg.messageType === 'regular-chat' &&
                    (msg.type === 'user' || msg.type === 'bot')
                );



                // Add the conversation history
                regularChatMessages.forEach((msg, index) => {
                    conversationMessages.push({
                        role: msg.type === 'user' ? 'user' : 'assistant',
                        content: msg.content
                    });
                    // Log first few messages for debugging

                });

                // Log last few messages with full content for debugging
                if (regularChatMessages.length > 3) {
                    const lastFew = regularChatMessages.slice(-3);
                    lastFew.forEach((msg, idx) => {
                        const actualIdx = regularChatMessages.length - 3 + idx;
                        console.log(`🔄 [CONTEXT] Message ${actualIdx + 1}:`, msg.type, '-', msg.content.substring(0, 100) + (msg.content.length > 100 ? '...' : ''));
                        // Log full content for hero-related messages to debug
                        if (msg.content.toLowerCase().includes('hero') || msg.content.toLowerCase().includes('batman')) {
                            console.log(`🔄 [CONTEXT] FULL CONTENT for message ${actualIdx + 1}:`, msg.content);
                        }
                    });
                }

                // Also search through all messages for hero-related content to verify it's included
                const heroMessages = regularChatMessages.filter(msg =>
                    msg.content.toLowerCase().includes('hero') ||
                    msg.content.toLowerCase().includes('batman') ||
                    msg.content.toLowerCase().includes('favorite')
                );

            }



            return {
                conversationMessages: conversationMessages,
                mode: currentMode,
                hasPracticeTest: !!(chatData.practiceTests && chatData.practiceTests.questions.length > 0)
            };

        } catch (error) {
            console.error('Error building conversation context:', error);
            return null;
        }
    }

    // Handle chat form submission
    if (chatForm) {
        chatForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            // Cancel any previous in-flight request
            if (currentController) {
                currentController.abort();
                currentController = null;
            }

            // Create new controller for this request
            currentController = new AbortController();
            const signal = currentController.signal;

            // Prevent chat if no published units are available
            if (window.noPublishedUnits) {

                return;
            }

            const message = chatInput.value.trim();
            if (!message) return;

            // Check message count BEFORE adding the user message
            const messageCountBefore = countMessagesFromFirstStudent();

            // Block input if session is already capped
            if (messageCountBefore >= MAX_MESSAGES) {
                disableChatInputForCap();
                return;
            }

            // Determine which warnings to show
            const warningAlreadyShown = hasWarningBeenShown();
            const shouldShowWarning15 = !warningAlreadyShown && (messageCountBefore === 13 || messageCountBefore === 14);

            const warning25AlreadyShown = hasWarning25BeenShown();
            const shouldShowWarning25 = !warning25AlreadyShown && (messageCountBefore === 23 || messageCountBefore === 24);

            const warning35AlreadyShown = hasWarning35BeenShown();
            const shouldShowWarning35 = !warning35AlreadyShown && (messageCountBefore === 33 || messageCountBefore === 34);

            // Check if this is the 15th message to trigger summary check on backend
            const shouldCheckSummaryAttempt = !warningAlreadyShown && messageCountBefore === 14;

            // Add user message to chat
            addMessage(message, 'user');

            // Clear input
            chatInput.value = '';

            const systemSource = {
                source: 'System',
                description: 'System notification',
                unitName: null,
                documentType: null
            };

            // Show 15-message warning if needed
            if (shouldShowWarning15) {
                addMessage('Please be aware that after 15 messages, the quality of the responses might be degraded. <a href="#" class="chat-limit-link">See why?</a>', 'bot', true, false, systemSource, true);
            }

            // Show 25-message warning if needed
            if (shouldShowWarning25) {
                addMessage('You\'ve reached 25 messages. We recommend starting a new session for better response quality. <a href="#" class="chat-limit-link">See why?</a>', 'bot', true, false, systemSource, true);
            }

            // Show 35-message warning if needed
            if (shouldShowWarning35) {
                addMessage('In 5 messages, this session will automatically close. Please wrap up your current discussion or start a new session. <a href="#" class="chat-limit-link">See why?</a>', 'bot', true, false, systemSource, true);
            }

            // Check if the bot response would hit or exceed the cap
            // messageCountBefore + 1 (user msg) + warnings + 1 (bot response)
            const currentCountAfterUser = countMessagesFromFirstStudent();
            const willHitCap = (currentCountAfterUser + 1) >= MAX_MESSAGES; // +1 for the upcoming bot response

            // Show typing indicator
            showTypingIndicator();

            // Send message to real LLM service
            try {
                // If we need to check for summary attempt, pass that flag to the backend
                if (shouldCheckSummaryAttempt) {

                }
                
                const response = await sendMessageToLLM(message, shouldCheckSummaryAttempt, signal);

                // Request completed successfully
                currentController = null;

                // Remove typing indicator
                removeTypingIndicator();

                // Add real bot response
                // Add real bot response




                // Check if we should append the Protege prompt
                const currentMode = localStorage.getItem('studentMode') || 'tutor';
                const isTutorMode = currentMode === 'tutor';
                const promptAlreadyShown = hasProtegePromptShown();
                
                // We initially check messageCountBefore (e.g. 12).
                // User adds message -> Total messages = 13 (assuming 1-based index or however countMessagesFromFirstStudent works).
                // If countMessagesFromFirstStudent returns the count of HISTORY, and we just added a user message:
                // If history was 12. New count is 13.
                // The bot response will be the 14th message.
                // So we want to trigger when `messageCountBefore` is 12 (or 13 to be safe).
                const shouldShowProtegePrompt = !promptAlreadyShown && isTutorMode && (messageCountBefore === 12 || messageCountBefore === 13);
                
                if (shouldShowProtegePrompt) {
                     response.message += '\n\n----------------\nDo you want to try and explain our chat above to me?';
                }

                if (response.struggleDebug) {
                    console.log('🕵️ [FRONTEND_DEBUG_V2] Backend Debug Info:', response.struggleDebug);
                }

                // Update Struggle UI if available
                if (response.struggleState) {
                    console.log('🕵️ [FRONTEND_DEBUG] Struggle State received:', response.struggleState);
                    updateStruggleUI(response.struggleState);
                    
                    // Check for active struggle topic to pass to addMessage
                    let activeTopic = null;
                    if (response.struggleState.topics && Array.isArray(response.struggleState.topics)) {
                        activeTopic = response.struggleState.topics.find(t => t.isActive);
                    } else if (response.struggleState.topic && response.struggleState.isActive) {
                        activeTopic = response.struggleState;
                    }

                    if (activeTopic) {
                        lastActiveStruggleTopic = activeTopic.topic;
                    } else {
                        // If we received a state where isActive is explicitly false, clear the topic
                        if (response.struggleState.isActive === false) {
                            lastActiveStruggleTopic = null;
                        } else if (response.struggleState.topics) {
                            // If we have a topics array and none are active, clear it
                            const anyActive = response.struggleState.topics.some(t => t.isActive);
                            if (!anyActive) lastActiveStruggleTopic = null;
                        }
                    }
                } else {
                    console.log('🕵️ [FRONTEND_DEBUG] No struggle state in response');
                }

                // Extract detected topic (even if not active yet) for "Explain" button
                // Priority: active topic -> latest detected topic in state -> simple topic string if passed (unlikely)
                let detectedTopic = null;
                if (response.struggleState) {
                    // 1. Try to find the topic that was just analyzed/updated
                    if (response.struggleDebug && response.struggleDebug.identifiedTopic) {
                        detectedTopic = response.struggleDebug.identifiedTopic;
                    } 
                    // 2. Fallback to extracting from topics array if active
                    else if (response.struggleState.topics && response.struggleState.topics.length > 0) {
                        // We might want the most recently updated one, but for now let's use the active one if any
                        const active = response.struggleState.topics.find(t => t.isActive);
                        if (active) detectedTopic = active.topic;
                    }
                    // 3. Simple topic property if it exists at top level (depends on backend structure)
                    else if (response.struggleState.topic) {
                        detectedTopic = response.struggleState.topic;
                    }
                }

                // If this bot response will hit the cap, append the session-closed notice
                if (willHitCap) {
                    response.message += '\n\n----------------\nThis chat session has been exhausted. Please start a new session to continue.';
                }

                // Only show "I understand X now" button when directive mode is active for this response
                const showStruggleReset = response.struggleDebug?.directiveModeActive ? lastActiveStruggleTopic : null;
                addMessage(response.message, 'bot', true, false, response.sourceAttribution, false, showStruggleReset, detectedTopic);

                // Disable chat input if session is now capped
                if (willHitCap) {
                    disableChatInputForCap();
                }

            } catch (error) {
                // Remove typing indicator
                removeTypingIndicator();

                if (error.name === 'AbortError') {
                    // Request was aborted by user starting a new message
                    addMessage('You have stopped this response', 'bot', false, true, null);
                    // Don't log error or show generic error message
                    return;
                }

                // Show error message
                console.error('Chat error:', error);

                addMessage('Sorry, I encountered an error processing your message. Please try again.', 'bot', false, true, null);
            }
        });
    }

    // Note: addMessage function is defined globally below with auto-save functionality

    // Function to show typing indicator
    function showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.classList.add('message', 'bot-message', 'typing-indicator');
        typingDiv.id = 'typing-indicator';

        const avatarDiv = document.createElement('div');
        avatarDiv.classList.add('message-avatar');
        avatarDiv.textContent = 'B';

        const dotsDiv = document.createElement('div');
        dotsDiv.classList.add('dots');

        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('div');
            dot.classList.add('dot');
            dotsDiv.appendChild(dot);
        }

        typingDiv.appendChild(avatarDiv);
        typingDiv.appendChild(dotsDiv);

        chatMessages.appendChild(typingDiv);

        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Function to remove typing indicator
    function removeTypingIndicator() {
        const typingIndicator = document.getElementById('typing-indicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }

    // Initialize Chat Limit Modal
    initializeChatLimitModal();

    // Expose functions to global scope for helper actions
    window.sendMessageToLLM = sendMessageToLLM;
    window.showTypingIndicator = showTypingIndicator;
    window.removeTypingIndicator = removeTypingIndicator;
});

/**
 * Initialize Chat Limit Modal functionality
 */
function initializeChatLimitModal() {
    // Event delegation for the "See why?" link
    document.addEventListener('click', (e) => {
        if (e.target && e.target.classList.contains('chat-limit-link')) {
            e.preventDefault();
            showChatLimitModal();
        }
    });

    // Event delegation for closing the modal
    document.addEventListener('click', (e) => {
        if (e.target) {
             // Close button
            if (e.target.id === 'close-info-modal-btn' || e.target.closest('#close-info-modal-btn')) {
                hideChatLimitModal();
            }
            // Overlay click (background)
            if (e.target.id === 'chat-limit-modal-overlay') {
                hideChatLimitModal();
            }
        }
    });
}

/**
 * Show the chat limit info modal
 * Creates it if it doesn't exist
 */
function showChatLimitModal() {
    let overlay = document.getElementById('chat-limit-modal-overlay');
    
    if (!overlay) {
        // Create modal structure
        overlay = document.createElement('div');
        overlay.id = 'chat-limit-modal-overlay';
        overlay.className = 'info-modal-overlay';
        
        overlay.innerHTML = `
            <div class="info-modal" role="dialog" aria-modal="true" aria-labelledby="limit-modal-title">
                <div class="info-modal-header">
                    <h2 id="limit-modal-title">Why the message limit?</h2>
                </div>
                
                <div class="info-modal-body">
                    <div class="info-section">
                        <p>We recommend starting a new session after about 15 messages for a few key reasons:</p>
                        
                        <h3>1. Response Quality</h3>
                        <p>As conversations get longer, the AI has to process much more information for every answer. This can sometimes cause it to "lose focus" or provide less accurate responses to your specific questions.</p>
                        
                        <h3>2. Staying on Topic</h3>
                        <p>Starting a fresh session helps keep the conversation focused on your current learning objectives. It's often cleaner to separate different topics into different sessions.</p>
                        
                        <h3>3. Best Practices</h3>
                        <ul>
                            <li><strong>New Topic = New Session:</strong> If you're switching to a completely different concept, start a new chat.</li>
                            <li><strong>Summarize First:</strong> Before leaving a long chat, ask BiocBot to "summarize what we discussed" so you can copy the key points to your notes!</li>
                            <li><strong>Check Your Understanding:</strong> Use the "Protégé Mode" to explain concepts back to BiocBot to solidify your learning.</li>
                        </ul>
                    </div>
                </div>
                
                <div class="info-modal-footer">
                    <button type="button" class="info-modal-btn" id="close-info-modal-btn">
                        Got it
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(overlay);
    }
    
    // Show modal
    overlay.classList.add('show');
    document.body.style.overflow = 'hidden'; // Prevent background scrolling
}

/**
 * Hide the chat limit info modal
 */
function hideChatLimitModal() {
    const overlay = document.getElementById('chat-limit-modal-overlay');
    if (overlay) {
        overlay.classList.remove('show');
        document.body.style.overflow = ''; // Restore scrolling
    }
}

function renderRevokedAccessUI() {
    try {
        // Only hide the chat body, keep the header (where course selector may live)
        const chatContainer = document.querySelector('.chat-container');
        if (chatContainer) {
            chatContainer.style.display = 'none';
        }

        // Insert warning below header
        const header = document.querySelector('.chat-header');
        if (header && header.parentElement) {
            const notice = document.createElement('div');
            notice.style.padding = '24px';
            notice.innerHTML = `
                <div style="background:#fff3cd;border:1px solid #ffeeba;color:#856404;padding:16px;border-radius:8px;">
                    <h2 style="margin-top:0;margin-bottom:8px;">Access disabled</h2>
                    <p>Your access in this course is revoked.</p>
                    <p>Please select another course from the course selector at the top if available.</p>
                </div>
            `;
            header.parentElement.insertBefore(notice, header.nextSibling);
            // Also render a standalone course selector since chat body is hidden
            renderStandaloneCourseSelectorBelowHeader(header.parentElement);
        }
        // Disable sidebar actions that start sessions
        const newSessionBtn = document.getElementById('new-session-btn');
        if (newSessionBtn) newSessionBtn.disabled = true;
    } catch (_) {}
}

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

// Global functions for flagging functionality

/**
 * Handle explanation request for a message
 * @param {string} text - The message text to explain
 * @param {string|null} topic - The detected topic associated with this message
 */
async function handleExplainAction(text, topic = null) {
    if (!text) return;
    
    // Check if we already have an ongoing request
    const existingTyping = document.getElementById('typing-indicator');
    if (existingTyping) return;

    // Clean up the text (remove any existing HTML tags if passed as innerHTML)
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = text;
    const cleanText = tempDiv.innerText;

    // prompt construction moved to backend
    
    // Show typing indicator
    showTypingIndicator();
    
    try {
        // Send the clean text to the LLM - backend will wrap it with the Explain Mode prompt
        // Pass the topic if available so backend can increment struggle count
        const explanationOptions = topic ? { topic: topic } : true;
        const response = await sendMessageToLLM(cleanText, false, null, explanationOptions);
        
        // Remove typing indicator
        removeTypingIndicator();
        
        // Add bot response
        addMessage(response.message, 'bot', true, false, response.sourceAttribution);
        
    } catch (error) {
        removeTypingIndicator();
        console.error('Explain error:', error);
        addMessage('Sorry, I encountered an error. Please try again.', 'bot', false, true, null);
    }
}

function buildSourceDownloadUrl(documentId, courseId) {
    const encodedDocId = encodeURIComponent(documentId);
    const encodedCourseId = encodeURIComponent(courseId);
    return `/api/chat/source-documents/${encodedDocId}/download?courseId=${encodedCourseId}`;
}

function renderSourceAttribution(sourceDiv, sourceAttribution) {
    const fallbackText = sourceAttribution && sourceAttribution.description
        ? sourceAttribution.description
        : 'TBD';
    const hasDownloadableSources = sourceAttribution
        && sourceAttribution.downloadsEnabled === true
        && Array.isArray(sourceAttribution.documents)
        && sourceAttribution.documents.some(doc => doc && doc.documentId);

    if (!hasDownloadableSources) {
        sourceDiv.textContent = `Source: ${fallbackText}`;
        return;
    }

    const courseId = localStorage.getItem('selectedCourseId');
    if (!courseId) {
        sourceDiv.textContent = `Source: ${fallbackText}`;
        return;
    }

    sourceDiv.textContent = '';
    sourceDiv.appendChild(document.createTextNode('Source: '));

    const docs = sourceAttribution.documents.filter(doc => doc && doc.documentId);
    docs.forEach((doc, index) => {
        if (index > 0) {
            sourceDiv.appendChild(document.createTextNode(', '));
        }

        const labelBase = doc.fileName || 'Source Document';
        const label = doc.lectureName ? `${labelBase} (${doc.lectureName})` : labelBase;
        const link = document.createElement('a');
        link.href = buildSourceDownloadUrl(doc.documentId, courseId);
        link.textContent = label;
        link.title = 'Download source document';
        sourceDiv.appendChild(link);
    });
}

/**
 * Global function to add a message to the chat
 * @param {string} content - The message content
 * @param {string} sender - 'user' or 'bot'
 * @param {boolean} withSource - Whether to show source citation
 * @param {boolean} skipAutoSave - Whether to skip auto-save for this message
 * @param {Object} sourceAttribution - Source attribution information
 * @param {boolean} isHtml - Whether content is HTML
 * @param {string} activeStruggleTopic - The currently active struggle topic (for Reset button)
 * @param {string} detectedTopic - The topic detected in this message (for Explain button)
 */
function addMessage(content, sender, withSource = false, skipAutoSave = false, sourceAttribution = null, isHtml = false, activeStruggleTopic = null, detectedTopic = null) {


    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) {
        console.error('Chat messages container not found');
        return;
    }

    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message', sender + '-message');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = sender === 'user' ? 'S' : 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const paragraph = document.createElement('p');
    // Use innerHTML if content is HTML, otherwise innerText
    if (isHtml) {
        paragraph.innerHTML = content;
    } else {
        // Use innerText to respect newlines from the source
        paragraph.innerText = content;
        // Ensure formatting is preserved
        paragraph.style.whiteSpace = 'pre-wrap';
    }

    contentDiv.appendChild(paragraph);

    // Create message footer for bottom elements
    const footerDiv = document.createElement('div');
    footerDiv.classList.add('message-footer');

    // Special handling: Never show source for the welcome message or the "Welcome to BiocBot!" unit selection message
    if (content && typeof content === 'string') {
        if ((content.includes("Hello! I'm BiocBot") && content.includes("AI study assistant")) ||
            (content.includes("Welcome to BiocBot!") && content.includes("I can see you have access to published units"))) {
            withSource = false;
        }
    }

    // Check for assessment start message to apply styling
    if (content && typeof content === 'string' && content.includes('Starting Assessment for')) {
        messageDiv.classList.add('assessment-start');
        // Force withSource to false for assessment start messages
        withSource = false;
    }

    // Add source citation if needed
    if (withSource && sender === 'bot') {
        const sourceDiv = document.createElement('div');
        sourceDiv.classList.add('message-source');

        renderSourceAttribution(sourceDiv, sourceAttribution);

        footerDiv.appendChild(sourceDiv);
    }

    // Create right side container for timestamp and flag button
    const rightContainer = document.createElement('div');
    rightContainer.classList.add('message-footer-right');

    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');

    // Create real timestamp
    const messageTime = new Date();
    timestamp.textContent = formatTimestamp(messageTime);

    // Store timestamp in message div for future updates
    messageDiv.dataset.timestamp = messageTime.getTime();

    // Add title attribute for exact time on hover
    timestamp.title = messageTime.toLocaleString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    });

    rightContainer.appendChild(timestamp);

    // Add flag button for bot messages
    if (sender === 'bot') {
        const flagContainer = document.createElement('div');
        flagContainer.classList.add('message-flag-container');

        // Add Explain Button
        // Only if message has content and is not the typing indicator
        if (content && !content.includes('<div class="dots">')) {
            const explainButton = document.createElement('button');
            explainButton.classList.add('message-action-btn');
            explainButton.innerHTML = 'Explain';
            explainButton.title = 'Explain this message for a novice';
            if (detectedTopic) {
                explainButton.title += ` (Topic: ${detectedTopic})`;
            }
            explainButton.style.marginRight = '8px'; // Add some spacing
            explainButton.onclick = () => handleExplainAction(content, detectedTopic);
            rightContainer.appendChild(explainButton);
        }

        const flagButton = document.createElement('button');
        flagButton.classList.add('flag-button');
        flagButton.innerHTML = '⚑';
        flagButton.title = 'Flag this message';
        flagButton.onclick = () => toggleFlagMenu(flagButton);

        // Create flag menu
        const flagMenu = document.createElement('div');
        flagMenu.classList.add('flag-menu');
        flagMenu.innerHTML = `
            <div class="flag-option" onclick="flagMessage(this, 'incorrect')">Incorrect</div>
            <div class="flag-option" onclick="flagMessage(this, 'inappropriate')">Inappropriate</div>
            <div class="flag-option" onclick="flagMessage(this, 'unclear')">Unclear</div>
            <div class="flag-option" onclick="flagMessage(this, 'confusing')">Confusing</div>
            <div class="flag-option" onclick="flagMessage(this, 'typo')">Typo/Error</div>
            <div class="flag-option" onclick="flagMessage(this, 'offensive')">Offensive</div>
            <div class="flag-option" onclick="flagMessage(this, 'irrelevant')">Irrelevant</div>
        `;

        flagContainer.appendChild(flagButton);
        flagContainer.appendChild(flagMenu);
        rightContainer.appendChild(flagContainer);

        // Add Struggle Reset Button if active topic exists
        if (activeStruggleTopic) {
            const resetBtn = document.createElement('button');
            resetBtn.className = 'message-action-btn struggle-reset-btn';
            resetBtn.style.marginLeft = '8px';
            resetBtn.style.color = '#dc3545'; // bootstrap danger color
            resetBtn.style.borderColor = '#dc3545';
            
            // Simple inline capitalization since helper might not be available
            const displayTopic = activeStruggleTopic.charAt(0).toUpperCase() + activeStruggleTopic.slice(1);
            resetBtn.textContent = `I understand ${displayTopic} now`;
            
            resetBtn.title = `Turn off Directive Mode for ${activeStruggleTopic}`;
            resetBtn.onclick = () => resetStruggleTopic(activeStruggleTopic);
            rightContainer.appendChild(resetBtn);
        }
    }

    footerDiv.appendChild(rightContainer);
    contentDiv.appendChild(footerDiv);

    messageDiv.appendChild(avatarDiv);
    messageDiv.appendChild(contentDiv);

    chatMessages.appendChild(messageDiv);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;

    // Auto-save the message
    // Only auto-save if not explicitly skipped
    if (!skipAutoSave) {
        autoSaveMessage(content, sender, withSource, sourceAttribution, isHtml, activeStruggleTopic);
    }
}

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
function autoSaveMessage(content, sender, withSource = false, sourceAttribution = null, isHtml = false, activeStruggleTopic = null) {
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
            activeStruggleTopic: activeStruggleTopic || null // Save active struggle topic
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
 * Reset a struggle topic
 * @param {string} topic - The topic to reset
 */
async function resetStruggleTopic(topic) {
    if (!confirm(`Are you sure you want to turn off Directive Mode for "${topic}"? This will reset your struggle history for this topic.`)) {
        return;
    }

    const courseId = localStorage.getItem('selectedCourseId');
    try {
        const response = await fetch('/api/student/struggle/reset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                topic: topic,
                courseId: courseId 
            })
        });

        const result = await response.json();

        if (result.success) {
            alert('Directive Mode turned off.');
            // Update UI without reload
            
            // 1. Clear global active topic
            lastActiveStruggleTopic = null;
            
            // 2. Remove the "Directive Mode Active" indicator
            const indicator = document.getElementById('directive-mode-indicator');
            if (indicator) indicator.remove();
            
            // 3. Remove all reset buttons to prevent double-clicking
            const buttons = document.querySelectorAll('.struggle-reset-btn');
            buttons.forEach(btn => btn.remove());
            
        } else {
            alert('Failed to reset: ' + result.message);
        }
    } catch (error) {
        console.error('Error resetting topic:', error);
        alert('Error connecting to server.');
    }
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
 * Setup Idle Listeners and Warning Logic
 * @param {number} timeoutSeconds - Timeout in seconds
 */





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
 * Format timestamp for display (global version)
 * @param {Date} timestamp - The timestamp to format
 * @returns {string} Formatted timestamp string
 */
function formatTimestamp(timestamp) {
    const now = new Date();
    const diffMs = now - timestamp;
    const diffSeconds = Math.floor(diffMs / 1000);
    const diffMinutes = Math.floor(diffSeconds / 60);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    // Format based on how long ago
    if (diffSeconds < 60) {
        return 'Just now';
    } else if (diffMinutes < 60) {
        return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`;
    } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
        return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    } else {
        // For older messages, show actual date
        return timestamp.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true
        });
    }
}
/**
 * Toggle the flag menu visibility
 * @param {HTMLElement} button - The flag button element
 */
function toggleFlagMenu(button) {
    // Close all other open menus first
    const allMenus = document.querySelectorAll('.flag-menu.show');
    allMenus.forEach(menu => {
        if (menu !== button.nextElementSibling) {
            menu.classList.remove('show');
        }
    });

    // Toggle the clicked menu
    const menu = button.nextElementSibling;
    if (menu && menu.classList.contains('flag-menu')) {
        menu.classList.toggle('show');
    }
}

/**
 * Handle flag message action
 * @param {HTMLElement} button - The flag option button
 * @param {string} flagType - The type of flag (now flagReason)
 */
function flagMessage(button, flagType) {
    const menu = button.closest('.flag-menu');
    const messageContent = menu.closest('.message-content');
    const messageText = messageContent.querySelector('p').textContent;

    // Close the menu
    menu.classList.remove('show');

    // Send flag to server
    submitFlag(messageText, flagType);

    // Replace the message content with thank you message
    replaceMessageWithThankYou(messageContent, flagType);
}

/**
 * Submit flag to server
 * @param {string} messageText - The flagged message text
 * @param {string} flagType - The type of flag (now flagReason)
 */
async function submitFlag(messageText, flagType) {
    try {
        // Get current course and student information
        const courseId = localStorage.getItem('selectedCourseId');
        if (!courseId) {
            throw new Error('No course selected. Please select a course first.');
        }
        const studentId = getCurrentStudentId();
        const studentName = getCurrentStudentName();
        const unitName = getCurrentUnitName();
        
        // Get current bot mode (protege or tutor)
        const botMode = localStorage.getItem('studentMode') || 'tutor';
        // fixed the resolved.

        // Create flag data for the new flagged questions API
        const flagData = {
            questionId: generateQuestionId(messageText), // Generate a unique ID for this "question"
            courseId: courseId,
            unitName: unitName,
            studentId: studentId,
            studentName: studentName,
            flagReason: flagType,
            flagDescription: `Student flagged bot response as ${flagType}`,
            botMode: botMode, // Include the bot mode (protege or tutor) when the flag was submitted
            questionContent: {
                question: messageText,
                questionType: 'bot-response',
                options: {},
                correctAnswer: 'N/A',
                explanation: 'This is a flagged bot response from the student chat interface'
            }
        };



        const response = await fetch('/api/flags', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(flagData)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();


        // Immediately refresh flag notifications to track the new flag
        // This ensures the flag is in lastKnownFlags so we can detect when it's approved
        if (result.success && typeof checkForFlagUpdates === 'function') {

            // Small delay to ensure the flag is saved on the server
            setTimeout(() => {
                checkForFlagUpdates();
            }, 1000);
        }

    } catch (error) {
        console.error('Error submitting flag:', error);
        // Still show confirmation to user even if server request fails
    }
}

/**
 * Replace the bot message with a thank you message
 * @param {HTMLElement} messageContent - The message content element
 * @param {string} flagType - The type of flag that was submitted (now flagReason)
 */
function replaceMessageWithThankYou(messageContent, flagType) {
    // Get the paragraph element
    const paragraph = messageContent.querySelector('p');

    // Map flag types to user-friendly descriptions
    const flagTypeDescriptions = {
        'incorrect': 'incorrect information',
        'inappropriate': 'inappropriate content',
        'unclear': 'unclear or confusing content',
        'confusing': 'confusing content',
        'typo': 'typo or error',
        'offensive': 'offensive content',
        'irrelevant': 'irrelevant content'
    };

    const description = flagTypeDescriptions[flagType] || flagType;

    // Replace the message text
    paragraph.textContent = `Thank you for reporting this response as ${description}. This has been logged and will be reviewed by your instructor.`;

    // Add a visual indicator that this message was flagged
    paragraph.style.color = '#666';
    paragraph.style.fontStyle = 'italic';

    // Remove the flag button and menu
    const flagContainer = messageContent.querySelector('.message-flag-container');
    if (flagContainer) {
        flagContainer.remove();
    }

    // Update the timestamp to show when it was flagged
    const timestamp = messageContent.querySelector('.timestamp');
    if (timestamp) {
        timestamp.textContent = 'Flagged just now';
        timestamp.style.color = '#888';
    }

    // Add a subtle background color to indicate the message was flagged
    messageContent.style.backgroundColor = '#f8f9fa';
    messageContent.style.border = '1px solid #e9ecef';
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
            <select id="course-select" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                <option value="">Choose a course...</option>
                ${courses.map(course => `<option value="${course.courseId}" data-enrolled="${course.isEnrolled}">${course.courseName}</option>`).join('')}
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
            const selectedOption = this.options[this.selectedIndex];
            const selectedCourseId = this.value;
            const isEnrolled = selectedOption.getAttribute('data-enrolled') === 'true';

            if (selectedCourseId) {
                console.log('Course selected:', selectedCourseId, 'Enrolled:', isEnrolled);
                
                if (isEnrolled) {
                    // Already enrolled, load normally
                    await loadCourseData(selectedCourseId, true);
                    // Hide the course selection after selection
                    const courseSelectionWrapper = document.getElementById('course-selection-wrapper');
                    if (courseSelectionWrapper) {
                        courseSelectionWrapper.style.display = 'none';
                    }
                } else {
                    // Not enrolled, prompt for code
                    const code = prompt("Please enter the Course Code provided by your instructor:");
                    if (code) {
                        try {
                            const response = await fetch(`/api/courses/${selectedCourseId}/join`, {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ code })
                            });
                            
                            const result = await response.json();
                            if (result.success) {
                                alert('Successfully joined the course!');
                                await loadCourseData(selectedCourseId, true);
                                const courseSelectionWrapper = document.getElementById('course-selection-wrapper');
                                if (courseSelectionWrapper) {
                                    courseSelectionWrapper.style.display = 'none';
                                }
                            } else {
                                alert(result.message || 'Failed to join course. Please check the code.');
                                this.value = ""; // Reset dropdown
                            }
                        } catch (err) {
                            console.error('Error joining course:', err);
                            alert('Error joining course. Please try again.');
                            this.value = ""; // Reset dropdown
                        }
                    } else {
                        this.value = ""; // Reset dropdown if cancelled
                    }
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

// Close flag menus when clicking outside
document.addEventListener('click', function(event) {
    if (!event.target.closest('.message-flag-container')) {
        const openMenus = document.querySelectorAll('.flag-menu.show');
        openMenus.forEach(menu => {
            menu.classList.remove('show');
        });
    }
});

// Calibration Questions functionality
let currentCalibrationQuestions = [];
let currentPassThreshold = 2; // Default pass threshold
let currentQuestionIndex = 0;
let studentAnswers = [];
window.studentEvaluations = []; // Store AI evaluations for written answers

// Make variables globally accessible for auto-save
window.currentCalibrationQuestions = currentCalibrationQuestions;
window.studentAnswers = studentAnswers;

/**
 * Check for published units and load real assessment questions
 * If no units are published, allow direct chat
 */
async function checkPublishedUnitsAndLoadQuestions() {
    try {


        // Prevent duplicate calls - if already checking, wait for it to complete
        if (window.isCheckingPublishedUnits) {

            return;
        }
        window.isCheckingPublishedUnits = true;

        // Check if chat was auto-continued
        if (window.autoContinued) {

            // We DO NOT return here anymore - we need to fetch units to show the dropdown
            // The loading of questions will be handled safely in loadQuestionsForSelectedUnit
        }

        // Get current course ID from localStorage
        const courseId = localStorage.getItem('selectedCourseId');
        if (!courseId) {

            window.isCheckingPublishedUnits = false; // Reset flag on early return
            return;
        }


        // Fetch course data to check which units are published
        const response = await fetch(`/api/courses/${courseId}`);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('API error response body:', errorText);

            // If course not found, clear localStorage and try to load available courses
            if (response.status === 404) {

                localStorage.removeItem('selectedCourseId');
                window.isCheckingPublishedUnits = false; // Reset flag before returning
                await loadAvailableCourses();
                return;
            }

            window.isCheckingPublishedUnits = false; // Reset flag on error
            throw new Error(`Failed to fetch course data: ${response.status} - ${errorText}`);
        }

        const courseData = await response.json();


        if (!courseData.data || !courseData.data.lectures) {

            showNoQuestionsMessage();
            window.isCheckingPublishedUnits = false; // Reset flag on early return
            return;
        }

        // Find published units
        const publishedUnits = courseData.data.lectures.filter(unit => unit.isPublished === true);


        if (publishedUnits.length === 0) {

            showNoQuestionsMessage();
            window.isCheckingPublishedUnits = false; // Reset flag on early return
            return;
        }

        // Show unit selection dropdown instead of automatically loading all questions

        showUnitSelectionDropdown(publishedUnits);

        // Reset the flag after completion
        window.isCheckingPublishedUnits = false;

    } catch (error) {
        console.error('=== ERROR CHECKING PUBLISHED UNITS ===');
        console.error('Error details:', error);
        console.error('Error stack:', error.stack);
        showNoQuestionsMessage();
        // Reset the flag even on error
        window.isCheckingPublishedUnits = false;
    }
}

/**
 * Enable chat input and clear noPublishedUnits flag
 * Called when units are available or assessment is completed
 */
function enableChatInput() {
    // Clear the noPublishedUnits flag since units are now available
    window.noPublishedUnits = false;

    // Show chat input container
    const chatInputContainer = document.querySelector('.chat-input-container');
    if (chatInputContainer) {
        chatInputContainer.style.display = 'block';
    }

    // Re-enable the chat input field
    const chatInput = document.getElementById('chat-input');
    if (chatInput) {
        chatInput.disabled = false;
        chatInput.placeholder = 'Type your message here...';
        chatInput.classList.remove('disabled-input');
        chatInput.style.cursor = 'text';
    }

    // Re-enable the send button
    const sendButton = document.getElementById('send-button');
    if (sendButton) {
        sendButton.disabled = false;
        sendButton.classList.remove('disabled-button');
        sendButton.style.cursor = 'pointer';
        sendButton.style.opacity = '1';
    }

    // Show mode toggle
    const modeToggleContainer = document.querySelector('.mode-toggle-container');
    if (modeToggleContainer) {
        modeToggleContainer.style.display = 'block';
    }
}

/**
 * Show message when no questions are available
 * Disables chat input and prevents chat functionality when no units are published
 */
function showNoQuestionsMessage() {


    // Set a global flag to prevent chat functionality
    window.noPublishedUnits = true;

    // Set default mode to tutor
    localStorage.setItem('studentMode', 'tutor');
    updateModeToggleUI('tutor');

    // Show chat input container but disable the input
    const chatInputContainer = document.querySelector('.chat-input-container');
    if (chatInputContainer) {
        chatInputContainer.style.display = 'block';
    }

    // Disable the chat input field - make it not typable
    const chatInput = document.getElementById('chat-input');
    if (chatInput) {
        chatInput.disabled = true;
        chatInput.placeholder = 'No units published - chat unavailable';
        chatInput.classList.add('disabled-input');
        chatInput.style.cursor = 'not-allowed';
    }

    // Disable the send button
    const sendButton = document.getElementById('send-button');
    if (sendButton) {
        sendButton.disabled = true;
        sendButton.classList.add('disabled-button');
        sendButton.style.cursor = 'not-allowed';
        sendButton.style.opacity = '0.6';
    }

    // Hide mode toggle since chat is disabled
    const modeToggleContainer = document.querySelector('.mode-toggle-container');
    if (modeToggleContainer) {
        modeToggleContainer.style.display = 'none';
    }

    // Add message to chat with the specified text
    const noQuestionsMessage = document.createElement('div');
    noQuestionsMessage.classList.add('message', 'bot-message');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const messageText = document.createElement('p');
    messageText.textContent = 'No units published at this time, so please check back with your instructor and get back to me with regards to anything you need';

    contentDiv.appendChild(messageText);

    // Add timestamp
    const footerDiv = document.createElement('div');
    footerDiv.classList.add('message-footer');
    const footerRight = document.createElement('div');
    footerRight.classList.add('message-footer-right');
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = 'Just now';
    footerRight.appendChild(timestamp);
    footerDiv.appendChild(footerRight);
    contentDiv.appendChild(footerDiv);

    noQuestionsMessage.appendChild(avatarDiv);
    noQuestionsMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(noQuestionsMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Show unit selection dropdown for published units
 * Automatically selects the most recently published unit
 * @param {Array} publishedUnits - Array of published unit objects
 */
function showUnitSelectionDropdown(publishedUnits) {
    console.log('=== SHOWING UNIT SELECTION DROPDOWN ===');
    console.log('Published units for dropdown:', publishedUnits);

    // Sort published units to find the most recently published one
    // Strategy: Try to sort by updatedAt first, then by unit number, then by array position
    const sortedUnits = [...publishedUnits].sort((a, b) => {
        // First, try to sort by updatedAt if available
        if (a.updatedAt && b.updatedAt) {
            const aDate = new Date(a.updatedAt);
            const bDate = new Date(b.updatedAt);
            if (aDate.getTime() !== bDate.getTime()) {
                return bDate - aDate; // Descending order (most recent first)
            }
        }

        // If updatedAt is not available or equal, extract unit number from name
        // Handles formats like "Unit 1", "Unit 4", "Week 1", etc.
        const extractUnitNumber = (name) => {
            const match = name.match(/(\d+)/);
            return match ? parseInt(match[1], 10) : 0;
        };

        const aNum = extractUnitNumber(a.name);
        const bNum = extractUnitNumber(b.name);

        if (aNum !== bNum) {
            return bNum - aNum; // Descending order (higher number = more recent)
        }

        // If unit numbers are the same or can't be extracted, maintain original order
        return 0;
    });

    // Get the most recently published unit (first in sorted array)
    const mostRecentUnit = sortedUnits.length > 0 ? sortedUnits[0] : null;


    // Show the unit selection container
    const unitSelectionContainer = document.getElementById('unit-selection-container');
    if (unitSelectionContainer) {
        unitSelectionContainer.style.display = 'flex';
    }

    // Populate the dropdown with published units
    const unitSelect = document.getElementById('unit-select');
    if (unitSelect) {
        // Clear existing options
        unitSelect.innerHTML = '<option value="">Choose a unit...</option>';

        // Remove any existing change event listeners by replacing the element
        // This prevents duplicate event listeners if the function is called multiple times
        const oldSelect = unitSelect;
        const newSelect = oldSelect.cloneNode(false); // Clone without children
        oldSelect.parentNode.replaceChild(newSelect, oldSelect);

        // Get reference to the new select element
        const updatedUnitSelect = document.getElementById('unit-select');

        // Add placeholder option
        const placeholderOption = document.createElement('option');
        placeholderOption.value = '';
        placeholderOption.textContent = 'Choose a unit...';
        updatedUnitSelect.appendChild(placeholderOption);

        // Add options for each published unit (in original order for display)
        publishedUnits.forEach(unit => {
            const option = document.createElement('option');
            option.value = unit.name; // Keep internal name as value
            
            // Format display: "1. Biology" if displayName exists, otherwise just "Unit 1"
            const unitNum = unit.name.match(/\d+/)?.[0] || '';
            const displayText = unit.displayName 
                ? `${unitNum}. ${unit.displayName}` 
                : unit.name;
            option.textContent = displayText;
            
            updatedUnitSelect.appendChild(option);
        });

        // Check for saved chat data first - if it exists and is within 30 minutes, restore that unit instead
        const savedChatData = getCurrentChatData();
        let shouldRestoreSavedUnit = false;
        let savedUnitName = null;

        if (savedChatData && savedChatData.lastActivityTimestamp) {
            const hasMessages = savedChatData.messages && savedChatData.messages.length > 0;
            const hasAssessment = (savedChatData.practiceTests && savedChatData.practiceTests.questions && savedChatData.practiceTests.questions.length > 0) || 
                                 (savedChatData.studentAnswers && savedChatData.studentAnswers.answers && savedChatData.studentAnswers.answers.length > 0);

            if (hasMessages || hasAssessment) {
                const lastActivity = new Date(savedChatData.lastActivityTimestamp);
                const now = new Date();
                const diffMs = now - lastActivity;
                const diffMinutes = Math.floor(diffMs / (1000 * 60));

                if (diffMinutes <= 30 && savedChatData.metadata && savedChatData.metadata.unitName) {
                    savedUnitName = savedChatData.metadata.unitName;
                    // Check if the saved unit is in the published units list
                    const savedUnitExists = publishedUnits.some(u => u.name === savedUnitName);
                    if (savedUnitExists) {
                        shouldRestoreSavedUnit = true;

                    } else {

                    }
                }
            }
        }

        // Auto-select unit: prefer saved unit if it exists, otherwise use most recent
        if (shouldRestoreSavedUnit && savedUnitName) {
            updatedUnitSelect.value = savedUnitName;


            // Persist selection for chat retrieval
            localStorage.setItem('selectedUnitName', savedUnitName);

            // Don't load questions immediately - let auto-continue handle the restoration
            // The auto-continue check will happen after auth is ready and will restore the chat
        } else if (mostRecentUnit) {
            updatedUnitSelect.value = mostRecentUnit.name;


            // Persist selection for chat retrieval
            localStorage.setItem('selectedUnitName', mostRecentUnit.name);

            // Trigger the load immediately (without waiting for user interaction)
            loadQuestionsForSelectedUnit(mostRecentUnit.name);
        }

        // Add event listener for manual unit selection changes
        updatedUnitSelect.addEventListener('change', async function() {
            const selectedUnit = this.value;
            if (selectedUnit) {

                // Persist selection for chat retrieval
                localStorage.setItem('selectedUnitName', selectedUnit);
                await loadQuestionsForSelectedUnit(selectedUnit);
            }
        });
    }

    // Check if we are loading from history or auto-continuing
    const isHistoryLoad = window.loadingFromHistory || 
                         sessionStorage.getItem('isContinuingChat') === 'true' || 
                         window.autoContinued;
    
    // Only show welcome message if NOT loading from history
    if (!isHistoryLoad) {
        showUnitSelectionWelcomeMessage();
    }

    // Hide chat input and mode toggle until assessment is completed
    // BUT ONLY if we are NOT loading from history or auto-continuing a chat
    // If we are loading history, the chat is already established so we need the input
    if (!isHistoryLoad) {
        const chatInputContainer = document.querySelector('.chat-input-container');
        if (chatInputContainer) {
            chatInputContainer.style.display = 'none';
        }
        const modeToggleContainer = document.querySelector('.mode-toggle-container');
        if (modeToggleContainer) {
            modeToggleContainer.style.display = 'none';
        }
    } else {
        // Explicitly ensure they are visible for history loads
        const chatInputContainer = document.querySelector('.chat-input-container');
        if (chatInputContainer) {
            chatInputContainer.style.display = 'block';
        }
        const modeToggleContainer = document.querySelector('.mode-toggle-container');
        if (modeToggleContainer) {
            modeToggleContainer.style.display = 'flex';
        }
    }
}

/**
 * Show welcome message with unit selection instructions
 */
/**
 * Show welcome message with unit selection instructions
 */
function showUnitSelectionWelcomeMessage() {


    const messageContent = `<strong>Welcome to BiocBot!</strong><br>
    I can see you have access to published units. Please select a unit from the dropdown above to start your assessment, or feel free to chat with me about any topics you'd like to discuss.`;

    // Use addMessage to ensure it's properly handled and auto-saved
    // sender='bot', hasFlagButton=false, skipAutoSave=false
    // Use addMessage to ensure it's properly handled and auto-saved
    // sender='bot', hasFlagButton=false, skipAutoSave=false, sourceAttribution=null, isHtml=true
    addMessage(messageContent, 'bot', false, false, null, true);
}

/**
 * Load assessment questions for a selected unit
 * @param {string} unitName - Name of the selected unit
 */
async function loadQuestionsForSelectedUnit(unitName) {
    try {


        // Check if we should auto-continue instead of starting a new assessment
        // If there's saved chat data for this unit within 30 minutes, skip loading questions
        const savedChatData = getCurrentChatData();
        if (savedChatData && savedChatData.messages && savedChatData.messages.length > 0 && savedChatData.lastActivityTimestamp) {
            const lastActivity = new Date(savedChatData.lastActivityTimestamp);
            const now = new Date();
            const diffMs = now - lastActivity;
            const diffMinutes = Math.floor(diffMs / (1000 * 60));

            if (diffMinutes <= 30 && savedChatData.metadata && savedChatData.metadata.unitName === unitName) {

                // Don't load questions - let auto-continue handle restoration
                return;
            }
        }

        // Hide chat input and mode toggle when starting new assessment
        const chatInputContainer = document.querySelector('.chat-input-container');
        // Do not hide input if we are loading from history and just checking units
        if (chatInputContainer && !window.loadingFromHistory && !sessionStorage.getItem('isContinuingChat')) {
            chatInputContainer.style.display = 'none';
        }
        const modeToggleContainer = document.querySelector('.mode-toggle-container');
        if (modeToggleContainer && !window.loadingFromHistory && !sessionStorage.getItem('isContinuingChat')) {
            modeToggleContainer.style.display = 'none';
        }

        // Get current course ID from localStorage
        const courseId = localStorage.getItem('selectedCourseId');
        if (!courseId) {
            throw new Error('No course selected. Please select a course first.');
        }

        // Find the selected unit from the published units
        const courseResponse = await fetch(`/api/courses/${courseId}`);
        if (!courseResponse.ok) {
            throw new Error(`Failed to fetch course data: ${courseResponse.status}`);
        }

        const courseData = await courseResponse.json();
        const selectedUnit = courseData.data.lectures.find(unit => unit.name === unitName);

        if (!selectedUnit) {
            throw new Error(`Unit ${unitName} not found`);
        }



        // Collect questions for this specific unit
        const unitQuestions = [];

        // Check if the unit has assessment questions directly embedded
        if (selectedUnit.assessmentQuestions && selectedUnit.assessmentQuestions.length > 0) {


            // Transform embedded questions to match our format
            const transformedQuestions = selectedUnit.assessmentQuestions.map(q => {
                // Clean the options format - remove "A,", "B,", "C," prefixes if present
                let cleanOptions = q.options || {};
                if (q.options && typeof q.options === 'object') {
                    cleanOptions = {};

                    Object.keys(q.options).forEach(key => {
                        let optionValue = q.options[key];

                        if (typeof optionValue === 'string') {
                            // Remove prefix like "A,", "B,", "C," - look for pattern of letter followed by comma
                            if (/^[A-Z],/.test(optionValue)) {
                                const originalValue = optionValue;
                                optionValue = optionValue.substring(2); // Remove "A,", "B,", etc.

                            } else {

                            }
                        }
                        cleanOptions[key] = optionValue;
                    });

                }

                return {
                    id: q.questionId || q.id || q._id,
                    type: q.questionType || 'multiple-choice',
                    question: q.question,
                    options: cleanOptions,
                    correctAnswer: q.correctAnswer,
                    explanation: q.explanation || '',
                    unitName: selectedUnit.name,
                    passThreshold: selectedUnit.passThreshold !== undefined && selectedUnit.passThreshold !== null ? selectedUnit.passThreshold : 0
                };
            });

            unitQuestions.push(...transformedQuestions);

        } else {


            try {
                // Try to fetch questions from API endpoint
                const questionsResponse = await fetch(`/api/questions/lecture?courseId=${courseId}&lectureName=${unitName}`);


                if (questionsResponse.ok) {
                    const questionsData = await questionsResponse.json();


                    if (questionsData.data && questionsData.data.questions && questionsData.data.questions.length > 0) {
                        // Transform API questions to match our format
                        const transformedQuestions = questionsData.data.questions.map(q => {


                            // Fix the correct answer format - remove "A" prefix if present
                            let cleanCorrectAnswer = q.correctAnswer;
                            if (typeof cleanCorrectAnswer === 'string' && cleanCorrectAnswer.startsWith('A')) {
                                cleanCorrectAnswer = cleanCorrectAnswer.substring(1);

                            }

                            // Fix the options format - remove "A,", "B,", "C," prefixes if present
                            let cleanOptions = q.options;
                            if (q.options && typeof q.options === 'object') {
                                cleanOptions = {};

                                Object.keys(q.options).forEach(key => {
                                    let optionValue = q.options[key];

                                    if (typeof optionValue === 'string') {
                                        // Remove prefix like "A,", "B,", "C," - look for pattern of letter followed by comma
                                        if (/^[A-Z],/.test(optionValue)) {
                                            const originalValue = optionValue;
                                            optionValue = optionValue.substring(2); // Remove "A,", "B,", etc.

                                        } else {

                                        }
                                    }
                                    cleanOptions[key] = optionValue;
                                });

                            }

                            return {
                                id: q.questionId || q.id || q._id,
                                type: q.questionType || 'multiple-choice',
                                question: q.question,
                                options: cleanOptions,
                                correctAnswer: cleanCorrectAnswer,
                                explanation: q.explanation || '',
                                unitName: selectedUnit.name,
                                passThreshold: selectedUnit.passThreshold !== undefined && selectedUnit.passThreshold !== null ? selectedUnit.passThreshold : 0
                            };
                        });

                        unitQuestions.push(...transformedQuestions);

                    } else {

                    }
                } else {
                    const errorText = await questionsResponse.text();
                    console.warn(`Failed to fetch API questions for ${unitName}:`, questionsResponse.status, errorText);
                }
            } catch (error) {
                console.error(`Error loading API questions for ${unitName}:`, error);
            }
        }



        if (unitQuestions.length === 0) {

            showNoQuestionsForUnitMessage(unitName);
            return;
        }

        // Start the assessment process with questions from the selected unit
        // Use the pass threshold from the unit, or default to 0 if not set
        // Note: Check for null/undefined separately since 0 is a valid threshold value
        const unitPassThreshold = (selectedUnit.passThreshold !== undefined && selectedUnit.passThreshold !== null)
            ? selectedUnit.passThreshold
            : 0;

        startAssessmentWithQuestions(unitQuestions, unitPassThreshold);

    } catch (error) {
        console.error(`Error loading questions for unit ${unitName}:`, error);
        showNoQuestionsForUnitMessage(unitName);
    }
}

/**
 * Show message when no questions are available for a specific unit
 * @param {string} unitName - Name of the unit that has no questions
 */
function showNoQuestionsForUnitMessage(unitName) {


    // Set default mode to tutor
    localStorage.setItem('studentMode', 'tutor');
    updateModeToggleUI('tutor');

    // Enable chat since questions are available for this unit
    enableChatInput();

    // Add message to chat
    const noQuestionsMessage = document.createElement('div');
    noQuestionsMessage.classList.add('message', 'bot-message');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const messageText = document.createElement('p');
    messageText.innerHTML = `<strong>No Questions Available</strong><br>
    There are no assessment questions available for ${unitName} at this time. You can select a different unit or chat directly with me about any topics you'd like to discuss.
    Please pick either tutor or protege mode to continue your learning journey.`;

    contentDiv.appendChild(messageText);

    // Add timestamp
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = 'Just now';
    contentDiv.appendChild(timestamp);

    noQuestionsMessage.appendChild(avatarDiv);
    noQuestionsMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(noQuestionsMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;

    // Set unit selection to the current unit to show what was selected
    const unitSelect = document.getElementById('unit-select');
    if (unitSelect) {
        unitSelect.value = unitName;
    }
}

/**
 * Start assessment with loaded questions
 */
function startAssessmentWithQuestions(questions, passThreshold = 0) {


    // Clear any existing mode
    localStorage.removeItem('studentMode');

    // Set up the questions and pass threshold
    currentCalibrationQuestions = questions;
    window.currentCalibrationQuestions = questions; // Update global reference
    // Adjust pass threshold to not exceed the number of questions available
    currentPassThreshold = Math.min(passThreshold, questions.length);
    window.currentPassThreshold = currentPassThreshold; // Update global reference
    currentQuestionIndex = 0;
    studentAnswers = [];
    window.studentAnswers = studentAnswers; // Update global reference



    // Hide chat input during assessment
    const chatInputContainer = document.querySelector('.chat-input-container');
    if (chatInputContainer) {
        chatInputContainer.style.display = 'none';
    }

    // Hide mode toggle during assessment
    const modeToggleContainer = document.querySelector('.mode-toggle-container');
    if (modeToggleContainer) {
        modeToggleContainer.style.display = 'none';
    }

    // Get chat messages container (needed for both clearing and adding messages)
    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) {
        console.error('Chat messages container not found');
        return;
    }

    // Only clear chat data if this is a new session (not auto-continued)
    // Check if chat was auto-continued before clearing
    if (!window.autoContinued) {
        // Clear any existing messages except the welcome message and unit selection dropdown
        const welcomeMessage = chatMessages.querySelector('.message:not(.calibration-question):not(.mode-result):not(.unit-selection-welcome)');
        if (welcomeMessage) {
            chatMessages.innerHTML = '';
            chatMessages.appendChild(welcomeMessage);

            // Clear auto-save data when starting assessment - this is a new session

            clearCurrentChatData();
        }
    } else {

    }

    // Add message about starting assessment for the selected unit
    const unitName = questions.length > 0 ? questions[0].unitName : 'the selected unit';
    const assessmentStartMessage = document.createElement('div');
    assessmentStartMessage.classList.add('message', 'bot-message', 'assessment-start');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const messageText = document.createElement('p');
    messageText.innerHTML = `<strong>Starting Assessment for ${unitName}</strong><br>
    I'll ask you a few questions to understand your current knowledge level. This will help me provide the most helpful responses for your learning needs.`;

    contentDiv.appendChild(messageText);

    // Add timestamp
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = 'Just now';
    contentDiv.appendChild(timestamp);

    assessmentStartMessage.appendChild(avatarDiv);
    assessmentStartMessage.appendChild(contentDiv);

    // Add to chat
    chatMessages.appendChild(assessmentStartMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;

    // Show first question
    showCalibrationQuestion();
}

/**
 * Show a specific calibration question
 */
function showCalibrationQuestion() {
    if (currentQuestionIndex >= currentCalibrationQuestions.length) {
        // All questions answered, calculate mode
        calculateStudentMode();
        return;
    }

    const question = currentCalibrationQuestions[currentQuestionIndex];

    // Create question message
    const questionMessage = document.createElement('div');
    questionMessage.classList.add('message', 'bot-message', 'calibration-question');
    questionMessage.id = `calibration-question-${currentQuestionIndex}`; // Unique ID for each question

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const questionText = document.createElement('p');
    questionText.textContent = `Question ${currentQuestionIndex + 1}: ${question.question}`;
    contentDiv.appendChild(questionText);

    // Handle different question types
    if (question.type === 'true-false') {
        // Create True/False options
        const optionsDiv = document.createElement('div');
        optionsDiv.classList.add('calibration-options');

        // For true-false, always create True/False options
        const options = ['True', 'False'];

        options.forEach((option, index) => {
            const optionContainer = document.createElement('div');
            optionContainer.classList.add('calibration-option-container');

            const optionButton = document.createElement('button');
            optionButton.classList.add('calibration-option');
            optionButton.textContent = option;
            optionButton.onclick = () => selectCalibrationAnswer(index, currentQuestionIndex);

            optionContainer.appendChild(optionButton);
            optionsDiv.appendChild(optionContainer);
        });

        contentDiv.appendChild(optionsDiv);

    } else if (question.type === 'multiple-choice') {
        // Create Multiple Choice options
        const optionsDiv = document.createElement('div');
        optionsDiv.classList.add('calibration-options');

        if (question.options && Object.keys(question.options).length > 0) {
            // Use the options from the question (handle both array and object formats)
            const optionEntries = Array.isArray(question.options) ? question.options : Object.entries(question.options);



            optionEntries.forEach((option, index) => {
                const optionContainer = document.createElement('div');
                optionContainer.classList.add('calibration-option-container');

                const optionButton = document.createElement('button');
                optionButton.classList.add('calibration-option');

                // Handle both array and object formats
                let optionText = '';
                if (Array.isArray(option)) {
                    // For Object.entries format: ["A", "MANGO"] -> use the second element (value)
                    optionText = option[1] || `Option ${index + 1}`;
                } else if (typeof option === 'object' && option !== null) {
                    optionText = option[1] || `Option ${index + 1}`;
                } else {
                    optionText = option || `Option ${index + 1}`;
                }



                // Don't add extra letters since we're cleaning the options from the database
                optionButton.textContent = `${String.fromCharCode(65 + index)}. ${optionText}`;
                optionButton.onclick = () => selectCalibrationAnswer(index, currentQuestionIndex);

                optionContainer.appendChild(optionButton);
                optionsDiv.appendChild(optionContainer);
            });
        } else {
            // Fallback options if none provided
            const fallbackOptions = ['Option A', 'Option B', 'Option C', 'Option D'];
            fallbackOptions.forEach((option, index) => {
                const optionContainer = document.createElement('div');
                optionContainer.classList.add('calibration-option-container');

                const optionButton = document.createElement('button');
                optionButton.classList.add('calibration-option');
                optionButton.textContent = `${String.fromCharCode(65 + index)}. ${option}`;
                optionButton.onclick = () => selectCalibrationAnswer(index, currentQuestionIndex);

                optionContainer.appendChild(optionButton);
                optionsDiv.appendChild(optionContainer);
            });
        }

        contentDiv.appendChild(optionsDiv);

    } else if (question.type === 'short-answer') {
        // Create Short Answer input
        const answerContainer = document.createElement('div');
        answerContainer.classList.add('calibration-short-answer');

        const answerInput = document.createElement('textarea');
        answerInput.classList.add('calibration-answer-input');
        answerInput.placeholder = 'Type your answer here...';
        answerInput.rows = 3;

        const submitButton = document.createElement('button');
        submitButton.classList.add('calibration-submit-btn');
        submitButton.textContent = 'Submit Answer';
        submitButton.onclick = () => submitShortAnswer(answerInput.value, currentQuestionIndex);

        answerContainer.appendChild(answerInput);
        answerContainer.appendChild(submitButton);
        contentDiv.appendChild(answerContainer);
    } else {
        // Handle unknown question types by defaulting to multiple choice
        console.warn(`Unknown question type: ${question.type}, defaulting to multiple choice`);

        const optionsDiv = document.createElement('div');
        optionsDiv.classList.add('calibration-options');

        const fallbackOptions = ['Option A', 'Option B', 'Option C', 'Option D'];
        fallbackOptions.forEach((option, index) => {
            const optionContainer = document.createElement('div');
            optionContainer.classList.add('calibration-option-container');

            const optionButton = document.createElement('button');
            optionButton.classList.add('calibration-option');
            optionButton.textContent = `${String.fromCharCode(65 + index)}. ${option}`;
            optionButton.onclick = () => selectCalibrationAnswer(index, currentQuestionIndex);

            optionContainer.appendChild(optionButton);
            optionsDiv.appendChild(optionContainer);
        });

        contentDiv.appendChild(optionsDiv);
    }

    // Create message footer for timestamp only (no flag button for calibration questions)
    const footerDiv = document.createElement('div');
    footerDiv.classList.add('message-footer');

    // Create right side container for timestamp only
    const rightContainer = document.createElement('div');
    rightContainer.classList.add('message-footer-right');

    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');

        // Create real timestamp for calibration question
        const questionTime = new Date();
        timestamp.textContent = formatTimestamp(questionTime);

        // Store timestamp in question message div for future updates
        questionMessage.dataset.timestamp = questionTime.getTime();

        // Add title attribute for exact time on hover
        timestamp.title = questionTime.toLocaleString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });

    rightContainer.appendChild(timestamp);

    footerDiv.appendChild(rightContainer);
    contentDiv.appendChild(footerDiv);

    questionMessage.appendChild(avatarDiv);
    questionMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(questionMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Handle calibration answer selection
 * @param {number} answerIndex - Selected answer index
 * @param {number} questionIndex - The question index this answer belongs to
 */
async function selectCalibrationAnswer(answerIndex, questionIndex) {
    // Store the answer
    studentAnswers[questionIndex] = answerIndex;
    window.studentAnswers = studentAnswers; // Update global reference

    // Disable all options to prevent changing answers AND update UI immediately so it's captured in save
    const questionMessage = document.getElementById(`calibration-question-${questionIndex}`);
    if (questionMessage) {
        const options = questionMessage.querySelectorAll('.calibration-option');
        options.forEach((option, index) => {
            // Disable all options
            option.disabled = true;
            option.style.cursor = 'not-allowed';

            // Highlight the selected answer
            if (index === answerIndex) {
                option.classList.add('selected');
                option.style.backgroundColor = 'var(--primary-color)';
                option.style.color = 'white';
                option.style.borderColor = 'var(--primary-color)';
            } else {
                option.classList.remove('selected');
                option.style.backgroundColor = '#f8f9fa';
                option.style.color = '#999';
                option.style.borderColor = '#ddd';
            }
        });
    }

    // Update auto-save with FRESH assessment data (capturing the UI state above)
    // We use collectAllChatData to ensure the messages array includes the question we just answered
    try {
        const studentId = getCurrentStudentId();
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        const currentChatData = await collectAllChatData();
        
        if (currentChatData) {
            // Explicitly update the last activity timestamp
            currentChatData.lastActivityTimestamp = new Date().toISOString();
            
            localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));

        }
    } catch (e) {
        console.error('Error auto-saving assessment answer:', e);
    }

    // Automatically proceed to next question after a short delay
    setTimeout(() => {
        currentQuestionIndex++;

        // Show next question or finish
        if (currentQuestionIndex < currentCalibrationQuestions.length) {
            showCalibrationQuestion();
        } else {
            calculateStudentMode();
        }
    }, 500); // 0.5 second delay
}

/**
 * Handle short answer submission
 * @param {string} answer - Student's short answer
 * @param {number} questionIndex - The question index this answer belongs to
 */
async function submitShortAnswer(answer, questionIndex) {
    if (!answer.trim()) {
        alert('Please enter an answer before submitting.');
        return;
    }

    // Store the answer
    studentAnswers[questionIndex] = answer;
    window.studentAnswers = studentAnswers; // Update global reference

    // UI Elements
    const questionMessage = document.getElementById(`calibration-question-${questionIndex}`);
    let answerInput, submitButton, feedbackDiv;

    if (questionMessage) {
        answerInput = questionMessage.querySelector('.calibration-answer-input');
        submitButton = questionMessage.querySelector('.calibration-submit-btn');
        
        // Create or get feedback div
        let existingFeedback = questionMessage.querySelector('.calibration-feedback');
        if (existingFeedback) {
            feedbackDiv = existingFeedback;
        } else {
            feedbackDiv = document.createElement('div');
            feedbackDiv.className = 'calibration-feedback';
            feedbackDiv.style.marginTop = '10px';
            feedbackDiv.style.padding = '12px';
            feedbackDiv.style.borderRadius = '6px';
            feedbackDiv.style.fontSize = '0.9em';
            feedbackDiv.style.lineHeight = '1.4';
            
            if (submitButton) {
                submitButton.parentNode.insertBefore(feedbackDiv, submitButton.nextSibling);
            } else if (answerInput) {
                answerInput.parentNode.appendChild(feedbackDiv);
            }
        }

        // Disable inputs
        if (answerInput) {
            answerInput.disabled = true;
            answerInput.style.backgroundColor = '#f8f9fa';
            answerInput.style.borderColor = 'var(--primary-color)';
        }

        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Checking...';
            submitButton.style.backgroundColor = 'var(--primary-color)';
            submitButton.style.opacity = '0.7';
        }
    }

    // Check answer with AI
    try {
        // Show loading
        if (feedbackDiv) {
            feedbackDiv.innerHTML = '<div style="display:flex; align-items:center; gap:8px;"><div class="loading-dots"><span>.</span><span>.</span><span>.</span></div> Checking your answer with AI...</div>';
            feedbackDiv.style.backgroundColor = '#e9ecef';
            feedbackDiv.style.color = '#495057';
        }

        const question = currentCalibrationQuestions[questionIndex];
        // Determine expected answer field
        const expectedAnswer = question.expectedAnswer || question.correctAnswer || question.answer;

        // Get student name for personalized feedback
        let studentName = 'Student';
        const currentUser = getCurrentUser();
        if (currentUser && currentUser.displayName) {
            studentName = currentUser.displayName;
        }

        const response = await fetch('/api/questions/check-answer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                question: question.question,
                studentAnswer: answer,
                expectedAnswer: expectedAnswer,
                questionType: 'short-answer',
                studentName: studentName
            })
        });

        const result = await response.json();

        if (result.success && result.data) {
            const evaluation = result.data;
            
            // Store evaluation
            if (!window.studentEvaluations) window.studentEvaluations = [];
            window.studentEvaluations[questionIndex] = evaluation;
            
            // Show feedback
            if (feedbackDiv) {
                const isCorrect = evaluation.correct;
                feedbackDiv.style.backgroundColor = isCorrect ? '#d4edda' : '#f8d7da';
                feedbackDiv.style.color = isCorrect ? '#155724' : '#721c24';
                feedbackDiv.style.border = isCorrect ? '1px solid #c3e6cb' : '1px solid #f5c6cb';
                
                feedbackDiv.innerHTML = `
                    <div style="font-weight:600; margin-bottom:4px;">${isCorrect ? '✅ Correct' : '❌ Needs Improvement'}</div>
                    <div>${evaluation.feedback}</div>
                `;
            }
            
            if (submitButton) {
                submitButton.textContent = 'Answer Submitted';
            }
        } else {
            throw new Error(result.message || 'Failed to check answer');
        }

    } catch (error) {
        console.error('Error checking answer:', error);
        if (feedbackDiv) {
            feedbackDiv.innerHTML = '<em>Unable to verify with AI. Proceeding...</em>';
        }
        
        // Fallback evaluation
        if (!window.studentEvaluations) window.studentEvaluations = [];
        window.studentEvaluations[questionIndex] = {
            correct: answer.length > 10,
            feedback: "Could not verify with AI. Marked based on length."
        };
    }

    // Update auto-save with FRESH assessment data (capturing the UI feedback state)
    try {
        const studentId = getCurrentStudentId();
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        const currentChatData = await collectAllChatData();
        
        if (currentChatData) {
            // Explicitly update the last activity timestamp
            currentChatData.lastActivityTimestamp = new Date().toISOString();
            
            localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));

        }
    } catch (e) {
        console.error('Error auto-saving assessment answer:', e);
    }

    // Automatically proceed to next question after a short delay to read feedback
    setTimeout(() => {
        currentQuestionIndex++;

        // Show next question or finish
        if (currentQuestionIndex < currentCalibrationQuestions.length) {
            showCalibrationQuestion();
        } else {
            calculateStudentMode();
        }
    }, 2500); // 2.5 second delay to read feedback
}

/**
 * Calculate student mode based on answers to real assessment questions
 */
async function calculateStudentMode() {
    try {
    

        // Calculate total correct answers
        let totalCorrect = 0;
        const totalQuestions = currentCalibrationQuestions.length;

        // Check each answer against the correct answer
        for (let i = 0; i < Math.min(studentAnswers.length, totalQuestions); i++) {
            const question = currentCalibrationQuestions[i];
            const studentAnswerIndex = studentAnswers[i];

            // Convert student answer index to actual answer text for display
            let studentAnswerText = '';
            if (question.type === 'true-false') {
                studentAnswerText = studentAnswerIndex === 0 ? 'True' : 'False';
            } else if (question.type === 'multiple-choice' && question.options) {
                // Get the actual option text from the options object
                const optionKeys = Object.keys(question.options);
                if (optionKeys[studentAnswerIndex]) {
                    studentAnswerText = question.options[optionKeys[studentAnswerIndex]];
                } else {
                    studentAnswerText = `Option ${studentAnswerIndex}`;
                }
            } else {
                studentAnswerText = studentAnswerIndex;
            }



            let isCorrect = false;

            if (question.type === 'true-false') {
                // For true-false, check if the answer matches
                // Handle both string and boolean formats
                const expectedAnswer = question.correctAnswer;
                const studentAnswerText = studentAnswerIndex === 0 ? 'True' : 'False';

                if (typeof expectedAnswer === 'string') {
                    // Convert to lowercase for comparison
                    isCorrect = (studentAnswerText.toLowerCase() === expectedAnswer.toLowerCase());
                } else if (typeof expectedAnswer === 'boolean') {
                    // Handle boolean format
                    isCorrect = (studentAnswerIndex === (expectedAnswer ? 0 : 1));
                } else {
                    // Default comparison
                    isCorrect = (studentAnswerIndex === expectedAnswer);
                }



            } else if (question.type === 'multiple-choice') {
                // For multiple choice, check if the answer index matches
                // Convert correct answer key to index
                let expectedIndex = question.correctAnswer;
                if (typeof expectedIndex === 'string') {
                    // Find the index of the correct answer key in the options
                    const optionKeys = Object.keys(question.options);
                    expectedIndex = optionKeys.indexOf(expectedIndex);
                    if (expectedIndex === -1) expectedIndex = 0; // Default to 0 if not found
                }
                isCorrect = (studentAnswerIndex === expectedIndex);

            } else if (question.type === 'short-answer') {
                // Use AI evaluation if available
                if (window.studentEvaluations && window.studentEvaluations[i]) {
                    isCorrect = window.studentEvaluations[i].correct;

                } else {
                    // Fallback: consider it correct if they provided any meaningful answer
                    isCorrect = (studentAnswerIndex && studentAnswerIndex.trim().length > 10);

                }
            } else {
                // For unknown types, default to checking if answer matches
                isCorrect = (studentAnswerIndex === question.correctAnswer);
            }

            if (isCorrect) {
                totalCorrect++;

            } else {

            }
        }



        // Calculate percentage
        const percentage = (totalCorrect / totalQuestions) * 100;


        // Determine mode based on performance using the instructor's pass threshold
        // If they get the required number of questions correct, they're in protégé mode
        // Otherwise, they're in tutor mode (need more guidance)
        const passed = totalCorrect >= currentPassThreshold;
        const mode = passed ? 'protege' : 'tutor';



        const score = {
            totalCorrect: totalCorrect,
            totalQuestions: totalQuestions,
            percentage: percentage,
            passThreshold: currentPassThreshold,
            passed: passed,
            mode: mode
        };



        // Store mode in localStorage
        localStorage.setItem('studentMode', mode);

        // Update mode toggle UI to reflect the determined mode
        updateModeToggleUI(mode);

        // Show mode result message
        showModeResult(mode, score);

        // Autosave the mode result message immediately
        // This ensures the rich HTML content we just created is saved
        try {
            const studentId = getCurrentStudentId();
            // detailed autosave logic similar to selectCalibrationAnswer
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            
            // We need to wait a tick for the DOM to update with the new message
            setTimeout(async () => {
                const currentChatData = await collectAllChatData();
                if (currentChatData) {
                    currentChatData.lastActivityTimestamp = new Date().toISOString();
                    localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));
                }
            }, 100);
        } catch (e) {
            console.error('Error auto-saving mode result:', e);
        }

        // Re-enable chat (clears noPublishedUnits flag and enables inputs)
        enableChatInput();

    } catch (error) {
        console.error('Error calculating mode:', error);
        // Default to tutor mode on error
        localStorage.setItem('studentMode', 'tutor');
        updateModeToggleUI('tutor');

        // Re-enable chat (clears noPublishedUnits flag and enables inputs)
        enableChatInput();
    }
}

/**
 * Show mode result to student
 * @param {string} mode - Determined mode (tutor or protege)
 * @param {object} score - Assessment score object
 */
function showModeResult(mode, score) {
    const modeMessage = document.createElement('div');
    modeMessage.classList.add('message', 'bot-message', 'mode-result', 'standard-mode-result');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content', 'standard-mode-content');

    const resultText = document.createElement('p');


    // Show mode explanation
    const modeExplanation = document.createElement('div');
    modeExplanation.classList.add('mode-explanation');

    if (mode === 'protege') {
        modeExplanation.innerHTML = `
            <strong>BiocBot is in protégé mode</strong><br>
            Excellent work! You've demonstrated strong understanding of the course material. I'm ready to be your study partner and help you explore advanced topics together. What questions do you have about the course material?`;
    } else {
        modeExplanation.innerHTML = `
            <strong>BiocBot is in tutor mode</strong><br>
            Thanks for completing the assessment! I'm here to guide your learning and help explain concepts clearly. What questions do you have about the course material?`;
    }

    contentDiv.appendChild(modeExplanation);

    // Add Assessment Summary
    if (window.currentCalibrationQuestions && window.currentCalibrationQuestions.length > 0) {
        const summaryContainer = document.createElement('div');
        summaryContainer.className = 'assessment-summary-container';

        // Header
        const header = document.createElement('div');
        header.className = 'assessment-summary-header';
        
        const title = document.createElement('h4');
        title.className = 'assessment-summary-title';
        title.innerHTML = 'Assessment Summary';
        
        const score = document.createElement('div');
        score.className = 'assessment-summary-score';
        // Score set after loop

        header.appendChild(title);
        header.appendChild(score);
        summaryContainer.appendChild(header);

        // Questions List
        const list = document.createElement('div');
        list.className = 'assessment-questions-list';

        let correctCount = 0;
        let totalCount = window.currentCalibrationQuestions.length;
        let hasEvaluations = window.studentEvaluations && Array.isArray(window.studentEvaluations);

        window.currentCalibrationQuestions.forEach((q, index) => {
            const card = document.createElement('div');
            card.className = 'summary-question-card';

            const questionHeader = document.createElement('div');
            questionHeader.className = 'summary-question-header';
            questionHeader.innerHTML = `
                <span class="summary-q-number">#${index + 1}</span>
                <span class="summary-q-text">${q.question}</span>
            `;
            card.appendChild(questionHeader);

            const studentAnsIndex = window.studentAnswers[index];
            let displayStudentAns = studentAnsIndex;
            let displayCorrectAns = q.correctAnswer || q.expectedAnswer || q.answer;
            let feedback = '';
            let isCorrect = false;

            // Logic to format answers
            if (q.type === 'true-false') {
                displayStudentAns = studentAnsIndex === 0 ? 'True' : (studentAnsIndex === 1 ? 'False' : studentAnsIndex);
                if (typeof displayCorrectAns === 'boolean') {
                    displayCorrectAns = displayCorrectAns ? 'True' : 'False';
                } else if (typeof displayCorrectAns === 'string') {
                    displayCorrectAns = displayCorrectAns.charAt(0).toUpperCase() + displayCorrectAns.slice(1);
                }
            } else if (q.type === 'multiple-choice' && q.options) {
                const optionKeys = Object.keys(q.options);
                if (optionKeys[studentAnsIndex]) {
                    displayStudentAns = `${optionKeys[studentAnsIndex]}) ${q.options[optionKeys[studentAnsIndex]]}`;
                }
                if (q.options[displayCorrectAns]) {
                    displayCorrectAns = `${displayCorrectAns}) ${q.options[displayCorrectAns]}`;
                }
            }
            
            // Check correctness
            if (hasEvaluations && window.studentEvaluations[index]) {
                 isCorrect = window.studentEvaluations[index].correct;
                 feedback = window.studentEvaluations[index].feedback;
            } else {
                 // Fallback logic
                 if (q.type === 'true-false' || q.type === 'multiple-choice') {
                      const sAns = String(displayStudentAns).trim().toLowerCase();
                      const cAns = String(displayCorrectAns).trim().toLowerCase();
                      if (sAns === cAns) {
                          isCorrect = true;
                      }
                 }
            }
            
            if (isCorrect) correctCount++;

            const answerSection = document.createElement('div');
            answerSection.className = 'summary-answer-section';
            
            const safeStudentAns = displayStudentAns !== undefined && displayStudentAns !== null ? displayStudentAns : 'No answer provided';
            const safeCorrectAns = displayCorrectAns !== undefined && displayCorrectAns !== null ? displayCorrectAns : 'N/A';
            
            answerSection.innerHTML = `
                <div class="answer-box student">
                    <span class="answer-box-label">Your Answer</span>
                    <div class="answer-box-content">${safeStudentAns}</div>
                </div>
                <div class="answer-box expected">
                    <span class="answer-box-label">Expected Answer</span>
                    <div class="answer-box-content">${safeCorrectAns}</div>
                </div>
            `;
            card.appendChild(answerSection);

            if (feedback) {
                const feedbackDiv = document.createElement('div');
                feedbackDiv.className = `summary-feedback-section ${isCorrect ? 'correct' : 'incorrect'}`;
                feedbackDiv.innerHTML = `
                    <div class="feedback-icon">${isCorrect ? '✅' : '❌'}</div>
                    <div class="feedback-content">
                        <strong>Feedback:</strong> ${feedback}
                    </div>
                `;
                card.appendChild(feedbackDiv);
            }

            list.appendChild(card);
        });

        if (score) score.textContent = `Score: ${correctCount}/${totalCount}`;
        summaryContainer.appendChild(list);
        contentDiv.appendChild(summaryContainer);
    }

    // Add unit selection option after assessment completion
    // const unitSelectionOption = document.createElement('div');
    // unitSelectionOption.classList.add('unit-selection-option');
    // unitSelectionOption.innerHTML = `
    //     <div style="margin-top: 15px; padding: 12px; background-color: #f8f9fa; border-radius: 6px; border-left: 4px solid var(--primary-color);">
    //         <strong>Want to try another unit?</strong><br>
    //         You can select a different unit from the dropdown above to take another assessment, or continue chatting with me about any topics you'd like to discuss.
    //     </div>
    // `;
    // contentDiv.appendChild(unitSelectionOption);

    // Add timestamp
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');

        // Create real timestamp for mode result
        const modeTime = new Date();
        timestamp.textContent = formatTimestamp(modeTime);

        // Store timestamp in mode message div for future updates
        modeMessage.dataset.timestamp = modeTime.getTime();

        // Add title attribute for exact time on hover
        timestamp.title = modeTime.toLocaleString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });

    contentDiv.appendChild(timestamp);

    modeMessage.appendChild(avatarDiv);
    modeMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(modeMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Show mode toggle result to student (different from calibration result)
 * @param {string} mode - Current mode (tutor or protege)
 */
function showModeToggleResult(mode) {
    const modeMessage = document.createElement('div');
    modeMessage.classList.add('message', 'bot-message', 'mode-toggle-result');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const resultText = document.createElement('p');
    if (mode === 'protege') {
        resultText.innerHTML = `<strong>BiocBot is now in protégé mode</strong><br>
        I'm ready to be your study partner! Ask me questions about the course material and I'll help you explore topics together.`;
    } else {
        resultText.innerHTML = `<strong>BiocBot is now in tutor mode</strong><br>
        I'm ready to guide your learning! I can help explain concepts, provide examples, and answer your questions about the course material.`;
    }

    contentDiv.appendChild(resultText);

    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');

        // Create real timestamp for mode toggle result
        const toggleTime = new Date();
        timestamp.textContent = formatTimestamp(toggleTime);

        // Store timestamp in mode message div for future updates
        modeMessage.dataset.timestamp = toggleTime.getTime();

        // Add title attribute for exact time on hover
        timestamp.title = toggleTime.toLocaleString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });

    contentDiv.appendChild(timestamp);

    modeMessage.appendChild(avatarDiv);
    modeMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(modeMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Render a restored mode result message
 * @param {Object} messageData - The message data object
 */
function renderRestoredModeResult(messageData) {
    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) return;

    const modeMessage = document.createElement('div');
    modeMessage.classList.add('message', 'bot-message', 'mode-result', 'standard-mode-result');
    modeMessage.dataset.timestamp = new Date(messageData.timestamp).getTime();

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content', 'standard-mode-content');

    // Use saved HTML content if available, otherwise fall back to text
    if (messageData.htmlContent) {
        contentDiv.innerHTML = messageData.htmlContent;
    } else {
        // Fallback for older messages
        const text = document.createElement('p');
        text.textContent = messageData.content;
        contentDiv.appendChild(text);
    }

    // Add timestamp if not already present in HTML (it shouldn't be as we removed it on save)
    if (!contentDiv.querySelector('.timestamp')) {
        const timestamp = document.createElement('span');
        timestamp.classList.add('timestamp');
        timestamp.textContent = messageData.displayTimestamp || formatTimestamp(new Date(messageData.timestamp));
        timestamp.title = new Date(messageData.timestamp).toLocaleString();
        contentDiv.appendChild(timestamp);
    }

    modeMessage.appendChild(avatarDiv);
    modeMessage.appendChild(contentDiv);
    chatMessages.appendChild(modeMessage);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Render a restored mode toggle result message
 * @param {Object} messageData - The message data object
 */
function renderRestoredModeToggleResult(messageData) {
    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) return;

    const modeMessage = document.createElement('div');
    modeMessage.classList.add('message', 'bot-message', 'mode-toggle-result');
    modeMessage.dataset.timestamp = new Date(messageData.timestamp).getTime();

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    // Use saved HTML content if available
    if (messageData.htmlContent) {
        contentDiv.innerHTML = messageData.htmlContent;
    } else {
        const text = document.createElement('p');
        text.textContent = messageData.content;
        contentDiv.appendChild(text);
    }

    // Add timestamp if needed
    if (!contentDiv.querySelector('.timestamp')) {
        const timestamp = document.createElement('span');
        timestamp.classList.add('timestamp');
        timestamp.textContent = messageData.displayTimestamp || formatTimestamp(new Date(messageData.timestamp));
        timestamp.title = new Date(messageData.timestamp).toLocaleString();
        contentDiv.appendChild(timestamp);
    }

    modeMessage.appendChild(avatarDiv);
    modeMessage.appendChild(contentDiv);
    chatMessages.appendChild(modeMessage);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Initialize mode toggle functionality
 */
function initializeModeToggle() {
    const modeToggleCheckbox = document.getElementById('mode-toggle-checkbox');
    const protegeLabel = document.querySelector('.protege-label');
    const tutorLabel = document.querySelector('.tutor-label');

    if (!modeToggleCheckbox) return;

    // Set initial mode from localStorage or default to tutor
    const currentMode = localStorage.getItem('studentMode') || 'tutor';

    updateModeToggleUI(currentMode);

    // Add event listener for mode toggle
    modeToggleCheckbox.addEventListener('change', function() {

        const newMode = this.checked ? 'tutor' : 'protege';


        // Update localStorage
        localStorage.setItem('studentMode', newMode);

        // Record the timestamp of this manual mode change
        localStorage.setItem('lastModeChange', Date.now().toString());


        // Update UI
        updateModeToggleUI(newMode);

        // Show mode confirmation popup
        showModeToggleResult(newMode);

        // Autosave the mode toggle message immediately
        try {
            const studentId = getCurrentStudentId();
            collectAllChatData().then(currentChatData => {
                if (currentChatData) {
                    const autoSaveKey = `biocbot_current_chat_${studentId}`;
                    currentChatData.lastActivityTimestamp = new Date().toISOString();
                    localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));
                }
            });
        } catch (e) {
            console.error('Error auto-saving mode toggle:', e);
        }

    });
}

/**
 * Update the mode toggle UI to reflect current mode
 * @param {string} mode - Current mode (tutor or protege)
 */
function updateModeToggleUI(mode) {
    const modeToggleCheckbox = document.getElementById('mode-toggle-checkbox');
    const protegeLabel = document.querySelector('.protege-label');
    const tutorLabel = document.querySelector('.tutor-label');

    if (!modeToggleCheckbox || !protegeLabel || !tutorLabel) return;

    if (mode === 'tutor') {
        // Checkbox checked = tutor mode
        modeToggleCheckbox.checked = true;
        tutorLabel.classList.add('active');
        protegeLabel.classList.remove('active');
    } else {
        // Checkbox unchecked = protégé mode
        modeToggleCheckbox.checked = false;
        protegeLabel.classList.add('active');
        tutorLabel.classList.remove('active');
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
 * Fetch current struggle state from backend
 * @returns {Promise<Object>} The struggle state object
 */
async function fetchCurrentStruggleState() {
    try {
        const response = await fetch('/api/student/struggle');
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                return data.struggleState;
            }
        }
    } catch (e) {
        console.error('Failed to fetch struggle state', e);
    }
    return null;
}

/**
 * Load chat data into the current chat interface
 * @param {Object} chatData - The chat data to load
 */
function loadChatData(chatData) {
    try {


        // Clear existing messages
        const chatMessages = document.getElementById('chat-messages');
        if (!chatMessages) {
            console.error('Chat messages container not found');
            return;
        }

        // Clear ALL existing messages
        chatMessages.innerHTML = '';

        // Don't clear auto-save data when loading from history - we want to preserve it


        // Add a loading message first
        const loadingMessage = document.createElement('div');
        loadingMessage.classList.add('message', 'bot-message');
        loadingMessage.innerHTML = `
            <div class="message-avatar">B</div>
            <div class="message-content">
                <p>Loading your previous chat...</p>
                <span class="timestamp">Just now</span>
            </div>
        `;
        chatMessages.appendChild(loadingMessage);

        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;

        // Use setTimeout to ensure the loading message is visible
        setTimeout(() => {
            // Clear the loading message
            chatMessages.innerHTML = '';

            // Load each message from the chat data WITHOUT triggering auto-save
            chatData.messages.forEach((messageData, index) => {


                if (messageData.type === 'user') {
                    addMessage(messageData.content, 'user', false, true, null, messageData.isHtml); // Skip auto-save
                } else if (messageData.type === 'bot') {
                    // Check if this is a special message type that needs special handling
                    if (messageData.messageType === 'assessment-start') {
                        // This is the assessment start message - add it as a regular bot message
                        addMessage(messageData.content, 'bot', messageData.hasFlagButton, true, messageData.sourceAttribution, true); // Skip auto-save, force HTML for assessment start
                    } else if (messageData.messageType === 'practice-test-question') {
                        // This is a practice test question - restore its UI
                        renderRestoredPracticeQuestion(messageData); // Skip auto-save implicit
                    } else if (messageData.messageType === 'mode-result') {
                        // This is a mode result message - use dedicated restorer
                        renderRestoredModeResult(messageData); // Skip auto-save
                    } else if (messageData.messageType === 'mode-toggle-result') {
                        // This is a mode toggle result message - use dedicated restorer
                        renderRestoredModeToggleResult(messageData); // Skip auto-save
                    } else {
                        // Regular bot message
                        // Check if the struggle topic is still active
                        let activeTopic = messageData.activeStruggleTopic;
                        if (activeTopic && window.currentStruggleState) {
                             const isStillActive = window.currentStruggleState.topics && 
                                                 window.currentStruggleState.topics.some(t => t.topic === activeTopic && t.isActive);
                             if (!isStillActive) {
                                 activeTopic = null;
                             }
                        }
                        
                        addMessage(messageData.content, 'bot', messageData.hasFlagButton, true, messageData.sourceAttribution, messageData.isHtml, activeTopic); // Skip auto-save, force HTML for result
                    }
                }
            });

            // Restore practice test data if present
            if (chatData.practiceTests && chatData.practiceTests.questions.length > 0) {

                // Map back questionType to type for compatibility with showCalibrationQuestion
                currentCalibrationQuestions = chatData.practiceTests.questions.map(q => ({
                    ...q,
                    type: q.questionType || q.type // Ensure type property exists
                }));
                window.currentCalibrationQuestions = currentCalibrationQuestions; // Sync global
                currentPassThreshold = chatData.practiceTests.passThreshold;
                window.currentPassThreshold = currentPassThreshold; // Update global reference
                
                studentAnswers = chatData.studentAnswers.answers.map(answer => answer.answer);
                window.studentAnswers = studentAnswers; // Sync global

                // Calculate the correct current question index based on answers provided
                // This is more reliable than the saved index which might be stale
                const answersProvidedCount = studentAnswers.filter(a => a !== undefined && a !== null).length;
                currentQuestionIndex = answersProvidedCount;


                // Resume assessment if incomplete
                if (currentQuestionIndex < currentCalibrationQuestions.length) {

                    
                    // Disable chat input during assessment
                    const chatInputContainer = document.querySelector('.chat-input-container');
                    if (chatInputContainer) {
                        chatInputContainer.style.display = 'none';
                    }

                    // Show the next question
                    // Use a small delay to ensure DOM is ready
                    setTimeout(() => {
                        showCalibrationQuestion();
                    }, 500);
                }
            }

            // Restore mode if present, but only if no recent mode change has occurred
            const currentStoredMode = localStorage.getItem('studentMode') || 'tutor';
            const chatDataMode = chatData.metadata.currentMode;

            // Check if the user has manually changed the mode recently (within last 5 minutes)
            const lastModeChange = localStorage.getItem('lastModeChange');
            const now = Date.now();
            const fiveMinutesAgo = now - (5 * 60 * 1000);

            if (lastModeChange && parseInt(lastModeChange) > fiveMinutesAgo) {
                // User recently changed mode, keep their current choice

                updateModeToggleUI(currentStoredMode);
            } else if (chatDataMode) {
                // No recent mode change, restore from chat data

                localStorage.setItem('studentMode', chatDataMode);
                updateModeToggleUI(chatDataMode);

            } else {

                updateModeToggleUI(currentStoredMode);
            }

            // Restore unit selection if present
            if (chatData.metadata.unitName) {

                localStorage.setItem('selectedUnitName', chatData.metadata.unitName);

                // Update unit selection dropdown if it exists
                const unitSelect = document.getElementById('unit-select');
                if (unitSelect) {
                    unitSelect.value = chatData.metadata.unitName;
                }
            }

            // Restore course selection if present
            if (chatData.metadata.courseId) {

                const currentCourseId = localStorage.getItem('selectedCourseId');
                
                // Only update if different
                if (currentCourseId !== chatData.metadata.courseId) {

                    localStorage.setItem('selectedCourseId', chatData.metadata.courseId);
                    
                    if (chatData.metadata.courseName) {
                        localStorage.setItem('selectedCourseName', chatData.metadata.courseName);
                    }

                    // Update course display (loadCourseData handles UI updates)
                    loadCourseData(chatData.metadata.courseId, false);
                }
            } else {
                // Ensure chat input is visible if no course context to restore
                const chatInputContainer = document.querySelector('.chat-input-container');
                if (chatInputContainer) {
                    chatInputContainer.style.display = 'block';
                }
            }

            // Ensure chat input and mode toggle are visible (enable chat) IF we are not in an assessment
            // Check if assessment is in progress (defined in the block above)
            const isAssessmentInProgress = window.currentCalibrationQuestions && 
                                          window.currentCalibrationQuestions.length > 0 && 
                                          window.studentAnswers && 
                                          window.studentAnswers.length < window.currentCalibrationQuestions.length;
            
            // Check if this loaded session has hit the message cap
            const regularChatMsgCount = chatData.messages.filter(msg =>
                (msg.type === 'user' || msg.type === 'bot') && msg.messageType === 'regular-chat'
            ).length;
            const isSessionAtCap = regularChatMsgCount >= 40;

            if (!isAssessmentInProgress) {

                enableChatInput();

                // Force show input container regardless of enableChatInput logic
                const chatInputContainer = document.querySelector('.chat-input-container');
                if (chatInputContainer) {
                    chatInputContainer.style.display = 'block';
                    // Ensure input itself is enabled
                    const chatInput = document.getElementById('chat-input');
                    if (chatInput) {
                        chatInput.disabled = false;
                        chatInput.style.cursor = 'text';
                        chatInput.classList.remove('disabled-input');
                        chatInput.placeholder = 'Type your message here...';
                    }
                    const sendButton = document.getElementById('send-button');
                    if (sendButton) {
                        sendButton.disabled = false;
                        sendButton.style.cursor = 'pointer';
                        sendButton.classList.remove('disabled-button');
                        sendButton.style.opacity = '1';
                    }
                }

                // Also ensure mode toggle is visible if not in assessment
                const modeToggleContainer = document.querySelector('.mode-toggle-container');
                if (modeToggleContainer) {
                    modeToggleContainer.style.display = 'flex';
                }

                // If session is capped, disable chat input after enabling it
                if (isSessionAtCap) {
                    const chatInput = document.getElementById('chat-input');
                    if (chatInput) {
                        chatInput.disabled = true;
                        chatInput.placeholder = 'This session has reached the 40-message limit. Please start a new session.';
                        chatInput.classList.add('disabled-input');
                        chatInput.style.cursor = 'not-allowed';
                    }
                    const sendButton = document.getElementById('send-button');
                    if (sendButton) {
                        sendButton.disabled = true;
                        sendButton.classList.add('disabled-button');
                        sendButton.style.cursor = 'not-allowed';
                        sendButton.style.opacity = '0.5';
                    }
                }
            } else {

                // Explicitly hide them just in case
                const chatInputContainer = document.querySelector('.chat-input-container');
                if (chatInputContainer) {
                    chatInputContainer.style.display = 'none';
                }
                const modeToggleContainer = document.querySelector('.mode-toggle-container');
                if (modeToggleContainer) {
                    modeToggleContainer.style.display = 'none';
                }
            }



            // Set flags for continuing chat
            sessionStorage.setItem('isContinuingChat', 'true');
            sessionStorage.setItem('loadedChatData', JSON.stringify(chatData));

            // Update the current session ID to match the loaded chat data
            if (chatData.sessionInfo && chatData.sessionInfo.sessionId) {
                const studentId = chatData.metadata.studentId;
                const courseId = chatData.metadata.courseId;
                const unitName = chatData.metadata.unitName;
                const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;

                // Store the session ID from the loaded chat data
                localStorage.setItem(sessionKey, chatData.sessionInfo.sessionId);

            } else {
                // If no session ID in chat data, generate one and store it
                const studentId = chatData.metadata.studentId;
                const courseId = chatData.metadata.courseId;
                const unitName = chatData.metadata.unitName;
                const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;

                // Generate a new session ID for this chat
                const newSessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                localStorage.setItem(sessionKey, newSessionId);

                // Update the chat data with the new session ID
                if (!chatData.sessionInfo) {
                    chatData.sessionInfo = {};
                }
                chatData.sessionInfo.sessionId = newSessionId;


            }

            // Replace the current auto-save data with the loaded chat data
            const studentId = chatData.metadata.studentId;
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));




        }, 500); // Small delay to show loading message

    } catch (error) {
        console.error('Error loading chat data:', error);
        addMessage('❌ Error loading chat history. Please try again.', 'bot', false, true, null);
    }
}


/**
 * Check for chat data to load from history
 */
async function checkForChatDataToLoad() {
    // Fetch current struggle state first
    if (typeof fetchCurrentStruggleState === 'function') {
        window.currentStruggleState = await fetchCurrentStruggleState();
         // Update UI indicator immediately
        if (typeof updateStruggleUI === 'function') {
            updateStruggleUI(window.currentStruggleState);
        }
    }
    try {

        const storedChatData = sessionStorage.getItem('loadChatData');


        if (storedChatData) {
            const chatData = JSON.parse(storedChatData);


            // Set flag to indicate we're loading from history
            window.loadingFromHistory = true;


            // Clear the stored data
            sessionStorage.removeItem('loadChatData');


            // Load the chat data

            loadChatData(chatData);
        } else {

        }
    } catch (error) {
        console.error('Error checking for chat data to load:', error);
    }
}

/**
 * Render a restored practice test question from reading history
 * @param {Object} messageData - The message data object
 */
function renderRestoredPracticeQuestion(messageData) {
    const questionData = messageData.questionData;
    if (!questionData) {
        // Fallback to text if data missing
        addMessage(messageData.content, 'bot', false, true);
        return;
    }

    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) return;

    const questionMessage = document.createElement('div');
    questionMessage.classList.add('message', 'bot-message', 'calibration-question');
    if (questionData.questionIndex !== undefined) {
        questionMessage.id = `calibration-question-${questionData.questionIndex}`;
    }

    // Avatar
    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    // Content
    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    // Question Text
    const questionTextParams = document.createElement('p');
    questionTextParams.textContent = questionData.questionText;
    questionTextParams.style.marginBottom = '15px';
    questionTextParams.style.fontWeight = '500';
    contentDiv.appendChild(questionTextParams);

    // Options Container
    const optionsDiv = document.createElement('div');
    optionsDiv.classList.add('calibration-options');

    if (questionData.options && questionData.options.length > 0) {
        questionData.options.forEach((opt) => {
            const optionContainer = document.createElement('div');
            optionContainer.classList.add('calibration-option-container');

            const optionButton = document.createElement('button');
            optionButton.classList.add('calibration-option');
            optionButton.textContent = opt.text;
            
            // Apply frozen state
            optionButton.disabled = true;
            optionButton.style.cursor = 'default';

            if (opt.isSelected) {
                optionButton.classList.add('selected');
                optionButton.style.backgroundColor = 'var(--primary-color)';
                optionButton.style.color = 'white';
                optionButton.style.borderColor = 'var(--primary-color)';
            } else {
                optionButton.style.backgroundColor = '#f8f9fa';
                optionButton.style.color = '#999';
                optionButton.style.borderColor = '#ddd';
            }

            optionContainer.appendChild(optionButton);
            optionsDiv.appendChild(optionContainer);
        });
    }

    contentDiv.appendChild(optionsDiv);

    // Short Answer Display
    if (questionData.studentAnswer) {
        const answerDisplay = document.createElement('div');
        answerDisplay.style.marginTop = '10px';
        answerDisplay.style.padding = '10px';
        answerDisplay.style.backgroundColor = '#f8f9fa';
        answerDisplay.style.border = '1px solid #ddd';
        answerDisplay.style.borderRadius = '5px';
        answerDisplay.style.color = '#555';
        answerDisplay.innerHTML = `<strong>Your Answer:</strong> ${questionData.studentAnswer}`;
        contentDiv.appendChild(answerDisplay);
    }

    // Feedback Display
    if (questionData.feedback) {
        const feedbackDiv = document.createElement('div');
        feedbackDiv.className = 'calibration-feedback';
        feedbackDiv.style.marginTop = '10px';
        feedbackDiv.style.padding = '12px';
        feedbackDiv.style.borderRadius = '6px';
        feedbackDiv.style.fontSize = '0.9em';
        feedbackDiv.style.lineHeight = '1.4';
        // We know feedback HTML is safe as it comes from our own generator
        feedbackDiv.innerHTML = questionData.feedback;
        contentDiv.appendChild(feedbackDiv);
    }

    // Timestamp
    const footerDiv = document.createElement('div');
    footerDiv.classList.add('message-footer');
    const rightContainer = document.createElement('div');
    rightContainer.classList.add('message-footer-right');
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = messageData.displayTimestamp || 'Just now';
    if (messageData.timestamp) {
        try {
            const date = new Date(messageData.timestamp);
            messageData.datasetTimestamp = date.getTime();
            timestamp.title = date.toLocaleString();
        } catch(e) {}
    }
    
    rightContainer.appendChild(timestamp);
    footerDiv.appendChild(rightContainer);
    contentDiv.appendChild(footerDiv);

    questionMessage.appendChild(avatarDiv);
    questionMessage.appendChild(contentDiv);
    
    if (messageData.datasetTimestamp) {
        questionMessage.dataset.timestamp = messageData.datasetTimestamp;
    }

    chatMessages.appendChild(questionMessage);
}
