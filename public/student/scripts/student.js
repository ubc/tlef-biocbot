document.addEventListener('DOMContentLoaded', async () => {
    try {
        const courseId = localStorage.getItem('selectedCourseId');
        if (courseId) {
            const resp = await fetch(`/api/courses/${courseId}/student-enrollment`, { credentials: 'include' });
            if (resp.ok) {
                const data = await resp.json();
                if (data && data.success && data.data && data.data.enrolled === false) {
                    renderRevokedAccessUI();
                    return; // stop further chat init
                }
            }
        }
    } catch (e) { console.warn('Enrollment check failed, proceeding:', e); }
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-input');
    const chatMessages = document.getElementById('chat-messages');

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
    console.log('Student chat interface initialized');

    // Wait for authentication to be ready before initializing auto-save
    const initializeAutoSaveWhenReady = async () => {
        console.log('🔐 [AUTH] Authentication ready, initializing auto-save...');
        await initializeAutoSave();

        // Check for auto-continue after authentication is ready
        // Add a small delay to ensure auto-save data is fully loaded
        setTimeout(() => {
            // Only check for auto-continue if we're NOT loading from history
            const isLoadingFromHistory = sessionStorage.getItem('loadChatData');
            const isAlreadyLoadingFromHistory = window.loadingFromHistory;

            if (!isLoadingFromHistory && !isAlreadyLoadingFromHistory) {
                console.log('🔄 [AUTO-CONTINUE] Checking for auto-continue after auth ready...');
                const wasAutoContinued = checkForAutoContinue();

        if (wasAutoContinued) {
            console.log('🔄 [AUTO-CONTINUE] Chat was auto-continued, skipping assessment questions');
            // Set a flag to prevent assessment questions from loading
            window.autoContinued = true;

            // Load the current session data into the interface
            // Add a small delay to ensure DOM is fully ready
            setTimeout(() => {
                try {
                    console.log('🔄 [AUTO-CONTINUE] Loading session into interface...');
                    loadCurrentSessionIntoInterface();
                } catch (error) {
                    console.error('🔄 [AUTO-CONTINUE] Error loading session into interface:', error);
                }
            }, 200);
        }
            } else {
                console.log('🔄 [AUTO-CONTINUE] Loading from history, skipping auto-continue check');
                console.log('🔄 [AUTO-CONTINUE] - sessionStorage loadChatData:', !!isLoadingFromHistory);
                console.log('🔄 [AUTO-CONTINUE] - window.loadingFromHistory:', !!isAlreadyLoadingFromHistory);
            }
        }, 100);
    };

    // Check if auth is already ready
    if (getCurrentUser()) {
        console.log('🔐 [AUTH] User already authenticated, initializing auto-save immediately...');
        await initializeAutoSaveWhenReady();
    } else {
        // Wait for auth:ready event
        document.addEventListener('auth:ready', initializeAutoSaveWhenReady);
    }

    // Add beforeunload event to ensure auto-save data is preserved and synced
    window.addEventListener('beforeunload', async () => {
        console.log('Page unloading - syncing final auto-save data with server...');
        const chatData = getCurrentChatData();
        if (chatData && chatData.messages.length > 0) {
            await syncAutoSaveWithServer(chatData);
        }
    });

    // Load current course information and update UI
    loadCurrentCourseInfo();

    // Check if we're loading from history first
    const isLoadingFromHistory = sessionStorage.getItem('loadChatData');

    if (!isLoadingFromHistory) {
        // Check for published units and load real assessment questions
        // If no units are published, allow direct chat
        checkPublishedUnitsAndLoadQuestions();
    } else {
        console.log('Loading from history, skipping assessment questions');
    }

    // Initialize mode toggle functionality
    initializeModeToggle();

    // Ensure mode toggle is properly set after a short delay (fallback for timing issues)
    setTimeout(() => {
        const currentMode = localStorage.getItem('studentMode') || 'tutor';
        console.log('🔧 [MODE_FALLBACK] Ensuring mode toggle is set to:', currentMode);
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

    // Initialize user agreement modal
    initializeUserAgreement();

    // Initialize new session button
    initializeNewSessionButton();

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
     * Send message to LLM service
     * @param {string} message - The message to send
     * @returns {Promise<Object>} Response from LLM service
     */
    async function sendMessageToLLM(message) {
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

            if (conversationContext) {
                console.log('🔄 [CONTEXT] Conversation context retrieved:', {
                    messageCount: conversationContext.conversationMessages ? conversationContext.conversationMessages.length : 0,
                    mode: conversationContext.mode,
                    hasPracticeTest: conversationContext.hasPracticeTest
                });
            } else {
                console.log('🔄 [CONTEXT] No conversation context - starting new conversation');
            }

            const requestBody = {
                message: message,
                mode: currentMode,
                courseId: courseId,
                unitName: unitName,
                conversationContext: conversationContext
            };


            console.log('🚀 [SEND] About to send request to /api/chat');
            console.log('🚀 [SEND] Request URL:', '/api/chat');
            console.log('🚀 [SEND] Request method:', 'POST');
            console.log('🚀 [SEND] Request body:', requestBody);
            if (conversationContext && conversationContext.conversationMessages) {
                console.log('🚀 [SEND] Conversation context includes', conversationContext.conversationMessages.length, 'messages');
            }

            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestBody)
            });

            console.log('🚀 [SEND] Response received:', response.status, response.statusText);

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
     * Count messages starting from the first student message
     * Only counts regular-chat messages (user and bot)
     * @returns {number} Count of messages from first student message
     */
    function countMessagesFromFirstStudent() {
        try {
            const chatData = getCurrentChatData();
            if (!chatData || !chatData.messages || chatData.messages.length === 0) {
                console.log('🔢 [COUNT] No chat data or messages found');
                return 0;
            }

            console.log('🔢 [COUNT] Total messages in chatData:', chatData.messages.length);

            // Find the index of the first user message
            const firstUserMessageIndex = chatData.messages.findIndex(msg =>
                msg.type === 'user' && msg.messageType === 'regular-chat'
            );

            // If no user message found, return 0
            if (firstUserMessageIndex === -1) {
                console.log('🔢 [COUNT] No first user message found');
                return 0;
            }

            console.log('🔢 [COUNT] First user message index:', firstUserMessageIndex);

            // Count all regular-chat messages (user and bot) from the first user message onwards
            const messagesFromFirstStudent = chatData.messages.slice(firstUserMessageIndex).filter(msg =>
                (msg.type === 'user' || msg.type === 'bot') && msg.messageType === 'regular-chat'
            );

            console.log('🔢 [COUNT] Messages from first student:', messagesFromFirstStudent.length, 'out of', chatData.messages.slice(firstUserMessageIndex).length, 'total from that point');
            console.log('🔢 [COUNT] Message types breakdown:', messagesFromFirstStudent.map(m => `${m.type}:${m.messageType || 'no-type'}`));

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
        console.log('🔄 [CONTEXT] Getting conversation context...');

        // Check if we're continuing a chat (this flag is set when loading chat data)
        const isContinuingChat = sessionStorage.getItem('isContinuingChat') === 'true';
        console.log('🔄 [CONTEXT] isContinuingChat flag:', isContinuingChat);

        // Always get the latest chat data from localStorage to ensure we have the most recent messages
        // The sessionStorage might be stale if messages were added after loading
        const currentChatData = getCurrentChatData();
        let loadedChatData = null;

        if (currentChatData && currentChatData.messages && currentChatData.messages.length > 0) {
            console.log('🔄 [CONTEXT] Found', currentChatData.messages.length, 'messages in localStorage (latest)');
            // Always use the latest data from localStorage
            loadedChatData = JSON.stringify(currentChatData);
            // Update sessionStorage with the latest data
            sessionStorage.setItem('isContinuingChat', 'true');
            sessionStorage.setItem('loadedChatData', loadedChatData);
            console.log('🔄 [CONTEXT] Using latest chat data from localStorage and updating sessionStorage');
        } else {
            // Fallback: try sessionStorage if localStorage is empty
            loadedChatData = sessionStorage.getItem('loadedChatData');
            console.log('🔄 [CONTEXT] No localStorage data, checking sessionStorage:', !!loadedChatData);
            if (!loadedChatData) {
                console.log('🔄 [CONTEXT] No chat data found in localStorage or sessionStorage');
            }
        }

        if (!loadedChatData) {
            console.log('🔄 [CONTEXT] No chat data available, returning null');
            return null;
        }

        console.log('🔄 [CONTEXT] Chat data found, building conversation context...');

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

            console.log('🔄 [CONTEXT] Session ID check - Current:', currentSessionId || 'none', 'Loaded:', loadedSessionId || 'none');

            // If we have a current session ID, verify it matches the loaded session ID
            if (currentSessionId && loadedSessionId && currentSessionId !== loadedSessionId) {
                console.log('🔄 [CONTEXT] Session ID mismatch! Current:', currentSessionId, 'Loaded:', loadedSessionId);
                console.log('🔄 [CONTEXT] This is a new session - clearing old context and returning null');
                // Clear the old context flags since they're from a different session
                sessionStorage.removeItem('isContinuingChat');
                sessionStorage.removeItem('loadedChatData');
                return null;
            }

            // If current session has no ID but loaded does, it means we're starting fresh
            // Don't use old session context - new sessions should not reference old conversations
            if (!currentSessionId && loadedSessionId) {
                console.log('🔄 [CONTEXT] Current session has no ID but loaded data has session ID - new session, clearing old context');
                sessionStorage.removeItem('isContinuingChat');
                sessionStorage.removeItem('loadedChatData');
                return null;
            }

            // If both have the same session ID, or if we're continuing a chat (auto-continue scenario),
            // we can use the context. If both are null, it's a brand new session without context.
            if (currentSessionId && loadedSessionId && currentSessionId === loadedSessionId) {
                console.log('🔄 [CONTEXT] Session ID matches - using context from session:', currentSessionId);
            } else if (!currentSessionId && !loadedSessionId) {
                // Both null - this shouldn't happen if loadedChatData exists, but handle it
                console.log('🔄 [CONTEXT] Both session IDs are null - might be continuing without explicit session ID');
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

                console.log('🔄 [CONTEXT] Found', regularChatMessages.length, 'regular chat messages to include in context');

                // Add the conversation history
                regularChatMessages.forEach((msg, index) => {
                    conversationMessages.push({
                        role: msg.type === 'user' ? 'user' : 'assistant',
                        content: msg.content
                    });
                    // Log first few messages for debugging
                    if (index < 3) {
                        console.log(`🔄 [CONTEXT] Message ${index + 1}:`, msg.type, '-', msg.content.substring(0, 50) + '...');
                    }
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
                if (heroMessages.length > 0) {
                    console.log('🔄 [CONTEXT] Found', heroMessages.length, 'messages with hero/batman/favorite keywords:');
                    heroMessages.forEach((msg, idx) => {
                        const msgIndex = regularChatMessages.indexOf(msg) + 1;
                        console.log(`🔄 [CONTEXT] Hero message ${msgIndex}:`, msg.type, '-', msg.content);
                    });
                }
            }

            console.log('🔄 [CONTEXT] Total conversation messages in context:', conversationMessages.length);
            console.log('🔄 [CONTEXT] Context summary:', {
                totalMessages: conversationMessages.length,
                mode: currentMode,
                hasPracticeTest: !!(chatData.practiceTests && chatData.practiceTests.questions.length > 0)
            });

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

            // Prevent chat if no published units are available
            if (window.noPublishedUnits) {
                console.log('Chat disabled - no published units available');
                return;
            }

            const message = chatInput.value.trim();
            if (!message) return;

            // Check if we need to show the 15-message warning BEFORE adding the user message
            // We want to show the warning before the bot responds to the student's 14th message
            // If count is 13, after adding user message = 14, bot response = 15 (show warning)
            // If count is 14, after adding user message = 15, bot response = 16 (we've passed the window)
            // So we check for count === 13 OR count === 14 (to catch edge cases)
            const messageCountBefore = countMessagesFromFirstStudent();
            const warningAlreadyShown = hasWarningBeenShown();
            const shouldShowWarning = !warningAlreadyShown && (messageCountBefore === 13 || messageCountBefore === 14);

            if (shouldShowWarning) {
                console.log('⚠️ [CHAT] Will show 15-message warning after user message (current count:', messageCountBefore, ', warning already shown:', warningAlreadyShown, ')');
            } else if (messageCountBefore === 13 || messageCountBefore === 14) {
                console.log('⚠️ [CHAT] Warning already shown, skipping (current count:', messageCountBefore, ')');
            }

            // Add user message to chat
            console.log('💬 [CHAT] Adding user message to chat:', message.substring(0, 50) + '...');
            addMessage(message, 'user');

            // Clear input
            chatInput.value = '';

            // Show warning message if needed (before the bot responds)
            // Since autoSaveMessage is synchronous, we can add the warning immediately
            if (shouldShowWarning) {
                console.log('⚠️ [CHAT] Showing 15-message warning');
                // Add the warning message just like a normal bot response, with source attribution
                addMessage('Please be aware that after 15 messages, the quality of the responses might be degraded.', 'bot', true, false, {
                    source: 'System',
                    description: 'System notification',
                    unitName: null,
                    documentType: null
                });
            }

            // Show typing indicator
            showTypingIndicator();

            // Send message to real LLM service
            try {
                const response = await sendMessageToLLM(message);

                // Remove typing indicator
                removeTypingIndicator();

                // Add real bot response
                console.log('💬 [CHAT] Adding bot response to chat:', response.message.substring(0, 50) + '...');

                // Log debug information for source attribution
                if (response.debug) {
                    console.log('🔍 [SOURCE_DEBUG] Search results count:', response.debug.searchResultsCount);
                    console.log('🔍 [SOURCE_DEBUG] Average score:', response.debug.avgScore);
                    console.log('🔍 [SOURCE_DEBUG] Max score:', response.debug.maxScore);
                    console.log('🔍 [SOURCE_DEBUG] Document types:', response.debug.documentTypes);
                    console.log('🔍 [SOURCE_DEBUG] Source attribution:', response.sourceAttribution);
                }

                addMessage(response.message, 'bot', true, false, response.sourceAttribution);

            } catch (error) {
                // Remove typing indicator
                removeTypingIndicator();

                // Show error message
                console.error('Chat error:', error);
                console.log('💬 [CHAT] Adding error message to chat');
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
});

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
 * Global function to add a message to the chat
 * @param {string} content - The message content
 * @param {string} sender - 'user' or 'bot'
 * @param {boolean} withSource - Whether to show source citation
 * @param {boolean} skipAutoSave - Whether to skip auto-save for this message
 * @param {Object} sourceAttribution - Source attribution information
 */
function addMessage(content, sender, withSource = false, skipAutoSave = false, sourceAttribution = null) {
    console.log('🔧 [ADD_MESSAGE] Function called with:', { content: content.substring(0, 50) + '...', sender, withSource });

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
    paragraph.textContent = content;

    contentDiv.appendChild(paragraph);

    // Create message footer for bottom elements
    const footerDiv = document.createElement('div');
    footerDiv.classList.add('message-footer');

    // Add source citation if needed
    if (withSource && sender === 'bot') {
        const sourceDiv = document.createElement('div');
        sourceDiv.classList.add('message-source');

        // Use actual source attribution if available, otherwise show TBD
        if (sourceAttribution && sourceAttribution.description) {
            sourceDiv.innerHTML = `Source: ${sourceAttribution.description}`;
        } else {
            sourceDiv.innerHTML = 'Source: TBD';
        }

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

        const flagButton = document.createElement('button');
        flagButton.classList.add('flag-button');
        flagButton.innerHTML = '⚑';
        flagButton.title = 'Flag this message';
        flagButton.onclick = () => toggleFlagMenu(flagButton);

        // Create flag menu
        const flagMenu = document.createElement('div');
        flagMenu.classList.add('flag-menu');
        flagMenu.innerHTML = `
            <div class="flag-option" onclick="flagMessage(this, 'inappropriate')">Inappropriate</div>
            <div class="flag-option" onclick="flagMessage(this, 'incorrect')">Incorrect</div>
            <div class="flag-option" onclick="flagMessage(this, 'unclear')">Unclear</div>
        `;

        flagContainer.appendChild(flagButton);
        flagContainer.appendChild(flagMenu);
        rightContainer.appendChild(flagContainer);
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
        console.log('🔧 [ADD_MESSAGE] About to trigger auto-save...');
        console.log('🔄 [AUTO-SAVE] Triggering auto-save for message:', { content: content.substring(0, 50) + '...', sender, withSource, sourceAttribution });
        autoSaveMessage(content, sender, withSource, sourceAttribution);
        console.log('🔧 [ADD_MESSAGE] Auto-save call completed');
    } else {
        console.log('🔧 [ADD_MESSAGE] Skipping auto-save for system message');
    }
}

/**
 * Initialize auto-save system for chat
 * Creates an empty chat data structure that will be updated with each message
 */
async function initializeAutoSave() {
    try {
        console.log('=== INITIALIZING AUTO-SAVE ===');

        // Get current student info using the same functions as the rest of the code
        const studentId = getCurrentStudentId();
        // Get student name synchronously from currentUser to avoid Promise issues
        const currentUser = getCurrentUser();
        const studentName = currentUser?.displayName || 'Anonymous Student';
        const courseId = localStorage.getItem('selectedCourseId') || 'unknown';
        const courseName = document.querySelector('.course-name')?.textContent || 'Unknown Course';
        const unitName = localStorage.getItem('selectedUnitName') || 'this unit';
        const currentMode = localStorage.getItem('studentMode') || 'tutor';

        console.log('Auto-save student info:', { studentId, studentName, courseId, courseName, unitName, currentMode });

        // Check if there's already existing chat data
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        const existingChatData = localStorage.getItem(autoSaveKey);

        if (existingChatData) {
            const parsedData = JSON.parse(existingChatData);
            if (parsedData.messages && parsedData.messages.length > 0) {
                console.log('🔄 [AUTO-SAVE] Existing chat data found with', parsedData.messages.length, 'messages, not overwriting');

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
                    console.log('🔄 [AUTO-SAVE] Restored session ID from localStorage:', existingSessionId);
                }
                // If chat data has a session ID but localStorage doesn't, restore it
                else if (parsedData.sessionInfo && parsedData.sessionInfo.sessionId && !existingSessionId) {
                    localStorage.setItem(sessionKey, parsedData.sessionInfo.sessionId);
                    console.log('🔄 [AUTO-SAVE] Restored session ID to localStorage:', parsedData.sessionInfo.sessionId);
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

        console.log('Auto-save initialized with empty chat data structure');
        console.log('Auto-save key:', autoSaveKey);

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
function autoSaveMessage(content, sender, withSource = false, sourceAttribution = null) {
    try {
        console.log('=== AUTO-SAVING MESSAGE ===');
        console.log('Message:', { content: content.substring(0, 50) + '...', sender, withSource });

        // Get current student ID using the same function as the rest of the code
        const studentId = getCurrentStudentId();
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        console.log('🔄 [AUTO-SAVE] Student ID:', studentId);
        console.log('🔄 [AUTO-SAVE] Auto-save key:', autoSaveKey);

        // Get current chat data
        let currentChatData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');
        console.log('🔄 [AUTO-SAVE] Current chat data exists:', !!currentChatData.messages);
        console.log('🔄 [AUTO-SAVE] Current message count:', currentChatData.messages ? currentChatData.messages.length : 0);

        // If no current chat data exists, initialize it
        if (!currentChatData.messages) {
            console.log('🔄 [AUTO-SAVE] No current chat data found, initializing...');
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
                console.log('🔄 [AUTO-SAVE] Created new session ID:', sessionId);
            } else {
                console.log('🔄 [AUTO-SAVE] Using existing session ID:', sessionId);
            }
            currentChatData.sessionInfo.sessionId = sessionId;

            console.log('🔄 [AUTO-SAVE] Initialized empty chat data structure with session ID');
        }

        // Create new message object
        const newMessage = {
            type: sender,
            content: content,
            timestamp: new Date().toISOString(),
            hasFlagButton: sender === 'bot' && withSource,
            messageType: 'regular-chat',
            sourceAttribution: sourceAttribution || null  // Save source attribution for restoration
        };

        // Add message to messages array
        currentChatData.messages.push(newMessage);

        // Update metadata - only count actual chat messages (not assessment messages)
        currentChatData.metadata.totalMessages = currentChatData.messages.length;
        currentChatData.metadata.exportDate = new Date().toISOString();
        currentChatData.metadata.currentMode = localStorage.getItem('studentMode') || 'tutor'; // Update current mode
        currentChatData.sessionInfo.endTime = new Date().toISOString();
        currentChatData.sessionInfo.duration = calculateSessionDuration(currentChatData);

        // Update last activity timestamp for auto-continue feature
        currentChatData.lastActivityTimestamp = new Date().toISOString();

        // Update assessment data if available
        updateAssessmentDataInAutoSave(currentChatData);

        // Save back to localStorage
        localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));

        console.log(`🔄 [AUTO-SAVE] ✅ Successfully auto-saved message. Total messages: ${currentChatData.messages.length}`);

        // Debug: Log the current auto-save data structure
        console.log('🔄 [AUTO-SAVE] Current auto-save data:', {
            totalMessages: currentChatData.messages.length,
            lastMessage: currentChatData.messages[currentChatData.messages.length - 1],
            courseId: currentChatData.metadata.courseId,
            studentId: currentChatData.metadata.studentId
        });

        // Verify the save worked
        const verifyData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');
        console.log('🔄 [AUTO-SAVE] Verification - saved data has', verifyData.messages ? verifyData.messages.length : 0, 'messages');

        // Sync with server after every message to ensure nothing is lost
        console.log('🔄 [AUTO-SAVE] Syncing with server after each message...');
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
        console.log('🔄 [SESSION] Using session ID from chat data:', chatData.sessionInfo.sessionId);
        return chatData.sessionInfo.sessionId;
    }

    // Check if we have a stored session ID for this chat
    const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
    let sessionId = localStorage.getItem(sessionKey);

    if (!sessionId) {
        // Create a new session ID
        sessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        localStorage.setItem(sessionKey, sessionId);
        console.log('🔄 [SESSION] Created new session ID:', sessionId);
    } else {
        console.log('🔄 [SESSION] Using existing session ID:', sessionId);
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
            console.log('🔄 [SESSION] Updated session ID in chat data');
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
        console.log('🔄 [SESSION] Assessment in progress (chat disabled) - creating new session');
        return true;
    }

    // If chat input is enabled, assessment is completed - use existing session
    console.log('🔄 [SESSION] Assessment completed (chat enabled) - using existing session');
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

        console.log('🔄 [AUTO-SAVE] Updated assessment data:', {
            questionsCount: chatData.practiceTests ? chatData.practiceTests.questions.length : 0,
            answersCount: chatData.studentAnswers.answers.length,
            passThreshold: chatData.practiceTests ? chatData.practiceTests.passThreshold : null
        });

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
        console.log('🔄 [SERVER-SYNC] Syncing auto-save data with server...');

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
            console.log('🔄 [SESSION] Creating new session (assessment in progress)');
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

        console.log('🔄 [SERVER-SYNC] Sending data to server:', {
            sessionId,
            courseId: serverData.courseId,
            studentId: serverData.studentId,
            studentName: serverData.studentName,
            messageCount: serverData.messageCount,
            isNewSession: shouldCreateNew
        });

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
                console.log('🔄 [SERVER-SYNC] ✅ Successfully synced with server');
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

            console.log('🔄 [AUTO-CONTINUE] Updated last activity timestamp:', chatData.lastActivityTimestamp);
        }
    } catch (error) {
        console.error('Error updating last activity timestamp:', error);
    }
}

/**
 * Load the current session data into the chat interface
 * This is used for auto-continue to restore the session without creating a new one
 */
function loadCurrentSessionIntoInterface() {
    try {
        console.log('🔄 [AUTO-CONTINUE] Loading current session into interface...');

        const chatData = getCurrentChatData();
        if (!chatData || !chatData.messages || chatData.messages.length === 0) {
            console.log('🔄 [AUTO-CONTINUE] No current session data to load');
            return;
        }

        console.log('🔄 [AUTO-CONTINUE] Loading', chatData.messages.length, 'messages into interface');

        // Set flags for continuing chat BEFORE loading data
        // This ensures getConversationContext() can access the data
        sessionStorage.setItem('isContinuingChat', 'true');
        sessionStorage.setItem('loadedChatData', JSON.stringify(chatData));
        console.log('🔄 [AUTO-CONTINUE] Set conversation context flags');

        // Load the chat data using the existing function
        loadChatData(chatData);

        console.log('🔄 [AUTO-CONTINUE] ✅ Current session loaded into interface');

    } catch (error) {
        console.error('Error loading current session into interface:', error);
    }
}

/**
 * Show a notification that the chat was auto-continued
 */
function showAutoContinueNotification() {
    try {
        // Create a simple notification element
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #4CAF50;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            max-width: 300px;
            animation: slideIn 0.3s ease-out;
        `;

        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 16px;">🔄</span>
                <span>Chat continued from where you left off</span>
            </div>
        `;

        // Add CSS animation
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);

        // Add to page
        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'slideIn 0.3s ease-out reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
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
        console.log('🔄 [AUTO-CONTINUE] Checking for auto-continue...');

        const chatData = getCurrentChatData();
        console.log('🔄 [AUTO-CONTINUE] Chat data found:', !!chatData);
        if (chatData) {
            console.log('🔄 [AUTO-CONTINUE] Messages count:', chatData.messages ? chatData.messages.length : 'No messages array');
            console.log('🔄 [AUTO-CONTINUE] Last activity timestamp:', chatData.lastActivityTimestamp);
        }

        if (!chatData || !chatData.messages || chatData.messages.length === 0) {
            console.log('🔄 [AUTO-CONTINUE] No chat data or empty chat, skipping auto-continue');
            return false;
        }

        // Check if we have a last activity timestamp
        if (!chatData.lastActivityTimestamp) {
            console.log('🔄 [AUTO-CONTINUE] No last activity timestamp found, skipping auto-continue');
            return false;
        }

        // Calculate time difference
        const lastActivity = new Date(chatData.lastActivityTimestamp);
        const now = new Date();
        const diffMs = now - lastActivity;
        const diffMinutes = Math.floor(diffMs / (1000 * 60));

        console.log('🔄 [AUTO-CONTINUE] Last activity:', lastActivity.toISOString());
        console.log('🔄 [AUTO-CONTINUE] Current time:', now.toISOString());
        console.log('🔄 [AUTO-CONTINUE] Time difference:', diffMinutes, 'minutes');

        // Check if within 30 minutes
        if (diffMinutes <= 30) {
            console.log('🔄 [AUTO-CONTINUE] ✅ Within 30 minutes, auto-continuing chat...');

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
                console.log('🔄 [AUTO-CONTINUE] Restored session ID:', existingSessionId);
            } else if (chatData.sessionInfo && chatData.sessionInfo.sessionId) {
                // If chat data has a session ID but localStorage doesn't, restore it
                localStorage.setItem(sessionKey, chatData.sessionInfo.sessionId);
                console.log('🔄 [AUTO-CONTINUE] Restored session ID to localStorage:', chatData.sessionInfo.sessionId);
            } else {
                // If neither has a session ID, get/create one and store it in both places
                const sessionId = getCurrentSessionId(chatData);
                if (!chatData.sessionInfo) {
                    chatData.sessionInfo = {};
                }
                chatData.sessionInfo.sessionId = sessionId;
                console.log('🔄 [AUTO-CONTINUE] Created new session ID:', sessionId);
            }

            // Update the current chat data with the restored data (including session ID)
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));

            console.log('🔄 [AUTO-CONTINUE] ✅ Successfully restored session state');

            // Show a brief notification to the user
            showAutoContinueNotification();

            return true;
        } else {
            console.log('🔄 [AUTO-CONTINUE] ❌ Outside 30-minute window, not auto-continuing');
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
        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        localStorage.removeItem(autoSaveKey);

        // Also clear session tracking data
        const courseId = localStorage.getItem('selectedCourseId') || 'unknown';
        const unitName = localStorage.getItem('selectedUnitName') || 'unknown';
        const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
        const lastSyncKey = `biocbot_last_sync_${studentId}_${courseId}_${unitName}`;
        localStorage.removeItem(sessionKey);
        localStorage.removeItem(lastSyncKey);

        // Clear conversation context flags from sessionStorage
        // This ensures new sessions don't reference old conversations
        sessionStorage.removeItem('isContinuingChat');
        sessionStorage.removeItem('loadChatData');
        sessionStorage.removeItem('loadedChatData');
        console.log('Cleared current chat data, session tracking, and conversation context flags');
    } catch (error) {
        console.error('Error clearing current chat data:', error);
    }
}

/**
 * Debug function to check current auto-save data
 * Can be called from browser console for testing
 */
function debugAutoSaveData() {
    const chatData = getCurrentChatData();
    if (chatData) {
        console.log('=== AUTO-SAVE DEBUG INFO ===');
        console.log('Total messages:', chatData.messages.length);
        console.log('Course ID:', chatData.metadata.courseId);
        console.log('Student ID:', chatData.metadata.studentId);
        console.log('Unit Name:', chatData.metadata.unitName);
        console.log('Session Duration:', chatData.sessionInfo.duration);
        console.log('Last Activity:', chatData.lastActivityTimestamp);
        console.log('Messages:', chatData.messages);
        console.log('============================');
    } else {
        console.log('No auto-save data found');
    }
}

/**
 * Debug function to test auto-continue feature
 * Can be called from browser console for testing
 */
function testAutoContinue() {
    console.log('=== TESTING AUTO-CONTINUE ===');
    const chatData = getCurrentChatData();

    if (!chatData || !chatData.messages || chatData.messages.length === 0) {
        console.log('❌ No chat data found. Send some messages first.');
        console.log('💡 To test: Send a message, then refresh the page within 30 minutes');
        return;
    }

    console.log('Current chat data found:');
    console.log('- Messages:', chatData.messages.length);
    console.log('- Last Activity:', chatData.lastActivityTimestamp);

    if (chatData.lastActivityTimestamp) {
        const lastActivity = new Date(chatData.lastActivityTimestamp);
        const now = new Date();
        const diffMs = now - lastActivity;
        const diffMinutes = Math.floor(diffMs / (1000 * 60));

        console.log('- Time since last activity:', diffMinutes, 'minutes');
        console.log('- Would auto-continue:', diffMinutes <= 30 ? 'YES' : 'NO');
    } else {
        console.log('❌ No last activity timestamp found');
    }

    console.log('===============================');
}

/**
 * Debug function to simulate auto-continue for testing
 * Can be called from browser console for testing
 */
function simulateAutoContinue() {
    console.log('=== SIMULATING AUTO-CONTINUE ===');
    const chatData = getCurrentChatData();

    if (!chatData || !chatData.messages || chatData.messages.length === 0) {
        console.log('❌ No chat data found. Send some messages first.');
        return;
    }

    console.log('Simulating auto-continue with current chat data...');

    // Store the chat data in sessionStorage (same as continue chat)
    sessionStorage.setItem('loadChatData', JSON.stringify(chatData));
    console.log('✅ Stored chat data in sessionStorage');

    // Load the chat data using the existing function
    loadChatData(chatData);
    console.log('✅ Loaded chat data into interface');

    console.log('===============================');
}

/**
 * Debug function to force auto-continue check
 * Can be called from browser console for testing
 */
function forceAutoContinueCheck() {
    console.log('=== FORCING AUTO-CONTINUE CHECK ===');
    const wasAutoContinued = checkForAutoContinue();

    if (wasAutoContinued) {
        console.log('✅ Auto-continue was successful');
        window.autoContinued = true;
    } else {
        console.log('❌ Auto-continue did not trigger');
    }

    console.log('===============================');
}

/**
 * Debug function to check what's in localStorage
 * Can be called from browser console for testing
 */
function checkLocalStorageData() {
    console.log('=== CHECKING LOCALSTORAGE DATA ===');
    const studentId = getCurrentStudentId();
    const autoSaveKey = `biocbot_current_chat_${studentId}`;

    console.log('Student ID:', studentId);
    console.log('Auto-save key:', autoSaveKey);

    const rawData = localStorage.getItem(autoSaveKey);
    console.log('Raw localStorage data:', rawData);

    if (rawData) {
        try {
            const parsedData = JSON.parse(rawData);
            console.log('Parsed data:', parsedData);
            console.log('Messages count:', parsedData.messages ? parsedData.messages.length : 'No messages array');
            console.log('Last activity timestamp:', parsedData.lastActivityTimestamp);
        } catch (error) {
            console.error('Error parsing localStorage data:', error);
        }
    } else {
        console.log('No data found in localStorage');
    }

    console.log('===============================');
}

/**
 * Debug function to check history loading status
 * Can be called from browser console for testing
 */
function checkHistoryLoadingStatus() {
    console.log('=== CHECKING HISTORY LOADING STATUS ===');
    console.log('sessionStorage loadChatData:', !!sessionStorage.getItem('loadChatData'));
    console.log('window.loadingFromHistory:', !!window.loadingFromHistory);
    console.log('window.autoContinued:', !!window.autoContinued);

    const loadChatData = sessionStorage.getItem('loadChatData');
    if (loadChatData) {
        try {
            const parsed = JSON.parse(loadChatData);
            console.log('History chat data messages:', parsed.messages ? parsed.messages.length : 'No messages');
        } catch (error) {
            console.error('Error parsing history data:', error);
        }
    }

    console.log('===============================');
}

/**
 * Debug function to check session ID status
 * Can be called from browser console for testing
 */
function checkSessionIdStatus() {
    console.log('=== CHECKING SESSION ID STATUS ===');

    const studentId = getCurrentStudentId();
    const courseId = localStorage.getItem('selectedCourseId');
    const unitName = localStorage.getItem('selectedUnitName') || 'this unit';

    console.log('Student ID:', studentId);
    console.log('Course ID:', courseId);
    console.log('Unit Name:', unitName);

    if (studentId && courseId) {
        const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
        const currentSessionId = localStorage.getItem(sessionKey);
        console.log('Session Key:', sessionKey);
        console.log('Current Session ID:', currentSessionId);

        // Check current chat data
        const chatData = getCurrentChatData();
        if (chatData && chatData.sessionInfo) {
            console.log('Chat Data Session ID:', chatData.sessionInfo.sessionId);
            console.log('Session IDs Match:', currentSessionId === chatData.sessionInfo.sessionId);
        }
    }

    console.log('===============================');
}

/**
 * Initialize the new session button functionality
 */
function initializeNewSessionButton() {
    try {
        const newSessionBtn = document.getElementById('new-session-btn');
        if (!newSessionBtn) {
            console.log('New session button not found');
            return;
        }

        newSessionBtn.addEventListener('click', handleNewSession);
        console.log('✅ New session button initialized');

    } catch (error) {
        console.error('Error initializing new session button:', error);
    }
}

/**
 * Handle new session button click
 */
async function handleNewSession() {
    try {
        console.log('🔄 [NEW-SESSION] Starting new session...');

        // Clear any existing session data
        clearCurrentChatData();

        // Generate a new session ID for the new session
        const studentId = getCurrentStudentId();
        const courseId = localStorage.getItem('selectedCourseId');
        const unitName = localStorage.getItem('selectedUnitName') || 'this unit';

        if (studentId && courseId) {
            const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
            const newSessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            localStorage.setItem(sessionKey, newSessionId);
            console.log('🔄 [NEW-SESSION] Generated new session ID:', newSessionId);
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
            chatMessages.innerHTML = `
                <div class="message bot-message">
                    <div class="message-avatar">B</div>
                    <div class="message-content">
                        <p>Hello! I'm BiocBot, your AI study assistant for ${courseName}. How can I help you today?</p>
                        <div class="message-footer">
                            <div class="message-footer-right">
                                <span class="timestamp">Just now</span>
                                <div class="message-flag-container">
                                    <button class="flag-button" onclick="toggleFlagMenu(this)">
                                        <span class="three-dots">⋯</span>
                                    </button>
                                    <div class="flag-menu">
                                        <button class="flag-option" onclick="flagMessage(this, 'incorrect')">Incorrect</button>
                                        <button class="flag-option" onclick="flagMessage(this, 'inappropriate')">Inappropriate</button>
                                        <button class="flag-option" onclick="flagMessage(this, 'unclear')">Unclear</button>
                                        <button class="flag-option" onclick="flagMessage(this, 'confusing')">Confusing</button>
                                        <button class="flag-option" onclick="flagMessage(this, 'typo')">Typo/Error</button>
                                        <button class="flag-option" onclick="flagMessage(this, 'offensive')">Offensive</button>
                                        <button class="flag-option" onclick="flagMessage(this, 'irrelevant')">Irrelevant</button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
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
        console.log('🔄 [NEW-SESSION] Triggering full initialization...');
        checkPublishedUnitsAndLoadQuestions();

        console.log('🔄 [NEW-SESSION] ✅ New session started successfully');

    } catch (error) {
        console.error('Error starting new session:', error);
    }
}

/**
 * Show a notification that a new session was started
 */
function showNewSessionNotification() {
    try {
        // Create a simple notification element
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #17a2b8;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            max-width: 300px;
            animation: slideIn 0.3s ease-out;
        `;

        notification.innerHTML = `
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 16px;">✨</span>
                <span>New chat session started</span>
            </div>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'slideIn 0.3s ease-out reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
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

        console.log('Submitting flag with data:', flagData);

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
        console.log('Flag submitted successfully:', result);

        // Immediately refresh flag notifications to track the new flag
        // This ensures the flag is in lastKnownFlags so we can detect when it's approved
        if (result.success && typeof checkForFlagUpdates === 'function') {
            console.log('🔄 [FLAG] Triggering immediate flag check after flag submission...');
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
        console.log('Loading current course information...');

        // Get student name first
        const studentName = await getCurrentStudentName();
        console.log('Student name loaded:', studentName);

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
        console.log('Loading available courses...');

        // Check if there's already a selected course in localStorage
        const storedCourseId = localStorage.getItem('selectedCourseId');
        const storedCourseName = localStorage.getItem('selectedCourseName');
        
        if (storedCourseId) {
            console.log('Found stored course ID, verifying it exists and belongs to current user:', storedCourseId);
            console.log('Found stored course name:', storedCourseName);
            
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
                        // Check if chat data exists, has messages, and matches the stored courseId
                        if (chatData && 
                            chatData.metadata && 
                            chatData.metadata.courseId === storedCourseId &&
                            chatData.metadata.studentId === studentId &&
                            chatData.messages && 
                            chatData.messages.length > 0) {
                            hasUserChatData = true;
                            console.log('Found actual chat messages for current user with stored course');
                        } else {
                            console.log('Chat data exists but no messages or wrong course - treating as first-time user');
                        }
                    } catch (e) {
                        console.log('Error parsing chat data:', e);
                    }
                } else {
                    console.log('No chat data found for current user - treating as first-time user');
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

    // Create course selection dropdown
    const courseSelectionHTML = `
        <div class="course-selection-container" style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 8px; border-left: 4px solid var(--primary-color);">
            <h3 style="margin: 0 0 10px 0; color: #333;">Select Your Course</h3>
            <p style="margin: 0 0 15px 0; color: #666;">Choose the course you want to access:</p>
            <select id="course-select" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                <option value="">Choose a course...</option>
                ${courses.map(course => `<option value="${course.courseId}">${course.courseName}</option>`).join('')}
            </select>
        </div>
    `;

    // Insert course selection before the chat messages
    const chatMessages = document.getElementById('chat-messages');
    const existingWelcome = chatMessages.querySelector('.message.bot-message');

    // Create a container for the course selection
    const courseSelectionDiv = document.createElement('div');
    courseSelectionDiv.innerHTML = courseSelectionHTML;
    courseSelectionDiv.id = 'course-selection-wrapper';

    // Insert before the existing welcome message
    if (existingWelcome) {
        chatMessages.insertBefore(courseSelectionDiv, existingWelcome);
    } else {
        chatMessages.appendChild(courseSelectionDiv);
    }

    // Add event listener for course selection
    const courseSelect = document.getElementById('course-select');
    if (courseSelect) {
        courseSelect.addEventListener('change', async function() {
            const selectedCourseId = this.value;
            if (selectedCourseId) {
                console.log('Course selected:', selectedCourseId);
                // This is a course change (user selected from dropdown)
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
        console.log('Loading course data for:', courseId, 'isCourseChange:', isCourseChange);

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
        console.log('Course data loaded:', course);
        console.log('Course name from API (courseName):', course.courseName);
        console.log('Course name from API (name):', course.name);

        // Use name property if courseName is not available (API compatibility)
        const courseName = course.courseName || course.name;
        console.log('Using course name:', courseName);

        // Store course name in localStorage for persistence
        if (courseName) {
            localStorage.setItem('selectedCourseName', courseName);
            console.log('Stored course name in localStorage:', courseName);
        }

        // Update UI elements with actual course information
        console.log('Calling updateCourseDisplay with course:', course);
        updateCourseDisplay(course);

        // Force a small delay and try again to ensure DOM is updated
        setTimeout(() => {
            console.log('Retrying course display update after delay...');
            updateCourseDisplay(course);
        }, 100);

        // Add change course functionality
        addChangeCourseButton();

        // If this is a course change (not initial load), create a new clean session
        if (actualCourseChange) {
            console.log('🔄 [COURSE-CHANGE] Creating new session for course change...');
            
            // Clear any existing session data for the old course
            clearCurrentChatData();

            // Clear the selected unit name so the unit dropdown will show up
            localStorage.removeItem('selectedUnitName');
            console.log('🔄 [COURSE-CHANGE] Cleared selected unit name to show unit dropdown');

            // Generate a new session ID for the new course
            const studentId = getCurrentStudentId();
            const unitName = localStorage.getItem('selectedUnitName') || 'this unit';

            if (studentId && courseId) {
                const sessionKey = `biocbot_session_${studentId}_${courseId}_${unitName}`;
                const newSessionId = `autosave_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                localStorage.setItem(sessionKey, newSessionId);
                console.log('🔄 [COURSE-CHANGE] Generated new session ID:', newSessionId);
            }

            // Clear the chat interface to start fresh
            const chatMessages = document.getElementById('chat-messages');
            if (chatMessages) {
                chatMessages.innerHTML = `
                    <div class="message bot-message">
                        <div class="message-avatar">B</div>
                        <div class="message-content">
                            <p>Hello! I'm BiocBot, your AI study assistant for ${courseName}. How can I help you today?</p>
                            <div class="message-footer">
                                <div class="message-footer-right">
                                    <span class="timestamp">Just now</span>
                                    <div class="message-flag-container">
                                        <button class="flag-button" onclick="toggleFlagMenu(this)">
                                            <span class="three-dots">⋯</span>
                                        </button>
                                        <div class="flag-menu">
                                            <button class="flag-option" onclick="flagMessage(this, 'incorrect')">Incorrect</button>
                                            <button class="flag-option" onclick="flagMessage(this, 'inappropriate')">Inappropriate</button>
                                            <button class="flag-option" onclick="flagMessage(this, 'unclear')">Unclear</button>
                                            <button class="flag-option" onclick="flagMessage(this, 'confusing')">Confusing</button>
                                            <button class="flag-option" onclick="flagMessage(this, 'typo')">Typo/Error</button>
                                            <button class="flag-option" onclick="flagMessage(this, 'offensive')">Offensive</button>
                                            <button class="flag-option" onclick="flagMessage(this, 'irrelevant')">Irrelevant</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }

            // Reset flags
            window.autoContinued = false;
            window.loadingFromHistory = false;

            // Load questions and proper prompts for the new course
            // Use a small delay to ensure DOM is fully updated
            setTimeout(() => {
                console.log('🔄 [COURSE-CHANGE] Loading questions for new course...');
                checkPublishedUnitsAndLoadQuestions();
            }, 200);
        } else {
            // On initial load, ensure session exists and questions are loaded
            console.log('🔄 [INITIAL-LOAD] Initial course load - ensuring session exists and questions are loaded');
            
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
                    console.log('🔄 [INITIAL-LOAD] Created new session ID:', sessionId);
                } else {
                    console.log('🔄 [INITIAL-LOAD] Using existing session ID:', sessionId);
                }
            }

            // Ensure questions are loaded after a delay to allow DOM to be ready
            // This handles the case where loadCourseData is called before checkPublishedUnitsAndLoadQuestions
            setTimeout(() => {
                console.log('🔄 [INITIAL-LOAD] Ensuring questions are loaded for initial course...');
                checkPublishedUnitsAndLoadQuestions();
            }, 300);
        }

    } catch (error) {
        console.error('Error loading course data:', error);

        // If this was a 404 error, clear localStorage and try to load available courses
        if (error.message.includes('404')) {
            console.log('Course not found, clearing localStorage and loading available courses');
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
    console.log('updateCourseDisplay called with course:', course);

    // Use name property if courseName is not available (API compatibility)
    const courseName = course.courseName || course.name;
    console.log('Using course name for display:', courseName);

    // Update course name in header - try multiple selectors
    let courseNameElement = document.querySelector('.course-name');
    console.log('courseNameElement found with .course-name:', courseNameElement);

    // If not found, try alternative selectors
    if (!courseNameElement) {
        courseNameElement = document.querySelector('span.course-name');
        console.log('courseNameElement found with span.course-name:', courseNameElement);
    }

    if (!courseNameElement) {
        courseNameElement = document.querySelector('.current-course .course-name');
        console.log('courseNameElement found with .current-course .course-name:', courseNameElement);
    }

    console.log('Final courseNameElement:', courseNameElement);
    console.log('courseName to use:', courseName);

    if (courseNameElement && courseName) {
        const oldText = courseNameElement.textContent;
        courseNameElement.textContent = courseName;
        console.log(`Updated course name from "${oldText}" to "${courseName}"`);

        // Verify the update worked
        const newText = courseNameElement.textContent;
        console.log('Verification - course name element now contains:', newText);
    } else {
        console.warn('Could not update course name - element or courseName missing');
        console.warn('Element found:', !!courseNameElement);
        console.warn('Course name provided:', courseName);

        // Try the more aggressive approach
        if (courseName) {
            console.log('Trying force update approach...');
            const forceUpdated = forceUpdateCourseName(courseName);
            if (forceUpdated) {
                console.log('Force update successful!');
            } else {
                console.error('Force update failed!');
            }
        }
    }

    // Update user role display
    const userRoleElement = document.querySelector('.user-role');
    if (userRoleElement && courseName) {
        userRoleElement.textContent = `Student - ${courseName}`;
        console.log('Updated user role to:', `Student - ${courseName}`);
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

    console.log('Course display updated with:', courseName, 'Student:', studentName || 'not provided');
}

/**
 * Force update course name in the header - more aggressive approach
 * @param {string} courseName - The course name to display
 */
function forceUpdateCourseName(courseName) {
    console.log('Force updating course name to:', courseName);

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
        console.log(`Found ${elements.length} elements with selector: ${selector}`);

        elements.forEach((element, index) => {
            console.log(`Element ${index}:`, element);
            console.log(`Current text: "${element.textContent}"`);
            element.textContent = courseName;
            console.log(`Updated text to: "${element.textContent}"`);
            updated = true;
        });
    }

    if (!updated) {
        console.error('Could not find any course name elements to update!');
        // List all elements that might be relevant
        const allSpans = document.querySelectorAll('span');
        console.log('All span elements:', allSpans);
        allSpans.forEach((span, index) => {
            if (span.textContent.includes('BIOC') || span.textContent.includes('Course')) {
                console.log(`Relevant span ${index}:`, span, 'text:', span.textContent);
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
        console.log('getCurrentStudentId - currentUser:', currentUser);

        if (currentUser && currentUser.userId) {
            console.log('getCurrentStudentId - using userId from currentUser:', currentUser.userId);
            return currentUser.userId;
        }

        // Fallback: try to get from localStorage or sessionStorage
        const storedUserId = localStorage.getItem('userId') || sessionStorage.getItem('userId');
        if (storedUserId) {
            console.log('getCurrentStudentId - using stored userId:', storedUserId);
            return storedUserId;
        }

        // Last resort: generate a unique ID for this session
        let sessionId = sessionStorage.getItem('sessionId');
        if (!sessionId) {
            sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('sessionId', sessionId);
            console.log('getCurrentStudentId - generated new sessionId:', sessionId);
        } else {
            console.log('getCurrentStudentId - using existing sessionId:', sessionId);
        }
        return sessionId;

    } catch (error) {
        console.error('Error getting student ID:', error);
        // Fallback to a unique session-based ID
        let sessionId = sessionStorage.getItem('sessionId');
        if (!sessionId) {
            sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('sessionId', sessionId);
            console.log('getCurrentStudentId - error fallback, generated sessionId:', sessionId);
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
                console.log('Using course from user preferences:', userData.user.preferences.courseId);
                return userData.user.preferences.courseId;
            }
        }

        // Check localStorage for previously selected course
        const storedCourseId = localStorage.getItem('selectedCourseId');
        if (storedCourseId) {
            console.log('Found stored course ID, will verify it exists:', storedCourseId);
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
            console.log('Only one course available, using it:', courses[0].courseId);
            // Store it in localStorage for future use
            localStorage.setItem('selectedCourseId', courses[0].courseId);
            return courses[0].courseId;
        } else if (courses.length > 1) {
            // Multiple courses available - don't auto-select, let user choose
            console.log('Multiple courses available, user should select one');
            throw new Error('Multiple courses available - user selection required');
        }

        // Fallback to a default course ID if no courses are available
        console.log('No courses available, using fallback');
        return 'default-course-id';

    } catch (error) {
        console.error('Error fetching course ID:', error);
        // Fallback to a default course ID if API fails
        return 'default-course-id';
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

// Make variables globally accessible for auto-save
window.currentCalibrationQuestions = currentCalibrationQuestions;
window.studentAnswers = studentAnswers;

/**
 * Check for published units and load real assessment questions
 * If no units are published, allow direct chat
 */
async function checkPublishedUnitsAndLoadQuestions() {
    try {
        console.log('=== CHECKING FOR PUBLISHED UNITS ===');

        // Prevent duplicate calls - if already checking, wait for it to complete
        if (window.isCheckingPublishedUnits) {
            console.log('🔄 [UNITS] Already checking published units, skipping duplicate call');
            return;
        }
        window.isCheckingPublishedUnits = true;

        // Check if chat was auto-continued
        if (window.autoContinued) {
            console.log('🔄 [AUTO-CONTINUE] Chat was auto-continued, skipping assessment questions');
            window.isCheckingPublishedUnits = false;
            return;
        }

        // Get current course ID from localStorage
        const courseId = localStorage.getItem('selectedCourseId');
        if (!courseId) {
            console.log('No course selected yet, skipping unit check');
            window.isCheckingPublishedUnits = false; // Reset flag on early return
            return;
        }
        console.log('Checking course:', courseId);

        // Fetch course data to check which units are published
        console.log(`Making API request to: /api/courses/${courseId}`);
        const response = await fetch(`/api/courses/${courseId}`);
        console.log('API response status:', response.status);
        console.log('API response headers:', Object.fromEntries(response.headers.entries()));

        if (!response.ok) {
            const errorText = await response.text();
            console.error('API error response body:', errorText);

            // If course not found, clear localStorage and try to load available courses
            if (response.status === 404) {
                console.log('Course not found, clearing localStorage and loading available courses');
                localStorage.removeItem('selectedCourseId');
                window.isCheckingPublishedUnits = false; // Reset flag before returning
                await loadAvailableCourses();
                return;
            }

            window.isCheckingPublishedUnits = false; // Reset flag on error
            throw new Error(`Failed to fetch course data: ${response.status} - ${errorText}`);
        }

        const courseData = await response.json();
        console.log('=== COURSE DATA RECEIVED ===');
        console.log('Full course data:', courseData);
        console.log('Course data structure:', {
            success: courseData.success,
            hasData: !!courseData.data,
            dataKeys: courseData.data ? Object.keys(courseData.data) : 'no data',
            hasLectures: courseData.data && !!courseData.data.lectures,
            lecturesType: courseData.data && courseData.data.lectures ? typeof courseData.data.lectures : 'no lectures',
            lecturesLength: courseData.data && courseData.data.lectures ? courseData.data.lectures.length : 'no lectures'
        });

        if (!courseData.data || !courseData.data.lectures) {
            console.log('No course data or lectures found');
            console.log('Available data keys:', courseData.data ? Object.keys(courseData.data) : 'no data');
            showNoQuestionsMessage();
            window.isCheckingPublishedUnits = false; // Reset flag on early return
            return;
        }

        // Find published units
        const publishedUnits = courseData.data.lectures.filter(unit => unit.isPublished === true);
        console.log('=== PUBLISHED UNITS ANALYSIS ===');
        console.log('All lectures:', courseData.data.lectures);
        console.log('Published units found:', publishedUnits);
        console.log('Published units count:', publishedUnits.length);

        if (publishedUnits.length === 0) {
            console.log('No published units found');
            console.log('All units:', courseData.data.lectures.map(u => ({ name: u.name, isPublished: u.isPublished })));
            showNoQuestionsMessage();
            window.isCheckingPublishedUnits = false; // Reset flag on early return
            return;
        }

        // Show unit selection dropdown instead of automatically loading all questions
        console.log('Showing unit selection dropdown for published units...');
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
    console.log('Showing no questions message - no published units available');

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
    console.log('Most recently published unit:', mostRecentUnit);
    console.log('Sorted units order:', sortedUnits.map(u => u.name));

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
            option.value = unit.name;
            option.textContent = unit.name;
            updatedUnitSelect.appendChild(option);
        });

        // Check for saved chat data first - if it exists and is within 30 minutes, restore that unit instead
        const savedChatData = getCurrentChatData();
        let shouldRestoreSavedUnit = false;
        let savedUnitName = null;

        if (savedChatData && savedChatData.messages && savedChatData.messages.length > 0 && savedChatData.lastActivityTimestamp) {
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
                    console.log(`🔄 [AUTO-CONTINUE] Found saved chat for unit: ${savedUnitName}, will restore instead of auto-selecting`);
                } else {
                    console.log(`🔄 [AUTO-CONTINUE] Saved unit ${savedUnitName} is not published, will auto-select most recent`);
                }
            }
        }

        // Auto-select unit: prefer saved unit if it exists, otherwise use most recent
        if (shouldRestoreSavedUnit && savedUnitName) {
            updatedUnitSelect.value = savedUnitName;
            console.log(`🔄 [AUTO-CONTINUE] Restored saved unit: ${savedUnitName}`);

            // Persist selection for chat retrieval
            localStorage.setItem('selectedUnitName', savedUnitName);

            // Don't load questions immediately - let auto-continue handle the restoration
            // The auto-continue check will happen after auth is ready and will restore the chat
        } else if (mostRecentUnit) {
            updatedUnitSelect.value = mostRecentUnit.name;
            console.log(`Auto-selected most recent unit: ${mostRecentUnit.name}`);

            // Persist selection for chat retrieval
            localStorage.setItem('selectedUnitName', mostRecentUnit.name);

            // Trigger the load immediately (without waiting for user interaction)
            loadQuestionsForSelectedUnit(mostRecentUnit.name);
        }

        // Add event listener for manual unit selection changes
        updatedUnitSelect.addEventListener('change', async function() {
            const selectedUnit = this.value;
            if (selectedUnit) {
                console.log(`Unit manually selected: ${selectedUnit}`);
                // Persist selection for chat retrieval
                localStorage.setItem('selectedUnitName', selectedUnit);
                await loadQuestionsForSelectedUnit(selectedUnit);
            }
        });
    }

    // Show welcome message with unit selection instructions
    showUnitSelectionWelcomeMessage();

    // Hide chat input and mode toggle until assessment is completed
    const chatInputContainer = document.querySelector('.chat-input-container');
    if (chatInputContainer) {
        chatInputContainer.style.display = 'none';
    }
    const modeToggleContainer = document.querySelector('.mode-toggle-container');
    if (modeToggleContainer) {
        modeToggleContainer.style.display = 'none';
    }
}

/**
 * Show welcome message with unit selection instructions
 */
function showUnitSelectionWelcomeMessage() {
    console.log('Showing unit selection welcome message');

    // Add message to chat
    const welcomeMessage = document.createElement('div');
    welcomeMessage.classList.add('message', 'bot-message', 'unit-selection-welcome');

    const avatarDiv = document.createElement('div');
    avatarDiv.classList.add('message-avatar');
    avatarDiv.textContent = 'B';

    const contentDiv = document.createElement('div');
    contentDiv.classList.add('message-content');

    const messageText = document.createElement('p');
    messageText.innerHTML = `<strong>Welcome to BiocBot!</strong><br>
    I can see you have access to published units. Please select a unit from the dropdown above to start your assessment, or feel free to chat with me about any topics you'd like to discuss.`;

    contentDiv.appendChild(messageText);

    // Add timestamp
    const timestamp = document.createElement('span');
    timestamp.classList.add('timestamp');
    timestamp.textContent = 'Just now';
    contentDiv.appendChild(timestamp);

    welcomeMessage.appendChild(avatarDiv);
    welcomeMessage.appendChild(contentDiv);

    // Add to chat
    const chatMessages = document.getElementById('chat-messages');
    chatMessages.appendChild(welcomeMessage);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

/**
 * Load assessment questions for a selected unit
 * @param {string} unitName - Name of the selected unit
 */
async function loadQuestionsForSelectedUnit(unitName) {
    try {
        console.log(`=== LOADING QUESTIONS FOR UNIT: ${unitName} ===`);

        // Check if we should auto-continue instead of starting a new assessment
        // If there's saved chat data for this unit within 30 minutes, skip loading questions
        const savedChatData = getCurrentChatData();
        if (savedChatData && savedChatData.messages && savedChatData.messages.length > 0 && savedChatData.lastActivityTimestamp) {
            const lastActivity = new Date(savedChatData.lastActivityTimestamp);
            const now = new Date();
            const diffMs = now - lastActivity;
            const diffMinutes = Math.floor(diffMs / (1000 * 60));

            if (diffMinutes <= 30 && savedChatData.metadata && savedChatData.metadata.unitName === unitName) {
                console.log(`🔄 [AUTO-CONTINUE] Found saved chat for unit ${unitName}, skipping question load - auto-continue will restore chat`);
                // Don't load questions - let auto-continue handle restoration
                return;
            }
        }

        // Hide chat input and mode toggle when starting new assessment
        const chatInputContainer = document.querySelector('.chat-input-container');
        if (chatInputContainer) {
            chatInputContainer.style.display = 'none';
        }
        const modeToggleContainer = document.querySelector('.mode-toggle-container');
        if (modeToggleContainer) {
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

        console.log(`Selected unit data:`, selectedUnit);
        console.log(`Unit pass threshold:`, selectedUnit.passThreshold);

        // Collect questions for this specific unit
        const unitQuestions = [];

        // Check if the unit has assessment questions directly embedded
        if (selectedUnit.assessmentQuestions && selectedUnit.assessmentQuestions.length > 0) {
            console.log(`Found ${selectedUnit.assessmentQuestions.length} embedded questions in ${unitName}`);

            // Transform embedded questions to match our format
            const transformedQuestions = selectedUnit.assessmentQuestions.map(q => {
                // Clean the options format - remove "A,", "B,", "C," prefixes if present
                let cleanOptions = q.options || {};
                if (q.options && typeof q.options === 'object') {
                    cleanOptions = {};
                    console.log(`Raw embedded options before cleaning:`, q.options);
                    Object.keys(q.options).forEach(key => {
                        let optionValue = q.options[key];
                        console.log(`Processing embedded option key "${key}" with value "${optionValue}"`);
                        if (typeof optionValue === 'string') {
                            // Remove prefix like "A,", "B,", "C," - look for pattern of letter followed by comma
                            if (/^[A-Z],/.test(optionValue)) {
                                const originalValue = optionValue;
                                optionValue = optionValue.substring(2); // Remove "A,", "B,", etc.
                                console.log(`Cleaned embedded option from "${originalValue}" to "${optionValue}"`);
                            } else {
                                console.log(`Embedded option "${optionValue}" doesn't match pattern, keeping as is`);
                            }
                        }
                        cleanOptions[key] = optionValue;
                    });
                    console.log(`Final cleaned embedded options:`, cleanOptions);
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
            console.log(`Added ${transformedQuestions.length} embedded questions from ${unitName}`);
        } else {
            console.log(`No embedded questions found for ${unitName}, trying API endpoint...`);

            try {
                // Try to fetch questions from API endpoint
                const questionsResponse = await fetch(`/api/questions/lecture?courseId=${courseId}&lectureName=${unitName}`);
                console.log(`API response for ${unitName}:`, questionsResponse.status, questionsResponse.statusText);

                if (questionsResponse.ok) {
                    const questionsData = await questionsResponse.json();
                    console.log(`API questions for ${unitName}:`, questionsData);

                    if (questionsData.data && questionsData.data.questions && questionsData.data.questions.length > 0) {
                        // Transform API questions to match our format
                        const transformedQuestions = questionsData.data.questions.map(q => {
                            console.log(`Raw question from API:`, q);

                            // Fix the correct answer format - remove "A" prefix if present
                            let cleanCorrectAnswer = q.correctAnswer;
                            if (typeof cleanCorrectAnswer === 'string' && cleanCorrectAnswer.startsWith('A')) {
                                cleanCorrectAnswer = cleanCorrectAnswer.substring(1);
                                console.log(`Cleaned correct answer from "${q.correctAnswer}" to "${cleanCorrectAnswer}"`);
                            }

                            // Fix the options format - remove "A,", "B,", "C," prefixes if present
                            let cleanOptions = q.options;
                            if (q.options && typeof q.options === 'object') {
                                cleanOptions = {};
                                console.log(`Raw options before cleaning:`, q.options);
                                Object.keys(q.options).forEach(key => {
                                    let optionValue = q.options[key];
                                    console.log(`Processing option key "${key}" with value "${optionValue}"`);
                                    if (typeof optionValue === 'string') {
                                        // Remove prefix like "A,", "B,", "C," - look for pattern of letter followed by comma
                                        if (/^[A-Z],/.test(optionValue)) {
                                            const originalValue = optionValue;
                                            optionValue = optionValue.substring(2); // Remove "A,", "B,", etc.
                                            console.log(`Cleaned option from "${originalValue}" to "${optionValue}"`);
                                        } else {
                                            console.log(`Option "${optionValue}" doesn't match pattern, keeping as is`);
                                        }
                                    }
                                    cleanOptions[key] = optionValue;
                                });
                                console.log(`Final cleaned options:`, cleanOptions);
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
                        console.log(`Added ${transformedQuestions.length} API questions from ${unitName}`);
                    } else {
                        console.log(`No API questions found for ${unitName}`);
                    }
                } else {
                    const errorText = await questionsResponse.text();
                    console.warn(`Failed to fetch API questions for ${unitName}:`, questionsResponse.status, errorText);
                }
            } catch (error) {
                console.error(`Error loading API questions for ${unitName}:`, error);
            }
        }

        console.log(`Total questions loaded for ${unitName}:`, unitQuestions.length);

        if (unitQuestions.length === 0) {
            console.log(`No assessment questions found for ${unitName}`);
            showNoQuestionsForUnitMessage(unitName);
            return;
        }

        // Start the assessment process with questions from the selected unit
        // Use the pass threshold from the unit, or default to 0 if not set
        // Note: Check for null/undefined separately since 0 is a valid threshold value
        const unitPassThreshold = (selectedUnit.passThreshold !== undefined && selectedUnit.passThreshold !== null)
            ? selectedUnit.passThreshold
            : 0;
        console.log(`Using pass threshold for ${unitName}: ${unitPassThreshold} (from unit data: ${selectedUnit.passThreshold})`);
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
    console.log(`Showing no questions message for unit: ${unitName}`);

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

    // Reset unit selection to allow choosing another unit
    const unitSelect = document.getElementById('unit-select');
    if (unitSelect) {
        unitSelect.value = '';
    }
}

/**
 * Start assessment with loaded questions
 */
function startAssessmentWithQuestions(questions, passThreshold = 0) {
    console.log('=== STARTING ASSESSMENT ===');
    console.log(`Original pass threshold: ${passThreshold}`);
    console.log(`Number of questions: ${questions.length}`);

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

    console.log(`Adjusted pass threshold: ${currentPassThreshold} (min of ${passThreshold} and ${questions.length})`);

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
            console.log('🔄 [AUTO-SAVE] Starting assessment - clearing auto-save data for new session');
            clearCurrentChatData();
        }
    } else {
        console.log('🔄 [AUTO-SAVE] Chat was auto-continued, preserving chat data');
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

            console.log(`Displaying question options:`, question.options);
            console.log(`Option entries for display:`, optionEntries);

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

                console.log(`Final option text for button ${index}: "${optionText}"`);

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
function selectCalibrationAnswer(answerIndex, questionIndex) {
    // Store the answer
    studentAnswers[questionIndex] = answerIndex;
    window.studentAnswers = studentAnswers; // Update global reference

    // Update auto-save with assessment data
    const studentId = getCurrentStudentId();
    const autoSaveKey = `biocbot_current_chat_${studentId}`;
    const currentChatData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');
    if (currentChatData.messages) {
        updateAssessmentDataInAutoSave(currentChatData);
        localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));
        console.log('🔄 [AUTO-SAVE] Updated assessment data after answer submission');
    }

    // Disable all options to prevent changing answers
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

    // Automatically proceed to next question after a short delay
    setTimeout(() => {
        currentQuestionIndex++;

        // Show next question or finish
        if (currentQuestionIndex < currentCalibrationQuestions.length) {
            showCalibrationQuestion();
        } else {
            calculateStudentMode();
        }
    }, 1000); // 1 second delay to show the selected answer
}

/**
 * Handle short answer submission
 * @param {string} answer - Student's short answer
 * @param {number} questionIndex - The question index this answer belongs to
 */
function submitShortAnswer(answer, questionIndex) {
    if (!answer.trim()) {
        alert('Please enter an answer before submitting.');
        return;
    }

    // Store the answer
    studentAnswers[questionIndex] = answer;
    window.studentAnswers = studentAnswers; // Update global reference

    // Update auto-save with assessment data
    const studentId = getCurrentStudentId();
    const autoSaveKey = `biocbot_current_chat_${studentId}`;
    const currentChatData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');
    if (currentChatData.messages) {
        updateAssessmentDataInAutoSave(currentChatData);
        localStorage.setItem(autoSaveKey, JSON.stringify(currentChatData));
        console.log('🔄 [AUTO-SAVE] Updated assessment data after text answer submission');
    }

    // Disable the input and submit button to show it's been answered
    const questionMessage = document.getElementById(`calibration-question-${questionIndex}`);
    if (questionMessage) {
        const answerInput = questionMessage.querySelector('.calibration-answer-input');
        const submitButton = questionMessage.querySelector('.calibration-submit-btn');

        if (answerInput) {
            answerInput.disabled = true;
            answerInput.style.backgroundColor = '#f8f9fa';
            answerInput.style.borderColor = 'var(--primary-color)';
        }

        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = 'Answer Submitted';
            submitButton.style.backgroundColor = 'var(--primary-color)';
            submitButton.style.opacity = '0.7';
        }
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
    }, 1000); // 1 second delay to show the submitted answer
}

/**
 * Calculate student mode based on answers to real assessment questions
 */
async function calculateStudentMode() {
    try {
        console.log('=== CALCULATING STUDENT MODE ===');
        console.log('Student answers:', studentAnswers);
        console.log('Questions:', currentCalibrationQuestions);

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

            console.log(`Question ${i + 1}:`, question.question);
            console.log(`Student answer index:`, studentAnswerIndex);
            console.log(`Student answer text:`, studentAnswerText);
            console.log(`Correct answer:`, question.correctAnswer);

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

                console.log(`True/False check: student answered ${studentAnswerText}, expected ${expectedAnswer}, correct: ${isCorrect}`);

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
                console.log(`Multiple choice check: student answered index ${studentAnswerIndex}, expected index ${expectedIndex}, correct: ${isCorrect}`);
            } else if (question.type === 'short-answer') {
                // For short answer, consider it correct if they provided any meaningful answer
                isCorrect = (studentAnswerIndex && studentAnswerIndex.trim().length > 10);
            } else {
                // For unknown types, default to checking if answer matches
                isCorrect = (studentAnswerIndex === question.correctAnswer);
            }

            if (isCorrect) {
                totalCorrect++;
                console.log(`Question ${i + 1} is CORRECT`);
            } else {
                console.log(`Question ${i + 1} is INCORRECT`);
            }
        }

        console.log(`Total correct: ${totalCorrect}/${totalQuestions}`);
        console.log(`Pass threshold: ${currentPassThreshold}`);

        // Calculate percentage
        const percentage = (totalCorrect / totalQuestions) * 100;
        console.log(`Percentage: ${percentage}%`);

        // Determine mode based on performance using the instructor's pass threshold
        // If they get the required number of questions correct, they're in protégé mode
        // Otherwise, they're in tutor mode (need more guidance)
        const passed = totalCorrect >= currentPassThreshold;
        const mode = passed ? 'protege' : 'tutor';

        console.log(`Student passed: ${passed} (needed ${currentPassThreshold}, got ${totalCorrect})`);

        const score = {
            totalCorrect: totalCorrect,
            totalQuestions: totalQuestions,
            percentage: percentage,
            passThreshold: currentPassThreshold,
            passed: passed,
            mode: mode
        };

        console.log(`Determined mode: ${mode}`);

        // Store mode in localStorage
        localStorage.setItem('studentMode', mode);

        // Update mode toggle UI to reflect the determined mode
        updateModeToggleUI(mode);

        // Show mode result message
        showModeResult(mode, score);

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
 * Initialize mode toggle functionality
 */
function initializeModeToggle() {
    const modeToggleCheckbox = document.getElementById('mode-toggle-checkbox');
    const protegeLabel = document.querySelector('.protege-label');
    const tutorLabel = document.querySelector('.tutor-label');

    if (!modeToggleCheckbox) return;

    // Set initial mode from localStorage or default to tutor
    const currentMode = localStorage.getItem('studentMode') || 'tutor';
    console.log('🔧 [MODE_INIT] Initializing mode toggle with mode:', currentMode);
    updateModeToggleUI(currentMode);

    // Add event listener for mode toggle
    modeToggleCheckbox.addEventListener('change', function() {
        console.log('Mode toggle changed!');
        const newMode = this.checked ? 'tutor' : 'protege';
        console.log(`New mode: ${newMode}`);

        // Update localStorage
        localStorage.setItem('studentMode', newMode);

        // Record the timestamp of this manual mode change
        localStorage.setItem('lastModeChange', Date.now().toString());
        console.log('🔧 [MODE_TOGGLE] Recorded manual mode change timestamp');

        // Update UI
        updateModeToggleUI(newMode);

        // Show mode confirmation popup
        console.log('Calling showModeToggleResult...');
        showModeToggleResult(newMode);

        console.log(`Mode switched to: ${newMode}`);
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
            startTime: getSessionStartTime(),
            endTime: new Date().toISOString(),
            duration: calculateSessionDuration(chatData)
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
            isAssessmentStart: isAssessmentStart
        };

        // Extract additional data for specific message types
        if (isCalibrationQuestion) {
            messageData.questionData = extractQuestionData(messageElement);
        }

        if (isModeResult) {
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

        return {
            questionText: questionText,
            options: options,
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
 * @returns {string} Session start time ISO string
 */
function getSessionStartTime() {
    // Try to get the timestamp from the current chat data
    if (currentChatData && currentChatData.messages && currentChatData.messages.length > 0) {
        // Find the first user message (student message)
        const firstUserMessage = currentChatData.messages.find(msg => msg.type === 'user');
        if (firstUserMessage && firstUserMessage.timestamp) {
            return firstUserMessage.timestamp;
        }

        // If no user message found, use the first message
        const firstMessage = currentChatData.messages[0];
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
    console.log('Chat history storage system initialized');
}

/**
 * Initialize user agreement modal
 * This will show the agreement modal for first-time users
 */
function initializeUserAgreement() {
    // The agreement modal is automatically initialized by the agreement-modal.js script
    // This function is here for consistency with other initialize functions
    console.log('User agreement system initialized');

    // Listen for agreement acceptance event
    document.addEventListener('userAgreementAccepted', (event) => {
        console.log('User agreement accepted:', event.detail);
        // You can add any additional logic here after agreement is accepted
    });
}

/**
 * Save chat data to history storage
 * @param {Object} chatData - The chat data to save
 */
function saveChatToHistory(chatData) {
    try {
        console.log('=== SAVING CHAT TO HISTORY ===');
        console.log('Chat data being saved:', {
            messageCount: chatData.messages.length,
            courseId: chatData.metadata.courseId,
            studentId: chatData.metadata.studentId,
            unitName: chatData.metadata.unitName,
            firstMessage: chatData.messages[0]?.content?.substring(0, 50) + '...',
            lastMessage: chatData.messages[chatData.messages.length - 1]?.content?.substring(0, 50) + '...'
        });

        // Use student-specific localStorage key for security
        const studentId = chatData.metadata.studentId;
        const historyKey = `biocbot_chat_history_${studentId}`;
        let history = JSON.parse(localStorage.getItem(historyKey) || '[]');
        console.log('Current history length:', history.length);

        // Create a unique ID for this chat session
        const chatId = `chat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        console.log('Generated chat ID:', chatId);

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

        console.log('Created history entry:', historyEntry);

        // Add to beginning of history (most recent first)
        history.unshift(historyEntry);
        console.log('History after adding entry, length:', history.length);

        // Keep only last 50 chat sessions to prevent storage bloat
        if (history.length > 50) {
            history = history.slice(0, 50);
            console.log('Trimmed history to 50 entries');
        }

        // Save back to localStorage
        localStorage.setItem(historyKey, JSON.stringify(history));
        console.log('Saved to localStorage, key:', historyKey);

        // Verify it was saved
        const savedData = localStorage.getItem(historyKey);
        console.log('Verification - saved data length:', savedData ? savedData.length : 'null');

        console.log('Chat saved to history successfully:', historyEntry.title);

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
        console.log('=== SAVING CHAT TO SERVER ===');

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

        console.log('Sending chat data to server:', {
            sessionId: serverData.sessionId,
            courseId: serverData.courseId,
            studentId: serverData.studentId,
            messageCount: serverData.messageCount
        });

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
        console.log('Chat saved to server successfully:', result);

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
        const history = getChatHistory();
        const filteredHistory = history.filter(chat => chat.id !== chatId);
        localStorage.setItem('biocbot_chat_history', JSON.stringify(filteredHistory));
        return true;
    } catch (error) {
        console.error('Error deleting chat from history:', error);
        return false;
    }
}

/**
 * Load chat data into the current chat interface
 * @param {Object} chatData - The chat data to load
 */
function loadChatData(chatData) {
    try {
        console.log('=== LOADING CHAT DATA ===');
        console.log('Chat data to load:', chatData);

        // Clear existing messages
        const chatMessages = document.getElementById('chat-messages');
        if (!chatMessages) {
            console.error('Chat messages container not found');
            return;
        }

        // Clear ALL existing messages
        chatMessages.innerHTML = '';

        // Don't clear auto-save data when loading from history - we want to preserve it
        console.log('🔄 [AUTO-SAVE] Loading chat history - preserving auto-save data');

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
                console.log(`Loading message ${index}:`, messageData);

                if (messageData.type === 'user') {
                    addMessage(messageData.content, 'user', false, true); // Skip auto-save
                } else if (messageData.type === 'bot') {
                    // Check if this is a special message type that needs special handling
                    if (messageData.messageType === 'assessment-start') {
                        // This is the assessment start message - add it as a regular bot message
                        addMessage(messageData.content, 'bot', messageData.hasFlagButton, true, messageData.sourceAttribution); // Skip auto-save
                    } else if (messageData.messageType === 'practice-test-question') {
                        // This is a practice test question - add it as a regular bot message
                        addMessage(messageData.content, 'bot', messageData.hasFlagButton, true, messageData.sourceAttribution); // Skip auto-save
                    } else if (messageData.messageType === 'mode-result') {
                        // This is a mode result message - add it as a regular bot message
                        addMessage(messageData.content, 'bot', messageData.hasFlagButton, true, messageData.sourceAttribution); // Skip auto-save
                    } else {
                        // Regular bot message
                        addMessage(messageData.content, 'bot', messageData.hasFlagButton, true, messageData.sourceAttribution); // Skip auto-save
                    }
                }
            });

            // Restore practice test data if present
            if (chatData.practiceTests && chatData.practiceTests.questions.length > 0) {
                console.log('Restoring practice test data:', chatData.practiceTests);
                currentCalibrationQuestions = chatData.practiceTests.questions;
                currentPassThreshold = chatData.practiceTests.passThreshold;
                window.currentPassThreshold = currentPassThreshold; // Update global reference
                currentQuestionIndex = chatData.practiceTests.currentQuestionIndex;
                studentAnswers = chatData.studentAnswers.answers.map(answer => answer.answer);
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
                console.log('🔄 [HISTORY] User recently changed mode, keeping current mode:', currentStoredMode);
                updateModeToggleUI(currentStoredMode);
            } else if (chatDataMode) {
                // No recent mode change, restore from chat data
                console.log('🔄 [HISTORY] Restoring mode from chat data:', chatDataMode);
                localStorage.setItem('studentMode', chatDataMode);
                updateModeToggleUI(chatDataMode);
                console.log('🔄 [HISTORY] Mode restored and UI updated');
            } else {
                console.log('🔄 [HISTORY] No mode found in chat data, using current localStorage value');
                updateModeToggleUI(currentStoredMode);
            }

            // Restore unit selection if present
            if (chatData.metadata.unitName) {
                console.log('Restoring unit:', chatData.metadata.unitName);
                localStorage.setItem('selectedUnitName', chatData.metadata.unitName);

                // Update unit selection dropdown if it exists
                const unitSelect = document.getElementById('unit-select');
                if (unitSelect) {
                    unitSelect.value = chatData.metadata.unitName;
                }
            }

            // Ensure chat input and mode toggle are visible (enable chat)
            enableChatInput();

            // Show success message (skip auto-save for system messages)
            addMessage('✅ Chat history loaded successfully! You can continue where you left off.', 'bot', false, true, null);

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
                console.log('🔄 [SESSION] Updated session ID to match loaded chat:', chatData.sessionInfo.sessionId);
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

                console.log('🔄 [SESSION] Generated new session ID for loaded chat:', newSessionId);
            }

            // Replace the current auto-save data with the loaded chat data
            const studentId = chatData.metadata.studentId;
            const autoSaveKey = `biocbot_current_chat_${studentId}`;
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));
            console.log('🔄 [HISTORY] Replaced current auto-save data with loaded chat data');

            console.log('Chat data loaded successfully');

        }, 500); // Small delay to show loading message

    } catch (error) {
        console.error('Error loading chat data:', error);
        addMessage('❌ Error loading chat history. Please try again.', 'bot', false, true, null);
    }
}

/**
 * Format date for display in history
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date
 */
function formatHistoryDate(dateString) {
    try {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

        if (diffDays === 0) {
            return 'Today, ' + date.toLocaleTimeString('en-US', {
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
        } else if (diffDays === 1) {
            return 'Yesterday, ' + date.toLocaleTimeString('en-US', {
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
        } else if (diffDays < 7) {
            return date.toLocaleDateString('en-US', {
                weekday: 'short',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
        } else {
            return date.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });
        }
    } catch (error) {
        console.error('Error formatting date:', error);
        return 'Unknown date';
    }
}

/**
 * Check for chat data to load from history
 */
function checkForChatDataToLoad() {
    try {
        console.log('=== CHECKING FOR CHAT DATA TO LOAD ===');
        const storedChatData = sessionStorage.getItem('loadChatData');
        console.log('Stored chat data:', storedChatData);

        if (storedChatData) {
            const chatData = JSON.parse(storedChatData);
            console.log('Parsed chat data:', chatData);
            console.log('Chat data messages count:', chatData.messages ? chatData.messages.length : 'No messages');

            // Set flag to indicate we're loading from history
            window.loadingFromHistory = true;
            console.log('🔄 [HISTORY] Set loadingFromHistory flag to true');

            // Clear the stored data
            sessionStorage.removeItem('loadChatData');
            console.log('Cleared loadChatData from sessionStorage');

            // Load the chat data
            console.log('Calling loadChatData...');
            loadChatData(chatData);
        } else {
            console.log('No chat data found in sessionStorage');
        }
    } catch (error) {
        console.error('Error checking for chat data to load:', error);
    }
}

/**
 * Test function to add sample chat data to history
 * This can be called from the browser console for testing
 */
function addSampleChatData() {
    const sampleChatData = {
        metadata: {
            exportDate: new Date().toISOString(),
            courseId: 'BIOC202-test',
            courseName: 'BIOC 202',
            studentId: 'test-student-123',
            studentName: 'Test Student',
            unitName: 'Unit 1',
            currentMode: 'tutor',
            totalMessages: 4,
            version: '1.0'
        },
        messages: [
            {
                index: 0,
                type: 'bot',
                timestamp: new Date(Date.now() - 3600000).toISOString(),
                displayTimestamp: '1 hour ago',
                content: 'Hello! I\'m BiocBot, your AI study assistant for BIOC 202. How can I help you today?',
                messageType: 'regular-chat',
                isCalibrationQuestion: false,
                isModeResult: false,
                isAssessmentStart: false,
                hasFlagButton: true
            },
            {
                index: 1,
                type: 'user',
                timestamp: new Date(Date.now() - 3500000).toISOString(),
                displayTimestamp: '1 hour ago',
                content: 'Can you explain protein folding and what determines the final 3D structure?',
                messageType: 'regular-chat',
                isCalibrationQuestion: false,
                isModeResult: false,
                isAssessmentStart: false
            },
            {
                index: 2,
                type: 'bot',
                timestamp: new Date(Date.now() - 3400000).toISOString(),
                displayTimestamp: '1 hour ago',
                content: 'Protein folding is determined by several factors:\n\n1. **Primary structure:** The sequence of amino acids forms the backbone.\n2. **Hydrogen bonding:** Creates secondary structures like alpha helices and beta sheets.\n3. **Hydrophobic interactions:** Non-polar amino acids cluster in the center, away from water.\n4. **Ionic interactions:** Charged amino acids form salt bridges.\n5. **Disulfide bridges:** Covalent bonds between cysteine residues stabilize the structure.\n\nThe final 3D structure represents the most energetically favorable conformation.',
                messageType: 'regular-chat',
                isCalibrationQuestion: false,
                isModeResult: false,
                isAssessmentStart: false,
                hasFlagButton: true
            },
            {
                index: 3,
                type: 'user',
                timestamp: new Date(Date.now() - 3300000).toISOString(),
                displayTimestamp: '1 hour ago',
                content: 'What happens if there\'s a mutation in the amino acid sequence?',
                messageType: 'regular-chat',
                isCalibrationQuestion: false,
                isModeResult: false,
                isAssessmentStart: false
            }
        ],
        practiceTests: {
            questions: [],
            totalQuestions: 0,
            passThreshold: 2,
            currentQuestionIndex: 0
        },
        studentAnswers: {
            answers: [],
            totalAnswers: 0,
            answersProvided: 0
        },
        sessionInfo: {
            startTime: new Date(Date.now() - 3600000).toISOString(),
            endTime: new Date().toISOString(),
            duration: '1h 0m 0s'
        }
    };

    saveChatToHistory(sampleChatData);
    console.log('Sample chat data added to history!');
}
