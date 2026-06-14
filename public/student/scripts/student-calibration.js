/**
 * Student chat: published-unit calibration questions, assessment flow, and
 * study-mode calculation/toggle.
 */

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
 * Show message when no questions are available
 * Disables chat input and prevents chat functionality when no units are published
 */
function showNoQuestionsMessage() {


    // Set a global flag to prevent chat functionality
    window.noPublishedUnits = true;

    // Default mode to tutor only when the student has never explicitly toggled
    // (lastModeChange is only set by the mode-toggle handler). Otherwise we
    // overwrite the user's deliberate selection every time this branch runs.
    if (!localStorage.getItem('lastModeChange')) {
        localStorage.setItem('studentMode', 'tutor');
        updateModeToggleUI('tutor');
    } else {
        updateModeToggleUI(localStorage.getItem('studentMode') || 'tutor');
    }

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


    // Default mode to tutor only if the student hasn't explicitly toggled.
    if (!localStorage.getItem('lastModeChange')) {
        localStorage.setItem('studentMode', 'tutor');
        updateModeToggleUI('tutor');
    } else {
        updateModeToggleUI(localStorage.getItem('studentMode') || 'tutor');
    }

    // Enable chat since questions are available for this unit
    enableChatInput();

    // Clear existing chat messages so old assessment questions don't persist
    const chatMessages = document.getElementById('chat-messages');
    if (chatMessages) {
        chatMessages.innerHTML = '';
    }
    clearCurrentChatData();

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

    // Clear chat when starting a new assessment (not auto-continued)
    if (!window.autoContinued) {
        chatMessages.innerHTML = '';
        clearCurrentChatData();
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

        // Short-answer evaluation is billed to the course's OpenAI key, so the
        // request must carry the courseId for the per-course key to resolve.
        const courseId = localStorage.getItem('selectedCourseId');

        const response = await fetch('/api/questions/check-answer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                courseId,
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
