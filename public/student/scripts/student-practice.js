/**
 * Student chat: practice questions and struggle-reset questions.
 */

/**
 * Handle "Ask me a question" button click
 * Generates a practice question from the unit's assessment questions
 * @param {string} topic - The detected topic
 */
async function handlePracticeQuestion(topic) {
    // Prevent multiple simultaneous requests
    const existingTyping = document.getElementById('typing-indicator');
    if (existingTyping) return;

    const courseId = localStorage.getItem('selectedCourseId');
    const unitName = localStorage.getItem('selectedUnitName') || getCurrentUnitName();

    if (!courseId || !unitName) {
        addMessage('Please select a course and unit first.', 'bot', false, true, null);
        return;
    }

    showTypingIndicator();

    try {
        const response = await fetch('/api/chat/practice-question', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ courseId, unitName, topic })
        });

        removeTypingIndicator();
        const result = await response.json();

        if (!result.success) {
            addMessage(result.message || 'Failed to generate a practice question.', 'bot', false, true, null);
            return;
        }

        if (result.noQuestions) {
            addMessage(result.message, 'bot', false, true, null);
            return;
        }

        // Render the practice question in chat
        renderPracticeQuestion(result.data);

    } catch (error) {
        removeTypingIndicator();
        console.error('Practice question error:', error);
        addMessage('Sorry, I encountered an error generating a practice question. Please try again.', 'bot', false, true, null);
    }
}

/**
 * Render a practice question as a bot message in the chat
 * @param {Object} questionData - { practiceId, questionType, question, options }
 */
function renderPracticeQuestion(questionData) {
    const { practiceId, questionType, question, options } = questionData;

    // Build question HTML
    let html = `<div class="practice-question-container" data-practice-id="${practiceId}" data-question-type="${questionType}">`;
    html += `<div class="practice-question-header">Practice Question</div>`;
    html += `<div class="practice-question-text">${question}</div>`;

    if (questionType === 'multiple-choice' && options) {
        html += `<div class="practice-options">`;
        for (const [key, value] of Object.entries(options)) {
            html += `<label class="practice-option-label" data-value="${key}">
                <input type="radio" name="practice-${practiceId}" value="${key}">
                <span class="practice-option-text"><strong>${key}.</strong> ${value}</span>
            </label>`;
        }
        html += `</div>`;
    } else if (questionType === 'true-false') {
        html += `<div class="practice-options">`;
        html += `<label class="practice-option-label" data-value="True">
            <input type="radio" name="practice-${practiceId}" value="True">
            <span class="practice-option-text"><strong>True</strong></span>
        </label>`;
        html += `<label class="practice-option-label" data-value="False">
            <input type="radio" name="practice-${practiceId}" value="False">
            <span class="practice-option-text"><strong>False</strong></span>
        </label>`;
        html += `</div>`;
    } else if (questionType === 'short-answer') {
        html += `<div class="practice-sa-container">
            <textarea class="practice-sa-input" rows="3" placeholder="Type your answer here..."></textarea>
        </div>`;
    }

    html += `<button class="practice-submit-btn" onclick="submitPracticeAnswer('${practiceId}')">Submit Answer</button>`;
    html += `<div class="practice-feedback" style="display:none;"></div>`;
    html += `</div>`;

    // Add as a bot message (isHtml = true)
    addMessage(html, 'bot', false, false, null, true);
}

/**
 * Submit a practice question answer for evaluation
 * @param {string} practiceId - The practice question ID
 */
async function submitPracticeAnswer(practiceId) {
    const container = document.querySelector(`.practice-question-container[data-practice-id="${practiceId}"]`);
    if (!container) return;

    const questionType = container.dataset.questionType;
    const submitBtn = container.querySelector('.practice-submit-btn');
    const feedbackDiv = container.querySelector('.practice-feedback');
    let studentAnswer = '';

    if (questionType === 'multiple-choice' || questionType === 'true-false') {
        const selected = container.querySelector(`input[name="practice-${practiceId}"]:checked`);
        if (!selected) {
            feedbackDiv.style.display = 'block';
            feedbackDiv.className = 'practice-feedback practice-feedback-error';
            feedbackDiv.textContent = 'Please select an answer.';
            return;
        }
        studentAnswer = selected.value;
    } else if (questionType === 'short-answer') {
        const textarea = container.querySelector('.practice-sa-input');
        studentAnswer = textarea ? textarea.value.trim() : '';
        if (!studentAnswer) {
            feedbackDiv.style.display = 'block';
            feedbackDiv.className = 'practice-feedback practice-feedback-error';
            feedbackDiv.textContent = 'Please type your answer.';
            return;
        }
    }

    // Disable submit button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Checking...';

    try {
        const currentUserObj = (typeof getCurrentUser === 'function') ? getCurrentUser() : window.currentUser;
        const displayName = (currentUserObj && (currentUserObj.displayName || currentUserObj.name || currentUserObj.username)) || 'Student';
        const response = await fetch('/api/chat/check-practice-answer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                practiceId,
                studentAnswer,
                studentName: displayName
            })
        });

        const result = await response.json();

        if (!result.success) {
            feedbackDiv.style.display = 'block';
            feedbackDiv.className = 'practice-feedback practice-feedback-error';
            feedbackDiv.textContent = result.message || 'Error checking answer.';
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit Answer';
            return;
        }

        const { correct, feedback, correctAnswer } = result.data;

        // Build static completed HTML that persists through save/reload
        const questionText = container.querySelector('.practice-question-text').textContent;
        let completedHtml = `<div class="practice-question-container practice-completed">`;
        completedHtml += `<div class="practice-question-header">Practice Question</div>`;
        completedHtml += `<div class="practice-question-text">${questionText}</div>`;

        // Show options with correct/incorrect highlighting (static)
        if (questionType === 'multiple-choice' || questionType === 'true-false') {
            completedHtml += `<div class="practice-options">`;
            const labels = container.querySelectorAll('.practice-option-label');
            labels.forEach(label => {
                const radio = label.querySelector('input[type="radio"]');
                const optionText = label.querySelector('.practice-option-text').innerHTML;
                const value = radio.value;
                const wasSelected = radio.checked;
                const isCorrectAnswer = correctAnswer !== null && correctAnswer !== undefined
                    && String(value).toLowerCase() === String(correctAnswer).trim().toLowerCase();

                let extraClass = 'practice-option-disabled';
                if (isCorrectAnswer && wasSelected) extraClass += ' practice-option-correct';
                else if (isCorrectAnswer) extraClass += ' practice-option-was-correct';
                else if (wasSelected) extraClass += ' practice-option-incorrect';

                const checkMark = wasSelected ? '●' : '○';
                completedHtml += `<div class="practice-option-label ${extraClass}">
                    <span style="flex-shrink:0;width:16px;text-align:center;font-size:12px;">${checkMark}</span>
                    <span class="practice-option-text">${optionText}</span>
                </div>`;
            });
            completedHtml += `</div>`;
        } else if (questionType === 'short-answer') {
            const saText = container.querySelector('.practice-sa-input').value;
            completedHtml += `<div class="practice-sa-container">
                <div class="practice-sa-input" style="background:#f5f5f5;padding:10px 12px;border:2px solid #e0e0e0;border-radius:8px;font-size:13px;white-space:pre-wrap;">${saText}</div>
            </div>`;
        }

        // Feedback
        const feedbackClass = correct ? 'practice-feedback-correct' : 'practice-feedback-incorrect';
        completedHtml += `<div class="practice-feedback ${feedbackClass}" style="display:block;">${feedback}</div>`;
        completedHtml += `</div>`;

        // Replace the entire container with static version
        container.outerHTML = completedHtml;

        // Update auto-save so the completed state persists through reload
        updatePracticeQuestionInAutoSave(practiceId, completedHtml);

    } catch (error) {
        console.error('Practice answer check error:', error);
        feedbackDiv.style.display = 'block';
        feedbackDiv.className = 'practice-feedback practice-feedback-error';
        feedbackDiv.textContent = 'Error connecting to server. Please try again.';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Answer';
    }
}

/**
 * Update auto-save data after a practice question is answered,
 * so the completed state persists through page reload.
 * @param {string} practiceId - The practice question ID
 * @param {string} completedHtml - The static completed HTML
 */
function updatePracticeQuestionInAutoSave(practiceId, completedHtml) {
    try {
        const studentId = getCurrentStudentId();
        if (!studentId) return;

        const autoSaveKey = `biocbot_current_chat_${studentId}`;
        const chatData = JSON.parse(localStorage.getItem(autoSaveKey) || '{}');

        if (!chatData.messages) return;

        // Find the message that contains this practice question's practiceId
        for (let i = 0; i < chatData.messages.length; i++) {
            const msg = chatData.messages[i];
            if (msg.isHtml && msg.content && msg.content.includes(practiceId)) {
                // Replace the content with the completed static HTML
                chatData.messages[i].content = completedHtml;
                break;
            }
        }

        chatData.lastActivityTimestamp = new Date().toISOString();
        localStorage.setItem(autoSaveKey, JSON.stringify(chatData));
        scheduleChatSessionExpiration(chatData);
    } catch (error) {
        console.error('Error updating practice question in auto-save:', error);
    }
}

/**
 * Handle "I understand X now" click — generates a practice question as a gate.
 * If the student answers correctly, their struggle state is reset.
 * If incorrect, they stay in directive mode with encouragement.
 * @param {string} topic - The struggle topic to potentially reset
 */
async function handleStruggleResetQuestion(topic) {
    // Prevent multiple simultaneous requests
    const existingTyping = document.getElementById('typing-indicator');
    if (existingTyping) return;

    const courseId = localStorage.getItem('selectedCourseId');
    const unitName = localStorage.getItem('selectedUnitName') || getCurrentUnitName();

    if (!courseId || !unitName) {
        addMessage('Please select a course and unit first.', 'bot', false, true, null);
        return;
    }

    showTypingIndicator();

    try {
        const response = await fetch('/api/chat/practice-question', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ courseId, unitName, topic })
        });

        removeTypingIndicator();
        const result = await response.json();

        if (!result.success) {
            addMessage(result.message || 'Failed to generate a question.', 'bot', false, true, null);
            return;
        }

        if (result.noQuestions) {
            // No questions available — fall back to instant reset
            if (confirm(`No practice questions available. Reset Directive Mode for "${topic}" anyway?`)) {
                await performStruggleReset(topic, courseId);
            }
            return;
        }

        // Render the question with the struggle-reset flag
        renderStruggleResetQuestion(result.data, topic);

    } catch (error) {
        removeTypingIndicator();
        console.error('Struggle reset question error:', error);
        addMessage('Sorry, I encountered an error. Please try again.', 'bot', false, true, null);
    }
}

/**
 * Render a practice question that gates struggle reset.
 * Similar to renderPracticeQuestion but on correct answer, resets struggle state.
 * @param {Object} questionData - { practiceId, questionType, question, options }
 * @param {string} topic - The struggle topic to reset on correct answer
 */
function renderStruggleResetQuestion(questionData, topic) {
    const { practiceId, questionType, question, options } = questionData;

    const displayTopic = topic.charAt(0).toUpperCase() + topic.slice(1);

    // Add a conversational lead-in as a regular bot message first
    addMessage(`Awesome! Before we move on, let's test your understanding of ${displayTopic}:`, 'bot', false, false, null);

    let html = `<div class="practice-question-container struggle-gate-question" data-practice-id="${practiceId}" data-question-type="${questionType}" data-struggle-topic="${topic}">`;
    html += `<div class="practice-question-text">${question}</div>`;

    if (questionType === 'multiple-choice' && options) {
        html += `<div class="practice-options">`;
        for (const [key, value] of Object.entries(options)) {
            html += `<label class="practice-option-label" data-value="${key}">
                <input type="radio" name="practice-${practiceId}" value="${key}">
                <span class="practice-option-text"><strong>${key}.</strong> ${value}</span>
            </label>`;
        }
        html += `</div>`;
    } else if (questionType === 'true-false') {
        html += `<div class="practice-options">`;
        html += `<label class="practice-option-label" data-value="True">
            <input type="radio" name="practice-${practiceId}" value="True">
            <span class="practice-option-text"><strong>True</strong></span>
        </label>`;
        html += `<label class="practice-option-label" data-value="False">
            <input type="radio" name="practice-${practiceId}" value="False">
            <span class="practice-option-text"><strong>False</strong></span>
        </label>`;
        html += `</div>`;
    } else if (questionType === 'short-answer') {
        html += `<div class="practice-sa-container">
            <textarea class="practice-sa-input" rows="3" placeholder="Type your answer here..."></textarea>
        </div>`;
    }

    html += `<button class="practice-submit-btn" onclick="submitStruggleResetAnswer('${practiceId}')">Submit Answer</button>`;
    html += `<div class="practice-feedback" style="display:none;"></div>`;
    html += `</div>`;

    addMessage(html, 'bot', false, false, null, true);
}

/**
 * Submit answer for a struggle-reset practice question.
 * If correct → reset struggle state. If incorrect → encourage and keep directive mode.
 * @param {string} practiceId - The practice question ID
 */
async function submitStruggleResetAnswer(practiceId) {
    const container = document.querySelector(`.struggle-gate-question[data-practice-id="${practiceId}"]`);
    if (!container) return;

    const questionType = container.dataset.questionType;
    const topic = container.dataset.struggleTopic;
    const submitBtn = container.querySelector('.practice-submit-btn');
    const feedbackDiv = container.querySelector('.practice-feedback');
    let studentAnswer = '';

    if (questionType === 'multiple-choice' || questionType === 'true-false') {
        const selected = container.querySelector(`input[name="practice-${practiceId}"]:checked`);
        if (!selected) {
            feedbackDiv.style.display = 'block';
            feedbackDiv.className = 'practice-feedback practice-feedback-error';
            feedbackDiv.textContent = 'Please select an answer.';
            return;
        }
        studentAnswer = selected.value;
    } else if (questionType === 'short-answer') {
        const textarea = container.querySelector('.practice-sa-input');
        studentAnswer = textarea ? textarea.value.trim() : '';
        if (!studentAnswer) {
            feedbackDiv.style.display = 'block';
            feedbackDiv.className = 'practice-feedback practice-feedback-error';
            feedbackDiv.textContent = 'Please type your answer.';
            return;
        }
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Checking...';

    try {
        const currentUserObj = (typeof getCurrentUser === 'function') ? getCurrentUser() : window.currentUser;
        const displayName = (currentUserObj && (currentUserObj.displayName || currentUserObj.name || currentUserObj.username)) || 'Student';
        const response = await fetch('/api/chat/check-practice-answer', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ practiceId, studentAnswer, studentName: displayName })
        });

        const result = await response.json();

        if (!result.success) {
            feedbackDiv.style.display = 'block';
            feedbackDiv.className = 'practice-feedback practice-feedback-error';
            feedbackDiv.textContent = result.message || 'Error checking answer.';
            submitBtn.disabled = false;
            submitBtn.textContent = 'Submit Answer';
            return;
        }

        const { correct, feedback, correctAnswer } = result.data;
        const courseId = localStorage.getItem('selectedCourseId');

        // Build static completed HTML
        const questionText = container.querySelector('.practice-question-text').textContent;
        let completedHtml = `<div class="practice-question-container practice-completed struggle-gate-question">`;
        completedHtml += `<div class="practice-question-text">${questionText}</div>`;

        if (questionType === 'multiple-choice' || questionType === 'true-false') {
            completedHtml += `<div class="practice-options">`;
            const labels = container.querySelectorAll('.practice-option-label');
            labels.forEach(label => {
                const radio = label.querySelector('input[type="radio"]');
                const optionText = label.querySelector('.practice-option-text').innerHTML;
                const value = radio.value;
                const wasSelected = radio.checked;
                const isCorrectAnswer = correctAnswer !== null && correctAnswer !== undefined
                    && String(value).toLowerCase() === String(correctAnswer).trim().toLowerCase();

                let extraClass = 'practice-option-disabled';
                if (isCorrectAnswer && wasSelected) extraClass += ' practice-option-correct';
                else if (isCorrectAnswer) extraClass += ' practice-option-was-correct';
                else if (wasSelected) extraClass += ' practice-option-incorrect';

                const checkMark = wasSelected ? '●' : '○';
                completedHtml += `<div class="practice-option-label ${extraClass}">
                    <span style="flex-shrink:0;width:16px;text-align:center;font-size:12px;">${checkMark}</span>
                    <span class="practice-option-text">${optionText}</span>
                </div>`;
            });
            completedHtml += `</div>`;
        } else if (questionType === 'short-answer') {
            const saText = container.querySelector('.practice-sa-input').value;
            completedHtml += `<div class="practice-sa-container">
                <div class="practice-sa-input" style="background:#f5f5f5;padding:10px 12px;border:2px solid #e0e0e0;border-radius:8px;font-size:13px;white-space:pre-wrap;">${saText}</div>
            </div>`;
        }

        const displayTopic = topic.charAt(0).toUpperCase() + topic.slice(1);

        if (correct) {
            // Correct! Reset the struggle state
            completedHtml += `<div class="practice-feedback practice-feedback-correct" style="display:block;">${feedback}<br><strong>Great job! Looks like you've got a solid understanding of ${displayTopic}. Let's keep going!</strong></div>`;
            completedHtml += `</div>`;
            container.outerHTML = completedHtml;

            // Actually reset the struggle state
            await performStruggleReset(topic, courseId);
        } else {
            // Incorrect — keep in directive mode, encourage them
            completedHtml += `<div class="practice-feedback practice-feedback-incorrect" style="display:block;">${feedback}<br>No worries! Let's keep working on ${displayTopic} together. Click "I understand ${displayTopic} now" when you're ready to try again.</div>`;
            completedHtml += `</div>`;
            container.outerHTML = completedHtml;
        }

        // Update auto-save
        updatePracticeQuestionInAutoSave(practiceId, completedHtml);

    } catch (error) {
        console.error('Struggle reset answer error:', error);
        feedbackDiv.style.display = 'block';
        feedbackDiv.className = 'practice-feedback practice-feedback-error';
        feedbackDiv.textContent = 'Error connecting to server. Please try again.';
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Answer';
    }
}

/**
 * Perform the actual struggle state reset (shared by direct reset and quiz-gated reset).
 * @param {string} topic - The topic to reset
 * @param {string} courseId - The course ID
 */
async function performStruggleReset(topic, courseId) {
    try {
        const response = await fetch('/api/student/struggle/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ topic, courseId })
        });

        const result = await response.json();

        if (result.success) {
            // Update UI
            lastActiveStruggleTopic = null;

            const indicator = document.getElementById('directive-mode-indicator');
            if (indicator) indicator.remove();

            const buttons = document.querySelectorAll('.struggle-reset-btn');
            buttons.forEach(btn => btn.remove());
        } else {
            console.error('Failed to reset struggle state:', result.message);
        }
    } catch (error) {
        console.error('Error resetting struggle state:', error);
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
