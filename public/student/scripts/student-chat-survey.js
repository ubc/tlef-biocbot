/**
 * Student chat usefulness survey popup.
 * The prompt is configured per course and is tracked per chat session.
 */

(function () {
    const SURVEY_STATE_ROOT = 'chatSurvey';
    const SETTINGS_CACHE_TTL_MS = 60000;
    const SYSTEM_NOTICE_SNIPPETS = [
        'Please be aware that after 15 messages',
        'You\'ve reached 25 messages',
        'In 5 messages, this session will automatically close',
        'This chat session has been exhausted'
    ];

    const surveyRuntime = {
        cacheKey: null,
        cachedPayload: null,
        cachedAt: 0,
        isShowing: false,
        isChecking: false
    };

    function getSurveyConversationId(chatData) {
        try {
            if (chatData && typeof getCurrentSessionId === 'function') {
                return getCurrentSessionId(chatData);
            }

            const studentId = typeof getCurrentStudentId === 'function' ? getCurrentStudentId() : null;
            const courseId = localStorage.getItem('selectedCourseId');
            const unitName = localStorage.getItem('selectedUnitName') || (typeof getCurrentUnitName === 'function' ? getCurrentUnitName() : 'this unit');
            if (!studentId || !courseId || !unitName) return null;

            return localStorage.getItem(`biocbot_session_${studentId}_${courseId}_${unitName}`);
        } catch (error) {
            console.warn('Could not resolve chat survey conversation id:', error);
            return null;
        }
    }

    function getStudentAutoSaveKey(chatData) {
        const studentId = typeof getCurrentStudentId === 'function'
            ? getCurrentStudentId()
            : chatData?.metadata?.studentId;
        return studentId ? `biocbot_current_chat_${studentId}` : null;
    }

    function ensureSurveyStateRoot(chatData) {
        if (!chatData[SURVEY_STATE_ROOT] || typeof chatData[SURVEY_STATE_ROOT] !== 'object') {
            chatData[SURVEY_STATE_ROOT] = {};
        }
        if (!chatData[SURVEY_STATE_ROOT].responses || typeof chatData[SURVEY_STATE_ROOT].responses !== 'object') {
            chatData[SURVEY_STATE_ROOT].responses = {};
        }
        return chatData[SURVEY_STATE_ROOT].responses;
    }

    function getLocalSurveyState(chatData, settingsFingerprint) {
        if (!chatData || !settingsFingerprint) return null;
        const responses = chatData[SURVEY_STATE_ROOT]?.responses;
        return responses && responses[settingsFingerprint] ? responses[settingsFingerprint] : null;
    }

    function saveLocalSurveyState(chatData, settingsFingerprint, patch) {
        if (!chatData || !settingsFingerprint) return null;

        const responses = ensureSurveyStateRoot(chatData);
        const current = responses[settingsFingerprint] || {};
        const next = {
            ...current,
            ...patch,
            settingsFingerprint,
            updatedAt: new Date().toISOString()
        };

        responses[settingsFingerprint] = next;
        chatData.lastActivityTimestamp = new Date().toISOString();

        const autoSaveKey = getStudentAutoSaveKey(chatData);
        if (autoSaveKey) {
            localStorage.setItem(autoSaveKey, JSON.stringify(chatData));
        }
        if (typeof syncAutoSaveWithServer === 'function') {
            syncAutoSaveWithServer(chatData);
        }

        return next;
    }

    function hasSurveyBeenHandled(state) {
        return !!(state && (state.shownAt || state.dismissedAt || state.submittedAt));
    }

    function isSystemNoticeMessage(message) {
        if (!message || message.type !== 'bot') return false;
        if (message.sourceAttribution && message.sourceAttribution.source === 'System') return true;
        const content = typeof message.content === 'string' ? message.content : '';
        return SYSTEM_NOTICE_SNIPPETS.some(snippet => content.includes(snippet));
    }

    function isSurveyCountableMessage(message) {
        if (!message || (message.type !== 'user' && message.type !== 'bot')) return false;
        if (message.messageType && message.messageType !== 'regular-chat') return false;
        return !isSystemNoticeMessage(message);
    }

    function countSurveyMessages(chatData) {
        if (!chatData || !Array.isArray(chatData.messages)) return 0;

        const firstStudentIndex = chatData.messages.findIndex(message =>
            message
            && message.type === 'user'
            && (!message.messageType || message.messageType === 'regular-chat')
        );
        if (firstStudentIndex === -1) return 0;

        return chatData.messages
            .slice(firstStudentIndex)
            .filter(isSurveyCountableMessage)
            .length;
    }

    async function loadChatSurveySettingsForCourse(force = false) {
        const courseId = localStorage.getItem('selectedCourseId');
        if (!courseId) return null;

        const chatData = typeof getCurrentChatData === 'function' ? getCurrentChatData() : null;
        const conversationId = getSurveyConversationId(chatData);
        const cacheKey = `${courseId}:${conversationId || ''}`;
        const cacheFresh = surveyRuntime.cachedPayload
            && surveyRuntime.cacheKey === cacheKey
            && Date.now() - surveyRuntime.cachedAt < SETTINGS_CACHE_TTL_MS;

        if (!force && cacheFresh) {
            return surveyRuntime.cachedPayload;
        }

        const params = new URLSearchParams({ courseId });
        if (conversationId) params.set('conversationId', conversationId);

        try {
            const response = await fetch(`/api/chat/survey-settings?${params.toString()}`, {
                credentials: 'include'
            });
            const result = await response.json();
            if (!response.ok || !result.success) {
                throw new Error(result.message || `Survey settings request failed: ${response.status}`);
            }

            surveyRuntime.cacheKey = cacheKey;
            surveyRuntime.cachedPayload = result.data;
            surveyRuntime.cachedAt = Date.now();
            return result.data;
        } catch (error) {
            console.warn('Could not load chat survey settings:', error);
            return null;
        }
    }

    async function postSurveyEvent(eventType, payload = {}) {
        const courseId = localStorage.getItem('selectedCourseId');
        const chatData = typeof getCurrentChatData === 'function' ? getCurrentChatData() : null;
        const conversationId = getSurveyConversationId(chatData);
        if (!courseId || !conversationId) {
            throw new Error('Missing course or conversation id for survey event');
        }

        const response = await fetch('/api/chat/survey', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                courseId,
                unitName: localStorage.getItem('selectedUnitName') || (typeof getCurrentUnitName === 'function' ? getCurrentUnitName() : null),
                conversationId,
                eventType,
                botMode: localStorage.getItem('studentMode') || 'tutor',
                ...payload
            })
        });

        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || `Survey event failed: ${response.status}`);
        }
        return result.data?.response || null;
    }

    function closeSurveyOverlay() {
        const overlay = document.getElementById('chat-survey-overlay');
        if (overlay) overlay.remove();
        surveyRuntime.isShowing = false;
    }

    function renderChatSurveyPopup({ settings, settingsFingerprint, messageCountAtPrompt, chatData }) {
        if (document.getElementById('chat-survey-overlay')) return;

        surveyRuntime.isShowing = true;
        let selectedRating = null;

        const overlay = document.createElement('div');
        overlay.id = 'chat-survey-overlay';
        overlay.className = 'chat-survey-overlay';

        const modal = document.createElement('div');
        modal.className = 'chat-survey-modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'chat-survey-title');

        const closeButton = document.createElement('button');
        closeButton.type = 'button';
        closeButton.className = 'chat-survey-close';
        closeButton.setAttribute('aria-label', 'Close survey');
        closeButton.textContent = '×';

        const title = document.createElement('h2');
        title.id = 'chat-survey-title';
        title.textContent = settings.promptText || 'Was this chat helpful?';

        const ratingLabel = document.createElement('p');
        ratingLabel.className = 'chat-survey-rating-label';
        ratingLabel.textContent = settings.ratingPrompt || 'How useful was this conversation?';

        const stars = document.createElement('div');
        stars.className = 'chat-survey-stars';
        stars.setAttribute('role', 'radiogroup');
        stars.setAttribute('aria-label', ratingLabel.textContent);

        const status = document.createElement('div');
        status.className = 'chat-survey-status';
        status.setAttribute('aria-live', 'polite');

        const submitButton = document.createElement('button');
        submitButton.type = 'button';
        submitButton.className = 'chat-survey-submit';
        submitButton.textContent = 'Submit';
        submitButton.disabled = true;

        function updateStars() {
            stars.querySelectorAll('.chat-survey-star').forEach(button => {
                const rating = Number(button.dataset.rating);
                const active = selectedRating && rating <= selectedRating;
                button.classList.toggle('active', !!active);
                button.textContent = active ? '★' : '☆';
                button.setAttribute('aria-checked', selectedRating === rating ? 'true' : 'false');
            });
            submitButton.disabled = !selectedRating;
            status.textContent = '';
        }

        for (let rating = 1; rating <= 5; rating += 1) {
            const starButton = document.createElement('button');
            starButton.type = 'button';
            starButton.className = 'chat-survey-star';
            starButton.dataset.rating = String(rating);
            starButton.setAttribute('role', 'radio');
            starButton.setAttribute('aria-label', `${rating} star${rating === 1 ? '' : 's'}`);
            starButton.textContent = '☆';
            starButton.addEventListener('click', () => {
                selectedRating = rating;
                updateStars();
            });
            stars.appendChild(starButton);
        }

        let commentInput = null;
        if (settings.allowFreeText) {
            commentInput = document.createElement('textarea');
            commentInput.className = 'chat-survey-comment';
            commentInput.maxLength = 2000;
            commentInput.rows = 3;
            commentInput.placeholder = 'Add a comment (optional)';
            commentInput.setAttribute('aria-label', 'Optional survey comment');
        }

        const actions = document.createElement('div');
        actions.className = 'chat-survey-actions';

        const dismissButton = document.createElement('button');
        dismissButton.type = 'button';
        dismissButton.className = 'chat-survey-dismiss';
        dismissButton.textContent = 'Not now';

        async function dismissSurvey() {
            closeSurveyOverlay();
            saveLocalSurveyState(chatData, settingsFingerprint, {
                dismissedAt: new Date().toISOString(),
                messageCountAtPrompt
            });
            try {
                await postSurveyEvent('dismissed', {
                    settingsFingerprint,
                    messageCountAtPrompt
                });
            } catch (error) {
                console.warn('Could not save survey dismissal:', error);
            }
        }

        closeButton.addEventListener('click', dismissSurvey);
        dismissButton.addEventListener('click', dismissSurvey);
        overlay.addEventListener('click', event => {
            if (event.target === overlay) dismissSurvey();
        });

        submitButton.addEventListener('click', async () => {
            if (!selectedRating) {
                status.textContent = 'Choose a star rating to submit.';
                return;
            }

            submitButton.disabled = true;
            dismissButton.disabled = true;
            closeButton.disabled = true;
            status.textContent = 'Saving...';

            const comment = commentInput ? commentInput.value.trim() : '';
            try {
                await postSurveyEvent('submitted', {
                    settingsFingerprint,
                    rating: selectedRating,
                    comment,
                    messageCountAtPrompt
                });

                saveLocalSurveyState(chatData, settingsFingerprint, {
                    submittedAt: new Date().toISOString(),
                    rating: selectedRating,
                    comment: comment || null,
                    messageCountAtPrompt
                });
                closeSurveyOverlay();
            } catch (error) {
                console.error('Could not save survey response:', error);
                status.textContent = 'Could not save. Please try again.';
                submitButton.disabled = false;
                dismissButton.disabled = false;
                closeButton.disabled = false;
            }
        });

        actions.appendChild(dismissButton);
        actions.appendChild(submitButton);

        modal.appendChild(closeButton);
        modal.appendChild(title);
        modal.appendChild(ratingLabel);
        modal.appendChild(stars);
        if (commentInput) modal.appendChild(commentInput);
        modal.appendChild(status);
        modal.appendChild(actions);
        overlay.appendChild(modal);
        document.body.appendChild(overlay);
        updateStars();
    }

    async function maybeShowChatSurvey() {
        if (surveyRuntime.isChecking || surveyRuntime.isShowing) return;

        surveyRuntime.isChecking = true;
        try {
            const chatData = typeof getCurrentChatData === 'function' ? getCurrentChatData() : null;
            if (!chatData) return;

            const payload = await loadChatSurveySettingsForCourse();
            const settings = payload?.settings;
            const settingsFingerprint = payload?.settingsFingerprint;
            if (!settings || !settings.enabled || !settingsFingerprint) return;

            if (payload.response && hasSurveyBeenHandled(payload.response)) {
                saveLocalSurveyState(chatData, settingsFingerprint, payload.response);
                return;
            }

            const localState = getLocalSurveyState(chatData, settingsFingerprint);
            if (hasSurveyBeenHandled(localState)) return;

            const messageCountAtPrompt = countSurveyMessages(chatData);
            const triggerMessageCount = Number(settings.triggerMessageCount) || 10;
            if (messageCountAtPrompt < triggerMessageCount) return;

            saveLocalSurveyState(chatData, settingsFingerprint, {
                shownAt: new Date().toISOString(),
                messageCountAtPrompt
            });

            postSurveyEvent('shown', {
                settingsFingerprint,
                messageCountAtPrompt
            }).catch(error => {
                console.warn('Could not save survey shown event:', error);
            });

            renderChatSurveyPopup({
                settings,
                settingsFingerprint,
                messageCountAtPrompt,
                chatData
            });
        } finally {
            surveyRuntime.isChecking = false;
        }
    }

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && surveyRuntime.isShowing) {
            const closeButton = document.querySelector('#chat-survey-overlay .chat-survey-close');
            if (closeButton) closeButton.click();
        }
    });

    window.loadChatSurveySettingsForCourse = loadChatSurveySettingsForCourse;
    window.maybeShowChatSurvey = maybeShowChatSurvey;
    window.countSurveyMessagesForCurrentChat = function () {
        const chatData = typeof getCurrentChatData === 'function' ? getCurrentChatData() : null;
        return countSurveyMessages(chatData);
    };
})();
