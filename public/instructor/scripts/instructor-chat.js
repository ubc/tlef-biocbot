document.addEventListener('DOMContentLoaded', async () => {
    await waitForAuthReady();

    const user = typeof getCurrentUser === 'function' ? getCurrentUser() : null;
    if (user && user.role !== 'instructor') {
        window.location.href = user.role === 'ta' ? '/ta' : '/login';
        return;
    }

    const form = document.getElementById('instructor-chat-form');
    const input = document.getElementById('instructor-chat-input');
    const messages = document.getElementById('chat-messages');
    const sendButton = document.getElementById('send-button');
    const newChatButton = document.getElementById('new-super-course-chat');
    const scopeLabel = document.getElementById('super-course-scope');
    const poolPanel = document.getElementById('super-course-pool-panel');
    const poolList = document.getElementById('super-course-pool-list');
    const conversationMessages = [];
    const instructorId = user?.userId || 'unknown-instructor';
    const instructorName = user?.displayName || user?.username || user?.email || 'Instructor';
    const currentChatKey = `biocbot_instructor_super_current_chat_${instructorId}`;
    const sessionKey = `biocbot_instructor_super_session_${instructorId}`;

    if (!form || !input || !messages || !sendButton) {
        return;
    }

    loadSourcePool();
    initializeAutoSave();
    restoreRecentSession();

    if (newChatButton) {
        newChatButton.addEventListener('click', () => {
            if (conversationMessages.length && !confirm('Start a new Super Course chat?')) {
                return;
            }
            startNewChat();
        });
    }

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const text = input.value.trim();
        if (!text) return;

        input.value = '';
        addMessage(text, 'user');
        conversationMessages.push({ role: 'user', content: text });

        const typing = addMessage('Thinking...', 'bot', { isPending: true, skipAutoSave: true });
        setBusy(true);

        try {
            const response = await fetch('/api/instructor/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    message: text,
                    conversationMessages
                })
            });

            const result = await response.json();
            if (!response.ok || !result.success) {
                throw new Error(result.message || 'Failed to send message');
            }

            typing.remove();
            addMessage(result.message || '', 'bot', {
                sourceAttribution: result.sourceAttribution,
                citations: result.citations
            });
            conversationMessages.push({ role: 'assistant', content: result.message || '' });
        } catch (error) {
            console.error('Instructor chat error:', error);
            typing.remove();
            addMessage(error.message || 'Sorry, I could not process that message. Please try again.', 'bot', {
                isError: true,
                skipAutoSave: true
            });
        } finally {
            setBusy(false);
            input.focus();
        }
    });

    function setBusy(isBusy) {
        sendButton.disabled = isBusy;
        input.disabled = isBusy;
        sendButton.textContent = isBusy ? 'Sending...' : 'Send';
    }

    function addMessage(content, sender, options = {}) {
        const message = document.createElement('div');
        message.className = `message ${sender}-message${options.isPending ? ' pending-message' : ''}${options.isError ? ' error-message' : ''}`;

        const avatar = document.createElement('div');
        avatar.className = 'message-avatar';
        avatar.textContent = sender === 'user' ? 'I' : 'B';

        const contentWrap = document.createElement('div');
        contentWrap.className = 'message-content';

        const text = document.createElement('p');
        text.innerText = content;
        text.style.whiteSpace = 'pre-wrap';
        contentWrap.appendChild(text);

        const footer = document.createElement('div');
        footer.className = 'message-footer';

        if (sender === 'bot' && options.sourceAttribution) {
            footer.appendChild(renderSourceAttribution(options.sourceAttribution));
        } else if (sender === 'bot' && Array.isArray(options.citations) && options.citations.length) {
            footer.appendChild(renderCitationSummary(options.citations));
        }

        const right = document.createElement('div');
        right.className = 'message-footer-right';
        const timestamp = document.createElement('span');
        timestamp.className = 'timestamp';
        timestamp.textContent = 'Just now';
        right.appendChild(timestamp);
        footer.appendChild(right);
        contentWrap.appendChild(footer);

        message.appendChild(avatar);
        message.appendChild(contentWrap);
        messages.appendChild(message);
        messages.scrollTop = messages.scrollHeight;

        if (!options.skipAutoSave && !options.isPending && !options.isError) {
            autoSaveMessage(content, sender, {
                sourceAttribution: options.sourceAttribution || null,
                citations: Array.isArray(options.citations) ? options.citations : [],
                isError: options.isError === true
            });
        }

        return message;
    }

    function initializeAutoSave() {
        const existing = getCurrentChatData();
        if (existing && Array.isArray(existing.messages)) {
            ensureSessionId(existing);
            localStorage.setItem(currentChatKey, JSON.stringify(existing));
            return;
        }

        localStorage.setItem(currentChatKey, JSON.stringify(createEmptyChatData()));
    }

    function createEmptyChatData() {
        const sessionId = getOrCreateSessionId();
        const now = new Date().toISOString();
        return {
            metadata: {
                exportDate: now,
                courseId: 'SUPER_COURSE',
                courseName: 'Super Course',
                instructorId,
                instructorName,
                unitName: 'Super Course',
                currentMode: 'instructor-super-course',
                totalMessages: 0,
                version: '1.0'
            },
            messages: [],
            sessionInfo: {
                sessionId,
                startTime: now,
                endTime: null,
                duration: '0s'
            },
            lastActivityTimestamp: now
        };
    }

    function autoSaveMessage(content, sender, options = {}) {
        try {
            const chatData = getCurrentChatData() || createEmptyChatData();
            ensureSessionId(chatData);

            chatData.messages.push({
                type: sender,
                content,
                timestamp: new Date().toISOString(),
                messageType: 'instructor-super-course-chat',
                sourceAttribution: options.sourceAttribution || null,
                citations: options.citations || [],
                isError: options.isError === true
            });

            chatData.metadata.totalMessages = chatData.messages.length;
            chatData.metadata.exportDate = new Date().toISOString();
            chatData.sessionInfo.endTime = new Date().toISOString();
            chatData.sessionInfo.duration = calculateSessionDuration(chatData);
            chatData.lastActivityTimestamp = new Date().toISOString();

            localStorage.setItem(currentChatKey, JSON.stringify(chatData));
            syncAutoSaveWithServer(chatData);
        } catch (error) {
            console.error('Error auto-saving instructor chat:', error);
        }
    }

    function restoreRecentSession() {
        const chatData = getCurrentChatData();
        if (!chatData || !Array.isArray(chatData.messages) || chatData.messages.length === 0) {
            return false;
        }

        const restorableMessages = chatData.messages.filter(message => !message.isError);
        if (restorableMessages.length === 0) {
            localStorage.removeItem(currentChatKey);
            return false;
        }

        if (!chatData.lastActivityTimestamp) {
            return false;
        }

        const lastActivity = new Date(chatData.lastActivityTimestamp);
        const diffMinutes = Math.floor((Date.now() - lastActivity.getTime()) / (1000 * 60));
        if (Number.isNaN(diffMinutes) || diffMinutes > 30) {
            return false;
        }

        ensureSessionId(chatData);
        loadChatData(chatData);
        showAutoContinueNotification();
        return true;
    }

    function loadChatData(chatData) {
        messages.innerHTML = '';
        conversationMessages.length = 0;

        const restorableMessages = chatData.messages.filter(messageData => !messageData.isError);
        if (!restorableMessages.length) {
            return;
        }

        restorableMessages.forEach(messageData => {
            addMessage(messageData.content, messageData.type, {
                sourceAttribution: messageData.sourceAttribution,
                citations: messageData.citations,
                isError: messageData.isError,
                skipAutoSave: true
            });

            if (messageData.type === 'user') {
                conversationMessages.push({ role: 'user', content: messageData.content });
            } else if (messageData.type === 'bot' && !messageData.isError) {
                conversationMessages.push({ role: 'assistant', content: messageData.content });
            }
        });

        localStorage.setItem(currentChatKey, JSON.stringify(chatData));
    }

    function startNewChat() {
        const current = getCurrentChatData();
        if (current?.sessionInfo?.sessionId) {
            fetch(`/api/instructor/chat/sessions/${encodeURIComponent(current.sessionInfo.sessionId)}`, {
                method: 'DELETE',
                credentials: 'include'
            }).catch(() => {});
        }

        localStorage.removeItem(currentChatKey);
        localStorage.removeItem(sessionKey);
        conversationMessages.length = 0;
        messages.innerHTML = `
            <div class="message bot-message">
                <div class="message-avatar">B</div>
                <div class="message-content">
                    <p>Ask about material across the Super Course. I will use opted-in uploaded course material when relevant and can draw on general biochemistry when the uploaded context is thin.</p>
                </div>
            </div>
        `;
        initializeAutoSave();
        input.focus();
    }

    function getCurrentChatData() {
        try {
            const raw = localStorage.getItem(currentChatKey);
            return raw ? JSON.parse(raw) : null;
        } catch (error) {
            console.error('Error reading instructor chat data:', error);
            return null;
        }
    }

    function getOrCreateSessionId() {
        let sessionId = localStorage.getItem(sessionKey);
        if (!sessionId) {
            sessionId = `autosave_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
            localStorage.setItem(sessionKey, sessionId);
        }
        return sessionId;
    }

    function ensureSessionId(chatData) {
        if (!chatData.sessionInfo) {
            chatData.sessionInfo = {};
        }

        if (chatData.sessionInfo.sessionId) {
            localStorage.setItem(sessionKey, chatData.sessionInfo.sessionId);
            return chatData.sessionInfo.sessionId;
        }

        const sessionId = getOrCreateSessionId();
        chatData.sessionInfo.sessionId = sessionId;
        return sessionId;
    }

    function calculateSessionDuration(chatData) {
        if (!chatData || !Array.isArray(chatData.messages) || chatData.messages.length === 0) {
            return '0s';
        }

        const firstUserMessage = chatData.messages.find(msg => msg.type === 'user');
        if (!firstUserMessage?.timestamp) {
            return '0s';
        }

        const lastBotMessage = chatData.messages.slice().reverse().find(msg => msg.type === 'bot');
        const lastMessage = lastBotMessage || chatData.messages[chatData.messages.length - 1];
        if (!lastMessage?.timestamp) {
            return '0s';
        }

        const diffMs = new Date(lastMessage.timestamp) - new Date(firstUserMessage.timestamp);
        const safeDiffMs = Math.max(0, Number.isFinite(diffMs) ? diffMs : 0);
        const hours = Math.floor(safeDiffMs / (1000 * 60 * 60));
        const minutes = Math.floor((safeDiffMs % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((safeDiffMs % (1000 * 60)) / 1000);

        if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
        if (minutes > 0) return `${minutes}m ${seconds}s`;
        return `${seconds}s`;
    }

    function syncAutoSaveWithServer(chatData) {
        const sessionId = ensureSessionId(chatData);
        const serverData = {
            sessionId,
            title: generateChatTitle(chatData),
            messageCount: chatData.metadata.totalMessages,
            duration: chatData.sessionInfo.duration,
            savedAt: chatData.metadata.exportDate,
            chatData
        };

        fetch('/api/instructor/chat/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(serverData)
        }).catch(error => {
            console.warn('Instructor chat server sync failed:', error.message);
        });
    }

    function generateChatTitle(chatData) {
        const firstUserMessage = chatData.messages.find(msg => msg.type === 'user');
        if (firstUserMessage) {
            const question = firstUserMessage.content.slice(0, 50);
            return `Super Course - ${question}${question.length >= 50 ? '...' : ''}`;
        }
        return `Super Course Chat (${chatData.metadata.totalMessages} messages)`;
    }

    function showAutoContinueNotification() {
        if (typeof showNotification === 'function') {
            showNotification('Chat continued from where you left off', 'success');
        }
    }

    function renderSourceAttribution(sourceAttribution) {
        const source = document.createElement('div');
        source.className = 'message-source super-course-source';

        const label = document.createElement('span');
        label.className = 'source-label';
        label.textContent = sourceAttribution.description || 'Super Course sources';
        source.appendChild(label);

        const documents = Array.isArray(sourceAttribution.documents)
            ? sourceAttribution.documents.slice(0, 5)
            : [];

        if (documents.length) {
            const list = document.createElement('div');
            list.className = 'super-course-citation-list';
            documents.forEach(doc => {
                const item = document.createElement('span');
                item.className = 'super-course-citation';
                item.textContent = [
                    doc.courseName || doc.courseId,
                    doc.unitName,
                    doc.fileName
                ].filter(Boolean).join(' / ');
                list.appendChild(item);
            });
            source.appendChild(list);
        } else if (Array.isArray(sourceAttribution.poolCourses) && sourceAttribution.poolCourses.length) {
            const poolNote = document.createElement('div');
            poolNote.className = 'super-course-pool-note';
            poolNote.textContent = `Configured sources: ${formatPoolCourseNames(sourceAttribution.poolCourses)}`;
            source.appendChild(poolNote);
        }

        return source;
    }

    function renderCitationSummary(citations) {
        return renderSourceAttribution({
            description: 'From uploaded Super Course material',
            documents: citations
        });
    }

    async function loadSourcePool() {
        if (!poolList) return;

        try {
            const response = await fetch('/api/instructor/chat/pool', { credentials: 'include' });
            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(result.message || 'Failed to load source pool');
            }

            const courses = Array.isArray(result.courses) ? result.courses : [];
            renderSourcePool(courses);
        } catch (error) {
            console.error('Source pool load error:', error);
            if (scopeLabel) scopeLabel.textContent = 'Source pool unavailable';
            poolList.textContent = 'Unable to load source pool.';
            if (poolPanel) poolPanel.classList.add('error');
        }
    }

    function renderSourcePool(courses) {
        if (scopeLabel) {
            scopeLabel.textContent = courses.length === 1
                ? formatPoolCourseName(courses[0])
                : `${courses.length} opted-in courses`;
        }

        if (!poolList) return;
        poolList.innerHTML = '';

        if (!courses.length) {
            poolList.textContent = 'No courses are currently included.';
            return;
        }

        const visibleCourses = courses.slice(0, 12);
        visibleCourses.forEach(course => {
            const chip = document.createElement('span');
            chip.className = 'super-course-pool-chip';
            chip.textContent = formatPoolCourseName(course);
            poolList.appendChild(chip);
        });

        if (courses.length > visibleCourses.length) {
            const more = document.createElement('span');
            more.className = 'super-course-pool-chip muted';
            more.textContent = `+${courses.length - visibleCourses.length} more`;
            poolList.appendChild(more);
        }
    }

    function formatPoolCourseName(course) {
        return course.courseName || course.courseId || 'Untitled course';
    }

    function formatPoolCourseNames(courses) {
        const names = courses.slice(0, 6).map(formatPoolCourseName).join(', ');
        return courses.length > 6 ? `${names}, and ${courses.length - 6} more` : names;
    }
});

function waitForAuthReady() {
    return new Promise(resolve => {
        if (typeof getCurrentUser === 'function' && getCurrentUser()) {
            resolve();
            return;
        }

        document.addEventListener('auth:ready', () => resolve(), { once: true });
        setTimeout(resolve, 5000);
    });
}
