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
    const scopeLabel = document.getElementById('super-course-scope');
    const poolPanel = document.getElementById('super-course-pool-panel');
    const poolList = document.getElementById('super-course-pool-list');
    const conversationMessages = [];

    if (!form || !input || !messages || !sendButton) {
        return;
    }

    loadSourcePool();

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const text = input.value.trim();
        if (!text) return;

        input.value = '';
        addMessage(text, 'user');
        conversationMessages.push({ role: 'user', content: text });

        const typing = addMessage('Thinking...', 'bot', { isPending: true });
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
            addMessage(error.message || 'Sorry, I could not process that message. Please try again.', 'bot', { isError: true });
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
        return message;
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
