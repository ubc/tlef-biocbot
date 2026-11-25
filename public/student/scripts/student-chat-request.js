/**
 * Student chat: posting a message to /api/chat and reading the response. It
 * has no DOM of its own, so a test can load it and post to the real route.
 *
 * The agent path streams what BiocBot is doing while it writes the reply. The
 * agents framework's chat client reads the stream: /vendor/agents-chat.js,
 * loaded before this file, sets UbcAgentsChat.
 */

/**
 * Post a chat message and return the response's status code and body. While
 * the agent path writes the reply, onStatus gets the text of what it's doing
 * now, for the status line.
 * @param {Object} requestBody - The body POST /api/chat reads
 * @param {{ signal?: AbortSignal|null, onStatus: (text: string) => void }} options
 * @returns {Promise<{ status: number, data: Object }>}
 */
async function requestChatReply(requestBody, { signal = null, onStatus }) {
    // Without the client (the framework isn't installed, so the agent path is
    // off), ask for JSON, which any path answers with.
    if (typeof UbcAgentsChat === 'undefined') {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody),
            ...(signal ? { signal } : {})
        });
        const data = await response.json();
        if (response.ok) announceReply();
        return { status: response.status, data };
    }

    const result = await UbcAgentsChat.sendChatMessage('/api/chat', {
        body: requestBody,
        ...(signal ? { signal } : {}),
        onActivity: activity => onStatus(activity.status)
    });
    if ('failure' in result) {
        // A request the student stopped fails as an AbortError, the way fetch
        // does, so the page still says it was stopped.
        if (result.failure.code === 'aborted') throw new DOMException(result.failure.message, 'AbortError');
        throw new Error(result.failure.message);
    }
    if (result.status >= 200 && result.status < 300) announceReply();
    return { status: result.status, data: result.body || {} };
}

/**
 * Tells the page BiocBot answered (`chat.reply.received` on the page's events,
 * biocbot-events.js), so the award toast looks for anything the message earned
 * (student-gamification.js). Nothing listens where gamification is off.
 */
function announceReply() {
    if (typeof BiocbotEvents !== 'undefined') BiocbotEvents.publish('chat.reply.received');
}
