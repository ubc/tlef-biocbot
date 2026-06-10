(function () {
    const DEFAULT_TYPE = 'info';
    const VALID_TYPES = new Set(['success', 'error', 'warning', 'info']);

    function normalizeType(type) {
        return VALID_TYPES.has(type) ? type : DEFAULT_TYPE;
    }

    function ensureNotificationContainer() {
        let container = document.querySelector('.notification-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'notification-container';
            document.body.appendChild(container);
        }
        // Announce notifications to assistive technology without stealing focus.
        container.setAttribute('role', 'status');
        container.setAttribute('aria-live', 'polite');
        return container;
    }

    function showNotification(message, type = DEFAULT_TYPE) {
        const normalizedType = normalizeType(type);
        const container = ensureNotificationContainer();
        const notification = document.createElement('div');
        notification.className = `notification ${normalizedType} notification-${normalizedType}`;

        const messageSpan = document.createElement('span');
        messageSpan.textContent = message;

        const closeButton = document.createElement('button');
        closeButton.className = 'notification-close';
        closeButton.type = 'button';
        closeButton.setAttribute('aria-label', 'Dismiss notification');
        closeButton.innerHTML = '&times;';
        closeButton.addEventListener('click', () => notification.remove());

        notification.appendChild(messageSpan);
        notification.appendChild(closeButton);
        container.appendChild(notification);

        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 5000);

        return notification;
    }

    window.showNotification = showNotification;
})();
