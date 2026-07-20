/* Shared keyboard and focus management for application modals. */
(function () {
    const modalState = new WeakMap();
    const focusableSelector = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

    function getDialogElement(modalRootEl, dialogEl) {
        return dialogEl || modalRootEl.querySelector('.modal-content') || modalRootEl.firstElementChild || modalRootEl;
    }

    function getFocusables(modalRootEl) {
        return Array.from(modalRootEl.querySelectorAll(focusableSelector))
            .filter((element) => element.offsetParent !== null && !element.hasAttribute('disabled'));
    }

    function resolveElement(modalRootEl, elementOrSelector) {
        if (typeof elementOrSelector === 'string') return modalRootEl.querySelector(elementOrSelector);
        return elementOrSelector || null;
    }

    function open(modalRootEl, options = {}) {
        if (!modalRootEl) return;
        close(modalRootEl, { restoreFocus: false });

        const {
            labelledBy,
            initialFocus,
            escapable = true,
            onRequestClose,
            dialogEl: requestedDialogEl
        } = options;
        const dialogEl = getDialogElement(modalRootEl, requestedDialogEl);
        dialogEl.setAttribute('role', 'dialog');
        dialogEl.setAttribute('aria-modal', 'true');

        let heading = null;
        if (labelledBy) {
            dialogEl.setAttribute('aria-labelledby', labelledBy);
        } else {
            heading = dialogEl.querySelector('h1, h2, h3, h4, h5, h6');
            if (heading) {
                if (!heading.id) heading.id = `${modalRootEl.id || 'modal'}-title`;
                dialogEl.setAttribute('aria-labelledby', heading.id);
            }
        }

        const restoreTarget = document.activeElement;
        const onKeydown = (event) => {
            if (event.key === 'Escape') {
                if (escapable) {
                    event.preventDefault();
                    if (onRequestClose) onRequestClose();
                    else close(modalRootEl);
                } else if (modalRootEl.contains(document.activeElement)) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                return;
            }

            if (event.key !== 'Tab') return;
            const focusables = getFocusables(modalRootEl);
            if (!focusables.length) {
                event.preventDefault();
                dialogEl.focus();
                return;
            }
            const first = focusables[0];
            const last = focusables[focusables.length - 1];
            if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        };

        modalRootEl.addEventListener('keydown', onKeydown);
        modalState.set(modalRootEl, { restoreTarget, onKeydown });

        const focusTarget = resolveElement(modalRootEl, initialFocus) || heading || dialogEl.querySelector('h1, h2, h3, h4, h5, h6');
        if (focusTarget) {
            if (!resolveElement(modalRootEl, initialFocus) && !focusTarget.hasAttribute('tabindex')) {
                focusTarget.setAttribute('tabindex', '-1');
            }
            focusTarget.focus();
        } else {
            dialogEl.setAttribute('tabindex', '-1');
            dialogEl.focus();
        }
    }

    function close(modalRootEl, { restoreFocus = true } = {}) {
        if (!modalRootEl) return;
        const state = modalState.get(modalRootEl);
        if (!state) return;
        modalRootEl.removeEventListener('keydown', state.onKeydown);
        modalState.delete(modalRootEl);
        if (restoreFocus && state.restoreTarget && document.contains(state.restoreTarget)) {
            state.restoreTarget.focus();
        }
    }

    window.a11yModal = { open, close };
})();
