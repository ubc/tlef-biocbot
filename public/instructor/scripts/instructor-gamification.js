/**
 * /instructor/gamification: a course's switch for gamification, and its rule
 * builder (the toolkit's <ubc-rule-builder>, /vendor/gamification-ui.js), on
 * /api/gamification (src/routes/gamification.js).
 *
 * Instructors turn it on and change the rules. TAs see both without changing
 * them. Where the server doesn't run gamification (BIOCBOT_GAMIFICATION unset),
 * the page says so.
 */
(function () {
    'use strict';

    const $ = id => document.getElementById(id);
    const API = '/api/gamification';

    function say(message) {
        const notice = $('gamification-unavailable');
        notice.textContent = message;
        notice.hidden = false;
    }

    function describeState(enabled, canChange) {
        if (enabled) {
            return 'On: students earn badges and points for what they do, and see them under Achievements.';
        }
        return canChange
            ? 'Off: nothing is counted and students see nothing. You can set up rules below first.'
            : 'Off: nothing is counted and students see nothing.';
    }

    function announce(text) {
        const status = $('gamification-switch-status');
        status.textContent = '';
        setTimeout(() => { status.textContent = text; }, 50);
    }

    function showSwitch(courseId, state) {
        const section = $('gamification-switch-section');
        const box = $('gamification-enabled');
        const text = $('gamification-switch-state');
        section.hidden = false;
        box.checked = state.enabled;
        text.textContent = describeState(state.enabled, state.canChange);
        if (!state.canChange) {
            // A TA sees whether it's on, as text: there's no control they can't use.
            box.closest('.gamification-check').hidden = true;
            return;
        }
        box.addEventListener('change', async () => {
            if (box.getAttribute('aria-busy') === 'true') return;
            const wanted = box.checked;
            box.setAttribute('aria-busy', 'true');
            try {
                const response = await fetch(`${API}/courses/${encodeURIComponent(courseId)}/enabled`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled: wanted })
                });
                const body = await response.json().catch(() => ({}));
                if (!response.ok) throw new Error(body.error || response.statusText);
                text.textContent = describeState(body.enabled, true);
                announce(body.enabled ? 'Gamification is now on in this course.' : 'Gamification is now off in this course.');
            } catch (error) {
                box.checked = !wanted;
                announce(`The switch didn't change: ${error.message}`);
            } finally {
                box.removeAttribute('aria-busy');
                box.focus();
            }
        });
    }

    async function start() {
        await waitForCurrentUser();
        let courseId = getCurrentCourseId();
        if (courseId && typeof courseId.then === 'function') courseId = await courseId;
        if (!courseId) {
            say('Choose a course on the Home page first.');
            return;
        }
        let state;
        try {
            const response = await fetch(`${API}/courses/${encodeURIComponent(courseId)}/enabled`);
            if (response.status === 404) {
                say("Gamification isn't running on this server.");
                return;
            }
            state = await response.json();
            if (state.running === false) {
                say("Gamification isn't running on this server.");
                return;
            }
            if (!response.ok) {
                say(state.error || "You can't see gamification in this course.");
                return;
            }
        } catch (error) {
            say("Gamification couldn't be loaded. Try again in a moment.");
            return;
        }
        showSwitch(courseId, state);

        const builder = $('gamification-builder');
        if (!window.customElements || !customElements.get('ubc-rule-builder')) {
            say("The rule builder couldn't be loaded.");
            return;
        }
        if (!state.canChange) builder.setAttribute('readonly', '');
        builder.setAttribute('course', courseId);
        builder.hidden = false;
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
