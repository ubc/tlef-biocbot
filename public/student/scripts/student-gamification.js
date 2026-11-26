/**
 * Award toasts on the student's chat and quiz pages: the gamification
 * toolkit's <ubc-award-toast> (/vendor/gamification-ui.js), which compares the
 * student's awards with the last look and says what's new.
 *
 * It's set up only where the server runs gamification and the student's
 * course has it on (src/routes/gamification.js). After that, each time the
 * page's events (biocbot-events.js) say BiocBot answered
 * (`chat.reply.received`) or a practice answer was saved
 * (`quiz.answer.saved`), it checks for new awards. The first check only
 * remembers, so nothing earned before shows up as new.
 */
(function () {
    'use strict';

    const toast = document.querySelector('ubc-award-toast');
    if (!toast) return;

    // Counting happens just after the server answers, so look a moment later.
    const SETTLE_MS = 800;

    async function setUp() {
        if (!window.customElements || !customElements.get('ubc-award-toast')) return false;
        await waitForCurrentUser();
        let courseId = getCurrentCourseId();
        if (courseId && typeof courseId.then === 'function') courseId = await courseId;
        if (!courseId) return false;
        try {
            const response = await fetch(`/api/gamification/courses/${encodeURIComponent(courseId)}/enabled`);
            if (!response.ok) return false;
            const state = await response.json();
            if (state.running === false || !state.enabled) return false;
        } catch (error) {
            return false;
        }
        toast.setAttribute('course', courseId);
        await toast.check();
        return true;
    }

    const ready = new Promise(resolve => {
        const start = () => setUp().then(resolve, () => resolve(false));
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
        else start();
    });

    async function look() {
        if (!(await ready)) return;
        setTimeout(() => { toast.check(); }, SETTLE_MS);
    }
    BiocbotEvents.subscribe('chat.reply.received', look);
    BiocbotEvents.subscribe('quiz.answer.saved', look);
})();
