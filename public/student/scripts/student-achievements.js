/**
 * /student/achievements: the student's own badges, points, streaks and
 * progress in their current course, from the gamification toolkit's
 * <ubc-badge-shelf> (/vendor/gamification-ui.js) on /api/gamification.
 *
 * The shelf hides itself where the student has nothing here (the course
 * hasn't turned gamification on, or the server doesn't run it), and the page
 * says so instead.
 */
(function () {
    'use strict';

    const shelf = document.getElementById('achievements');
    const unavailable = document.getElementById('achievements-unavailable');

    function showUnavailable() {
        if (shelf) shelf.hidden = true;
        if (unavailable) unavailable.hidden = false;
    }

    async function start() {
        if (!shelf) return;
        if (!window.customElements || !customElements.get('ubc-badge-shelf')) {
            showUnavailable();
            return;
        }
        shelf.addEventListener('ubc-gamification-unavailable', showUnavailable);
        await waitForCurrentUser();
        let courseId = getCurrentCourseId();
        if (courseId && typeof courseId.then === 'function') courseId = await courseId;
        if (!courseId) {
            showUnavailable();
            return;
        }
        shelf.setAttribute('course', courseId);
        await shelf.refresh();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
