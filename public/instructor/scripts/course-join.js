(function exposeCourseJoinApi(global) {
    async function joinInstructorCourse({ courseId, instructorId, code = '' }) {
        const response = await fetch(`/api/courses/${encodeURIComponent(courseId)}/instructors`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ instructorId, code })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || result.error || 'Failed to join course');
        }
        return result;
    }

    global.BiocBotCourseJoin = Object.freeze({ joinInstructorCourse });
})(window);
