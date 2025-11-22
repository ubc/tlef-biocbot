/**
 * Student Hub JavaScript
 * Allows instructors to view students per course and toggle enrollment
 */

let instructorCourses = [];
let currentStudents = [];
const dirtyEnrollment = new Map(); // studentId -> boolean (enrolled)

document.addEventListener('DOMContentLoaded', async function() {
    await waitForAuth();
    initializeStudentHub();
    await loadInstructorCourses();
});

function initializeStudentHub() {
    // Course selection is now handled by the home page
    // No need for dropdown change handler
}

async function loadInstructorCourses() {
    try {
        // Get selected course ID from URL or localStorage
        const urlParams = new URLSearchParams(window.location.search);
        const courseIdFromUrl = urlParams.get('courseId');
        const courseIdFromStorage = localStorage.getItem('selectedCourseId');
        const selectedCourseId = courseIdFromUrl || courseIdFromStorage;
        
        // Hide the course selector dropdown
        const courseSelect = document.getElementById('student-course-select');
        const controlsRow = courseSelect?.closest('.controls-row');
        if (controlsRow) {
            controlsRow.style.display = 'none';
        }
        
        if (selectedCourseId) {
            // Load the selected course
            await loadStudents(selectedCourseId);
        } else {
            // Fallback: try to get first course from instructor's courses
            const instructorId = getCurrentInstructorId();
            if (!instructorId) {
                showNotification('No course selected. Please select a course from the home page.', 'error');
                return;
            }

            const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const result = await response.json();
            instructorCourses = result.data?.courses || [];

            if (instructorCourses.length > 0) {
                await loadStudents(instructorCourses[0].courseId);
            } else {
                showNotification('No courses found. Please complete onboarding or select a course from the home page.', 'error');
            }
        }
    } catch (err) {
        console.error('Error loading instructor courses:', err);
        showNotification('Error loading courses. Please try again.', 'error');
    }
}

async function loadStudents(courseId) {
    try {
        const response = await authenticatedFetch(`/api/courses/${courseId}/students`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const result = await response.json();
        currentStudents = result.data?.students || [];
        renderStudents(courseId);
    } catch (err) {
        console.error('Error loading students:', err);
        showNotification('Error loading students. Please try again.', 'error');
    }
}

function renderStudents(courseId) {
    const container = document.getElementById('students-container');
    if (!container) return;

    if (currentStudents.length === 0) {
        container.innerHTML = '<p>No students found for this course yet.</p>';
        return;
    }

    container.innerHTML = currentStudents.map(s => {
        const enrolled = dirtyEnrollment.has(s.userId) ? dirtyEnrollment.get(s.userId) : !!s.enrolled;
        return `
            <div class="student-card">
                <div class="student-header">
                    <h3 class="student-name">${escapeHTML(s.displayName || s.username || s.userId)}</h3>
                    <span class="student-id">${escapeHTML(s.userId)}</span>
                </div>
                <div class="student-info">
                    <p><strong>Username:</strong> ${escapeHTML(s.username || '—')}</p>
                    <p><strong>Email:</strong> ${escapeHTML(s.email || '—')}</p>
                    <p><strong>Last Login:</strong> ${s.lastLogin ? new Date(s.lastLogin).toLocaleString() : '—'}</p>
                </div>
                <div class="student-actions">
                    <label class="enroll-toggle">
                        <input type="checkbox" ${enrolled ? 'checked' : ''} 
                               onchange="toggleEnrollment('${courseId}','${s.userId}', this.checked)">
                        <span>Enrolled in</span>
                    </label>
                    <button class="btn-small btn-secondary" id="save-${s.userId}" disabled
                            onclick="saveEnrollment('${courseId}','${s.userId}')">Save</button>
                </div>
            </div>
        `;
    }).join('');
}

window.toggleEnrollment = function(courseId, studentId, value) {
    dirtyEnrollment.set(studentId, !!value);
    const btn = document.getElementById(`save-${studentId}`);
    if (btn) btn.disabled = false;
};

window.saveEnrollment = async function(courseId, studentId) {
    try {
        const value = dirtyEnrollment.has(studentId) ? dirtyEnrollment.get(studentId) : true;
        const resp = await authenticatedFetch(`/api/courses/${courseId}/student-enrollment/${studentId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enrolled: value })
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        showNotification(`Enrollment ${value ? 'enabled' : 'disabled'} for ${studentId}`, 'success');
        const btn = document.getElementById(`save-${studentId}`);
        if (btn) btn.disabled = true;
    } catch (err) {
        console.error('Error saving enrollment:', err);
        showNotification('Failed to save enrollment. Please try again.', 'error');
    }
};

function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"]+/g, function(s) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
        return map[s] || s;
    });
}

async function waitForAuth() {
    let attempts = 0;
    const maxAttempts = 50;
    while (attempts < maxAttempts) {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) return;
        await new Promise(r => setTimeout(r, 100));
        attempts++;
    }
}

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 6px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: 10px;
        max-width: 400px;
        ${type === 'success' ? 'background-color: #28a745;' : 
          type === 'error' ? 'background-color: #dc3545;' : 
          type === 'warning' ? 'background-color: #ffc107; color: #000;' : 
          'background-color: #17a2b8;'}
    `;
    document.body.appendChild(notification);
    setTimeout(() => { if (notification.parentElement) notification.remove(); }, 5000);
}


