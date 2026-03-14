/**
 * Student Hub JavaScript
 * Allows instructors to view students per course and toggle enrollment
 */

let instructorCourses = [];
let currentStudents = [];
let currentTAs = []; // Store TAs for the current course
const dirtyEnrollment = new Map(); // studentId -> boolean (enrolled)

document.addEventListener('DOMContentLoaded', async function() {
    await waitForAuth();

    // Check if anonymize students is enabled - redirect away if so
    try {
        const courseId = getCurrentCourseId();
        if (courseId) {
            const anonRes = await fetch(`/api/settings/anonymize-students?courseId=${courseId}`);
            const anonData = await anonRes.json();
            if (anonData.success && anonData.enabled) {
                window.location.href = '/instructor/home';
                return;
            }
        }
    } catch (e) {
        // On error, continue loading normally
    }

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
        // 1. Fetch Students
        const studentsResponse = await authenticatedFetch(`/api/courses/${courseId}/students`);
        if (!studentsResponse.ok) throw new Error(`HTTP ${studentsResponse.status}`);
        const studentsResult = await studentsResponse.json();
        const students = studentsResult.data?.students || [];
        console.log('🔍 [STUDENT_HUB] Loaded students:', students);

        // 2. Fetch TAs for this course
        // We need to get the course details to see the TA list, then fetch TA details
        // Or we can fetch all TAs and filter. Let's try to be efficient.
        // Since we don't have a direct "get TAs for course" endpoint that returns full details,
        // we'll use the same approach as ta-hub.js: fetch all TAs and filter.
        
        let courseTAs = [];
        try {
            // Get course details to find assigned TA IDs
            const courseResponse = await authenticatedFetch(`/api/onboarding/${courseId}`);
            if (courseResponse.ok) {
                const courseResult = await courseResponse.json();
                const taIds = courseResult.data?.tas || [];
                
                if (taIds.length > 0) {
                    // Fetch all TAs to get details
                    const allTAsResponse = await authenticatedFetch('/api/auth/tas');
                    if (allTAsResponse.ok) {
                        const allTAsResult = await allTAsResponse.json();
                        const allTAs = allTAsResult.data || [];
                        courseTAs = allTAs.filter(ta => taIds.includes(ta.userId));
                    }
                }
            }
        } catch (taErr) {
            console.error('Error loading TAs:', taErr);
            // Continue with just students if TA load fails
        }

        // 3. Merge lists
        // Mark TAs with isTA property
        currentTAs = courseTAs.map(ta => ({ ...ta, isTA: true }));
        
        // Filter out students who are also TAs (to avoid duplicates if backend returns them in both)
        // or if we want to show them as TAs.
        const taIds = new Set(currentTAs.map(ta => ta.userId));
        const uniqueStudents = students.filter(s => !taIds.has(s.userId));
        
        // Combine: TAs first or mixed? User said "keep the student box from the TA in there".
        // Let's put TAs at the top for visibility, or sort alphabetically.
        // Let's just combine them.
        currentStudents = [...currentTAs, ...uniqueStudents];
        
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
        const isTA = !!s.isTA;
        
        return `
            <div class="student-card ${isTA ? 'ta-card' : ''}" style="${isTA ? 'border-left: 4px solid #17a2b8;' : ''}">
                <div class="student-header">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <h3 class="student-name">${escapeHTML(s.displayName || s.username || s.userId)}</h3>
                        ${isTA ? '<span class="badge badge-info" style="background: #17a2b8; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8em;">TA</span>' : ''}
                    </div>
                </div>
                <div class="student-info">
                    <p><strong>Username:</strong> ${escapeHTML(s.username || '—')}</p>
                    <p><strong>Email:</strong> ${escapeHTML(s.email || '—')}</p>
                    <p><strong>Last Login:</strong> ${s.lastLogin ? new Date(s.lastLogin).toLocaleString() : '—'}</p>
                    
                    <!-- Struggle Topics Section -->
                    <div class="struggle-topics-section" style="margin-top: 15px; border-top: 1px solid #eee; padding-top: 10px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <strong>Struggle Topics</strong>
                            ${s.struggleState && s.struggleState.topics && s.struggleState.topics.length > 0 
                                ? `<button class="btn-small btn-secondary download-struggle-btn" 
                                     onclick="downloadStruggleReport('${escapeHTML(s.userId)}', '${escapeHTML(s.displayName || s.username)}')">
                                     Download Report
                                   </button>` 
                                : ''
                            }
                        </div>
                        
                        ${renderStruggleTopics(s.struggleState)}
                    </div>
                </div>
                <div class="student-actions">
                    <label class="enroll-toggle">
                        <input type="checkbox" ${enrolled ? 'checked' : ''} 
                               onchange="toggleEnrollment('${courseId}','${s.userId}', this.checked)">
                        <span>Enrolled</span>
                    </label>
                    <button class="btn-small btn-secondary" id="save-${s.userId}" disabled
                            onclick="saveEnrollment('${courseId}','${s.userId}')">Save</button>
                    
                    ${isTA ? `
                        <button class="btn-small btn-danger" onclick="demoteFromTA('${s.userId}', '${escapeHTML(s.displayName || s.username)}')">
                            Demote from TA
                        </button>
                    ` : s.role === 'ta' ? `
                         <button class="btn-small btn-secondary" disabled style="opacity: 0.7; cursor: default;">
                            Pending TA joining course
                        </button>
                    ` : `
                        <button class="btn-small btn-primary" onclick="promoteToTA('${s.userId}', '${escapeHTML(s.displayName || s.username)}', '${courseId}')">
                            Promote to TA
                        </button>
                    `}
                </div>
            </div>
        `;
    }).join('');
}

window.promoteToTA = async function(studentId, studentName, courseId) {
    if (!courseId) {
        courseId = localStorage.getItem('selectedCourseId');
    }

    if (!confirm(`Are you sure you want to promote ${studentName} to a Teaching Assistant? This will give them TA permissions.`)) {
        return;
    }

    try {
        const resp = await authenticatedFetch('/api/auth/promote-to-ta', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userId: studentId, courseId: courseId })
        });

        if (!resp.ok) {
            const errorData = await resp.json();
            throw new Error(errorData.message || `HTTP ${resp.status}`);
        }

        showNotification(`Successfully promoted ${studentName} to TA`, 'success');
        
        // Reload students list to reflect changes (promoted student should ideally disappear or be marked)
        // Since this view shows "students", a TA might not show up here anymore depending on backend logic, 
        // or will show up but now have role='ta'. 
        // For now, we reload the list.
        const selectedCourseId = localStorage.getItem('selectedCourseId');
        if (selectedCourseId) {
            await loadStudents(selectedCourseId);
        }

    } catch (err) {
        console.error('Error promoting to TA:', err);
        showNotification(`Failed to promote to TA: ${err.message}`, 'error');
    }
};

window.demoteFromTA = async function(studentId, studentName) {
    if (!confirm(`Are you sure you want to demote ${studentName} from Teaching Assistant? They will lose TA permissions.`)) {
        return;
    }

    try {
        // Using the same endpoint as TA Hub to remove TA
        const resp = await authenticatedFetch(`/api/auth/tas/${studentId}`, {
            method: 'DELETE'
        });

        if (!resp.ok) {
            const errorData = await resp.json();
            throw new Error(errorData.message || `HTTP ${resp.status}`);
        }

        showNotification(`Successfully demoted ${studentName} from TA`, 'success');
        
        // Reload students list
        const selectedCourseId = localStorage.getItem('selectedCourseId');
        if (selectedCourseId) {
            await loadStudents(selectedCourseId);
        }

    } catch (err) {
        console.error('Error demoting from TA:', err);
        showNotification(`Failed to demote from TA: ${err.message}`, 'error');
    }
};

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

/**
 * Render struggle topics list
 */
function renderStruggleTopics(struggleState) {
    if (!struggleState || !struggleState.topics || struggleState.topics.length === 0) {
        return '<p style="color: #666; font-style: italic; font-size: 0.9em;">No active struggle topics.</p>';
    }

    const sortedTopics = struggleState.topics.sort((a, b) => new Date(b.lastStruggle) - new Date(a.lastStruggle));

    return `
        <ul style="list-style: none; padding: 0; margin: 0; max-height: 150px; overflow-y: auto;">
            ${sortedTopics.map(t => `
                <li style="padding: 4px 8px; margin-bottom: 4px; background: #f8f9fa; border-radius: 4px; border-left: 3px solid ${t.isActive ? '#dc3545' : '#28a745'}; font-size: 0.9em; display: flex; justify-content: space-between; align-items: center;">
                    <span>${capitalize(t.topic)}</span>
                    <div style="display: flex; gap: 8px; font-size: 0.85em; color: #555;">
                        <span>Count: ${t.count}</span>
                        <span>${t.lastStruggle ? new Date(t.lastStruggle).toLocaleDateString() : 'N/A'}</span>
                    </div>
                </li>
            `).join('')}
        </ul>
    `;
}

/**
 * Handle download of struggle report
 */
window.downloadStruggleReport = function(studentId, studentName) {
    const student = currentStudents.find(s => s.userId === studentId);
    if (!student || !student.struggleState || !student.struggleState.topics) {
        showNotification('No struggle data available for this student.', 'warning');
        return;
    }

    const topics = student.struggleState.topics.sort((a, b) => new Date(b.lastStruggle) - new Date(a.lastStruggle));
    
    let markdown = `# Struggle Report: ${studentName}\n`;
    markdown += `Generated on: ${new Date().toLocaleString()}\n\n`;
    
    if (topics.length === 0) {
        markdown += `No struggle topics recorded.\n`;
    } else {
        markdown += `## Active Struggle Topics\n\n`;
        markdown += `| Topic | Struggle Count | Last Occurred | Status |\n`;
        markdown += `|-------|----------------|---------------|--------|\n`;
        
        topics.forEach(t => {
            const status = t.isActive ? '**Directive Mode Active**' : 'Monitoring';
            const date = new Date(t.lastStruggle).toLocaleString();
            markdown += `| ${capitalize(t.topic)} | ${t.count} | ${date} | ${status} |\n`;
        });
        
        markdown += `\n## Details\n\n`;
        topics.forEach(t => {
            markdown += `### ${capitalize(t.topic)}\n`;
            markdown += `- **Count**: ${t.count}\n`;
            markdown += `- **Last Struggle**: ${new Date(t.lastStruggle).toLocaleString()}\n`;
            markdown += `- **Status**: ${t.isActive ? 'Active' : 'Resolved/Monitoring'}\n\n`;
        });
    }

    // Trigger download
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Struggle_Report_${studentName.replace(/\s+/g, '_')}_${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Report downloaded successfully.', 'success');
};

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}


