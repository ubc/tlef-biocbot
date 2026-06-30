/**
 * Student Hub JavaScript
 * Allows instructors to view students per course and toggle enrollment
 */

let instructorCourses = [];
let currentStudents = [];
let currentTAs = []; // Store TAs for the current course
let anonymizeStudentsEnabled = false;
let currentSurveyCourseId = null;
let currentSurveyResponses = [];
let currentSurveyStats = null;
const dirtyEnrollment = new Map(); // studentId -> boolean (enrolled)

document.addEventListener('DOMContentLoaded', async function() {
    await waitForAuth();

    initializeStudentHub();
    await loadInstructorCourses();
});

function initializeStudentHub() {
    // Course selection is now handled by the home page
    // No need for dropdown change handler
    const surveyStatusFilter = document.getElementById('survey-status-filter');
    if (surveyStatusFilter) {
        surveyStatusFilter.addEventListener('change', () => {
            if (currentSurveyCourseId) {
                loadChatSurveyResponses(currentSurveyCourseId);
            }
        });
    }

    const refreshSurveyButton = document.getElementById('refresh-survey-responses');
    if (refreshSurveyButton) {
        refreshSurveyButton.addEventListener('click', () => {
            if (currentSurveyCourseId) {
                loadChatSurveyResponses(currentSurveyCourseId);
            }
        });
    }

    const downloadSurveyButton = document.getElementById('download-survey-responses');
    if (downloadSurveyButton) {
        downloadSurveyButton.addEventListener('click', downloadChatSurveyResponses);
    }
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
        await loadAnonymizeStudentsSetting(courseId);

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
        await loadChatSurveyResponses(courseId);
    } catch (err) {
        console.error('Error loading students:', err);
        showNotification('Error loading students. Please try again.', 'error');
    }
}

async function loadChatSurveyResponses(courseId) {
    currentSurveyCourseId = courseId;
    const statusEl = document.getElementById('survey-responses-status');
    const container = document.getElementById('survey-responses-container');
    const downloadButton = document.getElementById('download-survey-responses');

    if (statusEl) {
        statusEl.textContent = 'Loading survey responses...';
        statusEl.classList.remove('error');
        statusEl.style.display = 'block';
    }
    if (container) {
        container.innerHTML = '';
    }
    if (downloadButton) {
        downloadButton.disabled = true;
    }

    try {
        const statusFilter = document.getElementById('survey-status-filter')?.value || 'all';
        const params = new URLSearchParams({ limit: '100' });
        if (statusFilter !== 'all') {
            params.set('status', statusFilter);
        }

        const response = await authenticatedFetch(`/api/chat/survey/course/${encodeURIComponent(courseId)}?${params.toString()}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const result = await response.json();
        if (!result.success) {
            throw new Error(result.message || 'Failed to load survey responses');
        }

        currentSurveyResponses = result.data?.responses || [];
        currentSurveyStats = result.data?.stats || null;
        renderSurveyStats(currentSurveyStats);
        renderSurveyResponses(currentSurveyResponses);
    } catch (err) {
        console.error('Error loading chat survey responses:', err);
        currentSurveyResponses = [];
        currentSurveyStats = null;
        renderSurveyStats(null);
        if (statusEl) {
            statusEl.textContent = 'Could not load survey responses. Please try again.';
            statusEl.classList.add('error');
            statusEl.style.display = 'block';
        }
    } finally {
        if (downloadButton) {
            downloadButton.disabled = !currentSurveyCourseId;
        }
    }
}

function renderSurveyStats(stats) {
    const shownEl = document.getElementById('survey-stat-shown');
    const submittedEl = document.getElementById('survey-stat-submitted');
    const dismissedEl = document.getElementById('survey-stat-dismissed');
    const accuracyEl = document.getElementById('survey-stat-average-accuracy');
    const satisfactionEl = document.getElementById('survey-stat-average-satisfaction');

    if (shownEl) shownEl.textContent = String(stats?.shown || 0);
    if (submittedEl) submittedEl.textContent = String(stats?.submitted || 0);
    if (dismissedEl) dismissedEl.textContent = String(stats?.dismissed || 0);
    if (accuracyEl) {
        accuracyEl.textContent = typeof stats?.averageAccuracy === 'number'
            ? `${stats.averageAccuracy.toFixed(1)}/5`
            : '--';
    }
    if (satisfactionEl) {
        satisfactionEl.textContent = typeof stats?.averageSatisfaction === 'number'
            ? `${stats.averageSatisfaction.toFixed(1)}/5`
            : '--';
    }
}

function renderSurveyResponses(responses) {
    const statusEl = document.getElementById('survey-responses-status');
    const container = document.getElementById('survey-responses-container');
    if (!container) return;

    if (!responses.length) {
        container.innerHTML = '';
        if (statusEl) {
            statusEl.textContent = 'No survey responses for this course yet.';
            statusEl.classList.remove('error');
            statusEl.style.display = 'block';
        }
        return;
    }

    if (statusEl) {
        statusEl.style.display = 'none';
    }

    container.innerHTML = responses.map(response => {
        const status = response.submittedAt ? 'Submitted' : response.dismissedAt ? 'Dismissed' : 'Shown';
        const formatRating = (value) => typeof value === 'number' ? `${value}/5` : '--';
        const accuracyRating = formatRating(response.ratingAccuracy);
        const satisfactionRating = formatRating(response.ratingSatisfaction);
        const accuracyPrompt = response.accuracyPrompt || response.settingsSnapshot?.accuracyPrompt || 'Accuracy';
        const satisfactionPrompt = response.satisfactionPrompt || response.settingsSnapshot?.satisfactionPrompt || 'Satisfaction';
        const studentName = response.studentName || response.studentId || 'Unknown student';
        const updatedAt = response.updatedAt || response.submittedAt || response.dismissedAt || response.shownAt || response.createdAt;
        const comment = response.comment || '';

        return `
            <article class="survey-response-card">
                <div class="survey-response-main">
                    <div>
                        <h3>${escapeHTML(studentName)}</h3>
                        <p class="survey-response-meta">
                            ${escapeHTML(response.unitName || 'Unknown unit')} &middot; Session ${escapeHTML(shortenId(response.conversationId))}
                        </p>
                    </div>
                    <div class="survey-response-rating">
                        <span class="survey-status-pill ${status.toLowerCase()}">${escapeHTML(status)}</span>
                    </div>
                </div>
                <dl class="survey-response-details">
                    <div>
                        <dt>${escapeHTML(accuracyPrompt)}</dt>
                        <dd>${escapeHTML(accuracyRating)}</dd>
                    </div>
                    <div>
                        <dt>${escapeHTML(satisfactionPrompt)}</dt>
                        <dd>${escapeHTML(satisfactionRating)}</dd>
                    </div>
                    <div>
                        <dt>Messages at prompt</dt>
                        <dd>${response.messageCountAtPrompt ?? '—'}</dd>
                    </div>
                    <div>
                        <dt>Last updated</dt>
                        <dd>${escapeHTML(formatDateTime(updatedAt))}</dd>
                    </div>
                </dl>
                ${comment ? `<p class="survey-response-comment">${escapeHTML(comment)}</p>` : ''}
            </article>
        `;
    }).join('');
}

async function downloadChatSurveyResponses() {
    if (!currentSurveyCourseId) {
        showNotification('No course selected for survey export.', 'warning');
        return;
    }

    const downloadButton = document.getElementById('download-survey-responses');
    const previousText = downloadButton ? downloadButton.textContent : '';
    if (downloadButton) {
        downloadButton.disabled = true;
        downloadButton.textContent = 'Downloading...';
    }

    try {
        const statusFilter = document.getElementById('survey-status-filter')?.value || 'all';
        const params = new URLSearchParams({ limit: '1000' });
        if (statusFilter !== 'all') {
            params.set('status', statusFilter);
        }

        const response = await authenticatedFetch(`/api/chat/survey/course/${encodeURIComponent(currentSurveyCourseId)}/export?${params.toString()}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const csv = await response.blob();
        const url = URL.createObjectURL(csv);
        const a = document.createElement('a');
        a.href = url;
        a.download = `chat-survey-responses-${currentSurveyCourseId}-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showNotification('Survey responses downloaded.', 'success');
    } catch (err) {
        console.error('Error downloading chat survey responses:', err);
        showNotification('Failed to download survey responses. Please try again.', 'error');
    } finally {
        if (downloadButton) {
            downloadButton.disabled = false;
            downloadButton.textContent = previousText || 'Download CSV';
        }
    }
}

async function loadAnonymizeStudentsSetting(courseId) {
    anonymizeStudentsEnabled = false;

    if (!courseId) {
        return;
    }

    try {
        const anonRes = await fetch(`/api/settings/anonymize-students?courseId=${courseId}`);
        const anonData = await anonRes.json();
        anonymizeStudentsEnabled = anonData.success && anonData.enabled === true;
    } catch (e) {
        anonymizeStudentsEnabled = false;
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
        const hasPendingTAInvite = !isTA && s.role === 'ta' && Array.isArray(s.invitedCourses) && s.invitedCourses.includes(courseId);
        const taInviteButtonLabel = s.role === 'ta' ? 'Invite to TA Course' : 'Promote to TA';
        const struggleTopicsSection = anonymizeStudentsEnabled ? '' : `
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
        `;
        
        return `
            <div class="student-card ${isTA ? 'ta-card' : ''}" style="${isTA ? 'border-left: 4px solid #17a2b8;' : ''}">
                <div class="student-header">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <h3 class="student-name">${escapeHTML(s.displayName || s.username || s.userId)}</h3>
                        ${isTA ? '<span class="badge badge-info" style="background: #117a8b; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.8em;">TA</span>' : ''}
                    </div>
                </div>
                <div class="student-info">
                    <p><strong>Username:</strong> ${escapeHTML(s.username || '—')}</p>
                    <p><strong>Email:</strong> ${escapeHTML(s.email || '—')}</p>
                    <p><strong>Last Login:</strong> ${s.lastLogin ? new Date(s.lastLogin).toLocaleString() : '—'}</p>
                    ${struggleTopicsSection}
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
                        <button class="btn-small btn-danger" onclick="demoteFromTA('${s.userId}', '${escapeHTML(s.displayName || s.username)}', '${courseId}')">
                            Demote from TA
                        </button>
                    ` : hasPendingTAInvite ? `
                         <button class="btn-small btn-secondary" disabled style="opacity: 0.7; cursor: default;">
                            Pending TA joining course
                        </button>
                    ` : `
                        <button class="btn-small btn-primary" onclick="promoteToTA('${s.userId}', '${escapeHTML(s.displayName || s.username)}', '${courseId}')">
                            ${taInviteButtonLabel}
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

    const isExistingTA = currentStudents.some(s => s.userId === studentId && s.role === 'ta');
    const confirmMessage = isExistingTA
        ? `Invite ${studentName} to join this course as a Teaching Assistant?`
        : `Are you sure you want to promote ${studentName} to a Teaching Assistant? This will give them TA permissions.`;

    if (!confirm(confirmMessage)) {
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

        showNotification(isExistingTA ? `Successfully invited ${studentName} to join this course as TA` : `Successfully promoted ${studentName} to TA`, 'success');
        
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

window.demoteFromTA = async function(studentId, studentName, courseId) {
    // Prefer the courseId passed in from the rendered card (matches the
    // visible URL course), then fall back to URL ?courseId=, then to storage.
    let selectedCourseId = courseId;
    if (!selectedCourseId) {
        const urlParams = new URLSearchParams(window.location.search);
        selectedCourseId = urlParams.get('courseId') || localStorage.getItem('selectedCourseId');
    }

    if (!selectedCourseId) {
        showNotification('No course selected. Please select a course first.', 'error');
        return;
    }

    if (!confirm(`Remove ${studentName} as a Teaching Assistant from this course? They will stay a TA in any other courses.`)) {
        return;
    }

    try {
        const resp = await authenticatedFetch(`/api/courses/${selectedCourseId}/tas/${studentId}`, {
            method: 'DELETE'
        });

        if (!resp.ok) {
            const errorData = await resp.json();
            throw new Error(errorData.message || `HTTP ${resp.status}`);
        }

        showNotification(`Successfully removed ${studentName} as TA from this course`, 'success');

        await loadStudents(selectedCourseId);

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

function shortenId(value) {
    const text = String(value || '');
    if (!text) return 'unknown';
    if (text.length <= 16) return text;
    return `${text.slice(0, 8)}...${text.slice(-4)}`;
}

function formatDateTime(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString();
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
