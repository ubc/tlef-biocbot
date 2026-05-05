/**
 * TA Home Page JavaScript
 * Handles the TA dashboard functionality
 */

let taCourses = [];
let taPermissions = {};
let selectedTACourseId = null;

function escapeHtml(value) {
    const div = document.createElement('div');
    div.textContent = value == null ? '' : String(value);
    return div.innerHTML;
}

function isCourseInactive(course = {}) {
    return (course.status || 'active') === 'inactive';
}

function getCourseDisplayName(course = {}) {
    const courseName = course.courseName || course.courseId || 'Untitled Course';
    return isCourseInactive(course) ? `${courseName} (Inactive)` : courseName;
}

function getCourseById(courseId) {
    return taCourses.find(course => course.courseId === courseId) || null;
}

function getSelectedTACourse() {
    return getCourseById(selectedTACourseId);
}

function getInitialSelectedCourseId() {
    const urlParams = new URLSearchParams(window.location.search);
    const candidates = [
        urlParams.get('courseId'),
        localStorage.getItem('selectedCourseId'),
        getCurrentUser()?.preferences?.courseId
    ];

    return candidates.find(courseId => courseId && getCourseById(courseId)) || taCourses[0]?.courseId || null;
}

function buildCourseUrl(path, courseId) {
    const url = new URL(path, window.location.origin);
    url.searchParams.set('courseId', courseId);
    return url.pathname + url.search;
}

function updateTAHomeUrl(courseId) {
    const url = new URL(window.location.href);
    if (courseId) {
        url.searchParams.set('courseId', courseId);
    } else {
        url.searchParams.delete('courseId');
    }
    window.history.replaceState({}, '', url.pathname + url.search);
}

function getCoursePermission(courseId, feature) {
    if (!courseId || !getCourseById(courseId)) {
        return false;
    }

    const permissions = taPermissions[courseId] || {};
    if (feature === 'courses') {
        return permissions.canAccessCourses !== false;
    }
    if (feature === 'flags') {
        return permissions.canAccessFlags !== false;
    }

    return false;
}

function hasPermissionForFeature(feature) {
    return getCoursePermission(selectedTACourseId, feature);
}

document.addEventListener('DOMContentLoaded', async function() {
    await waitForAuth();

    await loadTACourses();
    await loadTAPermissions();
    await initializeCoursePicker();

    displayTACourses();
    initializeDashboard();
});

/**
 * Load TA permissions for all courses
 */
async function loadTAPermissions() {
    try {
        const taId = getCurrentInstructorId();
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return;
        }

        taPermissions = {};

        for (const course of taCourses) {
            const response = await authenticatedFetch(`/api/courses/${course.courseId}/ta-permissions/${taId}`);

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    taPermissions[course.courseId] = result.data.permissions;
                }
            }
        }

        console.log('TA permissions loaded:', taPermissions);
    } catch (error) {
        console.error('Error loading TA permissions:', error);
    }
}

/**
 * Initialize dashboard functionality
 */
function initializeDashboard() {
    setupMyCoursesLink();
    setupStudentSupportLink();
    setupQuickActionsLinks();
    updateNavigationBasedOnPermissions();
    console.log('TA Dashboard initialized');
}

async function initializeCoursePicker() {
    const pickerSection = document.getElementById('ta-course-picker-section');
    const courseSelect = document.getElementById('ta-course-select');

    if (!pickerSection || !courseSelect) {
        return;
    }

    if (taCourses.length === 0) {
        pickerSection.style.display = 'none';
        selectedTACourseId = null;
        updateTAHomeUrl(null);
        return;
    }

    pickerSection.style.display = 'block';
    populateCourseDropdown(courseSelect);

    courseSelect.addEventListener('change', async (event) => {
        const courseId = event.target.value;
        if (!courseId) {
            return;
        }

        await setSelectedTACourse(courseId, { showMessage: true });
    });

    await setSelectedTACourse(getInitialSelectedCourseId(), { showMessage: false });
}

function populateCourseDropdown(courseSelect) {
    courseSelect.innerHTML = '';

    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = 'Choose a course...';
    courseSelect.appendChild(placeholder);

    appendCourseOptions(courseSelect, 'Active Courses', taCourses.filter(course => !isCourseInactive(course)));
    appendCourseOptions(courseSelect, 'Inactive Courses', taCourses.filter(isCourseInactive));
}

function appendCourseOptions(courseSelect, label, courses) {
    if (courses.length === 0) {
        return;
    }

    const group = document.createElement('optgroup');
    group.label = label;

    courses.forEach(course => {
        const option = document.createElement('option');
        option.value = course.courseId;
        option.textContent = getCourseDisplayName(course);
        group.appendChild(option);
    });

    courseSelect.appendChild(group);
}

async function setSelectedTACourse(courseId, options = {}) {
    const course = getCourseById(courseId);
    if (!course) {
        return;
    }

    selectedTACourseId = course.courseId;
    localStorage.setItem('selectedCourseId', course.courseId);
    updateTAHomeUrl(course.courseId);

    const courseSelect = document.getElementById('ta-course-select');
    if (courseSelect) {
        courseSelect.value = course.courseId;
    }

    updateSelectedCourseSummary();
    updateNavigationBasedOnPermissions();
    displayTACourses();

    if (typeof setCurrentCourseId === 'function') {
        setCurrentCourseId(course.courseId).catch(error => {
            console.warn('Failed to sync selected TA course to user preferences:', error);
        });
    }

    if (options.showMessage) {
        showNotification(`Selected ${getCourseDisplayName(course)}`, 'success');
    }
}

function updateSelectedCourseSummary() {
    const course = getSelectedTACourse();
    const nameElement = document.getElementById('selected-course-name');
    const idElement = document.getElementById('selected-course-id');
    const statusElement = document.getElementById('selected-course-status');

    if (!course) {
        if (nameElement) nameElement.textContent = 'No course selected';
        if (idElement) idElement.textContent = '-';
        if (statusElement) {
            statusElement.textContent = 'Active';
            statusElement.className = 'course-status active';
        }
        return;
    }

    const inactive = isCourseInactive(course);
    if (nameElement) nameElement.textContent = getCourseDisplayName(course);
    if (idElement) idElement.textContent = course.courseId;
    if (statusElement) {
        statusElement.textContent = inactive ? 'Inactive' : 'Active';
        statusElement.className = `course-status ${inactive ? 'inactive' : 'active'}`;
    }
}

/**
 * Update navigation based on selected-course TA permissions
 */
function updateNavigationBasedOnPermissions() {
    const course = getSelectedTACourse();
    const canAccessCourses = !!course && hasPermissionForFeature('courses');
    const canAccessFlags = !!course && hasPermissionForFeature('flags');

    setNavLinkVisible(document.getElementById('my-courses-link'), canAccessCourses);
    setNavLinkVisible(document.getElementById('student-support-link'), canAccessFlags);

    const quickCoursesLink = document.getElementById('quick-courses-link');
    if (quickCoursesLink) {
        quickCoursesLink.style.display = canAccessCourses ? 'block' : 'none';
        if (course) {
            quickCoursesLink.href = buildCourseUrl('/instructor/documents', course.courseId);
        }
    }

    const quickSupportLink = document.getElementById('quick-support-link');
    if (quickSupportLink) {
        quickSupportLink.style.display = canAccessFlags ? 'block' : 'none';
        if (course) {
            quickSupportLink.href = buildCourseUrl('/instructor/flagged', course.courseId);
        }
    }
}

function setNavLinkVisible(link, isVisible) {
    if (!link) {
        return;
    }

    const listItem = link.closest('li');
    const target = listItem || link;
    target.style.display = isVisible ? '' : 'none';
}

/**
 * Setup My Courses link to navigate to the selected assigned course
 */
function setupMyCoursesLink() {
    const myCoursesLink = document.getElementById('my-courses-link');
    if (myCoursesLink) {
        myCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            navigateToSelectedCourse('courses', '/instructor/documents', 'Course Upload');
        });
    }
}

/**
 * Setup Student Support link to navigate to the selected assigned course's flagged content
 */
function setupStudentSupportLink() {
    const studentSupportLink = document.getElementById('student-support-link');
    if (studentSupportLink) {
        studentSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            navigateToSelectedCourse('flags', '/instructor/flagged', 'Student Flags');
        });
    }
}

/**
 * Setup Quick Actions links to navigate with proper course context
 */
function setupQuickActionsLinks() {
    const quickCoursesLink = document.getElementById('quick-courses-link');
    if (quickCoursesLink) {
        quickCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            navigateToSelectedCourse('courses', '/instructor/documents', 'Course Upload');
        });
    }

    const quickSupportLink = document.getElementById('quick-support-link');
    if (quickSupportLink) {
        quickSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            navigateToSelectedCourse('flags', '/instructor/flagged', 'Student Flags');
        });
    }
}

function navigateToSelectedCourse(feature, targetPath, featureName) {
    const course = getSelectedTACourse();

    if (taCourses.length === 0) {
        showNotification('No courses assigned. Contact an instructor to be added to a course.', 'warning');
        return;
    }

    if (!course) {
        showNotification('Select a course first.', 'warning');
        return;
    }

    if (!getCoursePermission(course.courseId, feature)) {
        showNotification(`You do not have permission to access ${featureName} for this course. Contact your instructor.`, 'error');
        return;
    }

    localStorage.setItem('selectedCourseId', course.courseId);
    window.location.href = buildCourseUrl(targetPath, course.courseId);
}

/**
 * Load courses for the TA
 */
async function loadTACourses() {
    try {
        const taId = getCurrentInstructorId();
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return;
        }

        console.log(`Loading courses for TA: ${taId}`);

        const response = await authenticatedFetch(`/api/courses/ta/${taId}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const result = await response.json();

        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch TA courses');
        }

        taCourses = result.data || [];
        console.log('TA courses loaded:', taCourses);
    } catch (error) {
        console.error('Error loading TA courses:', error);
        showNotification('Error loading courses. Please try again.', 'error');
    }
}

/**
 * Display TA courses on the dashboard
 */
function displayTACourses() {
    const coursesContainer = document.getElementById('courses-container');

    if (!coursesContainer) {
        console.error('Courses container not found');
        return;
    }

    if (taCourses.length === 0) {
        coursesContainer.innerHTML = `
            <div class="no-courses-message">
                <h3>No courses assigned</h3>
                <p>You haven't been assigned to any courses yet. Contact an instructor to be added to a course.</p>
                <a href="/ta/onboarding" class="btn-primary">Join a Course</a>
            </div>
        `;
        return;
    }

    coursesContainer.innerHTML = taCourses.map(course => {
        const canAccessCourses = getCoursePermission(course.courseId, 'courses');
        const canAccessFlags = getCoursePermission(course.courseId, 'flags');
        const isInactive = isCourseInactive(course);
        const isSelected = selectedTACourseId === course.courseId;
        const statusLabel = isInactive ? 'Inactive' : 'Active';

        return `
        <div class="course-card ${isSelected ? 'selected' : ''}" data-course-id="${escapeHtml(course.courseId)}" role="button" tabindex="0" aria-pressed="${isSelected}">
            <div class="course-header">
                <h3>${escapeHtml(getCourseDisplayName(course))}</h3>
                <span class="course-status ${isInactive ? 'inactive' : 'active'}">${statusLabel}</span>
            </div>
            <div class="course-info">
                <p><strong>Course ID:</strong> ${escapeHtml(course.courseId)}</p>
                <p><strong>Instructor:</strong> ${escapeHtml(course.instructorId || 'Unknown')}</p>
                <p><strong>Units:</strong> ${escapeHtml(course.totalUnits || 0)}</p>
            </div>
            <div class="course-permissions">
                <span class="permission-pill ${canAccessCourses ? 'allowed' : 'denied'}">Course Upload: ${canAccessCourses ? 'Allowed' : 'Denied'}</span>
                <span class="permission-pill ${canAccessFlags ? 'allowed' : 'denied'}">Flags: ${canAccessFlags ? 'Allowed' : 'Denied'}</span>
            </div>
            <button type="button" class="course-select-button">${isSelected ? 'Selected' : 'Select Course'}</button>
        </div>
        `;
    }).join('');

    coursesContainer.querySelectorAll('.course-card').forEach(card => {
        const selectCard = () => setSelectedTACourse(card.dataset.courseId, { showMessage: true });
        card.addEventListener('click', selectCard);
        card.addEventListener('keydown', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                selectCard();
            }
        });
    });
}

/**
 * Wait for authentication to be initialized
 * @returns {Promise<void>}
 */
async function waitForAuth() {
    let attempts = 0;
    const maxAttempts = 50;

    while (attempts < maxAttempts) {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) {
            console.log('[AUTH] TA Authentication ready');
            return;
        }

        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }

    console.warn('[AUTH] TA Authentication not ready after 5 seconds, proceeding anyway');
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;

    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;

    const closeButton = document.createElement('button');
    closeButton.className = 'notification-close';
    closeButton.type = 'button';
    closeButton.innerHTML = '&times;';
    closeButton.addEventListener('click', () => notification.remove());

    notification.appendChild(messageSpan);
    notification.appendChild(closeButton);

    const colorByType = {
        success: '#28a745',
        warning: '#f0ad4e',
        error: '#dc3545',
        info: '#007bff'
    };

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
        background-color: ${colorByType[type] || colorByType.info};
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}
