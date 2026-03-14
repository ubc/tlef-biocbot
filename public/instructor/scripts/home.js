/**
 * Home Page JavaScript
 * Handles instructor dashboard functionality and interactions
 */

let anonymizeStudentsEnabled = false;

document.addEventListener('DOMContentLoaded', function() {
    // Wait for auth to be ready before initializing
    // This ensures getCurrentInstructorId() is available
    function tryInitialize() {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) {
            initializeHomePage();
            return true;
        }
        return false;
    }
    
    // Try initializing immediately if auth is already ready
    if (!tryInitialize()) {
        // Wait for auth:ready event if auth hasn't loaded yet
        // Use a one-time listener
        const authReadyHandler = function() {
            if (tryInitialize()) {
                document.removeEventListener('auth:ready', authReadyHandler);
            }
        };
        document.addEventListener('auth:ready', authReadyHandler);
        
        // Fallback: try initializing after a short delay if event doesn't fire
        setTimeout(() => {
            if (tryInitialize()) {
                document.removeEventListener('auth:ready', authReadyHandler);
            }
        }, 500);
    }
});

/**
 * Initialize all home page functionality
 */
async function initializeHomePage() {
    console.log('Home page initialized');
    
    try {
        // Check onboarding status first - if not complete, show prompt and hide other content
        const isOnboardingComplete = await checkOnboardingStatus();
        
        if (!isOnboardingComplete) {
            // If onboarding is not complete, show prompt and hide other sections
            showOnboardingPrompt();
            return; // Exit early - don't load other content
        }
        
        // Onboarding is complete, hide prompt and show normal content
        hideOnboardingPrompt();
        
        // Initialize course selection functionality (this will load current course and data)
        await initializeCourseSelection();
        
        // Statistics, flagged content, and missing content are loaded 
        // inside setSelectedCourse() after course is set
        // Only load them here if no course was selected (fallback)
        const selectedCourseId = getSelectedCourseId();
        if (!selectedCourseId) {
            // No course selected, try to load data for all courses
            await loadStatistics();
            await loadFlaggedContent();
            await checkMissingContent();
            await loadStruggleTopics();
            await loadApprovedGlobalTopics();
            await loadPersistenceTopics();
            await loadWeeklyStruggleChart();
        }

        // Add event listeners for live struggle table controls
        const filterCheckbox = document.getElementById('filter-active-only');
        if (filterCheckbox) {
            filterCheckbox.addEventListener('change', renderLiveStruggleTable);
        }
        
        const downloadCSVBtn = document.getElementById('download-csv-btn');
        if (downloadCSVBtn) {
            downloadCSVBtn.addEventListener('click', downloadStruggleActivityCSV);
        }

        // Weekly chart navigation
        const chartPrevBtn = document.getElementById('chart-prev-weeks');
        if (chartPrevBtn) {
            chartPrevBtn.addEventListener('click', () => {
                weeklyChartOffset++;
                loadWeeklyStruggleChart();
            });
        }

        const chartNextBtn = document.getElementById('chart-next-weeks');
        if (chartNextBtn) {
            chartNextBtn.addEventListener('click', () => {
                if (weeklyChartOffset > 0) {
                    weeklyChartOffset--;
                    loadWeeklyStruggleChart();
                }
            });
        }
    } catch (error) {
        console.error('Error initializing home page:', error);
        showErrorMessage('Failed to load home page data');
    }
}

/**
 * Check if instructor has completed onboarding
 * @returns {Promise<boolean>} True if onboarding is complete, false otherwise
 */
async function checkOnboardingStatus() {
    try {
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.log('No instructor ID found');
            return false;
        }
        
        console.log(`Checking onboarding status for instructor: ${instructorId}`);
        
        // Check if instructor has any courses with onboarding complete
        const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);
        
        if (!response.ok) {
            console.error('Failed to fetch instructor courses');
            return false;
        }
        
        const result = await response.json();
        
        if (!result.success || !result.data || !result.data.courses) {
            console.log('No courses found for instructor');
            return false;
        }
        
        // Check if any course has onboarding complete
        const completedCourse = result.data.courses.find(course => course.isOnboardingComplete === true);
        
        if (completedCourse) {
            console.log('✅ Onboarding complete - found completed course:', completedCourse.courseId);
            return true;
        }
        
        console.log('⚠️ Onboarding not complete - no completed courses found');
        return false;
        
    } catch (error) {
        console.error('Error checking onboarding status:', error);
        return false; // Default to showing onboarding prompt on error
    }
}

/**
 * Show onboarding prompt and hide other content sections
 */
function showOnboardingPrompt() {
    const onboardingPrompt = document.getElementById('onboarding-prompt-section');
    const flaggedSection = document.querySelector('.flagged-section');
    const missingItemsSection = document.getElementById('missing-items-section');
    const completeSection = document.getElementById('complete-section');
    const disclaimerSection = document.querySelector('.disclaimer-section');
    
    // Show onboarding prompt
    if (onboardingPrompt) {
        onboardingPrompt.style.display = 'block';
    }
    
    // Hide other content sections
    if (flaggedSection) {
        flaggedSection.style.display = 'none';
    }
    if (missingItemsSection) {
        missingItemsSection.style.display = 'none';
    }
    if (completeSection) {
        completeSection.style.display = 'none';
    }
    if (disclaimerSection) {
        disclaimerSection.style.display = 'none';
    }
}

/**
 * Hide onboarding prompt and show normal content sections
 */
function hideOnboardingPrompt() {
    const onboardingPrompt = document.getElementById('onboarding-prompt-section');
    
    if (onboardingPrompt) {
        onboardingPrompt.style.display = 'none';
    }
    
    // Other sections will be shown/hidden by their own functions
}

/**
 * Load statistics for all instructor courses
 */
async function loadStatistics() {
    try {
        const courseId = getSelectedCourseId();
        let url = '/api/courses/statistics';
        
        // If a course is selected, filter by course ID
        if (courseId) {
            url += `?courseId=${encodeURIComponent(courseId)}`;
        }
        
        const response = await fetch(url, {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Failed to fetch statistics');
        }
        
        const result = await response.json();
        
        if (!result.success || !result.data) {
            console.log('No statistics data available');
            return;
        }
        
        const stats = result.data;
        
        // Update statistics display
        updateStatisticsDisplay(stats);
        
    } catch (error) {
        console.error('Error loading statistics:', error);
        // Don't show error to user, just hide the section
        document.getElementById('statistics-section')?.setAttribute('style', 'display: none;');
    }
}

/**
 * Load struggle topics for the selected course
 */
async function loadStruggleTopics() {
    try {
        const courseId = getSelectedCourseId();
        if (!courseId) return;

        const response = await authenticatedFetch(`/api/courses/${courseId}/students`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const result = await response.json();
        const students = result.data?.students || [];

        // Aggregate struggle topics
        const topicMap = new Map(); // topic -> { count, students: [] }

        students.forEach(student => {
            if (student.struggleState && student.struggleState.topics && student.struggleState.topics.length > 0) {
                student.struggleState.topics.forEach(t => {
                    // Only count active struggles if that's the requirement, 
                    // but the prompt implies "pull different topics... Enzymes: 3 students"
                    // checking student-hub.js, it lists all topics in struggleState.
                    // Let's count all topics present in struggleState.
                    // We might want to filter by `isActive` if that's what "Struggle Topics" implies,
                    // but usually instructors want to see historical struggles too or current ones.
                    // Given the prompt "Struggle Topics" and "Enzymes: 3 students", implies active or recent.
                    // Let's count all for now, maybe distinguish active in the list.
                    
                    const topicName = t.topic.toLowerCase().trim();
                    if (!topicMap.has(topicName)) {
                        topicMap.set(topicName, { count: 0, students: [], isActiveCount: 0 });
                    }
                    
                    const entry = topicMap.get(topicName);
                    // Avoid counting the same student multiple times for the same topic if data allows duplicates (unlikely)
                    if (!entry.students.some(s => s.id === student.userId)) {
                        entry.count++;
                        entry.students.push({
                            id: student.userId,
                            name: student.displayName || student.username || 'Unknown',
                            isActive: t.isActive
                        });
                        if (t.isActive) entry.isActiveCount++;
                    }
                });
            }
        });

        renderStruggleTopics(topicMap);

    } catch (error) {
        console.error('Error loading struggle topics:', error);
        document.getElementById('struggle-topics-section')?.setAttribute('style', 'display: none;');
    }
}

/**
 * Render struggle topics list
 * @param {Map} topicMap - Aggregated struggle topics
 */
function renderStruggleTopics(topicMap) {
    const container = document.getElementById('struggle-topics-content');
    const section = document.getElementById('struggle-topics-section');
    
    if (!container || !section) return;

    if (topicMap.size === 0) {
        section.style.display = 'block';
        container.innerHTML = '<p class="no-data-message" style="text-align: center; color: #666; font-style: italic; padding: 20px;">No struggle topics recorded for this course yet.</p>';
        return;
    }

    section.style.display = 'block';
    
    // Sort by active count (descending), then total count
    const sortedTopics = Array.from(topicMap.entries()).sort((a, b) => {
        if (b[1].isActiveCount !== a[1].isActiveCount) {
            return b[1].isActiveCount - a[1].isActiveCount;
        }
        return b[1].count - a[1].count;
    });

    let html = '<div class="struggle-topics-list">';
    
    sortedTopics.forEach(([topic, data]) => {
        const displayTopic = topic.charAt(0).toUpperCase() + topic.slice(1);
        
        // Sort students: active first
        const sortedStudents = [...data.students].sort((a, b) => {
            if (a.isActive === b.isActive) return 0;
            return a.isActive ? -1 : 1;
        });

        // Generate student list with indicators
        // Limit to 10 names to avoid overcrowding, show "and X more" if needed
        const displayLimit = 10;
        const displayedStudents = sortedStudents.slice(0, displayLimit);
        const remaining = sortedStudents.length - displayLimit;

        const studentHtmlList = displayedStudents.map(s => {
            const indicator = s.isActive ? '🔴' : '⚪️';
            const title = s.isActive ? 'Active (Directive Mode)' : 'Inactive (Monitoring)';
            // safe check for escapeHTML in case it's not hoisted or defined yet (it is defined below in the file)
            // But to be safe, we can use a local helper or rely on the one in scope. 
            // Since this function is at the bottom, escapeHTML (defined above or below) should be visible if it's a function declaration.
            // In the previous view, escapeHTML was a function declaration.
            const displayName = anonymizeStudentsEnabled ? 'Student' : escapeHtml(s.name);
            return `<span title="${title}" style="display: inline-block; margin-right: 8px; white-space: nowrap;">${indicator} ${displayName}</span>`;
        }).join('');
        
        const moreText = remaining > 0 ? `<span style="color: #666; font-size: 0.9em;">+ ${remaining} more</span>` : '';

        // Badge color based on whether there are active struggles
        const badgeColor = data.isActiveCount > 0 ? '#dc3545' : '#6c757d';
        const badgeText = `${data.count} student${data.count !== 1 ? 's' : ''}` + 
                          (data.isActiveCount > 0 ? ` (${data.isActiveCount} active)` : '');

        html += `
            <div class="struggle-topic-item" style="background: white; padding: 15px; margin-bottom: 10px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid ${data.isActiveCount > 0 ? '#dc3545' : '#28a745'};">
                <div class="topic-header" onclick="toggleTopic(this)">
                    <h3 style="margin: 0; font-size: 1.1em; color: #333;">
                        <span class="toggle-icon">▼</span>
                         ${displayTopic}
                    </h3>
                    <span class="badge" style="background: ${badgeColor}; color: white; padding: 4px 10px; border-radius: 12px; font-weight: bold;">
                        ${badgeText}
                    </span>
                </div>
                <div class="topic-content">
                    <div style="font-size: 0.95em; color: #555; line-height: 1.5;">
                        ${studentHtmlList} ${moreText}
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    html += '<div style="margin-top: 10px; font-size: 0.85em; color: #666; text-align: right;">🔴 Active (Directive Mode) &nbsp; ⚪️ Inactive (Monitoring)</div>';
    
    container.innerHTML = html;
}

/**
 * Update the statistics display with fetched data
 * @param {Object} stats - Statistics data object
 */
function updateStatisticsDisplay(stats) {
    const statisticsSection = document.getElementById('statistics-section');
    if (!statisticsSection) {
        return;
    }
    
    // Show the section if we have data
    if (stats.totalSessions > 0) {
        statisticsSection.setAttribute('style', 'display: block;');
    } else {
        statisticsSection.setAttribute('style', 'display: none;');
        return;
    }
    
    // Update stat values
    const totalStudentsEl = document.getElementById('stat-total-students');
    const totalSessionsEl = document.getElementById('stat-total-sessions');
    const avgSessionLengthEl = document.getElementById('stat-avg-session-length');
    const avgMessageLengthEl = document.getElementById('stat-avg-message-length');
    
    if (totalStudentsEl) totalStudentsEl.textContent = stats.totalStudents || 0;
    if (totalSessionsEl) totalSessionsEl.textContent = stats.totalSessions || 0;
    if (avgSessionLengthEl) avgSessionLengthEl.textContent = stats.averageSessionLength || '0s';
    if (avgMessageLengthEl) avgMessageLengthEl.textContent = stats.averageMessageLength || 0;
    
    // Update mode distribution
    const tutorCount = stats.modeDistribution?.tutor || 0;
    const protegeCount = stats.modeDistribution?.protege || 0;
    const totalModes = tutorCount + protegeCount;
    
    const tutorCountEl = document.getElementById('tutor-count');
    const protegeCountEl = document.getElementById('protege-count');
    const tutorBarEl = document.getElementById('tutor-bar');
    const protegeBarEl = document.getElementById('protege-bar');
    
    if (tutorCountEl) tutorCountEl.textContent = tutorCount;
    if (protegeCountEl) protegeCountEl.textContent = protegeCount;
    
    if (totalModes > 0) {
        const tutorPercentage = Math.round((tutorCount / totalModes) * 100);
        const protegePercentage = Math.round((protegeCount / totalModes) * 100);
        
        if (tutorBarEl) tutorBarEl.style.width = `${tutorPercentage}%`;
        if (protegeBarEl) protegeBarEl.style.width = `${protegePercentage}%`;
    } else {
        if (tutorBarEl) tutorBarEl.style.width = '0%';
        if (protegeBarEl) protegeBarEl.style.width = '0%';
    }
}

/**
 * Load flagged content count for all instructor courses
 */
async function loadFlaggedContent() {
    try {
        const courseId = getSelectedCourseId();
        
        // If a course is selected, only get flags for that course
        if (courseId) {
            try {
                const flagsResponse = await fetch(`/api/flags/course/${courseId}?status=pending`, {
                    credentials: 'include'
                });
                if (flagsResponse.ok) {
                    const flagsData = await flagsResponse.json();
                    if (flagsData.success && flagsData.data && flagsData.data.flags) {
                        updateFlaggedCount(flagsData.data.flags.length);
                        return;
                    }
                }
            } catch (error) {
                console.error(`Error fetching flags for course ${courseId}:`, error);
            }
            updateFlaggedCount(0);
            return;
        }
        
        // Otherwise, get flags for all courses
        const coursesResponse = await fetch('/api/courses', {
            credentials: 'include'
        });
        if (!coursesResponse.ok) {
            throw new Error('Failed to fetch courses');
        }
        
        const coursesData = await coursesResponse.json();
        if (!coursesData.success || !coursesData.data) {
            console.log('No courses found');
            updateFlaggedCount(0);
            return;
        }
        
        const courses = coursesData.data;
        let totalPendingFlags = 0;
        
        // Get flags for each course
        for (const course of courses) {
            try {
                const flagsResponse = await fetch(`/api/flags/course/${course.id}?status=pending`, {
                    credentials: 'include'
                });
                if (flagsResponse.ok) {
                    const flagsData = await flagsResponse.json();
                    if (flagsData.success && flagsData.data && flagsData.data.flags) {
                        totalPendingFlags += flagsData.data.flags.length;
                    }
                }
            } catch (error) {
                console.error(`Error fetching flags for course ${course.id}:`, error);
                // Continue with other courses
            }
        }
        
        updateFlaggedCount(totalPendingFlags);
    } catch (error) {
        console.error('Error loading flagged content:', error);
        updateFlaggedCount(0);
    }
}

/**
 * Update the flagged count display
 * @param {number} count - Number of pending flags
 */
function updateFlaggedCount(count) {
    const flagCountElement = document.getElementById('pending-flags-count');
    if (flagCountElement) {
        flagCountElement.textContent = count;
        
        // Add visual indicator if there are pending flags
        const flaggedSection = document.querySelector('.flagged-section');
        if (count > 0 && flaggedSection) {
            flaggedSection.classList.add('has-pending-flags');
        } else if (flaggedSection) {
            flaggedSection.classList.remove('has-pending-flags');
        }
    }
}

/**
 * Check for missing course content in all units
 */
async function checkMissingContent() {
    try {
        const courseId = getSelectedCourseId();
        
        // If a course is selected, only check that course
        if (courseId) {
            try {
                const courseDetailResponse = await fetch(`/api/courses/${courseId}`, {
                    credentials: 'include'
                });
                if (!courseDetailResponse.ok) {
                    // Course not found or not accessible
                    document.getElementById('missing-items-section')?.setAttribute('style', 'display: none;');
                    document.getElementById('complete-section')?.setAttribute('style', 'display: none;');
                    return;
                }
                
                const courseDetailData = await courseDetailResponse.json();
                if (!courseDetailData.success || !courseDetailData.data || !courseDetailData.data.lectures) {
                    document.getElementById('missing-items-section')?.setAttribute('style', 'display: none;');
                    document.getElementById('complete-section')?.setAttribute('style', 'display: none;');
                    return;
                }
                
                const course = courseDetailData.data;
                const lectures = course.lectures;
                const missingItems = [];
                
                // Check each unit/lecture for missing items
                for (const lecture of lectures) {
                    const unitMissingItems = checkUnitMissingItems(courseId, course.courseName || courseId, lecture);
                    if (unitMissingItems.length > 0) {
                        missingItems.push(...unitMissingItems);
                    }
                }
                
                // Display results
                displayMissingItems(missingItems);
                return;
            } catch (error) {
                console.error(`Error checking course ${courseId}:`, error);
                document.getElementById('missing-items-section')?.setAttribute('style', 'display: none;');
                document.getElementById('complete-section')?.setAttribute('style', 'display: none;');
                return;
            }
        }
        
        // Otherwise, check all courses
        const coursesResponse = await fetch('/api/courses', {
            credentials: 'include'
        });
        if (!coursesResponse.ok) {
            throw new Error('Failed to fetch courses');
        }
        
        const coursesData = await coursesResponse.json();
        if (!coursesData.success || !coursesData.data || coursesData.data.length === 0) {
            // No courses, hide both sections
            document.getElementById('missing-items-section')?.setAttribute('style', 'display: none;');
            document.getElementById('complete-section')?.setAttribute('style', 'display: none;');
            return;
        }
        
        const courses = coursesData.data;
        const missingItems = [];
        
        // Check each course for missing content
        for (const course of courses) {
            try {
                // Get detailed course data with lectures
                const courseDetailResponse = await fetch(`/api/courses/${course.id}`, {
                    credentials: 'include'
                });
                if (!courseDetailResponse.ok) {
                    continue; // Skip this course if we can't get details
                }
                
                const courseDetailData = await courseDetailResponse.json();
                if (!courseDetailData.success || !courseDetailData.data || !courseDetailData.data.lectures) {
                    continue;
                }
                
                const lectures = courseDetailData.data.lectures;
                
                // Check each unit/lecture for missing items
                for (const lecture of lectures) {
                    const unitMissingItems = checkUnitMissingItems(course.id, course.name, lecture);
                    if (unitMissingItems.length > 0) {
                        missingItems.push(...unitMissingItems);
                    }
                }
            } catch (error) {
                console.error(`Error checking course ${course.id}:`, error);
                // Continue with other courses
            }
        }
        
        // Display results
        displayMissingItems(missingItems);
    } catch (error) {
        console.error('Error checking missing content:', error);
        // Hide both sections on error
        document.getElementById('missing-items-section')?.setAttribute('style', 'display: none;');
        document.getElementById('complete-section')?.setAttribute('style', 'display: none;');
    }
}

/**
 * Check a single unit for missing required items
 * @param {string} courseName - Name of the course
 * @param {Object} lecture - Lecture/unit object
 * @returns {Array} Array of missing item descriptions
 */
function checkUnitMissingItems(courseId, courseName, lecture) {
    const missingItems = [];
    const unitName = lecture.name || 'Unknown Unit';
    
    // Check for learning objectives
    const hasLearningObjectives = lecture.learningObjectives && 
                                   Array.isArray(lecture.learningObjectives) && 
                                   lecture.learningObjectives.length > 0;
    
    // Check for lecture notes: require at least one document tagged as lecture notes
    const hasLectureNotes = Array.isArray(lecture.documents) && lecture.documents.some(doc => {
        const t = (doc.documentType || '').toLowerCase();
        return t === 'lecture-notes' || t === 'lecture_notes' || t === 'notes';
    });
    
    // Check for practice questions: require at least one practice/tutorial document
    const hasPracticeDocs = Array.isArray(lecture.documents) && lecture.documents.some(doc => {
        const t = (doc.documentType || '').toLowerCase();
        return t === 'practice-quiz' || t === 'practice_q_tutorials' || t === 'practice' || t === 'tutorial';
    });
    const hasPracticeQuestions = hasPracticeDocs;
    
    // Build missing items list
    if (!hasLearningObjectives) {
        missingItems.push({ courseId, courseName, unitName, missingItem: 'Learning Objective' });
    }
    
    if (!hasLectureNotes) {
        missingItems.push({ courseId, courseName, unitName, missingItem: 'Lecture Note' });
    }
    
    if (!hasPracticeQuestions) {
        missingItems.push({ courseId, courseName, unitName, missingItem: 'Practice Question/Tutorial' });
    }
    
    return missingItems;
}

/**
 * Display missing items in the UI
 * @param {Array} missingItems - Array of missing item objects
 */
function displayMissingItems(missingItems) {
    const missingSection = document.getElementById('missing-items-section');
    const completeSection = document.getElementById('complete-section');
    const missingList = document.getElementById('missing-items-list');
    
    if (!missingSection || !completeSection || !missingList) {
        return;
    }
    
    if (missingItems.length === 0) {
        // All units are complete
        missingSection.setAttribute('style', 'display: none;');
        completeSection.setAttribute('style', 'display: block;');
    } else {
        // Show missing items
        missingSection.setAttribute('style', 'display: block;');
        completeSection.setAttribute('style', 'display: none;');
        
        // Clear existing list
        missingList.innerHTML = '';
        
        // Group missing items by course and unit
        const groupedItems = {};
        missingItems.forEach(item => {
            const key = `${item.courseName}|${item.unitName}`;
            if (!groupedItems[key]) {
                groupedItems[key] = {
                    courseId: item.courseId,
                    courseName: item.courseName,
                    unitName: item.unitName,
                    missingItems: []
                };
            }
            groupedItems[key].missingItems.push(item.missingItem);
        });
        
        // Create list items
        Object.values(groupedItems).forEach(group => {
            const listItem = document.createElement('div');
            listItem.className = 'missing-item';
            
            const missingItemsText = group.missingItems.join(', ');
            listItem.innerHTML = `
                <div class="missing-item-header">
                    <span class="missing-item-course">${escapeHtml(group.courseName)}</span>
                    <span class="missing-item-unit">${escapeHtml(group.unitName)}</span>
                </div>
                <div class="missing-item-details">
                    Missing: ${escapeHtml(missingItemsText)}
                </div>
                <div class="missing-item-actions">
                    <a class="action-btn primary" href="/instructor/documents?courseId=${encodeURIComponent(group.courseId)}&unit=${encodeURIComponent(group.unitName)}">Go to this unit</a>
                </div>
            `;
            
            missingList.appendChild(listItem);
        });
    }
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ===========================
// LIVE STRUGGLE TABLE & SOCKET.IO
// ===========================

/**
 * Global variables for Socket.IO and live struggle data
 */
let pollingInterval = null; // Polling interval ID
let struggleActivityData = []; // Array to store all struggle activity
const MAX_TABLE_ENTRIES = 100; // Limit stored entries to prevent memory issues
const POLLING_INTERVAL_MS = 10000; // Poll every 10 seconds

// Weekly struggle chart state
let weeklyStruggleChart = null;   // Chart.js instance
let weeklyChartOffset = 0;        // Navigation offset (0 = most recent page)
const WEEKS_PER_PAGE = 8;         // Weeks shown per page

/**
 * Start polling for struggle activity updates
 * Called when a course is selected
 */
function startPollingStruggleActivity() {
    const courseId = getSelectedCourseId();
    if (!courseId) {
        console.warn('Cannot start polling: No course selected');
        return;
    }
    
    // Stop existing polling if any
    stopPollingStruggleActivity();
    
    console.log(`\ud83d\udd04 Starting struggle activity polling for course: ${courseId}`);
    
    // Poll immediately once, then set interval
    pollStruggleActivity();
    pollingInterval = setInterval(pollStruggleActivity, POLLING_INTERVAL_MS);
}

/**
 * Stop polling for struggle activity updates
 */
function stopPollingStruggleActivity() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
        console.log('\u274c Stopped struggle activity polling');
    }
}

/**
 * Poll the server for new struggle activity data
 */
async function pollStruggleActivity() {
    try {
        const courseId = getSelectedCourseId();
        if (!courseId) return;
        
        // Fetch latest activity from API
        const response = await authenticatedFetch(`/api/struggle-activity/${courseId}?limit=100`);
        
        if (!response.ok) {
            console.warn('Failed to poll struggle activity');
            return;
        }
        
        const result = await response.json();
        const newActivities = result.data || [];
        
        // Update data array (replace entirely)
        struggleActivityData = newActivities;
        
        // Re-render table
        renderLiveStruggleTable();
        
    } catch (error) {
        console.error('Error polling struggle activity:', error);
    }
}

/**
 * Load initial struggle activity data from server
 * Fetches from persistent MongoDB history collection
 */
async function loadInitialStruggleActivity() {
    try {
        const courseId = getSelectedCourseId();
        if (!courseId) return;
        
        // Fetch from persistent history API
        const response = await authenticatedFetch(`/api/struggle-activity/${courseId}?limit=100`);
        
        if (!response.ok) {
            console.warn('Failed to load struggle activity history');
            return;
        }
        
        const result = await response.json();
        const activities = result.data || [];
        
        // Activities are already sorted by timestamp (newest first) from backend
        struggleActivityData = activities;
        
        // Show the table container
        const container = document.getElementById('live-struggle-container');
        if (container) {
            container.style.display = 'block';
        }
        
        renderLiveStruggleTable();
        
        console.log(`📊 Loaded ${struggleActivityData.length} struggle activity entries from history`);
        
    } catch (error) {
        console.error('Error loading struggle activity history:', error);
    }
}


/**
 * Render the live struggle table
 * Respects the "Show only active" filter
 */
function renderLiveStruggleTable() {
    const tbody = document.getElementById('live-struggle-tbody');
    if (!tbody) return;
    
    const filterActive =document.getElementById('filter-active-only')?.checked || false;
    
    // Filter data if needed
    let dataToDisplay = struggleActivityData;
    if (filterActive) {
        dataToDisplay = struggleActivityData.filter(item => item.state === 'Active');
    }
    
    // Hide/show Name column header based on anonymize setting
    const nameHeader = document.getElementById('struggle-name-th');
    if (nameHeader) nameHeader.style.display = anonymizeStudentsEnabled ? 'none' : '';

    const colSpan = anonymizeStudentsEnabled ? 3 : 4;

    if (dataToDisplay.length === 0) {
        tbody.innerHTML = `
            <tr class="no-data-row">
                <td colspan="${colSpan}" style="text-align: center; color: #666; padding: 20px;">
                    ${filterActive ? 'No active struggle activity.' : 'No struggle activity yet. Activity will appear here as students interact with topics.'}
                </td>
            </tr>
        `;
        return;
    }

    // Build table rows
    let html = '';
    dataToDisplay.forEach(item => {
        const timestamp = formatTimestampPST(item.timestamp);
        const stateBadge = item.state === 'Active'
            ? '<span class="state-badge active">Active</span>'
            : '<span class="state-badge inactive">Inactive</span>';

        html += `
            <tr>
                <td>${timestamp}</td>
                ${anonymizeStudentsEnabled ? '' : `<td>${escapeHtml(item.studentName)}</td>`}
                <td>${escapeHtml(capitalizeFirst(item.topic))}</td>
                <td>${stateBadge}</td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

/**
 * Format timestamp to PST timezone
 * @param {Date|string} timestamp - Timestamp to format
 * @returns {string} Formatted timestamp in PST (e.g., "February 13, 2024, 7:25 PM")
 */
function formatTimestampPST(timestamp) {
    const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
    
    // Format to PST (America/Los_Angeles) - automatically handles PST/PDT
    const options = {
        timeZone: 'America/Los_Angeles',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    };
    
    const formatter = new Intl.DateTimeFormat('en-US', options);
    return formatter.format(date);
}

/**
 * Capitalize first letter of string
 * @param {string} str - String to capitalize
 * @returns {string} Capitalized string
 */
function capitalizeFirst(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Download table data as CSV
 * Respects the "Show only active" filter
 */
function downloadStruggleActivityCSV() {
    const filterActive = document.getElementById('filter-active-only')?.checked || false;
    let dataToExport = struggleActivityData;
    
    if (filterActive) {
        dataToExport = struggleActivityData.filter(item => item.state === 'Active');
    }
    
    if (dataToExport.length === 0) {
        alert('No data to export');
        return;
    }
    
    // Build CSV
    let csv = anonymizeStudentsEnabled
        ? 'Time (PST),Topic,Status\n'
        : 'Time (PST),Name,Topic,Status\n';

    dataToExport.forEach(item => {
        const timestamp = formatTimestampPST(item.timestamp);
        const topic = capitalizeFirst(item.topic).replace(/"/g, '""');
        const status = item.state;

        if (anonymizeStudentsEnabled) {
            csv += `"${timestamp}","${topic}","${status}"\n`;
        } else {
            const name = item.studentName.replace(/"/g, '""');
            csv += `"${timestamp}","${name}","${topic}","${status}"\n`;
        }
    });
    
    // Create download link
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', `struggle_activity_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    console.log(`📥 Downloaded CSV with ${dataToExport.length} entries`);
}

// ===========================
// END OF LIVE STRUGGLE TABLE
// ===========================

// ===========================
// WEEKLY STRUGGLE CHART
// ===========================

/**
 * Load weekly active struggle data and render chart.
 * Generates a continuous weekly timeline (no gaps) and merges sparse backend data into it.
 */
async function loadWeeklyStruggleChart() {
    try {
        const courseId = getSelectedCourseId();
        if (!courseId) return;

        // Always fetch a generous window so we can paginate client-side
        const fetchWeeks = Math.max(52, (weeklyChartOffset + 1) * WEEKS_PER_PAGE + WEEKS_PER_PAGE);

        const response = await authenticatedFetch(
            `/api/struggle-activity/weekly/${courseId}?weeks=${fetchWeeks}`
        );
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const result = await response.json();
        const sparseWeeks = result.data || [];

        if (sparseWeeks.length === 0) {
            renderWeeklyStruggleChart([], 0);
            return;
        }

        // Build lookup by milliseconds. Backend $dateTrunc returns stable timestamps.
        const weekMap = new Map();
        sparseWeeks.forEach(w => {
            weekMap.set(new Date(w.weekStart).getTime(), w);
        });

        // Generate continuous timeline from first backend week to now, stepping +7 days
        const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
        const firstWeekMs = new Date(sparseWeeks[0].weekStart).getTime();
        const lastWeekMs = new Date(sparseWeeks[sparseWeeks.length - 1].weekStart).getTime();
        const endMs = Math.max(lastWeekMs, Date.now());

        const allWeeks = [];
        for (let ms = firstWeekMs; ms <= endMs; ms += WEEK_MS) {
            if (weekMap.has(ms)) {
                allWeeks.push(weekMap.get(ms));
            } else {
                allWeeks.push({ weekStart: new Date(ms).toISOString(), topics: [], totalCount: 0 });
            }
        }

        // Paginate: offset 0 = most recent WEEKS_PER_PAGE weeks
        const endIdx = allWeeks.length - (weeklyChartOffset * WEEKS_PER_PAGE);
        const sliceStart = Math.max(0, endIdx - WEEKS_PER_PAGE);
        const pageData = allWeeks.slice(sliceStart, Math.max(endIdx, 0));

        renderWeeklyStruggleChart(pageData, allWeeks.length);
    } catch (error) {
        console.error('Error loading weekly struggle chart:', error);
    }
}

/**
 * Render the weekly struggle stacked bar chart
 * @param {Array} weekData - Array of week objects with topics
 * @param {number} totalWeeksAvailable - Total weeks of data available
 */
function renderWeeklyStruggleChart(weekData, totalWeeksAvailable) {
    const container = document.getElementById('weekly-struggle-chart-container');
    const canvas = document.getElementById('weekly-struggle-chart');
    const rangeLabel = document.getElementById('chart-week-range');
    const prevBtn = document.getElementById('chart-prev-weeks');
    const nextBtn = document.getElementById('chart-next-weeks');

    if (!container || !canvas) return;

    if (weekData.length === 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'block';

    // Collect all unique topics across displayed weeks
    const allTopics = new Set();
    weekData.forEach(w => w.topics.forEach(t => allTopics.add(t.topic)));
    const topicList = Array.from(allTopics).sort();

    // Color palette
    const palette = [
        '#dc3545', '#4a90e2', '#ffc107', '#28a745', '#6f42c1',
        '#fd7e14', '#20c997', '#e83e8c', '#17a2b8', '#6c757d',
        '#8b5cf6', '#f59e0b', '#ef4444', '#10b981', '#3b82f6'
    ];

    // Build labels (week start dates)
    const labels = weekData.map(w => {
        const d = new Date(w.weekStart);
        return d.toLocaleDateString('en-US', {
            month: 'short', day: 'numeric',
            timeZone: 'America/Los_Angeles'
        });
    });

    // Build datasets (one per topic, stacked)
    const datasets = topicList.map((topic, i) => ({
        label: capitalizeFirst(topic),
        data: weekData.map(w => {
            const found = w.topics.find(t => t.topic === topic);
            return found ? found.studentCount : 0;
        }),
        backgroundColor: palette[i % palette.length],
        borderWidth: 0,
        borderRadius: 2
    }));

    // Update range label
    if (rangeLabel && weekData.length > 0) {
        const firstDate = new Date(weekData[0].weekStart);
        const lastDate = new Date(weekData[weekData.length - 1].weekStart);
        const lastEndDate = new Date(lastDate);
        lastEndDate.setDate(lastEndDate.getDate() + 6);
        const fmt = { month: 'short', day: 'numeric', timeZone: 'America/Los_Angeles' };
        rangeLabel.textContent = `${firstDate.toLocaleDateString('en-US', fmt)} – ${lastEndDate.toLocaleDateString('en-US', fmt)}`;
    }

    // Update navigation buttons
    if (prevBtn) {
        prevBtn.disabled = (weeklyChartOffset + 1) * WEEKS_PER_PAGE >= totalWeeksAvailable;
    }
    if (nextBtn) {
        nextBtn.disabled = weeklyChartOffset === 0;
    }

    // Destroy previous chart instance
    if (weeklyStruggleChart) {
        weeklyStruggleChart.destroy();
    }

    // Create stacked bar chart
    weeklyStruggleChart = new Chart(canvas, {
        type: 'bar',
        data: { labels, datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 15, usePointStyle: true, pointStyle: 'rect' }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        title: (items) => `Week of ${items[0].label}`,
                        afterBody: (items) => {
                            const total = items.reduce((sum, item) => sum + item.raw, 0);
                            return `\nTotal active: ${total} student${total !== 1 ? 's' : ''}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true,
                    grid: { display: false },
                    title: { display: true, text: 'Week Starting', font: { weight: 'bold' } }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: { stepSize: 1, precision: 0 },
                    title: { display: true, text: 'Active Students', font: { weight: 'bold' } }
                }
            }
        }
    });
}

// ===========================
// END OF WEEKLY STRUGGLE CHART
// ===========================


/**
 * Show info message
 * @param {string} message - Info message
 */
function showInfoMessage(message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification info';
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Show error message
 * @param {string} message - Error message
 */
function showErrorMessage(message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification error';
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Show success message
 * @param {string} message - Success message
 */
function showSuccessMessage(message) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'notification success';
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Initialize course selection functionality
 */
async function initializeCourseSelection() {
    // Set up event listeners
    const changeCourseBtn = document.getElementById('change-course-btn');
    const cancelCourseSelectBtn = document.getElementById('cancel-course-select-btn');
    const joinCourseBtn = document.getElementById('join-course-btn');
    const courseSelectDropdown = document.getElementById('course-select-dropdown');
    
    if (changeCourseBtn) {
        changeCourseBtn.addEventListener('click', showCourseSelector);
    }
    
    if (cancelCourseSelectBtn) {
        cancelCourseSelectBtn.addEventListener('click', hideCourseSelector);
    }
    
    if (joinCourseBtn) {
        joinCourseBtn.addEventListener('click', handleJoinCourse);
    }
    
    if (courseSelectDropdown) {
        courseSelectDropdown.addEventListener('change', handleCourseSelectionChange);
    }
    
    // Load available courses
    await loadAvailableCourses();
    
    // Load and display current course
    await loadCurrentCourse();
    
    // Update navigation links to include course ID
    updateNavigationLinks();
}

/**
 * Load available courses for selection
 */
async function loadAvailableCourses() {
    try {
        const courseSelectDropdown = document.getElementById('course-select-dropdown');
        if (!courseSelectDropdown) return;
        
        // Fetch courses from the API
        const response = await fetch('/api/courses/available/all', {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch courses');
        }
        
        const courses = result.data || [];
        
        // Filter out duplicate courses by courseId
        const uniqueCourses = courses.filter((course, index, self) => 
            index === self.findIndex(c => c.courseId === course.courseId)
        );
        
        // Clear existing options except the first placeholder
        courseSelectDropdown.innerHTML = '<option value="">Choose a course...</option>';
        
        // Add course options
        uniqueCourses.forEach(course => {
            const option = document.createElement('option');
            option.value = course.courseId;
            option.textContent = course.courseName;
            courseSelectDropdown.appendChild(option);
        });
        
        console.log('Available courses loaded:', uniqueCourses.length);
        
    } catch (error) {
        console.error('Error loading available courses:', error);
        // Keep the placeholder option if API fails
        const courseSelectDropdown = document.getElementById('course-select-dropdown');
        if (courseSelectDropdown) {
            courseSelectDropdown.innerHTML = '<option value="">Error loading courses</option>';
        }
    }
}

/**
 * Load and display the current selected course
 */
async function loadCurrentCourse() {
    try {
        // Get course ID from localStorage or URL params
        const urlParams = new URLSearchParams(window.location.search);
        const courseIdFromUrl = urlParams.get('courseId');
        const courseIdFromStorage = localStorage.getItem('selectedCourseId');
        const courseId = courseIdFromUrl || courseIdFromStorage;
        
        if (!courseId) {
            // Try to get the first course from instructor's courses
            const instructorId = getCurrentInstructorId();
            if (instructorId) {
                const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);
                if (response.ok) {
                    const result = await response.json();
                    if (result.data && result.data.courses && result.data.courses.length > 0) {
                        const firstCourse = result.data.courses[0];
                        await setSelectedCourse(firstCourse.courseId, firstCourse.courseName);
                        return;
                    }
                }
            }
            
            // No course found, show course selector
            showCourseSelector();
            return;
        }
        
        // Fetch course details
        const response = await authenticatedFetch(`/api/courses/${courseId}`);
        if (response.ok) {
            const result = await response.json();
            if (result.success && result.data) {
                await setSelectedCourse(courseId, result.data.courseName || courseId);
            } else {
                // Course not found, clear selection
                clearSelectedCourse();
                showCourseSelector();
            }
        } else {
            // Course not accessible, clear selection
            clearSelectedCourse();
            showCourseSelector();
        }
        
    } catch (error) {
        console.error('Error loading current course:', error);
        showCourseSelector();
    }
}

/**
 * Set the selected course and update UI
 * @param {string} courseId - Course ID to set
 * @param {string} courseName - Course name to display
 */
async function setSelectedCourse(courseId, courseName) {
    // Store in localStorage
    localStorage.setItem('selectedCourseId', courseId);
    
    // Update URL if not already set
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('courseId') !== courseId) {
        urlParams.set('courseId', courseId);
        window.history.replaceState({}, '', `${window.location.pathname}?${urlParams.toString()}`);
    }
    
    // Auto-add instructor to course's instructors array when they select a course
    // This ensures they have full access to the course features
    const instructorId = getCurrentInstructorId();
    if (instructorId) {
        try {
            await fetch(`/api/courses/${courseId}/instructors`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ instructorId })
            });
            console.log(`✅ Auto-added instructor ${instructorId} to course ${courseId}`);
        } catch (error) {
            console.warn('Could not auto-add instructor to course:', error);
        }
    }
    
    // Update UI
    const courseNameDisplay = document.getElementById('course-name-display');
    if (courseNameDisplay) {
        courseNameDisplay.textContent = courseName || courseId;
    }

    // Update Course Code display
    const courseCodeLabel = document.querySelector('.course-code-label');
    const courseCodeDisplay = document.getElementById('course-code-display');
    
    if (courseCodeDisplay && courseCodeLabel) {
        // We need to fetch the course details to get the code if we don't have it
        // Usually setSelectedCourse is called after fetching details, but let's be safe
        try {
            const response = await authenticatedFetch(`/api/courses/${courseId}`);
            if (response.ok) {
                const result = await response.json();
                if (result.success && result.data && result.data.courseCode) {
                    courseCodeDisplay.textContent = result.data.courseCode;
                    courseCodeDisplay.style.display = 'inline-block';
                    courseCodeLabel.style.display = 'inline-block';
                } else {
                    courseCodeDisplay.style.display = 'none';
                    courseCodeLabel.style.display = 'none';
                }
            }
        } catch (e) {
            console.error('Error fetching course code:', e);
            courseCodeDisplay.style.display = 'none';
            courseCodeLabel.style.display = 'none';
        }
    }
    
    // Show course selection container
    const courseSelectionContainer = document.getElementById('course-selection-container');
    if (courseSelectionContainer) {
        courseSelectionContainer.style.display = 'block';
    }
    
    // Hide course selector, show current course display
    hideCourseSelector();
    
    // Update course context in auth system
    if (typeof setCurrentCourseId === 'function') {
        await setCurrentCourseId(courseId);
    }
    
    // Update navigation links
    updateNavigationLinks();
    
    // Clear any cached course data
    if (typeof courseIdCache !== 'undefined') {
        courseIdCache = null;
    }
    
    // Fetch anonymize students setting for this course
    try {
        const anonRes = await fetch(`/api/settings/anonymize-students?courseId=${courseId}`);
        const anonData = await anonRes.json();
        anonymizeStudentsEnabled = anonData.success && anonData.enabled;
    } catch (e) {
        anonymizeStudentsEnabled = false;
    }

    // Reload page data with new course
    await loadStatistics();
    await loadFlaggedContent();
    await checkMissingContent();
    await loadStruggleTopics();
    await loadApprovedGlobalTopics();
    await loadPersistenceTopics();
    
    // Start polling for struggle activity updates
    startPollingStruggleActivity();

    // Load initial struggle activity data for the live table
    await loadInitialStruggleActivity();

    // Reset and load weekly struggle chart
    weeklyChartOffset = 0;
    await loadWeeklyStruggleChart();
}

/**
 * Clear the selected course
 */
function clearSelectedCourse() {
    localStorage.removeItem('selectedCourseId');
    const urlParams = new URLSearchParams(window.location.search);
    urlParams.delete('courseId');
    window.history.replaceState({}, '', window.location.pathname);
}

/**
 * Show the course selector UI
 */
function showCourseSelector() {
    const currentCourseDisplay = document.querySelector('.current-course-display');
    const courseSelector = document.getElementById('course-selector');
    const selectedCourseDetails = document.getElementById('selected-course-details');
    const joinCourseBtn = document.getElementById('join-course-btn');
    
    if (currentCourseDisplay) {
        currentCourseDisplay.style.display = 'none';
    }
    
    if (courseSelector) {
        courseSelector.style.display = 'flex';
    }
    
    if (selectedCourseDetails) {
        selectedCourseDetails.style.display = 'none';
    }
    
    if (joinCourseBtn) {
        joinCourseBtn.style.display = 'none';
    }
}

/**
 * Hide the course selector UI
 */
function hideCourseSelector() {
    const currentCourseDisplay = document.querySelector('.current-course-display');
    const courseSelector = document.getElementById('course-selector');
    const selectedCourseDetails = document.getElementById('selected-course-details');
    const joinCourseBtn = document.getElementById('join-course-btn');
    const courseSelectDropdown = document.getElementById('course-select-dropdown');
    
    if (currentCourseDisplay) {
        currentCourseDisplay.style.display = 'flex';
    }
    
    if (courseSelector) {
        courseSelector.style.display = 'none';
    }
    
    if (selectedCourseDetails) {
        selectedCourseDetails.style.display = 'none';
    }
    
    if (joinCourseBtn) {
        joinCourseBtn.style.display = 'none';
    }
    
    if (courseSelectDropdown) {
        courseSelectDropdown.value = '';
    }
}

/**
 * Handle course selection dropdown change
 */
function handleCourseSelectionChange(event) {
    const courseId = event.target.value;
    const selectedCourseDetails = document.getElementById('selected-course-details');
    const joinCourseBtn = document.getElementById('join-course-btn');
    const selectedCourseName = document.getElementById('selected-course-name');
    const selectedCourseId = document.getElementById('selected-course-id');
    
    if (!courseId) {
        if (selectedCourseDetails) {
            selectedCourseDetails.style.display = 'none';
        }
        if (joinCourseBtn) {
            joinCourseBtn.style.display = 'none';
        }
        return;
    }
    
    // Get course name from dropdown
    const selectedOption = event.target.options[event.target.selectedIndex];
    const courseName = selectedOption.textContent;
    
    // Show course details
    if (selectedCourseDetails) {
        selectedCourseDetails.style.display = 'block';
    }
    
    if (selectedCourseName) {
        selectedCourseName.textContent = courseName;
    }
    
    if (selectedCourseId) {
        selectedCourseId.textContent = courseId;
    }
    
    if (joinCourseBtn) {
        joinCourseBtn.style.display = 'inline-block';
    }
    
    // Store selected course ID for joining
    joinCourseBtn.dataset.courseId = courseId;
    joinCourseBtn.dataset.courseName = courseName;
}

/**
 * Handle joining a course
 */
async function handleJoinCourse() {
    const joinCourseBtn = document.getElementById('join-course-btn');
    if (!joinCourseBtn) return;
    
    const courseId = joinCourseBtn.dataset.courseId;
    const courseName = joinCourseBtn.dataset.courseName;
    
    if (!courseId) {
        showErrorMessage('No course selected');
        return;
    }
    
    try {
        // Show loading state
        const originalText = joinCourseBtn.textContent;
        joinCourseBtn.textContent = 'Joining Course...';
        joinCourseBtn.disabled = true;
        
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            throw new Error('No instructor ID found. User not authenticated.');
        }
        
        // Call the join course API
        const response = await fetch(`/api/courses/${courseId}/instructors`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to join course');
        }
        
        const result = await response.json();
        console.log('Successfully joined course:', result);
        
        // Mark instructor's onboarding as complete since they joined an existing course
        if (typeof markInstructorOnboardingComplete === 'function') {
            await markInstructorOnboardingComplete(courseId);
        } else {
            // Fallback: call the API directly
            try {
                await authenticatedFetch('/api/onboarding/complete', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        courseId: courseId,
                        instructorId: instructorId
                    })
                });
            } catch (error) {
                console.warn('Failed to mark onboarding as complete:', error);
            }
        }
        
        // Set the selected course
        await setSelectedCourse(courseId, courseName);
        
        // Show success message
        showSuccessMessage('Successfully joined the course!');
        
        // Reload page data
        await loadStatistics();
        await loadFlaggedContent();
        await checkMissingContent();
        
    } catch (error) {
        console.error('Error joining course:', error);
        showErrorMessage(`Error joining course: ${error.message}`);
        
        // Reset button state
        if (joinCourseBtn) {
            joinCourseBtn.textContent = 'Join Course';
            joinCourseBtn.disabled = false;
        }
    }
}

/**
 * Get the currently selected course ID
 * @returns {string|null} Current course ID or null
 */
function getSelectedCourseId() {
    const urlParams = new URLSearchParams(window.location.search);
    const courseIdFromUrl = urlParams.get('courseId');
    const courseIdFromStorage = localStorage.getItem('selectedCourseId');
    return courseIdFromUrl || courseIdFromStorage || null;
}

/**
 * Update navigation links to include course ID
 */
function updateNavigationLinks() {
    const courseId = getSelectedCourseId();
    if (!courseId) return;
    
    // List of navigation link IDs and their base paths
    const navLinks = {
        'nav-home': '/instructor/home',
        'nav-documents': '/instructor/documents',
        'nav-onboarding': '/instructor/onboarding',
        'nav-flagged': '/instructor/flagged',
        'nav-student-hub': '/instructor/student-hub',
        'nav-downloads': '/instructor/downloads',
        'nav-ta-hub': '/instructor/ta-hub',
        'nav-settings': '/instructor/settings'
    };
    
    // Update each navigation link
    Object.keys(navLinks).forEach(linkId => {
        const link = document.getElementById(linkId);
        if (link) {
            const basePath = navLinks[linkId];
            const url = new URL(basePath, window.location.origin);
            url.searchParams.set('courseId', courseId);
            link.href = url.pathname + url.search;
        }
    });
    
    // Also update the "View Flagged Questions" button
    const viewFlagsBtn = document.getElementById('view-flags-btn');
    if (viewFlagsBtn) {
        const url = new URL('/instructor/flagged', window.location.origin);
        url.searchParams.set('courseId', courseId);
        viewFlagsBtn.href = url.pathname + url.search;
    }
} 

/**
 * Load persistence (all-time) struggle topics for the selected course
 */
async function loadPersistenceTopics() {
    try {
        const courseId = getSelectedCourseId();
        if (!courseId) return;

        const response = await authenticatedFetch(`/api/struggle-activity/persistence/${courseId}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const result = await response.json();
        const topics = result.data || [];

        renderPersistenceTopics(topics);

    } catch (error) {
        console.error('Error loading persistence topics:', error);
        document.getElementById('persistence-topics-section')?.setAttribute('style', 'display: none;');
    }
}

/**
 * Load approved global topics for the selected course
 */
async function loadApprovedGlobalTopics() {
    try {
        const courseId = getSelectedCourseId();
        if (!courseId) return;

        const response = await authenticatedFetch(`/api/courses/${courseId}/approved-topics`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const result = await response.json();
        const topics = Array.isArray(result?.data?.topics) ? result.data.topics : [];

        renderApprovedGlobalTopics(topics, courseId);
    } catch (error) {
        console.error('Error loading approved global topics:', error);
        document.getElementById('approved-topics-section')?.setAttribute('style', 'display: none;');
    }
}

/**
 * Render approved global topics list with inline editing capabilities
 * @param {Array<string>} topics - Approved topic labels
 * @param {string} courseId - Current course ID
 */
function renderApprovedGlobalTopics(topics, courseId) {
    const container = document.getElementById('approved-topics-content');
    const section = document.getElementById('approved-topics-section');
    if (!container || !section) return;

    section.style.display = 'block';

    const cleanTopics = Array.isArray(topics)
        ? [...new Set(topics.map(t => String(t || '').trim()).filter(Boolean).map(t => t.toLowerCase()))]
            .map(normalized => {
                const original = topics.find(t => String(t || '').trim().toLowerCase() === normalized);
                return String(original || normalized).trim();
            })
        : [];

    window.courseApprovedTopicsByCourse = window.courseApprovedTopicsByCourse || {};
    window.courseApprovedTopicsByCourse[courseId] = cleanTopics;
    window.courseApprovedTopics = cleanTopics;

    // Build editable chips
    const chips = cleanTopics.map((topic, index) => `
        <span class="approved-topic-chip" data-index="${index}" data-topic="${escapeHtml(topic)}">
            <span class="topic-chip-label" ondblclick="startEditTopic(this)">${escapeHtml(topic)}</span>
            <button class="topic-chip-remove" onclick="removeApprovedTopic(${index})" title="Remove topic">&times;</button>
        </span>
    `).join('');

    const emptyMessage = cleanTopics.length === 0
        ? '<p class="no-data-message" style="text-align: center; color: #666; font-style: italic; padding: 10px;">No approved global topics set yet. Add one below.</p>'
        : '';

    container.innerHTML = `
        <div class="approved-topics-chips-container" id="approved-topics-chips">
            ${emptyMessage}
            ${chips}
        </div>
        <div class="approved-topics-add-row">
            <input
                type="text"
                id="new-topic-input"
                class="approved-topic-input"
                placeholder="Type a new topic and press Enter..."
                onkeydown="handleNewTopicKeydown(event)"
            />
            <button class="approved-topic-add-btn" onclick="addApprovedTopic()" title="Add topic">+ Add</button>
        </div>
        <div class="approved-topics-footer">
            <span>Total topics: <strong>${cleanTopics.length}</strong></span>
            <span class="approved-topics-hint">Double-click a topic to edit it</span>
        </div>
    `;
}

// ===========================
// APPROVED TOPICS CRUD
// ===========================

/**
 * Save the current approved topics list to the server
 * @param {string} [courseId] - Course ID (falls back to selected course)
 * @returns {Promise<boolean>} Whether save succeeded
 */
async function saveApprovedTopics(courseId) {
    courseId = courseId || getSelectedCourseId();
    if (!courseId) return false;

    const topics = window.courseApprovedTopics || [];

    try {
        const response = await authenticatedFetch(`/api/courses/${courseId}/approved-topics`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ topics })
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.message || `HTTP ${response.status}`);
        }

        return true;
    } catch (error) {
        console.error('Error saving approved topics:', error);
        showErrorMessage(`Failed to save topics: ${error.message}`);
        return false;
    }
}

/**
 * Add a new approved topic from the input field
 */
async function addApprovedTopic() {
    const input = document.getElementById('new-topic-input');
    if (!input) return;

    const value = input.value.trim();
    if (!value) {
        input.focus();
        return;
    }

    const topics = window.courseApprovedTopics || [];

    // Check for duplicates (case-insensitive)
    if (topics.some(t => t.toLowerCase() === value.toLowerCase())) {
        showErrorMessage('This topic already exists.');
        input.focus();
        input.select();
        return;
    }

    topics.push(value);
    window.courseApprovedTopics = topics;

    const courseId = getSelectedCourseId();

    // Optimistically re-render
    renderApprovedGlobalTopics(topics, courseId);
    showSuccessMessage(`Added topic "${value}"`);

    // Persist to server
    const saved = await saveApprovedTopics(courseId);
    if (!saved) {
        // Revert on failure
        topics.pop();
        window.courseApprovedTopics = topics;
        renderApprovedGlobalTopics(topics, courseId);
    } else {
        // Focus the input for rapid entry
        const newInput = document.getElementById('new-topic-input');
        if (newInput) newInput.focus();
    }
}

/**
 * Remove an approved topic by index
 * @param {number} index - Index in the approved topics array
 */
async function removeApprovedTopic(index) {
    const topics = window.courseApprovedTopics || [];
    if (index < 0 || index >= topics.length) return;

    const removedTopic = topics[index];

    if (!confirm(`Remove the topic "${removedTopic}"?`)) return;

    topics.splice(index, 1);
    window.courseApprovedTopics = topics;

    const courseId = getSelectedCourseId();

    // Optimistically re-render
    renderApprovedGlobalTopics(topics, courseId);
    showSuccessMessage(`Removed topic "${removedTopic}"`);

    // Persist to server
    const saved = await saveApprovedTopics(courseId);
    if (!saved) {
        // Revert on failure
        topics.splice(index, 0, removedTopic);
        window.courseApprovedTopics = topics;
        renderApprovedGlobalTopics(topics, courseId);
    }
}

/**
 * Start inline editing a topic chip label
 * Triggered by double-clicking the label text
 * @param {HTMLElement} labelEl - The .topic-chip-label span
 */
function startEditTopic(labelEl) {
    const chip = labelEl.closest('.approved-topic-chip');
    if (!chip || chip.classList.contains('editing')) return;

    const index = parseInt(chip.dataset.index, 10);
    const currentValue = (window.courseApprovedTopics || [])[index];
    if (currentValue === undefined) return;

    chip.classList.add('editing');

    // Replace label with an input
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'topic-chip-edit-input';
    input.value = currentValue;

    // Save on Enter, cancel on Escape
    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            commitEditTopic(chip, index, input.value.trim());
        } else if (e.key === 'Escape') {
            e.preventDefault();
            cancelEditTopic(chip, currentValue);
        }
    });

    // Save on blur (clicking away)
    input.addEventListener('blur', () => {
        // Small delay so that pressing Escape can fire first
        setTimeout(() => {
            if (chip.classList.contains('editing')) {
                commitEditTopic(chip, index, input.value.trim());
            }
        }, 100);
    });

    labelEl.replaceWith(input);
    input.focus();
    input.select();
}

/**
 * Commit an inline topic edit
 * @param {HTMLElement} chip - The .approved-topic-chip element
 * @param {number} index - Index in the topics array
 * @param {string} newValue - New topic text
 */
async function commitEditTopic(chip, index, newValue) {
    if (!chip.classList.contains('editing')) return;
    chip.classList.remove('editing');

    const topics = window.courseApprovedTopics || [];
    const oldValue = topics[index];

    // If empty or unchanged, just restore
    if (!newValue || newValue === oldValue) {
        cancelEditTopic(chip, oldValue);
        return;
    }

    // Check for duplicates
    if (topics.some((t, i) => i !== index && t.toLowerCase() === newValue.toLowerCase())) {
        showErrorMessage('A topic with that name already exists.');
        cancelEditTopic(chip, oldValue);
        return;
    }

    // Apply change
    topics[index] = newValue;
    window.courseApprovedTopics = topics;

    const courseId = getSelectedCourseId();
    renderApprovedGlobalTopics(topics, courseId);
    showSuccessMessage(`Renamed "${oldValue}" to "${newValue}"`);

    // Persist
    const saved = await saveApprovedTopics(courseId);
    if (!saved) {
        topics[index] = oldValue;
        window.courseApprovedTopics = topics;
        renderApprovedGlobalTopics(topics, courseId);
    }
}

/**
 * Cancel an inline edit and restore the original label
 * @param {HTMLElement} chip - The .approved-topic-chip element
 * @param {string} originalValue - Original topic text to restore
 */
function cancelEditTopic(chip, originalValue) {
    chip.classList.remove('editing');
    const input = chip.querySelector('.topic-chip-edit-input');
    if (input) {
        const label = document.createElement('span');
        label.className = 'topic-chip-label';
        label.setAttribute('ondblclick', 'startEditTopic(this)');
        label.textContent = originalValue;
        input.replaceWith(label);
    }
}

/**
 * Handle keydown in the "add new topic" input
 * @param {KeyboardEvent} event
 */
function handleNewTopicKeydown(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        addApprovedTopic();
    }
}

/**
 * Render persistence topics list
 * @param {Array} topics - Array of persistence topic objects
 */
function renderPersistenceTopics(topics) {
    const container = document.getElementById('persistence-topics-content');
    const section = document.getElementById('persistence-topics-section');
    
    if (!container || !section) return;

    if (topics.length === 0) {
        section.style.display = 'block';
        container.innerHTML = '<p class="no-data-message" style="text-align: center; color: #666; font-style: italic; padding: 20px;">No struggle data recorded yet.</p>';
        return;
    }

    section.style.display = 'block';
    
    // Sort by count (descending)
    const sortedTopics = [...topics].sort((a, b) => b.studentCount - a.studentCount);

    let html = '<div class="persistence-topics-list" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px;">';
    
    sortedTopics.forEach(topicData => {
        const displayTopic = topicData.topic.charAt(0).toUpperCase() + topicData.topic.slice(1);
        const count = topicData.studentCount;
        
        // Determine severity color
        let severityColor = '#28a745'; // Green (low)
        if (count >= 5) severityColor = '#ffc107'; // Yellow (medium)
        if (count >= 10) severityColor = '#dc3545'; // Red (high)
        
        html += `
            <div class="persistence-topic-card" style="background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-top: 4px solid ${severityColor}; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center;">
                <div style="font-size: 2.5em; font-weight: bold; color: #333; margin-bottom: 5px;">${count}</div>
                <div style="font-size: 0.9em; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px;">Students</div>
                <h3 style="margin: 0; font-size: 1.1em; color: #333; word-break: break-word;">${displayTopic}</h3>
            </div>
        `;
    });
    
    html += '</div>';
    
    container.innerHTML = html;
}

/**
 * Toggle visibility of struggle topic content
 * @param {HTMLElement} headerElement - The header element clicked
 */
function toggleTopic(headerElement) {
    const topicItem = headerElement.closest('.struggle-topic-item');
    if (topicItem) {
        topicItem.classList.toggle('collapsed');
    }
}

/**
 * Toggle visibility of an entire home section
 * @param {HTMLElement} headerElement - The header clicked
 */
function toggleSection(headerElement) {
    const section = headerElement.closest('.home-section');
    if (section) {
        section.classList.toggle('section-collapsed');
    }
}
