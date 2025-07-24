/**
 * Home Page JavaScript
 * Handles instructor dashboard functionality and interactions
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize home page functionality
    initializeHomePage();
});

/**
 * Initialize all home page functionality
 */
function initializeHomePage() {
    // Add event listeners for buttons
    setupButtonListeners();
    
    // Load dashboard data
    loadDashboardData();
    
    // Set up auto-refresh for activity feed
    setupAutoRefresh();
}

/**
 * Set up button event listeners
 */
function setupButtonListeners() {
    // Upload New Material button
    const uploadBtn = document.querySelector('.course-actions .action-btn:nth-child(1)');
    if (uploadBtn) {
        uploadBtn.addEventListener('click', handleUploadMaterial);
    }
    
    // Probe Questions button
    const probeBtn = document.querySelector('.course-actions .action-btn:nth-child(2)');
    if (probeBtn) {
        probeBtn.addEventListener('click', handleProbeQuestions);
    }
    
    // Investigate button
    const investigateBtn = document.querySelector('.digest-flags .action-btn');
    if (investigateBtn) {
        investigateBtn.addEventListener('click', handleInvestigateFlags);
    }
}

/**
 * Handle Upload New Material button click
 */
function handleUploadMaterial() {
    console.log('Navigate to upload page');
    // Navigate to the course upload page
    window.location.href = '/instructor';
}

/**
 * Handle Probe Questions button click
 */
function handleProbeQuestions() {
    console.log('Navigate to probe questions page');
    // TODO: Navigate to probe questions page when implemented
    showInfoMessage('Probe Questions feature coming soon!');
}

/**
 * Handle Investigate Flags button click
 */
function handleInvestigateFlags() {
    console.log('Navigate to flags investigation page');
    // TODO: Navigate to flags investigation page when implemented
    showInfoMessage('Flags investigation feature coming soon!');
}

/**
 * Load dashboard data from API
 */
async function loadDashboardData() {
    try {
        // Load course summary data
        await loadCourseSummary();
        
        // Load daily digest data
        await loadDailyDigest();
        
        // Load recent activity data
        await loadRecentActivity();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showErrorMessage('Failed to load dashboard data');
    }
}

/**
 * Load course summary data
 */
async function loadCourseSummary() {
    try {
        const instructorId = getCurrentInstructorId();
        const response = await fetch(`/api/courses?instructorId=${instructorId}`);
        
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.data.length > 0) {
                updateCourseSummary(data.data[0]); // Use first course for now
            }
        }
    } catch (error) {
        console.error('Error loading course summary:', error);
    }
}

/**
 * Update course summary display
 * @param {Object} courseData - Course data from API
 */
function updateCourseSummary(courseData) {
    const courseName = document.querySelector('.course-name');
    const courseMeta = document.querySelector('.course-meta');
    
    if (courseName && courseData.name) {
        courseName.textContent = courseData.name;
    }
    
    if (courseMeta && courseData) {
        // Generate course meta info
        const term = '2025 W1'; // This would come from course data
        const courseCode = courseData.name.replace(' ', '') + '25T1';
        courseMeta.textContent = `Term: ${term}, Course Code: ${courseCode}`;
    }
}

/**
 * Load daily digest data
 */
async function loadDailyDigest() {
    try {
        // TODO: Replace with actual API endpoint when implemented
        const mockData = {
            studyMinutes: 55,
            coveredTopics: ['Biology', 'Heart'],
            newFlags: 10
        };
        
        updateDailyDigest(mockData);
        
    } catch (error) {
        console.error('Error loading daily digest:', error);
    }
}

/**
 * Update daily digest display
 * @param {Object} digestData - Digest data
 */
function updateDailyDigest(digestData) {
    const studyMinutes = document.querySelector('.stat-item:nth-child(1) .stat-value');
    const coveredTopics = document.querySelector('.stat-item:nth-child(2) .stat-value');
    const flagsCount = document.querySelector('.flags-count');
    
    if (studyMinutes && digestData.studyMinutes) {
        studyMinutes.textContent = `${digestData.studyMinutes} min`;
    }
    
    if (coveredTopics && digestData.coveredTopics) {
        coveredTopics.textContent = digestData.coveredTopics.join(', ');
    }
    
    if (flagsCount && digestData.newFlags) {
        flagsCount.textContent = `${digestData.newFlags} New Flags Today`;
    }
}

/**
 * Load recent activity data
 */
async function loadRecentActivity() {
    try {
        // TODO: Replace with actual API endpoint when implemented
        const mockActivities = [
            { id: 1, text: 'Week_1 lecture uploaded', status: 'success' },
            { id: 2, text: 'Week_3 lecture uploaded', status: 'success' },
            { id: 3, text: 'LO_1 not uploaded properly', status: 'error' },
            { id: 4, text: 'LO_2 not parsed properly', status: 'error' }
        ];
        
        updateRecentActivity(mockActivities);
        
    } catch (error) {
        console.error('Error loading recent activity:', error);
    }
}

/**
 * Update recent activity display
 * @param {Array} activities - Array of activity objects
 */
function updateRecentActivity(activities) {
    const activityList = document.querySelector('.activity-list');
    
    if (!activityList) return;
    
    // Clear existing activities
    activityList.innerHTML = '';
    
    // Add new activities
    activities.forEach((activity, index) => {
        const activityItem = document.createElement('div');
        activityItem.className = `activity-item ${activity.status}`;
        activityItem.innerHTML = `
            <span class="activity-number">${index + 1}.</span>
            <span class="activity-text">${activity.text}</span>
        `;
        
        activityList.appendChild(activityItem);
    });
}

/**
 * Set up auto-refresh for activity feed
 */
function setupAutoRefresh() {
    // Refresh activity feed every 30 seconds
    setInterval(async () => {
        try {
            await loadRecentActivity();
        } catch (error) {
            console.error('Error refreshing activity feed:', error);
        }
    }, 30000);
}

/**
 * Get current instructor ID (placeholder)
 * @returns {string} Instructor ID
 */
function getCurrentInstructorId() {
    // This would typically come from JWT token or session
    // For now, return a placeholder
    return 'instructor-123';
}

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