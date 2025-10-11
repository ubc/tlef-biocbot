/**
 * Flagged Content Management JavaScript
 * Handles displaying and moderating student-flagged responses
 */

/**
 * Application state management
 */
const appState = {
    flags: [],
    filteredFlags: [],
    currentFilters: {
        flagType: 'all',
        status: 'pending'
    },
    stats: {
        totalFlags: 0,
        pendingFlags: 0,
        flagsToday: 0
    }
};

/**
 * Initialize the flagged content page
 */
document.addEventListener('DOMContentLoaded', async function() {
    initializeEventListeners();
    
    // Wait for authentication to be ready before loading courses
    await waitForAuth();
    
    // Load content directly
    initializeFilters();
    loadFlaggedContent();
    loadFlagStats();
});

/**
 * Initialize filter state to match dropdown values
 */
function initializeFilters() {
    const flagTypeFilter = document.getElementById('flag-type-filter');
    const statusFilter = document.getElementById('status-filter');
    
    if (flagTypeFilter && statusFilter) {
        appState.currentFilters.flagType = flagTypeFilter.value;
        appState.currentFilters.status = statusFilter.value;
        console.log('Filters initialized:', appState.currentFilters);
    }
}

/**
 * Sync filter state with UI dropdowns
 */
function syncFiltersWithUI() {
    const flagTypeFilter = document.getElementById('flag-type-filter');
    const statusFilter = document.getElementById('status-filter');
    
    if (flagTypeFilter && statusFilter) {
        // Update UI to match current filter state
        flagTypeFilter.value = appState.currentFilters.flagType;
        statusFilter.value = appState.currentFilters.status;
        console.log('UI synced with filter state:', appState.currentFilters);
    }
}

/**
 * Set up event listeners for the page
 */
function initializeEventListeners() {
    // Filter controls
    const flagTypeFilter = document.getElementById('flag-type-filter');
    const statusFilter = document.getElementById('status-filter');
    const refreshButton = document.getElementById('refresh-flags');
    if (flagTypeFilter) {
        flagTypeFilter.addEventListener('change', handleFilterChange);
    }
    
    if (statusFilter) {
        statusFilter.addEventListener('change', handleFilterChange);
    }
    
    if (refreshButton) {
        refreshButton.addEventListener('click', handleRefresh);
    }
}


/**
 * Handle filter changes and update the displayed content
 */
function handleFilterChange() {
    const flagTypeFilter = document.getElementById('flag-type-filter');
    const statusFilter = document.getElementById('status-filter');
    
    // Update current filters
    appState.currentFilters.flagType = flagTypeFilter.value;
    appState.currentFilters.status = statusFilter.value;
    
    // Apply filters and re-render
    applyFilters();
    renderFlaggedContent();
}

/**
 * Handle refresh button click
 */
function handleRefresh() {
    const refreshButton = document.getElementById('refresh-flags');
    refreshButton.textContent = 'Refreshing...';
    refreshButton.disabled = true;
    
    Promise.all([loadFlaggedContent(), loadFlagStats()])
        .finally(() => {
            refreshButton.textContent = 'Refresh';
            refreshButton.disabled = false;
        });
}

/**
 * Fetch flagged content from the API
 */
async function loadFlaggedContent() {
    try {
        showLoadingState();
        
        // Get current course ID from auth or other source
        const courseId = getCurrentCourseId();
        
        if (!courseId) {
            console.log('No course available, showing empty state');
            appState.flags = [];
            applyFilters();
            renderFlaggedContent();
            return;
        }
        
        console.log(`Loading flagged content for course: ${courseId}`);
        
        // Always load all flags for the course, let local filters handle filtering
        const apiUrl = `/api/flags/course/${courseId}`;
        
        const response = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (result.success) {
            appState.flags = result.data.flags || [];
            console.log(`Loaded ${appState.flags.length} flagged questions for course ${courseId}`);
            console.log('Flags data:', appState.flags);
            applyFilters();
            renderFlaggedContent();
        } else {
            throw new Error(result.message || 'Failed to load flagged content');
        }
        
    } catch (error) {
        console.error('Error loading flagged content:', error);
        showErrorState('Failed to load flagged content. Please try again.');
    }
}

/**
 * Fetch flag statistics from the API
 */
async function loadFlagStats() {
    try {
        // Get current course ID from auth or other source
        const courseId = getCurrentCourseId();
        
        if (!courseId) {
            console.log('No course available, using default stats');
            appState.stats = { total: 0, pending: 0, reviewed: 0, resolved: 0, dismissed: 0 };
            updateStatsDisplay();
            return;
        }
        
        console.log(`Loading flag statistics for course: ${courseId}`);
        
        const response = await fetch(`/api/flags/stats/${courseId}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (result.success) {
            appState.stats = result.data.statistics;
            console.log('Flag statistics loaded:', appState.stats);
            updateStatsDisplay();
        }
        
    } catch (error) {
        console.error('Error loading flag stats:', error);
        // Don't show error for stats, just use defaults
        appState.stats = { total: 0, pending: 0, reviewed: 0, resolved: 0, dismissed: 0 };
        updateStatsDisplay();
    }
}

/**
 * Apply current filters to the flags data
 */
function applyFilters() {
    const { flagType, status } = appState.currentFilters;
    
    console.log('Applying filters with state:', appState.currentFilters);
    console.log('Available flags:', appState.flags);
    
    appState.filteredFlags = appState.flags.filter(flag => {
        const matchesFlagType = flagType === 'all' || flag.flagReason === flagType;
        const matchesStatus = status === 'all' || flag.flagStatus === status;
        
        console.log(`Flag ${flag.flagId}: flagReason=${flag.flagReason}, flagStatus=${flag.flagStatus}`);
        console.log(`  matchesFlagType: ${flagType} === 'all' || ${flag.flagReason} === ${flagType} = ${matchesFlagType}`);
        console.log(`  matchesStatus: ${status} === 'all' || ${flag.flagStatus} === ${status} = ${matchesStatus}`);
        
        return matchesFlagType && matchesStatus;
    });
    
    console.log(`Applied filters: flagType=${flagType}, status=${status}`);
    console.log(`Filtered ${appState.filteredFlags.length} flags from ${appState.flags.length} total`);
    console.log('Filtered flags:', appState.filteredFlags);
}

/**
 * Render the flagged content list
 */
function renderFlaggedContent() {
    const flaggedList = document.getElementById('flagged-list');
    const loadingState = document.getElementById('loading-state');
    const emptyState = document.getElementById('empty-state');
    
    // Hide loading state
    if (loadingState) {
        loadingState.style.display = 'none';
    }
    
    if (!flaggedList) return;
    
    // Clear existing content
    flaggedList.innerHTML = '';
    
    if (appState.filteredFlags.length === 0) {
        // Show empty state
        if (emptyState) {
            emptyState.style.display = 'block';
        }
        return;
    }
    
    // Hide empty state
    if (emptyState) {
        emptyState.style.display = 'none';
    }
    
    // Render each flagged item
    appState.filteredFlags.forEach(flag => {
        const flagElement = createFlagElement(flag);
        flaggedList.appendChild(flagElement);
    });
}

/**
 * Create a DOM element for a single flagged item
 * @param {Object} flag - The flag data object
 * @returns {HTMLElement} The created flag element
 */
function createFlagElement(flag) {
    const flagDiv = document.createElement('div');
    flagDiv.className = 'flagged-item';
    flagDiv.setAttribute('data-flag-id', flag.flagId);
    
    // Format timestamp for display
    const timestamp = formatTimestamp(flag.createdAt);
    
    // Create flag reason display text
    const flagReasonDisplay = getFlagReasonDisplay(flag.flagReason);
    
    // Get question content for display
    const questionContent = flag.questionContent || {};
    
    flagDiv.innerHTML = `
        <div class="flag-header">
            <div class="flag-meta">
                <div class="flag-reason ${flag.flagReason}">${flagReasonDisplay}</div>
                <div class="flag-student-info">Flagged by: ${flag.studentName || `Student ${flag.studentId}`}</div>
                <div class="flag-timestamp">${timestamp}</div>
                <div class="flag-priority">Priority: ${flag.priority || 'medium'}</div>
            </div>
            <div class="flag-status">
                <span class="status-badge ${flag.flagStatus}">${getStatusDisplayText(flag.flagStatus)}</span>
            </div>
        </div>
        
        <div class="flag-content">
            <div class="question-content">
                <div class="content-label">Flagged Question:</div>
                <div class="question-text">${escapeHtml(questionContent.question || 'Question content not available')}</div>
                <div class="question-details">
                    <span class="question-type">Type: ${questionContent.questionType || 'Unknown'}</span>
                    <span class="unit-name">Unit: ${flag.unitName || 'Unknown'}</span>
                </div>
            </div>
            
            <div class="flag-description">
                <div class="content-label">Student's Concern:</div>
                <div class="flag-message">${escapeHtml(flag.flagDescription)}</div>
            </div>
            
            ${flag.instructorResponse ? `
                <div class="instructor-response">
                    <div class="content-label">Instructor Response:</div>
                    <div class="response-text">${escapeHtml(flag.instructorResponse)}</div>
                    <div class="response-meta">Responded by: ${flag.instructorName || 'Instructor'} on ${formatTimestamp(flag.updatedAt)}</div>
                </div>
            ` : ''}
        </div>
        
        <div class="flag-actions">
            ${createActionButtons(flag)}
        </div>
    `;
    
    return flagDiv;
}

/**
 * Create action buttons based on flag status
 * @param {Object} flag - The flag data object
 * @returns {string} HTML for action buttons
 */
function createActionButtons(flag) {
    if (flag.flagStatus === 'pending') {
        return `
            <button class="action-btn approve-btn" onclick="showApprovalForm('${flag.flagId}')">
                Approve
            </button>
            <button class="action-btn dismiss-btn" onclick="handleFlagAction('${flag.flagId}', 'rejected')">
                Dismiss
            </button>
            <div id="approval-form-${flag.flagId}" class="approval-form" style="display: none;">
                <div class="form-header">
                    <h4>Send Follow-up to Student</h4>
                    <p class="form-description">This message will be sent to the student who flagged this content.</p>
                </div>
                <div class="form-group">
                    <label for="message-content-${flag.flagId}">Message:</label>
                    <textarea id="message-content-${flag.flagId}" class="message-textarea" rows="4">Thanks for flagging this, please follow up on this email or come to my office hours if you are still working on this topic</textarea>
                </div>
                <div class="form-actions">
                    <button class="action-btn send-approve-btn" onclick="sendApprovalMessage('${flag.flagId}')">
                        Send & Approve
                    </button>
                    <button class="action-btn cancel-btn" onclick="hideApprovalForm('${flag.flagId}')">
                        Cancel
                    </button>
                </div>
                <!-- Hidden email field for backend processing -->
                <input type="hidden" id="student-email-${flag.flagId}" value="student.${flag.studentId}@university.edu">
            </div>
        `;
    } else {
        return `
            <button class="action-btn view-btn" onclick="viewFlagDetails('${flag.flagId}')">
                View Details
            </button>
        `;
    }
}

/**
 * Show the approval form for a specific flag
 * @param {string} flagId - The flag ID
 */
function showApprovalForm(flagId) {
    const approvalForm = document.getElementById(`approval-form-${flagId}`);
    const approveButton = document.querySelector(`[data-flag-id="${flagId}"] .approve-btn`);
    const dismissButton = document.querySelector(`[data-flag-id="${flagId}"] .dismiss-btn`);
    
    if (approvalForm) {
        approvalForm.style.display = 'block';
        approvalForm.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        
        // Hide the action buttons while form is open
        if (approveButton) approveButton.style.display = 'none';
        if (dismissButton) dismissButton.style.display = 'none';
    }
}

/**
 * Hide the approval form for a specific flag
 * @param {string} flagId - The flag ID
 */
function hideApprovalForm(flagId) {
    const approvalForm = document.getElementById(`approval-form-${flagId}`);
    const approveButton = document.querySelector(`[data-flag-id="${flagId}"] .approve-btn`);
    const dismissButton = document.querySelector(`[data-flag-id="${flagId}"] .dismiss-btn`);
    
    if (approvalForm) {
        approvalForm.style.display = 'none';
        
        // Show the action buttons again
        if (approveButton) approveButton.style.display = 'inline-block';
        if (dismissButton) dismissButton.style.display = 'inline-block';
    }
}

/**
 * Send approval message and approve the flag
 * @param {string} flagId - The flag ID
 */
async function sendApprovalMessage(flagId) {
    try {
        const emailInput = document.getElementById(`student-email-${flagId}`);
        const messageTextarea = document.getElementById(`message-content-${flagId}`);
        
        if (!emailInput || !messageTextarea) {
            throw new Error('Form elements not found');
        }
        
        const studentEmail = emailInput.value.trim(); // Hidden field, automatically generated
        const messageContent = messageTextarea.value.trim();
        
        if (!messageContent) {
            alert('Please enter a message to send to the student.');
            return;
        }
        
        // Disable form while processing
        const sendButton = document.querySelector(`[data-flag-id="${flagId}"] .send-approve-btn`);
        const cancelButton = document.querySelector(`[data-flag-id="${flagId}"] .cancel-btn`);
        
        if (sendButton) {
            sendButton.textContent = 'Sending...';
            sendButton.disabled = true;
        }
        if (cancelButton) {
            cancelButton.disabled = true;
        }
        
        // TODO: Replace with actual instructor ID from auth
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        const instructorName = 'Instructor Name';
        
        // Send instructor response using the new API
        const response = await fetch(`/api/flags/${flagId}/response`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                response: messageContent,
                instructorId: instructorId,
                instructorName: instructorName,
                flagStatus: 'resolved'
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (result.success) {
            // Update the flag in local state
            const flagIndex = appState.flags.findIndex(flag => flag.flagId === flagId);
            if (flagIndex !== -1) {
                appState.flags[flagIndex].flagStatus = 'resolved';
                appState.flags[flagIndex].instructorResponse = messageContent;
                appState.flags[flagIndex].instructorId = instructorId;
                appState.flags[flagIndex].instructorName = instructorName;
                appState.flags[flagIndex].updatedAt = new Date().toISOString();
            }
            
            // Hide the approval form
            hideApprovalForm(flagId);
            
            // Re-apply filters and re-render
            applyFilters();
            renderFlaggedContent();
            
            // Refresh stats
            loadFlagStats();
            
            // Show combined success message
            showSuccessMessage('Follow-up message sent to student and flag resolved successfully');
            
        } else {
            throw new Error(result.message || 'Failed to send instructor response');
        }
        
    } catch (error) {
        console.error('Error sending approval message:', error);
        showErrorMessage('Failed to send message. Please try again.');
        
        // Re-enable form
        const sendButton = document.querySelector(`[data-flag-id="${flagId}"] .send-approve-btn`);
        const cancelButton = document.querySelector(`[data-flag-id="${flagId}"] .cancel-btn`);
        
        if (sendButton) {
            sendButton.textContent = 'Send & Approve';
            sendButton.disabled = false;
        }
        if (cancelButton) {
            cancelButton.disabled = false;
        }
    }
}

/**
 * Handle flag action (approve/reject)
 * @param {string} flagId - The flag ID
 * @param {string} action - The action to take (resolved/dismissed)
 * @param {boolean} skipSuccessMessage - Whether to skip showing the success message
 */
async function handleFlagAction(flagId, action, skipSuccessMessage = false) {
    try {
        // Disable buttons to prevent double-clicking
        const flagElement = document.querySelector(`[data-flag-id="${flagId}"]`);
        const buttons = flagElement.querySelectorAll('.action-btn');
        buttons.forEach(btn => btn.disabled = true);
        
        // TODO: Replace with actual instructor ID from auth
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        const instructorName = 'Instructor Name';
        
        // Map old action names to new ones
        const actionMap = {
            'approved': 'resolved',
            'rejected': 'dismissed'
        };
        
        const newStatus = actionMap[action] || action;
        
        // Update flag status using the new API
        const response = await fetch(`/api/flags/${flagId}/status`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                status: newStatus,
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (result.success) {
            // Update the flag in local state
            const flagIndex = appState.flags.findIndex(flag => flag.flagId === flagId);
            if (flagIndex !== -1) {
                appState.flags[flagIndex].flagStatus = newStatus;
            }
            
            // Re-apply filters and re-render
            applyFilters();
            renderFlaggedContent();
            
            // Refresh stats
            loadFlagStats();
            
            // Show success message only if not skipped
            if (!skipSuccessMessage) {
                const actionText = newStatus === 'dismissed' ? 'dismissed' : newStatus;
                showSuccessMessage(`Flag ${actionText} successfully`);
            }
            
        } else {
            throw new Error(result.message || `Failed to ${newStatus} flag`);
        }
        
    } catch (error) {
        const actionText = action === 'rejected' ? 'dismiss' : action;
        console.error(`Error ${actionText} flag:`, error);
        showErrorMessage(`Failed to ${actionText} flag. Please try again.`);
        
        // Re-enable buttons
        const flagElement = document.querySelector(`[data-flag-id="${flagId}"]`);
        const buttons = flagElement.querySelectorAll('.action-btn');
        buttons.forEach(btn => btn.disabled = false);
    }
}

/**
 * View flag details (placeholder for future implementation)
 * @param {string} flagId - The flag ID
 */
function viewFlagDetails(flagId) {
    const flag = appState.flags.find(f => f.flagId === flagId);
    if (flag) {
        // TODO: Implement detailed view modal or navigation
        alert(`Flag Details:\n\nStudent: ${flag.studentId}\nType: ${flag.flagReason}\nStatus: ${flag.flagStatus}\nTimestamp: ${flag.createdAt}\n\nMessage: ${flag.flagDescription}`);
    }
}

/**
 * Update the statistics display
 */
function updateStatsDisplay() {
    const totalElement = document.getElementById('total-flags');
    const pendingElement = document.getElementById('pending-flags');
    const todayElement = document.getElementById('today-flags');
    
    if (totalElement) {
        totalElement.textContent = appState.stats.total || 0;
    }
    
    if (pendingElement) {
        pendingElement.textContent = appState.stats.pending || 0;
    }
    
    if (todayElement) {
        // Calculate today's flags from the flags array
        const today = new Date();
        const todayStart = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        const todayFlags = appState.flags.filter(flag => {
            const flagDate = new Date(flag.createdAt);
            return flagDate >= todayStart;
        }).length;
        todayElement.textContent = todayFlags;
    }
}

/**
 * Show loading state
 */
function showLoadingState() {
    const loadingState = document.getElementById('loading-state');
    const emptyState = document.getElementById('empty-state');
    const flaggedList = document.getElementById('flagged-list');
    
    if (loadingState) {
        loadingState.style.display = 'block';
    }
    
    if (emptyState) {
        emptyState.style.display = 'none';
    }
    
    if (flaggedList) {
        flaggedList.innerHTML = '';
    }
}

/**
 * Show error state
 * @param {string} message - Error message to display
 */
function showErrorState(message) {
    const loadingState = document.getElementById('loading-state');
    const emptyState = document.getElementById('empty-state');
    const flaggedList = document.getElementById('flagged-list');
    
    if (loadingState) {
        loadingState.style.display = 'none';
    }
    
    if (emptyState) {
        emptyState.innerHTML = `<p style="color: #ef4444;">${message}</p>`;
        emptyState.style.display = 'block';
    }
    
    if (flaggedList) {
        flaggedList.innerHTML = '';
    }
}

/**
 * Utility Functions
 */

/**
 * Format timestamp for display
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted timestamp
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    
    try {
        const date = new Date(timestamp);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) {
            return 'Just now';
        } else if (diffMins < 60) {
            return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
        } else if (diffHours < 24) {
            return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
        } else if (diffDays < 7) {
            return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
        } else {
            return date.toLocaleDateString();
        }
    } catch (error) {
        return 'Invalid date';
    }
}

/**
 * Get display text for flag reason
 * @param {string} flagReason - The flag reason
 * @returns {string} Display text for the flag reason
 */
function getFlagReasonDisplay(flagReason) {
    const reasonMap = {
        'incorrect': 'Incorrect',
        'inappropriate': 'Inappropriate',
        'unclear': 'Unclear',
        'confusing': 'Confusing',
        'typo': 'Typo/Error',
        'offensive': 'Offensive',
        'irrelevant': 'Irrelevant'
    };
    
    return reasonMap[flagReason] || flagReason;
}

/**
 * Get display text for flag status
 * @param {string} status - The flag status
 * @returns {string} Display text for the status
 */
function getStatusDisplayText(status) {
    const statusMap = {
        'pending': 'Pending Review',
        'reviewed': 'Reviewed',
        'resolved': 'Resolved',
        'dismissed': 'Dismissed'
    };
    
    return statusMap[status] || status;
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show success message (simple implementation)
 * @param {string} message - Success message
 */
function showSuccessMessage(message) {
    // Calculate position based on existing toasts
    const existingToasts = document.querySelectorAll('.success-toast');
    const topOffset = 20 + (existingToasts.length * 60); // Stack toasts 60px apart
    
    // Simple toast notification implementation
    const toast = document.createElement('div');
    toast.className = 'success-toast';
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        top: ${topOffset}px;
        right: 20px;
        background: #10b981;
        color: white;
        padding: 12px 20px;
        border-radius: 6px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        z-index: 1000;
        font-size: 14px;
        font-weight: 500;
        animation: slideInRight 0.3s ease-out;
        max-width: 300px;
        word-wrap: break-word;
    `;
    
    // Add animation keyframes to document if not already added
    if (!document.querySelector('#toast-animations')) {
        const style = document.createElement('style');
        style.id = 'toast-animations';
        style.textContent = `
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOutRight {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }
    
    document.body.appendChild(toast);
    
    // Auto-remove after 4 seconds (longer for longer message)
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, 4000);
    
    console.log('Success:', message);
}

/**
 * Show error message (simple implementation)
 * @param {string} message - Error message
 */
function showErrorMessage(message) {
    // TODO: Implement proper toast notification system
    console.error('Error:', message);
    alert(message); // Temporary simple alert
}

/**
 * Get auth token from storage (placeholder for future implementation)
 * @returns {string|null} Auth token
 */
function getAuthToken() {
    // TODO: Implement actual token retrieval from localStorage/sessionStorage
    return null;
}

/**
 * Wait for authentication to be initialized
 * @returns {Promise<void>}
 */
async function waitForAuth() {
    // Wait for auth.js to initialize
    let attempts = 0;
    const maxAttempts = 50; // 5 seconds max wait
    
    while (attempts < maxAttempts) {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) {
            console.log('✅ [AUTH] Authentication ready');
            return;
        }
        
        // Wait 100ms before next attempt
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }
    
    console.warn('⚠️ [AUTH] Authentication not ready after 5 seconds, proceeding anyway');
}