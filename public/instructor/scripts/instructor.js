// API base URL configuration - change this if proxy isn't working
const API_BASE_URL = ''; // Empty string for relative URLs, 'http://localhost:8085' for absolute

// AI generation tracking variables
let aiGenerationCount = 0;
let lastGeneratedContent = null;
let currentQuestionType = null;

/**
 * Wait for authentication to be ready
 * @returns {Promise<void>}
 */
async function waitForAuth() {
    return new Promise((resolve) => {
        // Check if auth is already ready
        if (getCurrentUser()) {
            resolve();
            return;
        }
        
        // Wait for auth:ready event
        document.addEventListener('auth:ready', () => {
            console.log('✅ [AUTH] Authentication ready');
            resolve();
        }, { once: true });
        
        // Fallback timeout in case auth never loads
        setTimeout(() => {
            console.warn('⚠️ [AUTH] Authentication timeout, proceeding anyway');
            resolve();
        }, 5000);
    });
}

document.addEventListener('DOMContentLoaded', async () => {
    console.log('🚀 [DOM_LOADED] Instructor page loaded');
    
    // Wait for authentication to be initialized
    await waitForAuth();
    
    // Update sidebar for TAs
    await updateSidebarForTA();
    
    // Set up periodic permission refresh for TAs
    if (typeof isTA === 'function' && isTA()) {
        // Refresh permissions every 30 seconds
        setInterval(async () => {
            await updateTANavigationBasedOnPermissions();
        }, 30000);
        
        // Also refresh when page becomes visible
        document.addEventListener('visibilitychange', async () => {
            if (!document.hidden) {
                await updateTANavigationBasedOnPermissions();
            }
        });
    }
    const uploadDropArea = document.getElementById('upload-drop-area');
    const fileUpload = document.getElementById('file-upload');
    const documentSearch = document.getElementById('document-search');
    const documentFilter = document.getElementById('document-filter');
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    const sectionHeaders = document.querySelectorAll('.section-header');
    
    // Make sure all "Add Additional Material" buttons are visible
    const additionalMaterialButtons = document.querySelectorAll('.add-content-btn.additional-material');
    additionalMaterialButtons.forEach(button => {
        button.style.display = 'flex';
        button.style.visibility = 'visible';
        button.style.opacity = '1';
    });
    
    // Add click outside modal to close functionality
    document.addEventListener('click', (e) => {
        const uploadModal = document.getElementById('upload-modal');
        const calibrationModal = document.getElementById('calibration-modal');
        const viewModal = document.getElementById('view-modal');
        const questionModal = document.getElementById('question-modal');
        
        // Close upload modal if clicking outside
        if (uploadModal && uploadModal.classList.contains('show') && e.target === uploadModal) {
            closeUploadModal();
        }
        

        
        // Close question modal if clicking outside
        if (questionModal && questionModal.classList.contains('show') && e.target === questionModal) {
            closeQuestionModal();
        }
    });
    
    // Initialize section headers to be clickable
    sectionHeaders.forEach(header => {
        header.addEventListener('click', (e) => {
            toggleSection(header, e);
        });
        
        // Make sure toggle icon matches initial state
        const sectionContent = header.nextElementSibling;
        const toggleIcon = header.querySelector('.toggle-section');
        if (sectionContent && toggleIcon) {
            if (sectionContent.classList.contains('collapsed')) {
                toggleIcon.textContent = '▶';
            } else {
                toggleIcon.textContent = '▼';
            }
        }
    });

// Unit Management Functions

/**
 * Add a new unit to the course
 */
async function addNewUnit() {
    const addUnitBtn = document.getElementById('add-unit-btn');
    if (addUnitBtn) {
        addUnitBtn.disabled = true;
        addUnitBtn.innerHTML = '<span class="loading-spinner-small"></span> Adding...';
    }
    
    // Mark container as adding
    const container = document.getElementById('dynamic-units-container');
    if (container) container.dataset.addingUnit = 'true';
    
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        const response = await fetch(`/api/courses/${courseId}/units`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ instructorId })
        });
        
        if (!response.ok) {
            throw new Error('Failed to add unit');
        }
        
        const result = await response.json();
        showNotification(result.message, 'success');
        
        // Reload course data to refresh the UI
        if (container) delete container.dataset.addingUnit;
        await loadSpecificCourse(courseId);
        
    } catch (error) {
        console.error('Error adding new unit:', error);
        showNotification('Failed to add new unit: ' + error.message, 'error');
        if (addUnitBtn) {
            addUnitBtn.disabled = false;
            addUnitBtn.innerHTML = '<span class="btn-icon">➕</span> Add New Unit';
        }
        if (container) delete container.dataset.addingUnit;
    }
}

// Delete Unit Modal Logic
let unitToDelete = null;

function openDeleteUnitModal(unitName) {
    // Stop propagation if triggered from inside the accordion header
    if (window.event) {
        window.event.stopPropagation();
    }
    
    unitToDelete = unitName;
    const modal = document.getElementById('delete-unit-modal');
    const displaySpan = document.getElementById('delete-unit-name-display');
    
    if (displaySpan) displaySpan.textContent = unitName;
    if (modal) {
        modal.style.display = ''; // Clear inline style to let CSS class handle display: flex
        modal.classList.add('show');
    }
}

function closeDeleteUnitModal() {
    unitToDelete = null;
    const modal = document.getElementById('delete-unit-modal');
    if (modal) {
        modal.classList.remove('show');
        modal.style.display = 'none';
    }
}

async function confirmDeleteUnit() {
    if (!unitToDelete) return;
    
    const confirmBtn = document.getElementById('confirm-delete-unit-btn');
    if (confirmBtn) {
        confirmBtn.disabled = true;
        confirmBtn.textContent = 'Deleting...';
    }
    
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        // Encode unit name for URL (it might have spaces)
        const encodedUnitName = encodeURIComponent(unitToDelete);
        
        const response = await fetch(`/api/courses/${courseId}/units/${encodedUnitName}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ instructorId })
        });
        
        if (!response.ok) {
            throw new Error('Failed to delete unit');
        }
        
        const result = await response.json();
        showNotification(result.message, 'success');
        
        closeDeleteUnitModal();
        
        // Reload course data
        await loadSpecificCourse(courseId);
        
    } catch (error) {
        console.error('Error deleting unit:', error);
        showNotification('Failed to delete unit: ' + error.message, 'error');
    } finally {
        if (confirmBtn) {
            confirmBtn.disabled = false;
            confirmBtn.textContent = 'Delete Unit';
        }
    }
}

// Make functions globally available
window.addNewUnit = addNewUnit;
window.openDeleteUnitModal = openDeleteUnitModal;
window.closeDeleteUnitModal = closeDeleteUnitModal;
window.confirmDeleteUnit = confirmDeleteUnit;

    
    // Load the saved publish status from the database
    loadPublishStatus();
    
    // Start polling for publish status changes (to detect updates from other users)
    startPublishStatusPolling();
    
    // Only run dashboard initialization if we're on the dashboard page
    const dashboardContainer = document.getElementById('dynamic-units-container') || document.getElementById('upload-drop-area');
    if (dashboardContainer) {
        // Load the saved learning objectives from the database
        loadLearningObjectives();
        
        // Load the saved documents from the database
        loadDocuments().then(() => {
            updatePublishedSummary();
        });
        
        // Load the saved assessment questions from the database first
        loadAssessmentQuestions().then(() => {
            // Wait a bit for DOM to be ready, then load thresholds
            setTimeout(() => {
                loadPassThresholds();
            }, 500);
        });
        
        // Set up threshold input event listeners
        setupThresholdInputListeners();
        
        // Load course data if available (either from onboarding or existing course)
        loadCourseData();
    }
    
    // Add global cleanup button

    
    // Handle accordion toggling
    accordionHeaders.forEach(header => {
        header.addEventListener('click', (e) => {
            // Don't toggle if clicking on the toggle switch
            if (e.target.closest('.publish-toggle')) {
                return;
            }
            
            const accordionItem = header.parentElement;
            const content = accordionItem.querySelector('.accordion-content');
            const toggle = header.querySelector('.accordion-toggle');
            
            // Use the improved toggle function
            toggleAccordionDynamic(content, toggle);
        });
    });
    
    

    

    
    // Initialize assessment system
    initializeAssessmentSystem();
    
    // Start monitoring lecture notes status changes
    monitorLectureNotesStatus();
});

// Global function to show notification
function showNotification(message, type = 'info') {
    // Check if notification container exists, if not create it
    let notificationContainer = document.querySelector('.notification-container');
    if (!notificationContainer) {
        notificationContainer = document.createElement('div');
        notificationContainer.classList.add('notification-container');
        document.body.appendChild(notificationContainer);
    }
    
    // Create notification element
    const notification = document.createElement('div');
    notification.classList.add('notification', type);
    notification.textContent = message;
    
    // Add close button
    const closeBtn = document.createElement('button');
    closeBtn.classList.add('notification-close');
    closeBtn.innerHTML = '&times;';
    closeBtn.addEventListener('click', () => {
        notification.remove();
    });
    
    notification.appendChild(closeBtn);
    notificationContainer.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Modal functionality for content upload
let uploadedFile = null;
let currentWeek = null;
let currentContentType = null;
let topicReviewResolve = null;

function normalizeTopicLabel(topic) {
    if (typeof topic !== 'string') return '';
    return topic.replace(/\s+/g, ' ').trim();
}

function dedupeTopics(topics = []) {
    const seen = new Set();
    const output = [];

    topics.forEach((topic) => {
        const normalized = normalizeTopicLabel(topic);
        if (!normalized) return;
        const key = normalized.toLowerCase();
        if (seen.has(key)) return;
        seen.add(key);
        output.push(normalized);
    });

    return output;
}

function setCourseTopicsGlobal(courseId, topics) {
    if (!courseId) return;
    const cleanTopics = dedupeTopics(topics);
    window.courseApprovedTopicsByCourse = window.courseApprovedTopicsByCourse || {};
    window.courseApprovedTopicsByCourse[courseId] = cleanTopics;
    window.courseApprovedTopics = cleanTopics;
}

async function fetchCourseApprovedTopics(courseId) {
    const response = await fetch(`/api/courses/${courseId}/approved-topics`);
    if (!response.ok) {
        throw new Error(`Failed to fetch approved topics: ${response.status}`);
    }

    const result = await response.json();
    const topics = dedupeTopics(result?.data?.topics || []);
    setCourseTopicsGlobal(courseId, topics);
    return topics;
}

async function extractTopicsForUploadedDocument(courseId, documentId) {
    if (!documentId) return [];

    const response = await fetch(`/api/courses/${courseId}/extract-topics`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ documentId, maxTopics: 8 })
    });

    if (!response.ok) {
        throw new Error(`Failed to extract topics: ${response.status}`);
    }

    const result = await response.json();
    return dedupeTopics(result?.data?.topics || []);
}

async function saveCourseApprovedTopics(courseId, topics) {
    const response = await fetch(`/api/courses/${courseId}/approved-topics`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topics: dedupeTopics(topics) })
    });

    if (!response.ok) {
        throw new Error(`Failed to save approved topics: ${response.status}`);
    }

    const result = await response.json();
    const savedTopics = dedupeTopics(result?.data?.topics || []);
    setCourseTopicsGlobal(courseId, savedTopics);
    return savedTopics;
}

function ensureTopicReviewModal() {
    let modal = document.getElementById('topic-review-modal');
    if (modal) return modal;

    if (!document.getElementById('topic-review-style')) {
        const style = document.createElement('style');
        style.id = 'topic-review-style';
        style.textContent = `
            .topic-review-context {
                margin: 0 0 10px;
                color: #333;
                font-size: 14px;
            }
            .topic-review-hint {
                margin: 0 0 12px;
                color: #666;
                font-size: 13px;
            }
            .topic-review-list {
                display: flex;
                flex-direction: column;
                gap: 8px;
                max-height: 280px;
                overflow-y: auto;
                margin-bottom: 10px;
            }
            .topic-review-item {
                display: grid;
                grid-template-columns: 1fr auto;
                gap: 8px;
                align-items: center;
            }
            .topic-review-input {
                width: 100%;
                padding: 10px;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                font-size: 14px;
            }
            .topic-review-remove {
                border: 1px solid #d0d7de;
                background: #fff;
                color: #a61b1b;
                border-radius: 6px;
                padding: 8px 10px;
                cursor: pointer;
                font-size: 12px;
            }
            .topic-review-add-row {
                display: grid;
                grid-template-columns: 1fr auto;
                gap: 8px;
                margin-top: 6px;
            }
            .topic-review-empty {
                padding: 10px;
                border: 1px dashed #c7ced6;
                border-radius: 6px;
                color: #666;
                font-size: 13px;
                text-align: center;
            }
        `;
        document.head.appendChild(style);
    }

    modal = document.createElement('div');
    modal.id = 'topic-review-modal';
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h2>Review Detected Topics</h2>
                <button class="modal-close" id="topic-review-close-btn">×</button>
            </div>
            <div class="modal-body">
                <p class="topic-review-context" id="topic-review-context"></p>
                <p class="topic-review-hint">These are topics found in this upload only. Edit, add, or remove before saving. Existing course topics are not affected.</p>
                <div class="topic-review-list" id="topic-review-list"></div>
                <div class="topic-review-add-row">
                    <input id="topic-review-new-input" class="topic-review-input" type="text" placeholder="Add a topic (e.g., Enzyme Kinetics)" />
                    <button class="btn-secondary" id="topic-review-add-btn">Add Topic</button>
                </div>
            </div>
            <div class="modal-footer">
                <div class="modal-actions">
                    <button class="btn-secondary" id="topic-review-cancel-btn">Cancel</button>
                    <button class="btn-primary" id="topic-review-save-btn">Save Topics</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    const closeWithResult = (topics) => {
        modal.classList.remove('show');
        modal.style.display = 'none';
        const resolver = topicReviewResolve;
        topicReviewResolve = null;
        if (resolver) resolver(topics);
    };

    modal.addEventListener('click', (event) => {
        if (event.target === modal) closeWithResult(null);
    });

    modal.querySelector('#topic-review-close-btn').addEventListener('click', () => closeWithResult(null));
    modal.querySelector('#topic-review-cancel-btn').addEventListener('click', () => closeWithResult(null));

    modal.querySelector('#topic-review-add-btn').addEventListener('click', () => {
        const input = modal.querySelector('#topic-review-new-input');
        const value = normalizeTopicLabel(input.value);
        if (!value) return;
        addTopicReviewRow(value);
        input.value = '';
        input.focus();
    });

    modal.querySelector('#topic-review-save-btn').addEventListener('click', () => {
        closeWithResult(collectTopicReviewRows());
    });

    return modal;
}

function addTopicReviewRow(topic) {
    const modal = ensureTopicReviewModal();
    const list = modal.querySelector('#topic-review-list');

    // Remove empty placeholder when first real topic is added.
    const emptyState = list.querySelector('.topic-review-empty');
    if (emptyState) emptyState.remove();

    const row = document.createElement('div');
    row.className = 'topic-review-item';
    const input = document.createElement('input');
    input.className = 'topic-review-input';
    input.type = 'text';
    input.value = topic;

    const removeButton = document.createElement('button');
    removeButton.className = 'topic-review-remove';
    removeButton.type = 'button';
    removeButton.textContent = 'Remove';

    row.appendChild(input);
    row.appendChild(removeButton);

    removeButton.addEventListener('click', () => {
        row.remove();
        if (!list.querySelector('.topic-review-item')) {
            list.innerHTML = '<div class="topic-review-empty">No topics yet. Add at least one topic to track struggle mapping.</div>';
        }
    });

    list.appendChild(row);
}

function collectTopicReviewRows() {
    const modal = ensureTopicReviewModal();
    const rows = Array.from(modal.querySelectorAll('.topic-review-item .topic-review-input'));
    return dedupeTopics(rows.map((input) => input.value));
}

function populateTopicReviewRows(topics) {
    const modal = ensureTopicReviewModal();
    const list = modal.querySelector('#topic-review-list');
    list.innerHTML = '';

    const cleanTopics = dedupeTopics(topics);
    if (cleanTopics.length === 0) {
        list.innerHTML = '<div class="topic-review-empty">No new topics detected from this upload. You can add topics manually below.</div>';
        return;
    }

    cleanTopics.forEach((topic) => addTopicReviewRow(topic));
}

function openTopicReviewModal(courseId, sourceName, existingTopics, suggestedTopics) {
    const modal = ensureTopicReviewModal();

    // Only show NEW topics that don't already exist in the course list
    const existingSet = new Set((existingTopics || []).map(t => t.toLowerCase().trim()));
    const newOnlyTopics = dedupeTopics(
        (suggestedTopics || []).filter(t => !existingSet.has(t.toLowerCase().trim()))
    );

    const contextText = sourceName
        ? `New topics detected from: ${sourceName}`
        : 'New topics detected from the uploaded content.';

    modal.querySelector('#topic-review-context').textContent = contextText;
    modal.querySelector('#topic-review-new-input').value = '';
    populateTopicReviewRows(newOnlyTopics);

    // Show a read-only count of existing topics so the instructor has context
    let existingNote = modal.querySelector('#topic-review-existing-note');
    if (!existingNote) {
        existingNote = document.createElement('p');
        existingNote.id = 'topic-review-existing-note';
        existingNote.style.cssText = 'margin:0 0 10px; color:#666; font-size:12px; font-style:italic;';
        const hint = modal.querySelector('.topic-review-hint');
        if (hint) hint.insertAdjacentElement('afterend', existingNote);
    }
    if (existingTopics && existingTopics.length > 0) {
        existingNote.textContent = `${existingTopics.length} existing topic${existingTopics.length === 1 ? '' : 's'} already saved for this course (not shown).`;
        existingNote.style.display = '';
    } else {
        existingNote.style.display = 'none';
    }

    modal.style.display = '';
    modal.classList.add('show');

    return new Promise((resolve) => {
        topicReviewResolve = resolve;
    });
}

async function runTopicReviewAfterUpload(courseId, documentId, sourceName) {
    if (!courseId) return;

    let existingTopics = [];
    let suggestedTopics = [];

    try {
        existingTopics = await fetchCourseApprovedTopics(courseId);
    } catch (error) {
        console.warn('Could not load existing approved topics:', error);
    }

    try {
        suggestedTopics = await extractTopicsForUploadedDocument(courseId, documentId);
    } catch (error) {
        console.warn('Could not extract topics from uploaded document:', error);
    }

    // Modal only shows NEW topics from this upload (existing are hidden)
    const reviewedNewTopics = await openTopicReviewModal(courseId, sourceName, existingTopics, suggestedTopics);
    if (!reviewedNewTopics) {
        showNotification('Topic review skipped. Existing course topics were unchanged.', 'info');
        return;
    }

    // Merge: keep all existing topics + append the reviewed new ones
    const mergedTopics = dedupeTopics([...existingTopics, ...reviewedNewTopics]);

    const savedTopics = await saveCourseApprovedTopics(courseId, mergedTopics);
    const addedCount = savedTopics.length - existingTopics.length;
    if (addedCount > 0) {
        showNotification(`Added ${addedCount} new topic${addedCount === 1 ? '' : 's'} (${savedTopics.length} total).`, 'success');
    } else {
        showNotification('No new topics were added.', 'info');
    }
}

/**
 * Open the upload modal for a specific week and content type
 * @param {string} week - The week identifier (e.g., 'Week 1')
 * @param {string} contentType - The content type ('lecture-notes', 'practice-quiz', 'additional', etc.)
 */
function openUploadModal(week, contentType = '') {
    currentWeek = week;
    currentContentType = contentType;
    
    // Set dynamic modal title based on content type
    const modalTitle = document.getElementById('modal-title');
    const uploadFileBtn = document.querySelector('.upload-file-btn span:last-child');
    const nameInputSection = document.getElementById('name-input-section');
    let title = 'Upload Content';
    let buttonText = 'Upload Content';
    
    switch (contentType) {
        case 'lecture-notes':
            title = 'Upload Lecture Notes';
            buttonText = 'Upload Lecture Notes';
            break;
        case 'practice-quiz':
            title = 'Upload Practice Questions/Tutorial';
            buttonText = 'Upload Practice Questions';
            break;
        case 'additional':
            title = 'Upload Additional Material';
            buttonText = 'Upload Additional Material';
            break;
        default:
            title = `Upload Content for ${week}`;
            buttonText = 'Upload Content';
    }
    
    modalTitle.textContent = title;
    if (uploadFileBtn) {
        uploadFileBtn.textContent = buttonText;
    }
    
    // Always minimize name input section as per user request to remove rename capability
    if (nameInputSection) {
        nameInputSection.style.display = 'none';
    }
    
    // Reset the modal to initial state
    resetModal();
    
    // Show the modal
    const modal = document.getElementById('upload-modal');
    modal.style.display = '';
    modal.classList.add('show');
}

/**
 * Close the upload modal
 */
function closeUploadModal() {
    // Check if upload is in progress
    const loadingIndicator = document.getElementById('upload-loading-indicator');
    if (loadingIndicator && loadingIndicator.style.display === 'block') {
        // Upload in progress, prevent closing
        showNotification('Please wait for the upload to complete before closing.', 'warning');
        return;
    }
    
    const modal = document.getElementById('upload-modal');
    modal.classList.remove('show');
    modal.style.display = 'none';
    resetModal();
}

/**
 * Reset modal to initial state
 */
function resetModal() {
    uploadedFile = null;
    pendingTopicReviewData = null;

    // Reset file input and info
    const fileInput = document.getElementById('file-input');
    const fileInfo = document.getElementById('file-info');
    const textInput = document.getElementById('text-input');
    const materialName = document.getElementById('material-name');
    const uploadFileBtn = document.querySelector('.upload-file-btn span:last-child');

    if (fileInput) fileInput.value = '';
    if (fileInfo) fileInfo.style.display = 'none';
    if (textInput) textInput.value = '';
    if (materialName) materialName.value = '';

    // Reset upload file button text to default
    if (uploadFileBtn) {
        uploadFileBtn.textContent = 'Upload Content';
    }

    // Reset upload button text and show it; hide Save Topics button
    const uploadBtn = document.getElementById('upload-btn');
    const saveBtn = document.getElementById('save-topics-btn');
    if (uploadBtn) {
        uploadBtn.textContent = 'Upload';
        uploadBtn.disabled = false;
        uploadBtn.style.display = '';
    }
    if (saveBtn) saveBtn.style.display = 'none';

    // Hide loading indicator and show upload section; hide topic review section
    const loadingIndicator = document.getElementById('upload-loading-indicator');
    const uploadSection = document.getElementById('upload-section');
    const topicSection = document.getElementById('topic-review-section');
    if (loadingIndicator) loadingIndicator.style.display = 'none';
    if (uploadSection) uploadSection.style.display = 'block';
    if (topicSection) topicSection.style.display = 'none';

    // Reset to selection view
    resetToSelection();
}

/**
 * Show file upload section
 */
function showFileUpload() {
    document.getElementById('upload-method-selection').style.display = 'none';
    document.getElementById('file-upload-section').style.display = 'block';
    document.getElementById('text-input-section').style.display = 'none';
}

/**
 * Show text input section
 */
function showTextInput() {
    document.getElementById('upload-method-selection').style.display = 'none';
    document.getElementById('file-upload-section').style.display = 'none';
    document.getElementById('text-input-section').style.display = 'block';
}

/**
 * Reset to selection view
 */
function resetToSelection() {
    document.getElementById('upload-method-selection').style.display = 'flex';
    document.getElementById('file-upload-section').style.display = 'none';
    document.getElementById('text-input-section').style.display = 'none';
}

// --- Inline Topic Review (inside upload modal) ---

// State for pending topic save after inline review
let pendingTopicReviewData = null;

function ensureTopicReviewStyles() {
    if (document.getElementById('topic-review-style')) return;
    const style = document.createElement('style');
    style.id = 'topic-review-style';
    style.textContent = `
        .topic-review-context { margin: 0 0 10px; color: #333; font-size: 14px; }
        .topic-review-hint { margin: 0 0 12px; color: #666; font-size: 13px; }
        .topic-review-list { display: flex; flex-direction: column; gap: 8px; max-height: 280px; overflow-y: auto; margin-bottom: 10px; }
        .topic-review-item { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center; }
        .topic-review-input { width: 100%; padding: 10px; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; }
        .topic-review-remove { border: 1px solid #d0d7de; background: #fff; color: #a61b1b; border-radius: 6px; padding: 8px 10px; cursor: pointer; font-size: 12px; }
        .topic-review-add-row { display: grid; grid-template-columns: 1fr auto; gap: 8px; margin-top: 6px; }
        .topic-review-empty { padding: 10px; border: 1px dashed #c7ced6; border-radius: 6px; color: #666; font-size: 13px; text-align: center; }
    `;
    document.head.appendChild(style);
}

function addInlineTopicRow(topic) {
    const list = document.getElementById('upload-topic-review-list');
    if (!list) return;

    const emptyState = list.querySelector('.topic-review-empty');
    if (emptyState) emptyState.remove();

    const row = document.createElement('div');
    row.className = 'topic-review-item';
    const input = document.createElement('input');
    input.className = 'topic-review-input';
    input.type = 'text';
    input.value = topic;

    const removeButton = document.createElement('button');
    removeButton.className = 'topic-review-remove';
    removeButton.type = 'button';
    removeButton.textContent = 'Remove';

    row.appendChild(input);
    row.appendChild(removeButton);

    removeButton.addEventListener('click', () => {
        row.remove();
        if (!list.querySelector('.topic-review-item')) {
            list.innerHTML = '<div class="topic-review-empty">No topics yet. Add at least one topic to track struggle mapping.</div>';
        }
    });

    list.appendChild(row);
}

function collectInlineTopicRows() {
    const rows = Array.from(document.querySelectorAll('#upload-topic-review-list .topic-review-item .topic-review-input'));
    return dedupeTopics(rows.map((input) => input.value));
}

function showInlineTopicReview(courseId, sourceName, existingTopics, suggestedTopics) {
    ensureTopicReviewStyles();

    // Filter to only new topics
    const existingSet = new Set((existingTopics || []).map(t => t.toLowerCase().trim()));
    const newOnlyTopics = dedupeTopics(
        (suggestedTopics || []).filter(t => !existingSet.has(t.toLowerCase().trim()))
    );

    // Store data for when Save is clicked
    pendingTopicReviewData = { courseId, existingTopics };

    // Update modal title
    const modalTitle = document.getElementById('modal-title');
    if (modalTitle) modalTitle.textContent = 'Review Detected Topics';

    // Hide upload section and loading, show topic review section
    const uploadSection = document.getElementById('upload-section');
    const loadingIndicator = document.getElementById('upload-loading-indicator');
    const topicSection = document.getElementById('topic-review-section');
    if (uploadSection) uploadSection.style.display = 'none';
    if (loadingIndicator) loadingIndicator.style.display = 'none';
    if (topicSection) topicSection.style.display = 'block';

    // Set context text
    const contextEl = document.getElementById('upload-topic-review-context');
    if (contextEl) {
        contextEl.textContent = sourceName
            ? `New topics detected from: ${sourceName}`
            : 'New topics detected from the uploaded content.';
    }

    // Show existing topic count
    const existingNote = document.getElementById('upload-topic-existing-note');
    if (existingNote) {
        if (existingTopics && existingTopics.length > 0) {
            existingNote.textContent = `${existingTopics.length} existing topic${existingTopics.length === 1 ? '' : 's'} already saved for this course (not shown).`;
            existingNote.style.display = '';
        } else {
            existingNote.style.display = 'none';
        }
    }

    // Populate topic rows
    const list = document.getElementById('upload-topic-review-list');
    if (list) {
        list.innerHTML = '';
        const cleanTopics = dedupeTopics(newOnlyTopics);
        if (cleanTopics.length === 0) {
            list.innerHTML = '<div class="topic-review-empty">No new topics detected from this upload. You can add topics manually below.</div>';
        } else {
            cleanTopics.forEach(topic => addInlineTopicRow(topic));
        }
    }

    // Reset the new-topic input
    const newInput = document.getElementById('upload-topic-new-input');
    if (newInput) newInput.value = '';

    // Switch footer buttons: hide Upload, show Save Topics
    const uploadBtn = document.getElementById('upload-btn');
    const saveBtn = document.getElementById('save-topics-btn');
    if (uploadBtn) uploadBtn.style.display = 'none';
    if (saveBtn) saveBtn.style.display = '';

    // Wire up the Add Topic button
    const addBtn = document.getElementById('upload-topic-add-btn');
    if (addBtn) {
        // Remove old listeners by cloning
        const newAddBtn = addBtn.cloneNode(true);
        addBtn.parentNode.replaceChild(newAddBtn, addBtn);
        newAddBtn.addEventListener('click', () => {
            const input = document.getElementById('upload-topic-new-input');
            const value = normalizeTopicLabel(input.value);
            if (!value) return;
            addInlineTopicRow(value);
            input.value = '';
            input.focus();
        });
    }

    // Re-enable modal close button
    const modalCloseBtn = document.querySelector('#upload-modal .modal-close');
    if (modalCloseBtn) {
        modalCloseBtn.style.pointerEvents = 'auto';
        modalCloseBtn.style.opacity = '1';
    }
}

async function handleSaveTopicsFromModal() {
    if (!pendingTopicReviewData) {
        closeUploadModal();
        return;
    }

    const { courseId, existingTopics } = pendingTopicReviewData;
    const reviewedNewTopics = collectInlineTopicRows();

    // Merge existing + reviewed new topics
    const mergedTopics = dedupeTopics([...(existingTopics || []), ...reviewedNewTopics]);

    try {
        const savedTopics = await saveCourseApprovedTopics(courseId, mergedTopics);
        const addedCount = savedTopics.length - (existingTopics || []).length;
        if (addedCount > 0) {
            showNotification(`Added ${addedCount} new topic${addedCount === 1 ? '' : 's'} (${savedTopics.length} total).`, 'success');
        } else {
            showNotification('No new topics were added.', 'info');
        }
    } catch (err) {
        console.error('Error saving topics:', err);
        showNotification('Could not save topics. Please try again.', 'error');
    }

    pendingTopicReviewData = null;
    closeUploadModal();
}

// --- End Inline Topic Review ---

/**
 * Trigger file input when upload button is clicked
 */
function triggerFileInput() {
    const fileInput = document.getElementById('file-input');
    fileInput.click();
}

/**
 * Handle file upload
 * @param {File} file - The uploaded file
 */
function handleFileUpload(file) {
    uploadedFile = file;
    
    // Show file info
    document.getElementById('file-name').textContent = file.name;
    document.getElementById('file-size').textContent = formatFileSize(file.size);
    document.getElementById('file-info').style.display = 'flex';
    
    showNotification(`File "${file.name}" selected successfully`, 'success');
}

/**
 * Handle the main upload action
 */
async function handleUpload() {
    const textInput = document.getElementById('text-input').value.trim();
    const materialNameInput = document.getElementById('material-name').value.trim();
    const uploadBtn = document.getElementById('upload-btn');
    
    // Check if at least one input method is provided
    if (!uploadedFile && !textInput) {
        showNotification('Please provide content via file upload or direct text input', 'error');
        return;
    }
    
    // Show loading indicator and hide upload section
    const loadingIndicator = document.getElementById('upload-loading-indicator');
    const uploadSection = document.getElementById('upload-section');
    if (loadingIndicator) loadingIndicator.style.display = 'block';
    if (uploadSection) uploadSection.style.display = 'none';
    
    // Disable upload button and show loading state
    uploadBtn.textContent = 'Uploading...';
    uploadBtn.disabled = true;
    
    // Disable modal close button during upload
    const modalCloseBtn = document.querySelector('#upload-modal .modal-close');
    if (modalCloseBtn) modalCloseBtn.style.pointerEvents = 'none';
    if (modalCloseBtn) modalCloseBtn.style.opacity = '0.5';
    
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        const lectureName = currentWeek;
        
        let uploadResult;
        
        if (uploadedFile) {
            // Handle file upload
            const formData = new FormData();
            formData.append('file', uploadedFile);
            formData.append('courseId', courseId);
            formData.append('lectureName', lectureName);
            formData.append('documentType', currentContentType);
            formData.append('instructorId', instructorId);

            // Determine strict title based on content type to ensure consistency
            let strictTitle = '';
            if (currentContentType === 'lecture-notes') {
                strictTitle = `*Lecture Notes - ${lectureName}`;
            } else if (currentContentType === 'practice-quiz') {
                strictTitle = `*Practice Questions/Tutorial - ${lectureName}`;
            } else if (currentContentType === 'additional') {
                strictTitle = `Additional Material - ${lectureName}`;
            }

            if (strictTitle) {
                formData.append('title', strictTitle);
            }
            
            const response = await fetch('/api/documents/upload', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Upload failed: ${response.status} ${errorText}`);
            }
            
            uploadResult = await response.json();
            
        } else if (textInput) {
            // Handle text submission
            const title = materialNameInput || `${currentContentType} - ${currentWeek}`;
            
            const response = await fetch('/api/documents/text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    courseId: courseId,
                    lectureName: lectureName,
                    documentType: currentContentType,
                    instructorId: instructorId,
                    content: textInput,
                    title: title,
                    description: ''
                })
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Text submission failed: ${response.status} ${errorText}`);
            }
            
            uploadResult = await response.json();
            
        } else if (urlInput) {
            // Handle URL import (treat as text with URL as description)
            const title = materialNameInput || `Content from URL - ${currentWeek}`;
            
            const response = await fetch('/api/documents/text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    courseId: courseId,
                    lectureName: lectureName,
                    documentType: currentContentType,
                    instructorId: instructorId,
                    content: `Content imported from: ${urlInput}`,
                    title: title,
                    description: urlInput
                })
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`URL import failed: ${response.status} ${errorText}`);
            }
            
            uploadResult = await response.json();
        }
        
        // Generate proper file name based on content type
        let fileName = '';
        switch (currentContentType) {
            case 'lecture-notes':
                fileName = `*Lecture Notes - ${currentWeek}`;
                break;
            case 'practice-quiz':
                fileName = `*Practice Questions/Tutorial - ${currentWeek}`;
                break;
            case 'additional':
                fileName = materialNameInput || `Additional Material - ${currentWeek}`;
                break;
            default:
                fileName = uploadResult?.data?.title || `Content - ${currentWeek}`;
        }
        
        // Add the content to the appropriate week with document ID
        const documentId = uploadResult?.data?.documentId;
        const uploadStatus = uploadResult?.data?.qdrantProcessed ? 'processed' : 'uploaded';
        addContentToWeek(currentWeek, fileName, `Uploaded successfully - ${uploadResult?.data?.filename || fileName}`, documentId, uploadStatus, currentContentType);
        
        showNotification(uploadResult?.message || 'Content uploaded successfully!', 'success');

        // Transition to inline topic review within the same modal
        try {
            let existingTopics = [];
            let suggestedTopics = [];

            try {
                existingTopics = await fetchCourseApprovedTopics(courseId);
            } catch (e) {
                console.warn('Could not load existing approved topics:', e);
            }

            try {
                suggestedTopics = await extractTopicsForUploadedDocument(courseId, documentId);
            } catch (e) {
                console.warn('Could not extract topics from uploaded document:', e);
            }

            showInlineTopicReview(courseId, fileName, existingTopics, suggestedTopics);
        } catch (topicError) {
            console.error('Error during topic review flow:', topicError);
            showNotification('Upload succeeded, but topic review could not be completed.', 'warning');
            closeUploadModal();
        }

    } catch (error) {
        console.error('Error uploading content:', error);
        showNotification(`Error uploading content: ${error.message}`, 'error');

        // Hide loading indicator and show upload section on error
        if (loadingIndicator) loadingIndicator.style.display = 'none';
        if (uploadSection) uploadSection.style.display = 'block';

        // Re-enable modal close button
        if (modalCloseBtn) modalCloseBtn.style.pointerEvents = 'auto';
        if (modalCloseBtn) modalCloseBtn.style.opacity = '1';

        // Re-enable upload button
        uploadBtn.textContent = 'Upload';
        uploadBtn.disabled = false;
    }
}

/**
 * Add content to a specific week
 * @param {string} week - The week identifier
 * @param {string} fileName - The file name to display
 * @param {string} description - The file description
 * @param {string} documentId - The document ID from the database
 * @param {string} status - The status to display ('uploaded' or 'processed')
 * @param {string} contentType - The content type ('lecture-notes', 'practice-quiz', etc.)
 */
function addContentToWeek(week, fileName, description, documentId, status = 'uploaded', contentType = null) {
    // Find the week accordion item using data-unit-name attribute (internal name like "Unit 1")
    const weekAccordion = document.querySelector(`.accordion-item[data-unit-name="${week}"]`);
    
    if (!weekAccordion) {
        console.error('Could not find week accordion for', week);
        return;
    }
    
    // Find existing file item to replace or create new one
    const courseMaterialsContent = weekAccordion.querySelector('.course-materials-section .section-content');
    let targetFileItem = null;
    
    // Check if we're replacing an existing placeholder
    const existingItems = courseMaterialsContent.querySelectorAll('.file-item');
    existingItems.forEach(item => {
        const title = item.querySelector('.file-info h3').textContent;
        const isPlaceholder = item.classList.contains('placeholder-item');
        
        // Check if this is a placeholder that matches our content type
        if (isPlaceholder) {
            if ((contentType === 'lecture-notes' && title.includes('*Lecture Notes')) ||
                (contentType === 'practice-quiz' && title.includes('*Practice Questions/Tutorial'))) {
                targetFileItem = item;
                console.log(`🔄 [ADD_CONTENT] Found matching placeholder for ${contentType}: "${title}"`);
            }
        }
    });
    
    if (targetFileItem) {
        // Update existing placeholder item
        console.log(`🔄 [ADD_CONTENT] Replacing placeholder with uploaded content: ${fileName}`);
        
        // Remove placeholder class and add document type
        targetFileItem.classList.remove('placeholder-item');
        if (contentType) {
            targetFileItem.dataset.documentType = contentType === 'lecture-notes' ? 'lecture_notes' : 
                                                contentType === 'practice-quiz' ? 'practice_q_tutorials' : contentType;
        }
        
        // Update content
        targetFileItem.querySelector('.file-info h3').textContent = fileName;
        targetFileItem.querySelector('.file-info p').textContent = description;
        targetFileItem.querySelector('.status-text').textContent = status === 'processed' ? 'Processed' : 'Uploaded';
        targetFileItem.querySelector('.status-text').className = `status-text ${status}`;
        
        // Set document ID for proper deletion
        if (documentId) {
            targetFileItem.dataset.documentId = documentId;
        }
        
        // Update action buttons - replace all buttons
        const actionsDiv = targetFileItem.querySelector('.file-actions');
        actionsDiv.innerHTML = ''; // Clear existing buttons
        
        // Add view button
        const viewButton = document.createElement('button');
        viewButton.className = 'action-button view';
        viewButton.textContent = 'View';
        viewButton.onclick = () => {
            if (documentId) {
                viewDocument(documentId);
            }
        };
        actionsDiv.appendChild(viewButton);
        
        // Add delete button
        const deleteButton = document.createElement('button');
        deleteButton.className = 'action-button delete';
        deleteButton.textContent = 'Delete';
        deleteButton.onclick = () => {
            if (documentId) {
                deleteDocument(documentId);
            }
        };
        actionsDiv.appendChild(deleteButton);
        
        console.log(`✅ [ADD_CONTENT] Successfully replaced placeholder with uploaded content: ${fileName}`);
    } else {
        // Create new file item
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        
        // Set document ID and type if available
        if (documentId) {
            fileItem.dataset.documentId = documentId;
        }
        if (contentType) {
            fileItem.dataset.documentType = contentType === 'lecture-notes' ? 'lecture_notes' : 
                                          contentType === 'practice-quiz' ? 'practice_q_tutorials' : contentType;
        }
        
        fileItem.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-info">
                <h3>${fileName}</h3>
                <p>${description}</p>
                <span class="status-text ${status}">${status === 'processed' ? 'Processed' : 'Uploaded'}</span>
            </div>
            <div class="file-actions">
                ${documentId ? `<button class="action-button view" onclick="viewDocument('${documentId}')">View</button>` : ''}
                ${documentId ? `<button class="action-button delete" onclick="deleteDocument('${documentId}')">Delete</button>` : ''}
            </div>
        `;
        
        // Insert before the action buttons section to maintain proper order
        const actionButtonsSection = courseMaterialsContent.querySelector('.add-content-section, .save-objectives');
        if (actionButtonsSection) {
            courseMaterialsContent.insertBefore(fileItem, actionButtonsSection);
        } else {
            // If no action buttons exist yet, add to the end
            courseMaterialsContent.appendChild(fileItem);
        }
    }
}

// Update the existing file upload event listener
document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('file-input');
    
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileUpload(e.target.files[0]);
            }
        });
    }
});

/**
 * Format file size
 * @param {number} bytes - File size in bytes
 * @returns {string} Formatted file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Old modal functions removed - using simple modal now

// Old confirmUpload and addContentToAccordion functions removed - replaced with addContentToWeek

/**
 * Toggle publish status for a lecture/week
 * @param {string} lectureName - Name of the lecture/week
 * @param {boolean} isPublished - Whether the content should be published
 */
function togglePublish(lectureName, isPublished) {
    // Find the accordion item using data-unit-name attribute (internal name like "Unit 1")
    const accordionItems = document.querySelectorAll('.accordion-item');
    let targetAccordion = null;
    
    for (let item of accordionItems) {
        const unitName = item.getAttribute('data-unit-name');
        if (unitName === lectureName) {
            targetAccordion = item;
            break;
        }
    }
    
    if (targetAccordion) {
        // Update visual state
        if (isPublished) {
            targetAccordion.classList.add('published');
            showNotification(`${lectureName} is now published and visible to students`, 'success');
        } else {
            targetAccordion.classList.remove('published');
            showNotification(`${lectureName} is now unpublished and hidden from students`, 'info');
        }
        
        // In a real implementation, this would make an API call to update the publish status
        updatePublishStatus(lectureName, isPublished);
    }
}

/**
 * Update publish status on the server
 * @param {string} lectureName - Name of the lecture/week
 * @param {boolean} isPublished - Whether the content should be published
 */
async function updatePublishStatus(lectureName, isPublished) {
    // Update cache and mark as local change IMMEDIATELY (optimistic update)
    // This prevents polling from detecting our own change as external
    currentPublishStatus[lectureName] = isPublished;
    recentLocalChanges[lectureName] = Date.now();
    
    // Clean up old entries from recentLocalChanges after cooldown period
    setTimeout(() => {
        delete recentLocalChanges[lectureName];
    }, LOCAL_CHANGE_COOLDOWN);
    
    try {
        // Get the current course ID (for now, using a default)
        const courseId = await getCurrentCourseId();
        
        const requestBody = {
            lectureName: lectureName,
            isPublished: isPublished,
            instructorId: getCurrentInstructorId(),
            courseId: courseId
        };
        
        const response = await fetch('/api/lectures/publish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
            console.error('Error response:', errorData);
            
            // Revert optimistic cache update on error
            const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
            const toggle = document.getElementById(toggleId);
            if (toggle) {
                // Revert to opposite of what we tried to set
                const revertedStatus = !isPublished;
                currentPublishStatus[lectureName] = revertedStatus;
                delete recentLocalChanges[lectureName];
                toggle.checked = revertedStatus;
                togglePublish(lectureName, revertedStatus);
            }
            
            // Show specific error message
            const errorMessage = errorData.message || errorData.error || `Failed to update publish status: ${response.status}`;
            showNotification(`Error: ${errorMessage}`, 'error');
            return;
        }
        
        const result = await response.json();
        
        // Verify the update was successful (cache already updated optimistically above)
        if (!result.success || !result.data) {
            // If API says it failed, revert our optimistic update
            const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
            const toggle = document.getElementById(toggleId);
            if (toggle) {
                const revertedStatus = !isPublished;
                currentPublishStatus[lectureName] = revertedStatus;
                delete recentLocalChanges[lectureName];
                toggle.checked = revertedStatus;
                togglePublish(lectureName, revertedStatus);
            }
            showNotification('Failed to update publish status. Please try again.', 'error');
            return;
        }
        
        // Show success notification
        // Success notification removed to prevent double notifications (already shown in togglePublish)
        console.log(result.message || 'Publish status updated successfully');
        
    } catch (error) {
        console.error('Error updating publish status:', error);
        
        // Revert optimistic cache update on error
        const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
        const toggle = document.getElementById(toggleId);
        if (toggle) {
            const revertedStatus = !isPublished;
            currentPublishStatus[lectureName] = revertedStatus;
            delete recentLocalChanges[lectureName];
            toggle.checked = revertedStatus;
            togglePublish(lectureName, revertedStatus);
        }
        
        showNotification('Error updating publish status. Please try again.', 'error');
    }
}

// getCurrentInstructorId() is now provided by ../common/scripts/auth.js

// Global variables to prevent multiple API calls and redirects
let courseIdCache = null;
let courseIdPromise = null;
let redirectInProgress = false;

/**
 * Update sidebar navigation for TAs
 */
async function updateSidebarForTA() {
    // Check if user is a TA
    if (typeof isTA === 'function' && isTA()) {
        console.log('🔄 [SIDEBAR] Updating sidebar for TA user');
        
        // Hide instructor navigation items
        const instructorNavItems = [
            'instructor-home-nav',
            'instructor-documents-nav', 
            'instructor-onboarding-nav',
            'instructor-flagged-nav',
            'instructor-downloads-nav',
            'instructor-ta-hub-nav',
            'instructor-settings-nav'
        ];
        
        instructorNavItems.forEach(id => {
            const element = document.getElementById(id);
            if (element) element.style.display = 'none';
        });
        
        // Show TA navigation items
        const taNavItems = [
            'ta-dashboard-nav',
            'ta-courses-nav',
            'ta-support-nav',
            'ta-settings-nav'
        ];
        
        taNavItems.forEach(id => {
            const element = document.getElementById(id);
            if (element) element.style.display = 'block';
        });
        
        // Update user info
        const userAvatar = document.querySelector('.user-avatar');
        if (userAvatar) {
            userAvatar.textContent = 'T';
        }
        
        const userRole = document.querySelector('.user-role');
        if (userRole) {
            userRole.textContent = 'Teaching Assistant';
        }
        
        // Setup TA navigation handlers
        setupTANavigationHandlers();
        
        // Update navigation based on permissions
        await updateTANavigationBasedOnPermissions();
        
        console.log('✅ [SIDEBAR] Sidebar updated for TA');
    } else {
        // Explicitly set role for regular Instructors
        const userRole = document.querySelector('.user-role');
        if (userRole) {
            userRole.textContent = 'Instructor';
        }
    }
}

/**
 * Setup TA navigation handlers
 */
function setupTANavigationHandlers() {
    console.log('🔍 [TA NAV] Setting up TA navigation handlers');
    
    // TA My Courses link
    const taMyCoursesLink = document.getElementById('ta-my-courses-link');
    if (taMyCoursesLink) {
        taMyCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('🔍 [TA NAV] My Courses clicked');
            // Already on courses page, do nothing
        });
    }
    
    // TA Student Support link
    const taStudentSupportLink = document.getElementById('ta-student-support-link');
    console.log('🔍 [TA NAV] Looking for ta-student-support-link element:', taStudentSupportLink);
    if (taStudentSupportLink) {
        console.log('🔍 [TA NAV] Setting up TA Student Support link');
        taStudentSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('🔍 [TA NAV] Student Support clicked');
            
            // Get courseId from URL
            const urlParams = new URLSearchParams(window.location.search);
            const courseId = urlParams.get('courseId');
            console.log('🔍 [TA NAV] Current URL:', window.location.href);
            console.log('🔍 [TA NAV] CourseId from URL:', courseId);
            
            if (courseId) {
                console.log('🔍 [TA NAV] Navigating to flagged page with courseId:', courseId);
                window.location.href = `/instructor/flagged?courseId=${courseId}`;
            } else {
                console.error('❌ [TA NAV] No courseId found in URL');
                alert('No course selected. Please try again.');
            }
        });
    } else {
        console.warn('⚠️ [TA NAV] TA Student Support link not found');
    }
}

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
        
        console.log(`Loading permissions for TA: ${taId}`);
        
        // First, we need to load TA courses to get the course IDs
        const coursesResponse = await authenticatedFetch(`/api/courses/ta/${taId}`);
        
        if (!coursesResponse.ok) {
            throw new Error(`HTTP error! status: ${coursesResponse.status}`);
        }
        
        const coursesResult = await coursesResponse.json();
        
        if (!coursesResult.success) {
            throw new Error(coursesResult.message || 'Failed to fetch TA courses');
        }
        
        const courses = coursesResult.data || [];
        console.log('TA courses for permissions:', courses);
        
        // Load permissions for each course
        const permissions = {};
        for (const course of courses) {
            const response = await authenticatedFetch(`/api/courses/${course.courseId}/ta-permissions/${taId}`);
            
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    permissions[course.courseId] = result.data.permissions;
                }
            }
        }
        
        console.log('TA permissions loaded:', permissions);
        
        // Store permissions globally
        window.taPermissions = permissions;
        
    } catch (error) {
        console.error('Error loading TA permissions:', error);
        window.taPermissions = {};
    }
}

/**
 * Check if TA has permission for a specific feature in any course
 */
function hasPermissionForFeature(feature) {
    // If no permissions loaded, deny access
    if (!window.taPermissions || Object.keys(window.taPermissions).length === 0) {
        return false;
    }
    
    // Check permissions for all courses - if any course allows access, grant it
    for (const courseId in window.taPermissions) {
        const permissions = window.taPermissions[courseId];
        if (permissions) {
            if (feature === 'courses' && permissions.canAccessCourses) {
                return true;
            }
            if (feature === 'flags' && permissions.canAccessFlags) {
                return true;
            }
        }
    }
    
    return false;
}

/**
 * Update TA navigation based on permissions
 */
async function updateTANavigationBasedOnPermissions() {
    console.log('🔍 [PERMISSIONS] Starting permission update...');
    
    // Load permissions first
    await loadTAPermissions();
    
    console.log('🔍 [PERMISSIONS] Loaded permissions:', window.taPermissions);
    console.log('🔍 [PERMISSIONS] Can access courses:', hasPermissionForFeature('courses'));
    console.log('🔍 [PERMISSIONS] Can access flags:', hasPermissionForFeature('flags'));
    
    // Hide/show My Courses link
    const taMyCoursesLink = document.getElementById('ta-my-courses-link');
    console.log('🔍 [PERMISSIONS] My Courses link element:', taMyCoursesLink);
    if (taMyCoursesLink) {
        if (hasPermissionForFeature('courses')) {
            taMyCoursesLink.style.display = 'block';
            console.log('🔍 [PERMISSIONS] Showing My Courses link');
        } else {
            taMyCoursesLink.style.display = 'none';
            console.log('🔍 [PERMISSIONS] Hiding My Courses link');
        }
    } else {
        console.warn('⚠️ [PERMISSIONS] My Courses link not found');
    }
    
    // Hide/show Student Support link
    const taStudentSupportLink = document.getElementById('ta-student-support-link');
    console.log('🔍 [PERMISSIONS] Student Support link element:', taStudentSupportLink);
    if (taStudentSupportLink) {
        if (hasPermissionForFeature('flags')) {
            taStudentSupportLink.style.display = 'block';
            console.log('🔍 [PERMISSIONS] Showing Student Support link');
        } else {
            taStudentSupportLink.style.display = 'none';
            console.log('🔍 [PERMISSIONS] Hiding Student Support link');
        }
    } else {
        console.warn('⚠️ [PERMISSIONS] Student Support link not found');
    }
    
    console.log('🔍 [PERMISSIONS] Navigation updated based on TA permissions');
}

/**
 * Get the current course ID for the instructor
 * @returns {Promise<string>} Course ID
 */
async function getCurrentCourseId() {
    // Return cached result if available
    if (courseIdCache !== null) {
        return courseIdCache;
    }
    
    // If a request is already in progress, wait for it
    if (courseIdPromise) {
        return courseIdPromise;
    }
    
    // Start the request and cache the promise
    courseIdPromise = fetchCourseId();
    const result = await courseIdPromise;
    
    // Cache the result
    courseIdCache = result;
    
    return result;
}

async function fetchCourseId() {
    // Check if we have a courseId from URL parameters (onboarding redirect)
    const urlParams = new URLSearchParams(window.location.search);
    const courseIdFromUrl = urlParams.get('courseId');
    
    if (courseIdFromUrl) {
        return courseIdFromUrl;
    }

    // Check localStorage for the last selected course
    const storedCourseId = localStorage.getItem('selectedCourseId');
    if (storedCourseId) {
        console.log(`🔍 [GET_COURSE_ID] Found course in localStorage: ${storedCourseId}`);
        return storedCourseId;
    }
    
    // If no course ID in URL or storage, try to get it from the user's courses
    try {
        // Wait for auth to be ready if needed
        if (!getCurrentInstructorId()) {
             await waitForAuth();
        }

        const userId = getCurrentInstructorId(); // This works for both instructors and TAs
        if (!userId) {
            console.error('No user ID available');
            return null;
        }
        
        // Check if user is TA or instructor using the proper role check
        let apiEndpoint;
        let isTAUser = false;
        
        if (typeof isTA === 'function' && isTA()) {
            console.log(`🔍 [GET_COURSE_ID] Fetching courses for TA: ${userId}`);
            apiEndpoint = `/api/courses/ta/${userId}`;
            isTAUser = true;
        } else {
            console.log(`🔍 [GET_COURSE_ID] Fetching courses for instructor: ${userId}`);
            apiEndpoint = `/api/onboarding/instructor/${userId}`;
            isTAUser = false;
        }
        
        const response = await fetch(apiEndpoint, {
            credentials: 'include'
        });
        
        console.log(`🔍 [GET_COURSE_ID] Response status: ${response.status} ${response.statusText}`);
        
        if (response.ok) {
            const result = await response.json();
            console.log(`🔍 [GET_COURSE_ID] API response:`, result);
            
            let courses = [];
            if (isTAUser) {
                courses = result.data || [];
            } else {
                courses = result.data && result.data.courses ? result.data.courses : [];
            }
            
            if (courses.length > 0) {
                // Return the first course found
                const firstCourse = courses[0];
                console.log(`🔍 [GET_COURSE_ID] Found course:`, firstCourse.courseId);
                return firstCourse.courseId;
            } else {
                console.log(`🔍 [GET_COURSE_ID] No courses found in response`);
            }
        } else {
            const errorText = await response.text();
            console.error(`🔍 [GET_COURSE_ID] API error: ${response.status} - ${errorText}`);
        }
    } catch (error) {
        console.error('Error fetching instructor courses:', error);
    }
    
    
    // Additional fallback: Check if we can get course ID from the current user's preferences
    const currentUser = getCurrentUser();
    if (currentUser && currentUser.preferences && currentUser.preferences.courseId) {
        console.log(`🔍 [GET_COURSE_ID] Using course from user preferences: ${currentUser.preferences.courseId}`);
        return currentUser.preferences.courseId;
    }
    
    // If no course found, show an error and redirect to onboarding (only once)
    if (!redirectInProgress) {
        redirectInProgress = true;
        console.error('No course ID found. Redirecting to onboarding...');
        showNotification('No course found. Please complete onboarding first.', 'error');
        setTimeout(() => {
            window.location.href = '/instructor/onboarding';
        }, 2000);
    }
    
    // Return a placeholder (this should not be reached due to redirect)
    return null;
}

// Settings page: wire additive retrieval toggle if present
document.addEventListener('DOMContentLoaded', async function() {
    try {
        const toggle = document.getElementById('additive-retrieval-toggle');
        if (!toggle) return;

        async function initToggleWithCourse() {
            // Get course ID from URL or localStorage (same priority as other pages)
            const urlParams = new URLSearchParams(window.location.search);
            const courseIdFromUrl = urlParams.get('courseId');
            const courseIdFromStorage = localStorage.getItem('selectedCourseId');
            let courseId = courseIdFromUrl || courseIdFromStorage;
            
            // Fallback to getCurrentCourseId if not found
            if (!courseId) {
                courseId = await getCurrentCourseId();
            }
            
            if (!courseId) {
                // No course context yet; disable toggle gracefully
                toggle.disabled = true;
                console.warn('No course ID found for additive retrieval toggle');
                return;
            }
            
            console.log('Initializing additive retrieval toggle for course:', courseId);

            // Load current setting
            const res = await fetch(`/api/courses/${courseId}`);
            if (res.ok) {
                const data = await res.json();
                if (data && data.data) {
                    toggle.checked = !!data.data.isAdditiveRetrieval;
                }
            }

            toggle.disabled = false;

            // Save on change
            toggle.addEventListener('change', async function() {
                try {
                    const saveRes = await fetch(`/api/courses/${courseId}/retrieval-mode`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ isAdditiveRetrieval: this.checked })
                    });
                    const result = await saveRes.json();
                    if (!saveRes.ok || !result.success) throw new Error(result.message || 'Failed to save');
                    showNotification && showNotification('Retrieval mode updated', 'success');
                } catch (e) {
                    console.error(e);
                    this.checked = !this.checked;
                    showNotification && showNotification('Failed to update retrieval mode', 'error');
                }
            });
        }

        // If auth not ready yet, wait for it
        if (typeof getCurrentUser === 'function' && !getCurrentUser()) {
            toggle.disabled = true;
            const onAuthReady = async () => {
                document.removeEventListener('auth:ready', onAuthReady);
                await initToggleWithCourse();
            };
            document.addEventListener('auth:ready', onAuthReady);
        } else {
            await initToggleWithCourse();
        }
    } catch (err) {
        // Non-fatal for unrelated pages
    }
});

// Removed: documents page retrieval toggle wiring (settings-only per user request)

// Store current publish status for comparison during polling
let currentPublishStatus = {};

// Track recent local changes to avoid false positives in polling
// Format: { lectureName: timestamp }
let recentLocalChanges = {};
const LOCAL_CHANGE_COOLDOWN = 5000; // 5 seconds - ignore polling changes within this window

/**
 * Load the saved publish status for all lectures from the database
 * @param {boolean} silent - If true, suppress notifications (used for polling)
 * @returns {Promise<Object>} The fetched publish status object
 */
async function loadPublishStatus(silent = false) {
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        const response = await fetch(`/api/lectures/publish-status?instructorId=${instructorId}&courseId=${courseId}`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch publish status');
        }
        
        const result = await response.json();
        const publishStatus = result.data.publishStatus;
        
        // Track changes to detect external updates
        const changedUnits = [];
        
        // Update all toggle switches to reflect the saved state
        Object.keys(publishStatus).forEach(lectureName => {
            const isPublished = publishStatus[lectureName];
            const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
            const toggle = document.getElementById(toggleId);
            
            if (toggle) {
                // Check if the status has changed from what we last saw (external update detection)
                const previousStatus = currentPublishStatus[lectureName];
                const wasExternallyChanged = previousStatus !== undefined && previousStatus !== isPublished;
                
                // Check if this was a recent local change (within cooldown window)
                const recentLocalChange = recentLocalChanges[lectureName];
                const isRecentLocalChange = recentLocalChange && (Date.now() - recentLocalChange) < LOCAL_CHANGE_COOLDOWN;
                
                // Only update UI if the toggle state doesn't match the fetched state
                // This ensures we sync with the database state
                if (toggle.checked !== isPublished) {
                    // Update the toggle state
                    toggle.checked = isPublished;
                    
                    // Track external changes for notification
                    // Only show notification if:
                    // 1. Status changed from previous fetch (wasExternallyChanged)
                    // 2. This was NOT a recent local change (isRecentLocalChange = false)
                    // 3. Not in silent mode (or if we want to show it)
                    if (wasExternallyChanged && !isRecentLocalChange) {
                        changedUnits.push({
                            name: lectureName,
                            isPublished: isPublished
                        });
                    }
                    
                    // Update the visual state
                    const accordionItem = toggle.closest('.accordion-item');
                    if (accordionItem) {
                        if (isPublished) {
                            accordionItem.classList.add('published');
                        } else {
                            accordionItem.classList.remove('published');
                        }
                    }
                }
            }
        });
        
        // Store current state for future comparisons (only after we've processed all units)
        currentPublishStatus = { ...publishStatus };
        
        // Notify user of external changes (only show for genuine external changes, not local ones)
        if (changedUnits.length > 0 && !silent) {
            const changes = changedUnits.map(unit => 
                `${unit.name} ${unit.isPublished ? 'published' : 'unpublished'}`
            ).join(', ');
            showNotification(`Publish status updated by another user: ${changes}`, 'info');
        }
        
        return publishStatus;
        
    } catch (error) {
        console.error('Error loading publish status:', error);
        if (!silent) {
            showNotification('Error loading publish status. Using default values.', 'warning');
        }
        return {};
    }
}

/**
 * Polling interval reference for publish status updates
 */
let publishStatusPollingInterval = null;

/**
 * Start polling for publish status changes
 * Checks for updates every 10 seconds when the page is visible
 */
function startPublishStatusPolling() {
    // Clear any existing polling interval
    if (publishStatusPollingInterval) {
        clearInterval(publishStatusPollingInterval);
        publishStatusPollingInterval = null;
    }
    
    // Only poll if we're on the documents page (where publish status is displayed)
    const accordionItems = document.querySelectorAll('.accordion-item');
    if (accordionItems.length === 0) {
        // Not on documents page, don't poll
        return;
    }
    
    // Poll every 10 seconds (adjustable)
    const POLL_INTERVAL = 10000; // 10 seconds
    
    // Note: Initial load already happens via loadPublishStatus() call in DOMContentLoaded
    // We don't need to call it again here to avoid duplicate requests
    
    // Set up polling interval
    publishStatusPollingInterval = setInterval(() => {
        // Only poll if the page is visible
        if (!document.hidden) {
            loadPublishStatus(true); // Silent polling to avoid spam
        }
    }, POLL_INTERVAL);
    
    // Handle page visibility changes
    // Pause polling when tab is hidden, resume when visible
    const handleVisibilityChange = () => {
        if (document.hidden) {
            // Page is hidden, polling will be skipped (handled in setInterval callback)
            console.log('📊 [POLLING] Page hidden, pausing publish status polling');
        } else {
            // Page is visible, immediately check for updates
            console.log('📊 [POLLING] Page visible, resuming publish status polling');
            loadPublishStatus(true); // Silent check when resuming
        }
    };
    
    // Add event listener (only add once)
    // Note: Document doesn't support hasAttribute/setAttribute; use documentElement
    const docEl = document.documentElement;
    if (!docEl.hasAttribute('data-publish-polling-listener')) {
        document.addEventListener('visibilitychange', handleVisibilityChange);
        docEl.setAttribute('data-publish-polling-listener', 'true');
    }
    
    console.log('📊 [POLLING] Started publish status polling (every 10 seconds)');
}


/**
 * Load the saved learning objectives for all lectures from the database
 */
async function loadLearningObjectives() {
    try {
        console.log('📚 [LEARNING_OBJECTIVES] Starting to load learning objectives...');
        const courseId = await getCurrentCourseId();
        console.log(`📚 [LEARNING_OBJECTIVES] Course ID: ${courseId}`);
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        console.log(`📚 [LEARNING_OBJECTIVES] Found ${accordionItems.length} accordion items (units/weeks)`);
        
        for (const item of accordionItems) {
            // Use data-unit-name attribute for internal name (e.g., "Unit 1")
            const lectureName = item.getAttribute('data-unit-name');
            if (!lectureName) continue;
            
            console.log(`📚 [LEARNING_OBJECTIVES] Processing lecture/unit: ${lectureName}`);
            
            console.log(`📡 [MONGODB] Making API request to /api/learning-objectives?week=${encodeURIComponent(lectureName)}&courseId=${courseId}`);
            const response = await fetch(`/api/learning-objectives?week=${encodeURIComponent(lectureName)}&courseId=${courseId}`);
            console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
            console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
            
            if (response.ok) {
                const result = await response.json();
                console.log(`📡 [MONGODB] Learning objectives data for ${lectureName}:`, result);
                const objectives = result.data.objectives;
                
                if (objectives && objectives.length > 0) {
                    console.log(`📚 [LEARNING_OBJECTIVES] Found ${objectives.length} objectives for ${lectureName}:`, objectives);
                    // Clear existing objectives
                    const objectivesList = item.querySelector('.objectives-list');
                    if (objectivesList) {
                        objectivesList.innerHTML = '';
                        
                        // Add each objective
                        objectives.forEach((objective, index) => {
                            console.log(`📚 [LEARNING_OBJECTIVES] Adding objective ${index + 1} to UI: ${objective}`);
                            const objectiveItem = document.createElement('div');
                            objectiveItem.className = 'objective-display-item';
                            objectiveItem.innerHTML = `
                                <span class="objective-text">${objective}</span>
                                <button class="remove-objective" onclick="removeObjective(this)">×</button>
                            `;
                            objectivesList.appendChild(objectiveItem);
                        });
                        console.log(`✅ [LEARNING_OBJECTIVES] Successfully added ${objectives.length} objectives to UI for ${lectureName}`);
                    } else {
                        console.warn(`⚠️ [LEARNING_OBJECTIVES] No objectives list found for ${lectureName}`);
                    }
                } else {
                    console.log(`📚 [LEARNING_OBJECTIVES] No objectives found for ${lectureName}`);
                }
            } else {
                console.warn(`⚠️ [MONGODB] Failed to load learning objectives for ${lectureName}: ${response.status} ${response.statusText}`);
            }
        }
        
        console.log('✅ [LEARNING_OBJECTIVES] Learning objectives loading process completed');
        
    } catch (error) {
        console.error('❌ [LEARNING_OBJECTIVES] Error loading learning objectives:', error);
        showNotification('Error loading learning objectives. Using default values.', 'warning');
    }
}

/**
 * Load the saved documents for all lectures from the database
 */
async function loadDocuments() {
    try {
        console.log('📁 [DOCUMENTS] Starting to load documents...');
        const courseId = await getCurrentCourseId();
        console.log(`📁 [DOCUMENTS] Course ID: ${courseId}`);
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        console.log(`📁 [DOCUMENTS] Found ${accordionItems.length} accordion items (units/weeks)`);
        
        for (const item of accordionItems) {
            // Use data-unit-name attribute for internal name (e.g., "Unit 1")
            const lectureName = item.getAttribute('data-unit-name');
            if (!lectureName) {
                console.warn(`⚠️ [DOCUMENTS] No unit name found for accordion item`);
                continue;
            }
            
            console.log(`📁 [DOCUMENTS] Processing lecture/unit: ${lectureName}`);
            
            // Load documents from the course structure instead of separate API
            console.log(`📡 [MONGODB] Making API request to /api/courses/${courseId}?instructorId=${getCurrentInstructorId()}`);
            const response = await fetch(`/api/courses/${courseId}?instructorId=${getCurrentInstructorId()}`);
            console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
            console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
            
            if (response.ok) {
                const result = await response.json();
                console.log(`📡 [MONGODB] Course data for ${lectureName}:`, result);
                const course = result.data;
                
                if (course && course.lectures) {
                    console.log(`🔍 [DOCUMENTS] Course has ${course.lectures.length} lectures:`, course.lectures.map(l => ({ name: l.name, documentsCount: l.documents?.length || 0 })));
                    const unit = course.lectures.find(l => l.name === lectureName);
                    console.log(`🔍 [DOCUMENTS] Looking for unit "${lectureName}" in lectures:`, unit);
                    const documents = unit ? (unit.documents || []) : [];
                    console.log(`📁 [DOCUMENTS] Found ${documents.length} documents for ${lectureName}:`, documents);
                    
                    // Find the course materials section
                    const courseMaterialsSection = item.querySelector('.course-materials-section .section-content');
                    if (courseMaterialsSection) {
                        console.log(`📁 [DOCUMENTS] Course materials section found for ${lectureName}`);
                        
                        // Clear ALL existing document items (both placeholders and actual documents)
                        const existingItems = courseMaterialsSection.querySelectorAll('.file-item');
                        console.log(`📁 [DOCUMENTS] Clearing ${existingItems.length} existing document items for ${lectureName}`);
                        
                        existingItems.forEach(item => {
                            item.remove();
                        });
                        
                        // Clear action buttons and cleanup sections to ensure proper reordering
                        const actionSections = courseMaterialsSection.querySelectorAll('.add-content-section, .save-objectives, .cleanup-section');
                        actionSections.forEach(section => {
                            section.remove();
                        });
                        
                        // ADD ALL DOCUMENTS - BACKEND HANDLES DELETION FROM BOTH DBs
                        if (documents && documents.length > 0) {
                            console.log(`📁 [DOCUMENTS] Adding ${documents.length} documents to UI for ${lectureName}`);
                            
                            // Add all documents - backend ensures they exist in both databases
                            documents.forEach((doc, index) => {
                                console.log(`📁 [DOCUMENTS] Adding document ${index + 1} to UI:`, doc);
                                const documentItem = createDocumentItem(doc);
                                courseMaterialsSection.appendChild(documentItem);
                            });
                            console.log(`✅ [DOCUMENTS] Successfully added ${documents.length} documents to UI for ${lectureName}`);
                        } else {
                            console.log(`📁 [DOCUMENTS] No documents to add for ${lectureName}`);
                        }
                        
                        // ALWAYS check for missing placeholders, regardless of whether documents exist
                        // This ensures placeholders appear for individual missing document types
                        console.log(`🔍 [DOCUMENTS] Checking for missing placeholders in ${lectureName}`);
                        addRequiredPlaceholders(courseMaterialsSection, lectureName);
                        

                        
                        // ALWAYS add the "Add Additional Material" button and "Confirm Course Materials" button LAST
                        // This ensures they stay at the bottom, regardless of whether there are documents
                        console.log(`🔧 [DOCUMENTS] Adding action buttons for ${lectureName} - this should be LAST`);
                        addActionButtonsIfMissing(courseMaterialsSection, lectureName);
                        console.log(`✅ [DOCUMENTS] Action buttons added for ${lectureName}`);
                        
                        // Debug: Log the final DOM order to verify button positioning
                        console.log(`🔍 [DOCUMENTS] Final DOM order for ${lectureName}:`);
                        const finalItems = courseMaterialsSection.querySelectorAll('.file-item, .add-content-section, .save-objectives, .cleanup-section');
                        finalItems.forEach((item, index) => {
                            const itemType = item.classList.contains('file-item') ? 'File' : 
                                           item.classList.contains('add-content-section') ? 'Add Content' :
                                           item.classList.contains('save-objectives') ? 'Confirm Button' :
                                           item.classList.contains('cleanup-section') ? 'Cleanup' : 'Unknown';
                            console.log(`  ${index + 1}. ${itemType}: ${item.textContent.substring(0, 50)}...`);
                        });
                        
                        // Additional debug: Check if buttons are actually at the bottom
                        const allChildren = Array.from(courseMaterialsSection.children);
                        const lastChild = allChildren[allChildren.length - 1];
                        const secondLastChild = allChildren[allChildren.length - 2];
                        
                        console.log(`🔍 [DOCUMENTS] Last child: ${lastChild.className} - ${lastChild.textContent.substring(0, 30)}...`);
                        console.log(`🔍 [DOCUMENTS] Second last child: ${secondLastChild.className} - ${secondLastChild.textContent.substring(0, 30)}...`);
                        
                        // Verify button positioning
                        if (lastChild.classList.contains('save-objectives')) {
                            console.log(`✅ [DOCUMENTS] Confirm button is correctly at the bottom!`);
                        } else {
                            console.warn(`⚠️ [DOCUMENTS] Confirm button is NOT at the bottom! Last child is: ${lastChild.className}`);
                        }
                    } else {
                        console.error('Course materials section not found for', lectureName);
                    }
                } else {
                    // No course or lectures data found
                }
            } else {
                console.error('Failed to load course data:', response.status);
                
                // Even if API fails, still add the required buttons and placeholders
                const courseMaterialsSection = item.querySelector('.course-materials-section .section-content');
                if (courseMaterialsSection) {
                    console.log(`🔧 [DOCUMENTS] API failed for ${lectureName}, adding buttons anyway`);
                    
                    // Add required placeholders
                    addRequiredPlaceholders(courseMaterialsSection, lectureName);
                    
                    // Add action buttons
                    addActionButtonsIfMissing(courseMaterialsSection, lectureName);
                }
            }
        }
        
        // Ensure all units have action buttons, regardless of API success/failure
        console.log(`🔧 [DOCUMENTS] Final check: Ensuring all units have action buttons`);
        const allAccordionItems = document.querySelectorAll('.accordion-item');
        allAccordionItems.forEach(accordionItem => {
            // Use data-unit-name attribute for internal name (e.g., "Unit 1")
            const unitName = accordionItem.getAttribute('data-unit-name');
            if (!unitName) return;
            
            const courseMaterialsSection = accordionItem.querySelector('.course-materials-section .section-content');
            
            if (courseMaterialsSection) {
                // Check if action buttons exist
                const hasActionButtons = courseMaterialsSection.querySelector('.add-content-section, .save-objectives');
                
                if (!hasActionButtons) {
                    console.log(`🔧 [DOCUMENTS] Adding missing action buttons for ${unitName} (final check)`);
                    addActionButtonsIfMissing(courseMaterialsSection, unitName);
                }
            }
        });
        
        // After all documents are loaded and accordion items exist, load thresholds
        console.log('🔄 [DOCUMENTS] All documents loaded, now loading thresholds after delay...');
        setTimeout(() => {
            console.log('🔄 [DOCUMENTS] Loading thresholds now...');
            const accordionCount = document.querySelectorAll('.accordion-item').length;
            const thresholdInputCount = document.querySelectorAll('input[id^="pass-threshold-"]').length;
            console.log(`🔄 [DOCUMENTS] Found ${accordionCount} accordion items, ${thresholdInputCount} threshold inputs before loading`);
            loadPassThresholds();
        }, 800);
        
    } catch (error) {
        console.error('Error loading documents:', error);
        showNotification('Error loading documents. Using default values.', 'warning');
        
        // Even if there's an error, try to add buttons
        try {
            const allAccordionItems = document.querySelectorAll('.accordion-item');
            allAccordionItems.forEach(accordionItem => {
                // Use data-unit-name attribute for internal name (e.g., "Unit 1")
                const unitName = accordionItem.getAttribute('data-unit-name');
                if (!unitName) return;
                
                const courseMaterialsSection = accordionItem.querySelector('.course-materials-section .section-content');
                
                if (courseMaterialsSection) {
                    addRequiredPlaceholders(courseMaterialsSection, unitName);
                    addActionButtonsIfMissing(courseMaterialsSection, unitName);
                }
            });
        } catch (fallbackError) {
            console.error('Fallback button addition also failed:', fallbackError);
        }
    }
}

/**
 * Create a document item element for display
 * @param {Object} doc - Document object from database
 * @returns {HTMLElement} Document item element
 */
function createDocumentItem(doc) {
    const documentItem = document.createElement('div');
    documentItem.className = 'file-item';
    documentItem.dataset.documentId = doc.documentId;
    
    // Add the document type to the dataset for robust placeholder checking
    // Map document types to consistent format for placeholder detection
    let documentType = '';
    if (doc.type) {
        documentType = doc.type;
    } else if (doc.documentType) {
        // Map hyphenated types to underscore format for consistency
        documentType = doc.documentType === 'lecture-notes' ? 'lecture_notes' :
                      doc.documentType === 'practice-quiz' ? 'practice_q_tutorials' :
                      doc.documentType;
    }
    documentItem.dataset.documentType = documentType;
    
    const fileIcon = doc.contentType === 'text' ? '📝' : '📄';
    
    // Map status values to display text consistently
    let statusText;
    switch (doc.status) {
        case 'uploaded':
            statusText = 'Uploaded';
            break;
        case 'parsed':
            statusText = 'Processed';
            break;
        case 'parsing':
            statusText = 'Processing';
            break;
        case 'error':
            statusText = 'Error';
            break;
        default:
            statusText = doc.status || 'Unknown';
    }
    
    documentItem.innerHTML = `
        <span class="file-icon">${fileIcon}</span>
        <div class="file-info">
            <h3>${doc.filename || doc.originalName}</h3>
            ${doc.metadata?.description ? `<p>${doc.metadata.description}</p>` : ''}
            <span class="status-text">${statusText}</span>
        </div>
        <div class="file-actions">
            <button class="action-button view" onclick="viewDocument('${doc.documentId}')">View</button>
            <button class="action-button delete" onclick="deleteDocument('${doc.documentId}')">Delete</button>
        </div>
    `;
    
    return documentItem;
}

/**
 * Delete a document
 * @param {string} documentId - Document identifier
 */
async function deleteDocument(documentId) {
    try {
        const instructorId = getCurrentInstructorId();
        const courseId = await getCurrentCourseId();
        
        // Step 1: Try to delete from documents collection first
        let documentDeleted = false;
        try {
            const deleteResponse = await fetch(`/api/documents/${documentId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    instructorId: instructorId
                })
            });
            
            if (deleteResponse.ok) {
                documentDeleted = true;
            } else if (deleteResponse.status === 404) {
                documentDeleted = true; // Consider it "deleted" if it doesn't exist
            } else {
                const errorText = await deleteResponse.text();
                console.warn(`Document deletion warning: ${deleteResponse.status} ${errorText}`);
                // Continue with course cleanup even if document deletion fails
            }
        } catch (deleteError) {
            console.warn('Document deletion endpoint not available:', deleteError);
            // Continue with course cleanup
        }
        
        // Step 2: Always remove from course structure (regardless of document deletion status)
        let courseUpdateSuccess = false;
        
        try {
            const courseResponse = await fetch(`/api/courses/${courseId}/remove-document`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    documentId: documentId,
                    instructorId: instructorId
                })
            });
            
            if (courseResponse.ok) {
                courseUpdateSuccess = true;
            } else {
                const errorText = await courseResponse.text();
                console.warn(`Course structure update failed: ${courseResponse.status} - ${errorText}`);
            }
        } catch (courseError) {
            console.warn('Course structure update endpoint not available or failed:', courseError);
        }
        
        // Step 3: If course structure update failed, use manual approach
        if (!courseUpdateSuccess) {
            try {
                const manualResult = await removeDocumentFromCourseStructure(documentId, courseId, instructorId);
                if (manualResult) {
                    courseUpdateSuccess = true;
                } else {
                    console.warn('Manual cleanup returned false');
                }
            } catch (fallbackError) {
                console.warn('Manual course structure update failed:', fallbackError);
                // Last resort: try global cleanup
                try {
                    await cleanupOrphanedDocuments();
                } catch (cleanupError) {
                    console.warn('Global cleanup also failed:', cleanupError);
                }
            }
        }
        
        // Remove the document item from the UI immediately
        const documentItem = document.querySelector(`[data-document-id="${documentId}"]`);
        let deletedDocumentType = null;
        
        if (documentItem) {
            // Get the document type before removing it
            deletedDocumentType = documentItem.dataset.documentType;
            console.log(`🗑️ [DELETE] Removing document with type: "${deletedDocumentType}"`);
            documentItem.remove();
        }
        
        // Immediately check and add placeholder for the deleted material type
        if (deletedDocumentType) {
            console.log(`🔍 [DELETE] Document type "${deletedDocumentType}" was deleted, checking if placeholder is needed...`);
            
            // Find the unit this document belonged to
            const unitName = await findUnitNameForDocument(documentId, courseId);
            if (unitName) {
                console.log(`🔍 [DELETE] Found unit: ${unitName} for deleted document`);
                
                // Find the course materials section for this unit
                const unitElement = findUnitElementByName(unitName);
                if (unitElement) {
                    const courseMaterialsSection = unitElement.querySelector('.course-materials-section .section-content');
                    if (courseMaterialsSection) {
                        console.log(`🔍 [DELETE] Found course materials section for ${unitName}, updating placeholders...`);
                        
                        // Remove any existing placeholders first to prevent duplicates
                        removeExistingPlaceholders(courseMaterialsSection);
                        
                        // Add required placeholders for this specific unit
                        addRequiredPlaceholders(courseMaterialsSection, unitName);
                        console.log(`✅ [DELETE] Placeholders successfully updated for ${unitName} after deletion`);
                    } else {
                        console.warn(`⚠️ [DELETE] Could not find course materials section for ${unitName}`);
                    }
                } else {
                    console.warn(`⚠️ [DELETE] Could not find unit element for ${unitName}`);
                }
            } else {
                console.warn(`⚠️ [DELETE] Could not determine unit name for deleted document ${documentId}`);
            }
        } else {
            console.log(`ℹ️ [DELETE] No document type found, skipping placeholder update`);
        }
        
        // Reload documents to sync with database (this will also refresh placeholders)
        await loadDocuments();
        
        // Show appropriate success message
        if (documentDeleted && courseUpdateSuccess) {
            showNotification('Document deleted from both collections successfully!', 'success');
        } else if (courseUpdateSuccess) {
            showNotification('Document removed from course structure successfully!', 'success');
        } else {
            showNotification('Document deletion completed with some cleanup issues. Use cleanup button if needed.', 'warning');
        }
        
    } catch (error) {
        console.error('Error deleting document:', error);
        showNotification(`Error deleting document: ${error.message}`, 'error');
    }
}


/**
 * Find the unit name for a specific document
 * @param {string} documentId - Document ID to find
 * @param {string} courseId - Course ID
 * @returns {Promise<string|null>} Unit name or null if not found
 */
async function findUnitNameForDocument(documentId, courseId) {
    try {
        const instructorId = getCurrentInstructorId();
        const response = await fetch(`/api/courses/${courseId}?instructorId=${instructorId}`);
        
        if (!response.ok) {
            console.warn(`Failed to fetch course structure for document ${documentId}`);
            return null;
        }
        
        const result = await response.json();
        const course = result.data;
        
        if (!course || !course.lectures) {
            return null;
        }
        
        // Search through all units to find which one contains this document
        for (const unit of course.lectures) {
            if (unit.documents && unit.documents.some(doc => doc.documentId === documentId)) {
                return unit.name;
            }
        }
        
        return null;
    } catch (error) {
        console.warn(`Error finding unit for document ${documentId}:`, error);
        return null;
    }
}

/**
 * Find a unit element by name in the DOM
 * @param {string} unitName - Name of the unit to find
 * @returns {HTMLElement|null} Unit element or null if not found
 */
function findUnitElementByName(unitName) {
    // Use data-unit-name attribute selector for internal name (e.g., "Unit 1")
    return document.querySelector(`.accordion-item[data-unit-name="${unitName}"]`);
}

/**
 * Remove existing placeholder items to prevent duplicates
 * @param {HTMLElement} container - The container to clean up
 */
function removeExistingPlaceholders(container) {
    const existingPlaceholders = container.querySelectorAll('.file-item.placeholder-item');
    console.log(`🧹 [PLACEHOLDERS] Removing ${existingPlaceholders.length} existing placeholders`);
    
    existingPlaceholders.forEach(placeholder => {
        placeholder.remove();
    });
}

/**
 * Manually remove a document reference from the course structure
 * This is a fallback when the backend endpoint is not available
 * @param {string} documentId - Document ID to remove
 * @param {string} courseId - Course ID
 * @param {string} instructorId - Instructor ID
 */
async function removeDocumentFromCourseStructure(documentId, courseId, instructorId) {
    try {
        // Get the current course structure
        const response = await fetch(`/api/courses/${courseId}?instructorId=${instructorId}`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch course structure');
        }
        
        const result = await response.json();
        const course = result.data;
        
        // Find and remove the document from all units
        let documentRemoved = false;
        
        // Check different possible property names for units
        const units = course.lectures || course.units || course.weeks || [];
        
        // Also check courseMaterials field
        if (course.courseMaterials) {
            // Course materials field exists
        }
        
        units.forEach((unit, index) => {
            // Check different possible property names for documents
            const documents = unit.documents || unit.materials || unit.files || [];
            
            if (documents.length > 0) {
                const initialLength = documents.length;
                const filteredDocuments = documents.filter(doc => {
                    const docId = doc.documentId || doc.id || doc._id;
                    return docId !== documentId;
                });
                
                if (filteredDocuments.length < initialLength) {
                    documentRemoved = true;
                    
                    // Update the unit's documents array
                    if (unit.documents) unit.documents = filteredDocuments;
                    if (unit.materials) unit.materials = filteredDocuments;
                    if (unit.files) unit.files = filteredDocuments;
                }
            }
        });
        
        // Also check if document is in courseMaterials
        if (course.courseMaterials && Array.isArray(course.courseMaterials)) {
            const initialLength = course.courseMaterials.length;
            course.courseMaterials = course.courseMaterials.filter(doc => {
                const docId = doc.documentId || doc.id || doc._id;
                return docId !== documentId;
            });
            
            if (course.courseMaterials.length < initialLength) {
                documentRemoved = true;
            }
        }
        
        // Also check unitFiles field
        if (course.unitFiles && Array.isArray(course.unitFiles)) {
            const initialLength = course.unitFiles.length;
            course.unitFiles = course.unitFiles.filter(doc => {
                const docId = doc.documentId || doc.id || doc._id;
                return docId !== documentId;
            });
            
            if (course.unitFiles.length < initialLength) {
                documentRemoved = true;
            }
        }
        
        if (documentRemoved) {
            // Update the course structure in the backend
            const updateResponse = await fetch(`/api/courses/${courseId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ...course,
                    instructorId: instructorId
                })
            });
            
            if (updateResponse.ok) {
                return true;
            } else {
                throw new Error('Failed to update course structure');
            }
        } else {
            return true; // Document wasn't in course structure, so nothing to update
        }
        
    } catch (error) {
        console.error('Error manually updating course structure:', error);
        throw error;
    }
}



/**
 * Clean up orphaned document references in the course structure
 * This can be called manually to fix any existing orphaned documents
 */
async function cleanupOrphanedDocuments() {
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        showNotification('Cleaning up orphaned documents...', 'info');
        
        const response = await fetch('/api/documents/cleanup-orphans', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Cleanup failed: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        
        if (result.data.totalOrphans > 0) {
            showNotification(`Cleanup completed! Removed ${result.data.totalOrphans} orphaned documents.`, 'success');
            // Reload documents to reflect the cleanup
            await loadDocuments();
        } else {
            showNotification('No orphaned documents found. Course structure is clean!', 'success');
        }
        
    } catch (error) {
        console.error('Error cleaning up orphaned documents:', error);
        showNotification(`Error during cleanup: ${error.message}`, 'error');
    }
}

/**
 * View document content in a modal
 * @param {string} documentId - Document identifier
 */
async function viewDocument(documentId) {
    try {
        // Fetch document content
        const response = await fetch(`/api/documents/${documentId}`);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to fetch document: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        const document = result.data;
        
        console.log('📄 Document data received:', {
            documentId: document.documentId,
            originalName: document.originalName,
            contentType: document.contentType,
            hasContent: !!document.content,
            contentLength: document.content ? document.content.length : 0,
            contentPreview: document.content ? document.content.substring(0, 100) + '...' : 'No content'
        });
        
        if (!document) {
            throw new Error('Document not found');
        }
        
        // Create and show modal with document content
        showDocumentModal(document);
        
    } catch (error) {
        console.error('Error viewing document:', error);
        showNotification(`Error viewing document: ${error.message}`, 'error');
    }
}

/**
 * Load assessment questions directly from course data (for initial load)
 * @param {Object} courseData - Course data with lectures and assessment questions
 */
function loadAssessmentQuestionsFromCourseData(courseData) {
    if (!courseData.lectures) return;
    
    courseData.lectures.forEach(unit => {
        if (unit.assessmentQuestions && unit.assessmentQuestions.length > 0) {
            // Store questions in the local assessmentQuestions object
            if (!assessmentQuestions[unit.name]) {
                assessmentQuestions[unit.name] = [];
            }
            
            // Clear existing questions and add new ones
            assessmentQuestions[unit.name] = [];
            
            // Convert database questions to local format
            unit.assessmentQuestions.forEach(dbQuestion => {
                const localQuestion = {
                    id: dbQuestion.questionId,
                    questionId: dbQuestion.questionId,
                    type: dbQuestion.questionType,
                    question: dbQuestion.question,
                    answer: dbQuestion.correctAnswer,
                    options: dbQuestion.options || {}
                };
                
                assessmentQuestions[unit.name].push(localQuestion);
            });
            
            // Update the display for this unit
            updateQuestionsDisplay(unit.name);
        }
    });
}

/**
 * Load the saved assessment questions for all lectures from the database
 */
async function loadAssessmentQuestions() {
    try {
        console.log('❓ [ASSESSMENT_QUESTIONS] Starting to load assessment questions...');
        const courseId = await getCurrentCourseId();
        console.log(`❓ [ASSESSMENT_QUESTIONS] Course ID: ${courseId}`);
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        console.log(`❓ [ASSESSMENT_QUESTIONS] Found ${accordionItems.length} accordion items (units/weeks)`);
        
        if (accordionItems.length === 0) {
            console.log('❓ [ASSESSMENT_QUESTIONS] No accordion items found, skipping assessment questions loading');
            return;
        }
        
        for (const item of accordionItems) {
            // Use data-unit-name attribute for internal name (e.g., "Unit 1")
            const lectureName = item.getAttribute('data-unit-name');
            if (!lectureName) {
                console.warn(`⚠️ [ASSESSMENT_QUESTIONS] No unit name found for accordion item`);
                continue;
            }
            
            console.log(`❓ [ASSESSMENT_QUESTIONS] Processing lecture/unit: ${lectureName}`);
            
            console.log(`📡 [MONGODB] Making API request to ${API_BASE_URL}/api/questions/lecture?courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
            const response = await fetch(`${API_BASE_URL}/api/questions/lecture?courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
            console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
            console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
            
            if (response.ok) {
                const result = await response.json();
                console.log(`📡 [MONGODB] Assessment questions data for ${lectureName}:`, result);
                const questions = result.data.questions;
                
                if (questions && questions.length > 0) {
                    console.log(`❓ [ASSESSMENT_QUESTIONS] Found ${questions.length} questions for ${lectureName}:`, questions);
                    // Store questions in the assessmentQuestions object
                    if (!assessmentQuestions[lectureName]) {
                        assessmentQuestions[lectureName] = [];
                    }
                    
                    // Clear existing questions first to prevent duplicates
                    assessmentQuestions[lectureName] = [];
                    
                    // Convert database questions to local format
                    questions.forEach((dbQuestion, index) => {
                        console.log(`❓ [ASSESSMENT_QUESTIONS] Converting question ${index + 1} for ${lectureName}:`, dbQuestion);
                        const localQuestion = {
                            id: dbQuestion.questionId,
                            questionId: dbQuestion.questionId,
                            type: dbQuestion.questionType,
                            question: dbQuestion.question,
                            answer: dbQuestion.correctAnswer,
                            options: dbQuestion.options || {}
                        };
                        console.log(`❓ [ASSESSMENT_QUESTIONS] Converted question ${index + 1}:`, localQuestion);
                        assessmentQuestions[lectureName].push(localQuestion);
                    });
                    
                    console.log(`✅ [ASSESSMENT_QUESTIONS] Successfully processed ${questions.length} questions for ${lectureName}`);
                    // Update the display for this lecture
                    updateQuestionsDisplay(lectureName);
                } else {
                    // No questions found - explicitly set threshold to 0 for this unit
                    console.log(`❓ [ASSESSMENT_QUESTIONS] No questions found for ${lectureName}`);
                    const weekId = lectureName.toLowerCase().replace(/\s+/g, '-');
                    const thresholdInput = document.getElementById(`pass-threshold-${weekId}`);
                    if (thresholdInput) {
                        thresholdInput.value = 0;
                        console.log(`[ASSESSMENT_QUESTIONS] No questions for ${lectureName}, set threshold to 0`);
                    }
                }
            } else {
                console.warn(`⚠️ [MONGODB] Failed to load assessment questions for ${lectureName}: ${response.status} ${response.statusText}`);
            }
        }
        
        console.log('✅ [ASSESSMENT_QUESTIONS] Assessment questions loading process completed');
        
        // After all questions are loaded, force-check and update all thresholds
        // This ensures units with 0 questions have threshold set to 0
        forceUpdateThresholdsForZeroQuestions();
        
    } catch (error) {
        console.error('❌ [ASSESSMENT_QUESTIONS] Error loading assessment questions:', error);
        showNotification('Error loading assessment questions. Using default values.', 'warning');
    }
}

/**
 * Force update all thresholds to 0 for units with no questions
 */
function forceUpdateThresholdsForZeroQuestions() {
    console.log('🔧 [FORCE_UPDATE] Starting force update of thresholds...');
    const thresholdInputs = document.querySelectorAll('input[id^="pass-threshold-"]');
    console.log(`🔧 [FORCE_UPDATE] Found ${thresholdInputs.length} threshold inputs`);
    
    thresholdInputs.forEach(thresholdInput => {
        const weekId = thresholdInput.id.replace('pass-threshold-', '');
        const lectureName = weekId.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const currentValue = thresholdInput.value;
        
        console.log(`🔧 [FORCE_UPDATE] Checking ${lectureName} (ID: ${weekId}), current threshold: ${currentValue}`);
        
        // Check both DOM and object
        const questionsContainer = document.getElementById(`assessment-questions-${weekId}`);
        const domQuestions = questionsContainer ? questionsContainer.querySelectorAll('.question-item').length : 0;
        const objectQuestions = assessmentQuestions[lectureName] ? assessmentQuestions[lectureName].length : 0;
        const totalQuestions = Math.max(domQuestions, objectQuestions);
        
        console.log(`🔧 [FORCE_UPDATE] ${lectureName}: DOM questions=${domQuestions}, Object questions=${objectQuestions}, Total=${totalQuestions}, assessmentQuestions keys:`, Object.keys(assessmentQuestions));
        
        if (totalQuestions === 0) {
            const oldValue = thresholdInput.value;
            thresholdInput.value = 0;
            console.log(`🔧 [FORCE_UPDATE] ✅ FORCED threshold from ${oldValue} to 0 for ${lectureName} (no questions found)`);
            console.log(`🔧 [FORCE_UPDATE] Verification - threshold input value is now: ${thresholdInput.value}`);
        } else {
            console.log(`🔧 [FORCE_UPDATE] ⏭️ Skipping ${lectureName} - has ${totalQuestions} questions, threshold remains: ${thresholdInput.value}`);
        }
    });
    console.log('🔧 [FORCE_UPDATE] Force update completed');
}

/**
 * Delete an assessment question
 * @param {string} questionId - Question identifier
 * @param {string} week - Week identifier
 */
async function deleteAssessmentQuestion(questionId, week) {
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        const response = await fetch(`${API_BASE_URL}/api/questions/${questionId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: week,
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Delete failed: ${response.status} ${errorText}`);
        }
        
        // Reload questions from database to ensure consistency
        await reloadQuestionsForUnit(week);
        
        // Update the display
        updateQuestionsDisplay(week);
        
        showNotification('Question deleted successfully!', 'success');
        
    } catch (error) {
        console.error('Error deleting question:', error);
        showNotification(`Error deleting question: ${error.message}`, 'error');
    }
}

/**
 * Save the pass threshold for a specific lecture
 * @param {string} lectureName - Name of the lecture/unit
 * @param {number} threshold - Number of questions required to pass
 */
async function savePassThreshold(lectureName, threshold) {
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        console.log(`[SAVE_PASS_THRESHOLD] Saving threshold for ${lectureName}: ${threshold} (courseId: ${courseId}, instructorId: ${instructorId})`);
        
        const response = await fetch('/api/lectures/pass-threshold', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: lectureName,
                passThreshold: threshold,
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to save threshold: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log(`[SAVE_PASS_THRESHOLD] Success response:`, result);
        
        // Show success notification
        showNotification(result.message, 'success');
        
        // No need to reload all thresholds - the UI is already updated
        // and the database has the correct value
        
    } catch (error) {
        console.error('Error saving pass threshold:', error);
        showNotification(`Error saving pass threshold: ${error.message}`, 'error');
    }
}

/**
 * Reload pass thresholds from the database (for use after updates)
 */
async function reloadPassThresholds() {
    try {
        const courseId = await getCurrentCourseId();
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        
        for (const item of accordionItems) {
            // Use data-unit-name attribute for internal name (e.g., "Unit 1")
            const lectureName = item.getAttribute('data-unit-name');
            if (!lectureName) continue;
            
            const response = await fetch(`/api/lectures/pass-threshold?courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
            
            if (response.ok) {
                const result = await response.json();
                const passThreshold = result.data.passThreshold;
                
                // Find and update the threshold input for this lecture
                // Convert lecture name to ID format (e.g., "Unit 1" -> "unit-1")
                const thresholdId = `pass-threshold-${lectureName.toLowerCase().replace(/\s+/g, '-')}`;
                const thresholdInput = item.querySelector(`#${thresholdId}`);
                
                if (thresholdInput) {
                    thresholdInput.value = passThreshold;
                    console.log(`[RELOAD_PASS_THRESHOLDS] Updated threshold input for ${lectureName}: ${passThreshold}`);
                    
                    // Threshold input updated
                }
            }
        }
        
    } catch (error) {
        console.error('Error reloading pass thresholds:', error);
        showNotification('Error reloading pass thresholds.', 'warning');
    }
}

/**
 * Load the saved pass thresholds for all lectures from the database
 */
async function loadPassThresholds() {
    try {
        const courseId = await getCurrentCourseId();
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        
        for (const item of accordionItems) {
            // Use data-unit-name attribute for internal name (e.g., "Unit 1")
            const lectureName = item.getAttribute('data-unit-name');
            if (!lectureName) continue;
            
            const response = await fetch(`/api/lectures/pass-threshold?courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
            
            // Find the threshold input for this lecture (regardless of whether API call succeeded)
            // Convert lecture name to ID format (e.g., "Unit 1" -> "unit-1")
            const thresholdId = `pass-threshold-${lectureName.toLowerCase().replace(/\s+/g, '-')}`;
            const thresholdInput = item.querySelector(`#${thresholdId}`);
            
            if (thresholdInput) {
                const weekId = thresholdInput.id.replace('pass-threshold-', '');
                const currentValue = thresholdInput.value;
                console.log(`📊 [LOAD_PASS_THRESHOLDS] Processing ${lectureName} (ID: ${weekId}), current input value: ${currentValue}`);
                
                // Check how many questions exist for this unit (check both the assessmentQuestions object and DOM)
                const questionsContainer = document.getElementById(`assessment-questions-${weekId}`);
                const domQuestions = questionsContainer ? questionsContainer.querySelectorAll('.question-item').length : 0;
                const objectQuestions = assessmentQuestions[lectureName] ? assessmentQuestions[lectureName].length : 0;
                const totalQuestions = Math.max(domQuestions, objectQuestions);
                
                console.log(`📊 [LOAD_PASS_THRESHOLDS] ${lectureName}: DOM questions=${domQuestions}, Object questions=${objectQuestions}, Total=${totalQuestions}`);
                console.log(`📊 [LOAD_PASS_THRESHOLDS] assessmentQuestions object keys:`, Object.keys(assessmentQuestions));
                console.log(`📊 [LOAD_PASS_THRESHOLDS] assessmentQuestions[${lectureName}]:`, assessmentQuestions[lectureName]);
                
                // If there are no questions, ALWAYS set threshold to 0 (ignore any saved value)
                if (totalQuestions === 0) {
                    const oldValue = thresholdInput.value;
                    thresholdInput.value = 0;
                    console.log(`📊 [LOAD_PASS_THRESHOLDS] ✅ FORCED threshold from ${oldValue} to 0 for ${lectureName} (no questions found)`);
                    console.log(`📊 [LOAD_PASS_THRESHOLDS] Verification - threshold input value after setting: ${thresholdInput.value}`);
                } else if (response.ok) {
                    const result = await response.json();
                    const passThreshold = result.data.passThreshold;
                    
                    console.log(`📊 [LOAD_PASS_THRESHOLDS] API response for ${lectureName}:`, result);
                    console.log(`📊 [LOAD_PASS_THRESHOLDS] API returned passThreshold: ${passThreshold}`);
                    
                    // Update threshold input with loaded value (but only if questions exist)
                    thresholdInput.value = passThreshold;
                    console.log(`📊 [LOAD_PASS_THRESHOLDS] Updated threshold input for ${lectureName} to: ${passThreshold}`);
                } else {
                    // No threshold set yet, default to 0 but don't save it
                    console.log(`📊 [LOAD_PASS_THRESHOLDS] No API threshold set for ${lectureName}, defaulting to 0`);
                    thresholdInput.value = 0;
                }
            } else {
                console.log(`❌ [LOAD_PASS_THRESHOLDS] Threshold input not found for ${lectureName} (ID: ${thresholdId})`);
            }
        }
        
        console.log('📊 [LOAD_PASS_THRESHOLDS] Finished loading all thresholds, running force update...');
        
        // Force update thresholds again after loading (to catch any units with 0 questions)
        forceUpdateThresholdsForZeroQuestions();
        
        console.log('📊 [LOAD_PASS_THRESHOLDS] All threshold loading completed');
        
    } catch (error) {
        console.error('❌ [LOAD_PASS_THRESHOLDS] Error loading pass thresholds:', error);
        showNotification('Error loading pass thresholds. Using default values.', 'warning');
    }
}

/**
 * Set up event listeners for threshold inputs
 */
function setupThresholdInputListeners() {
    // Get all threshold inputs
    const thresholdInputs = document.querySelectorAll('input[id^="pass-threshold-"]');
    
    thresholdInputs.forEach(input => {
        // Add change event listener
        input.addEventListener('change', function(event) {
            const threshold = parseInt(this.value);
            // Extract the exact lecture name from the ID (e.g., "Unit-1" -> "Unit 1")
            const lectureName = this.id.replace('pass-threshold-', '').replace(/-/g, ' ');
            
            // Update the display first
            handleThresholdInputChange(event);
            
            // Save the threshold to MongoDB
            savePassThreshold(lectureName, threshold);
        });
        
        // Add input event listener for real-time updates
        input.addEventListener('input', handleThresholdInputChange);
    });
}



// Mode Questions Modal functionality
let currentQuestions = [];
let questionCounter = 1;

/**
 * Open the mode questions modal
 */
 

/**
 * Toggle a section's visibility
 * @param {HTMLElement} headerElement - The section header element
 * @param {Event} e - The event object
 */
function toggleSection(headerElement, e) {
    // If an event was passed, prevent it from bubbling up
    if (e) {
        e.stopPropagation();
    }
    
    // If the clicked element is not the section header itself, find the closest section header
    const sectionHeader = headerElement.classList.contains('section-header') ? 
                          headerElement : headerElement.closest('.section-header');
    
    const sectionContent = sectionHeader.nextElementSibling;
    const toggleIcon = sectionHeader.querySelector('.toggle-section');
    
    // Toggle the collapsed class
    sectionContent.classList.toggle('collapsed');
    
    // Update the toggle icon
    if (sectionContent.classList.contains('collapsed')) {
        toggleIcon.textContent = '▶';
    } else {
        toggleIcon.textContent = '▼';
    }
}

/**
 * Add a new learning objective from the input field
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
function addObjectiveFromInput(week) {
    // Find the week element using data-unit-name attribute (internal name like "Unit 1")
    const weekElement = document.querySelector(`.accordion-item[data-unit-name="${week}"]`);
    if (!weekElement) {
        console.error('Could not find week element for:', week);
        showNotification('Error: Could not find unit element', 'error');
        return;
    }
    
    // Convert unit name to ID format (e.g., "Unit 1" -> "Unit-1")
    const unitId = week.toLowerCase().replace(/\s+/g, '-');
    
    const inputField = weekElement.querySelector(`#objective-input-${unitId}`);
    
    if (!inputField) {
        console.error('Could not find input field for:', week, 'with ID:', `objective-input-${unitId}`);
        showNotification('Error: Could not find input field', 'error');
        return;
    }
    
    const objectiveText = inputField.value.trim();
    
    if (!objectiveText) {
        showNotification('Please enter a learning objective.', 'error');
        return;
    }
    
    // Get the objectives list
    const objectivesList = weekElement.querySelector(`#objectives-list-${unitId}`);
    
    if (!objectivesList) {
        console.error('Could not find objectives list for:', week);
        showNotification('Error: Could not find objectives list', 'error');
        return;
    }
    
    // Create new objective display item
    const objectiveItem = document.createElement('div');
    objectiveItem.className = 'objective-display-item';
    objectiveItem.innerHTML = `
        <span class="objective-text">${objectiveText}</span>
        <button class="remove-objective" onclick="removeObjective(this)">×</button>
    `;
    
    // Add to the list
    objectivesList.appendChild(objectiveItem);
    
    // Clear the input field
    inputField.value = '';
    inputField.focus();
    
    showNotification('Learning objective added successfully!', 'success');
}

/**
 * Remove a learning objective
 * @param {HTMLElement} button - The remove button element
 */
function removeObjective(button) {
    const objectiveItem = button.closest('.objective-display-item');
    if (objectiveItem) {
        objectiveItem.remove();
        showNotification('Learning objective removed.', 'error');
    } else {
        console.error('Could not find objective item to remove');
    }
}

/**
 * Add a new learning objective for a unit (used in onboarding)
 * @param {string} unitName - The unit name (e.g., 'Unit 1')
 */


/**
 * Save learning objectives for a week
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
async function saveObjectives(week) {
    // Find the week element using data-unit-name attribute (internal name like "Unit 1")
    const weekElement = document.querySelector(`.accordion-item[data-unit-name="${week}"]`);
    if (!weekElement) {
        console.error('Could not find week element for:', week);
        showNotification('Error: Could not find unit element', 'error');
        return;
    }
    
    const objectiveItems = weekElement.querySelectorAll('.objective-text');
    
    // Collect all objectives
    const objectives = Array.from(objectiveItems).map(item => item.textContent.trim()).filter(value => value);
    
    if (objectives.length === 0) {
        showNotification('Please add at least one learning objective.', 'error');
        return;
    }
    
    try {
        // Get the current course ID
        const courseId = await getCurrentCourseId();
        
        const requestBody = {
            lectureName: week, // Use lectureName for consistency
            objectives: objectives,
            instructorId: getCurrentInstructorId(),
            courseId: courseId
        };
        
        const response = await fetch('/api/learning-objectives', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response:', errorText);
            throw new Error(`Failed to save learning objectives: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        showNotification(result.message, 'success');
        
    } catch (error) {
        console.error('Error saving learning objectives:', error);
        showNotification('Error saving learning objectives. Please try again.', 'error');
    }
}

/**
 * Confirm course materials for a week
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
async function confirmCourseMaterials(week) {
    // Find the week element using data-unit-name attribute (internal name like "Unit 1")
    const weekElement = document.querySelector(`.accordion-item[data-unit-name="${week}"]`);
    if (!weekElement) {
        console.error('Could not find week element for:', week);
        showNotification('Error: Could not find unit element', 'error');
        return;
    }
    const fileItems = weekElement.querySelectorAll('.course-materials-section .file-item');
    
    console.log(`🔍 [CONFIRM_MATERIALS] Checking materials for ${week}`);
    console.log(`🔍 [CONFIRM_MATERIALS] Found ${fileItems.length} file items`);
    
    // Debug: Log all file items to see what we're working with
    fileItems.forEach((item, index) => {
        const title = item.querySelector('.file-info h3');
        const statusText = item.querySelector('.status-text');
        const documentType = item.dataset.documentType;
        console.log(`🔍 [CONFIRM_MATERIALS] File item ${index + 1}:`, {
            title: title ? title.textContent : 'No title',
            status: statusText ? statusText.textContent : 'No status',
            documentType: documentType || 'No document type',
            isPlaceholder: item.classList.contains('placeholder-item')
        });
    });
    
    // Check if mandatory materials are present
    let hasLectureNotes = false;
    let hasPracticeQuestions = false;
    
    fileItems.forEach((item, index) => {
        const title = item.querySelector('.file-info h3');
        const statusText = item.querySelector('.status-text');
        const documentType = item.dataset.documentType;
        
        if (title && statusText) {
            const titleText = title.textContent;
            const status = statusText.textContent;
            
            console.log(`🔍 [CONFIRM_MATERIALS] Item ${index + 1}: "${titleText}" - Status: "${status}" - Type: "${documentType}"`);
            console.log(`🔍 [CONFIRM_MATERIALS] Debug - documentType === 'lecture_notes': ${documentType === 'lecture_notes'}, documentType === 'practice_q_tutorials': ${documentType === 'practice_q_tutorials'}`);
            
            // Check if this is a lecture notes document that's processed/uploaded
            // Use document type for more reliable checking, fallback to title text
            const isLectureNotesType = documentType === 'lecture_notes' || 
                                     documentType === 'lecture-notes' ||
                                     titleText.includes('Lecture Notes');
            const isLectureNotesStatus = status === 'Processed' || status === 'Uploaded' || status === 'uploaded' || status === 'parsed' || status === 'Processing';
            console.log(`🔍 [CONFIRM_MATERIALS] Lecture Notes check - Type match: ${isLectureNotesType}, Status match: ${isLectureNotesStatus}`);
            
            if (isLectureNotesType && isLectureNotesStatus) {
                hasLectureNotes = true;
                console.log(`✅ [CONFIRM_MATERIALS] Found valid lecture notes with status: "${status}" and type: "${documentType}"`);
            }
            
            // Check if this is a practice questions document that's processed/uploaded
            // Use document type for more reliable checking, fallback to title text
            const isPracticeQuestionsType = documentType === 'practice_q_tutorials' || 
                                          documentType === 'practice-quiz' ||
                                          titleText.includes('Practice Questions') || 
                                          titleText.includes('Practice Questions/Tutorial');
            const isPracticeQuestionsStatus = status === 'Processed' || status === 'Uploaded' || status === 'uploaded' || status === 'parsed' || status === 'Processing';
            console.log(`🔍 [CONFIRM_MATERIALS] Practice Questions check - Type match: ${isPracticeQuestionsType}, Status match: ${isPracticeQuestionsStatus}`);
            
            if (isPracticeQuestionsType && isPracticeQuestionsStatus) {
                hasPracticeQuestions = true;
                console.log(`✅ [CONFIRM_MATERIALS] Found valid practice questions with status: "${status}" and type: "${documentType}"`);
            }
        }
    });
    
    console.log(`🔍 [CONFIRM_MATERIALS] Final check - Lecture Notes: ${hasLectureNotes}, Practice Questions: ${hasPracticeQuestions}`);
    console.log(`🔍 [CONFIRM_MATERIALS] Summary - Found ${fileItems.length} file items, ${hasLectureNotes ? '1' : '0'} lecture notes, ${hasPracticeQuestions ? '1' : '0'} practice questions`);
    
    // Validate mandatory materials
    if (!hasLectureNotes || !hasPracticeQuestions) {
        let missingItems = [];
        if (!hasLectureNotes) missingItems.push('Lecture Notes');
        if (!hasPracticeQuestions) missingItems.push('Practice Questions/Tutorial');
        
        const errorMsg = `Missing mandatory materials: ${missingItems.join(', ')}. Please add them before confirming.`;
        console.warn(`❌ [CONFIRM_MATERIALS] ${errorMsg}`);
        showNotification(errorMsg, 'error');
        return;
    }
    
    try {
        // Try to save to the server
        console.log(`🔧 [CONFIRM_MATERIALS] Making API call to /api/courses/course-materials/confirm`);
        console.log(`🔧 [CONFIRM_MATERIALS] Request body:`, { week, instructorId: getCurrentInstructorId() });
        
        const response = await fetch('/api/courses/course-materials/confirm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                week: week,
                instructorId: getCurrentInstructorId()
            })
        });
        
        console.log(`🔧 [CONFIRM_MATERIALS] Response status: ${response.status} ${response.statusText}`);
        console.log(`🔧 [CONFIRM_MATERIALS] Response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (response.ok) {
            const result = await response.json();
            showNotification(result.message || `Course materials for ${week} confirmed successfully!`, 'success');
        } else {
            // If the endpoint doesn't exist yet, show a different message
            if (response.status === 404) {
                showNotification(`Course materials for ${week} validated successfully! (Backend endpoint not yet implemented)`, 'info');
            } else {
                const errorText = await response.text();
                throw new Error(`Server error: ${response.status} ${errorText}`);
            }
        }
        
    } catch (error) {
        console.error('Error confirming course materials:', error);
        
        // Check if it's a network/endpoint not found error
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            showNotification(`Course materials for ${week} validated successfully! (Backend not available)`, 'info');
        } else {
            showNotification(`Error confirming course materials: ${error.message}`, 'error');
        }
    }
}

// Initialize sections when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all sections to be expanded by default
    document.querySelectorAll('.section-content').forEach(section => {
        if (!section.classList.contains('collapsed')) {
            const toggleButton = section.previousElementSibling.querySelector('.toggle-section');
            if (toggleButton) {
                toggleButton.textContent = '▼';
            }
        }
    });
});

/**
 * Focus and expand a specific unit on the documents page based on URL param
 * Supports /instructor/documents?courseId=...&unit=Unit%203
 */
function focusUnitFromURL() {
    try {
        const params = new URLSearchParams(window.location.search);
        const unitNameParam = params.get('unit');
        if (!unitNameParam) return;
        
        // Find the accordion item using data-unit-name attribute (internal name like "Unit 1")
        const accordionItem = document.querySelector(`.accordion-item[data-unit-name="${unitNameParam}"]`);
        if (!accordionItem) return;
        const header = accordionItem.querySelector('.accordion-header');
        const content = accordionItem.querySelector('.accordion-content');
        
        if (content && content.classList.contains('collapsed') && header) {
            header.click();
        }
        
        // Scroll into view
        accordionItem.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
        console.warn('focusUnitFromURL error:', e);
    }
}

/**
 * Toggle accordion with dynamic height calculation
 * @param {HTMLElement} content - The accordion content element
 * @param {HTMLElement} toggle - The toggle icon element
 */


// ==========================================
// Assessment Questions Functionality
// ==========================================

// Global variables for assessment questions
let assessmentQuestions = {
    'Week 1': [],
    'Week 2': [],
    'Week 3': []
};

/**
 * Open the question creation modal
 * @param {string} week - Week identifier (e.g., 'Week 1')
 */
function openQuestionModal(week) {
    currentWeek = week;
    const modal = document.getElementById('question-modal');
    if (modal) {
        modal.classList.add('show');
        // Reset form
        resetQuestionForm();
    }
}

/**
 * Close the question creation modal
 */
function closeQuestionModal() {
    const modal = document.getElementById('question-modal');
    if (modal) {
        modal.classList.remove('show');
        resetQuestionForm();
    }
}

/**
 * Reset the question form to initial state
 */
function resetQuestionForm() {
    document.getElementById('question-type').value = '';
    document.getElementById('question-text').value = '';
    
    // Hide all answer sections
    document.getElementById('tf-answer-section').style.display = 'none';
    document.getElementById('mcq-answer-section').style.display = 'none';
    document.getElementById('sa-answer-section').style.display = 'none';
    
    // Clear radio buttons
    const radioButtons = document.querySelectorAll('input[type="radio"]');
    radioButtons.forEach(radio => radio.checked = false);
    
    // Clear MCQ inputs
    const mcqInputs = document.querySelectorAll('.mcq-input');
    mcqInputs.forEach(input => input.value = '');
    
    // Clear short answer
    document.getElementById('sa-answer').value = '';
    
    // Reset AI generation tracking
    aiGenerationCount = 0;
    lastGeneratedContent = null;
    currentQuestionType = null;
    
    // Hide AI generation button
    const aiButton = document.getElementById('ai-generate-btn');
    if (aiButton) {
        aiButton.style.display = 'none';
        aiButton.disabled = false;
        aiButton.innerHTML = '<span class="ai-icon">🤖</span> Generate with AI'; // Reset button text
        console.log(`🔍 [RESET_FORM] AI button hidden and reset`);
    } else {
        console.warn(`🔍 [RESET_FORM] AI button not found during reset`);
    }
}

/**
 * Clear all form fields (question text and answers for all types)
 */
function clearAllFormFields() {
    console.log('🧹 [CLEAR_FORM] Clearing all form fields due to question type change');
    
    // Clear question text
    const questionTextInput = document.getElementById('question-text');
    if (questionTextInput) {
        questionTextInput.value = '';
    }
    
    // Clear True/False answers
    const tfRadios = document.querySelectorAll('input[name="tf-answer"]');
    tfRadios.forEach(radio => radio.checked = false);
    
    // Clear Multiple Choice answers
    const mcqInputs = document.querySelectorAll('.mcq-input');
    mcqInputs.forEach(input => input.value = '');
    
    const mcqRadios = document.querySelectorAll('input[name="mcq-correct"]');
    mcqRadios.forEach(radio => radio.checked = false);
    
    // Clear Short Answer
    const saAnswer = document.getElementById('sa-answer');
    if (saAnswer) {
        saAnswer.value = '';
    }
    
    console.log('✅ [CLEAR_FORM] All form fields cleared');
}

/**
 * Update question form based on selected question type
 */
function updateQuestionForm() {
    const questionType = document.getElementById('question-type').value;
    
    // Reset AI generation tracking and clear form if question type changed
    if (questionType !== currentQuestionType) {
        aiGenerationCount = 0;
        lastGeneratedContent = null;
        currentQuestionType = questionType;
        
        // Reset button text if it exists
        const aiButton = document.getElementById('ai-generate-btn');
        if (aiButton) {
            aiButton.innerHTML = '<span class="ai-icon">🤖</span> Generate with AI';
        }
        
        // Clear all form fields when switching question types
        clearAllFormFields();
    }
    
    // Hide all sections first
    document.getElementById('tf-answer-section').style.display = 'none';
    document.getElementById('mcq-answer-section').style.display = 'none';
    document.getElementById('sa-answer-section').style.display = 'none';
    
    // Show relevant section
    if (questionType === 'true-false') {
        document.getElementById('tf-answer-section').style.display = 'block';
    } else if (questionType === 'multiple-choice') {
        document.getElementById('mcq-answer-section').style.display = 'block';
        // Add event listeners for MCQ inputs
        setupMCQValidation();
    } else if (questionType === 'short-answer') {
        document.getElementById('sa-answer-section').style.display = 'block';
    }
    
    // Check if AI generation should be available
    console.log(`🔍 [UPDATE_FORM] Calling checkAIGenerationInModal...`);
    
    // Debug: Check if AI button exists at this point
    const aiButtonDebug = document.getElementById('ai-generate-btn');
    console.log(`🔍 [UPDATE_FORM] AI button found during update: ${!!aiButtonDebug}`);
    
    checkAIGenerationInModal();
}

/**
 * Setup validation for multiple choice inputs
 */
function setupMCQValidation() {
    const mcqInputs = document.querySelectorAll('.mcq-input');
    const radioButtons = document.querySelectorAll('input[name="mcq-correct"]');
    
    // Clear all radio buttons initially
    radioButtons.forEach(radio => {
        radio.checked = false;
        radio.disabled = true;
    });
    
    // Add event listeners to inputs
    mcqInputs.forEach(input => {
        input.addEventListener('input', function() {
            const option = this.dataset.option;
            const radioButton = document.querySelector(`input[name="mcq-correct"][value="${option}"]`);
            
            if (this.value.trim()) {
                radioButton.disabled = false;
            } else {
                radioButton.disabled = true;
                radioButton.checked = false;
            }
        });
    });
}

/**
 * Save the created question
 */
async function saveQuestion() {
    // Check authentication first
    const currentUser = getCurrentUser();
    if (!currentUser) {
        showNotification('Authentication error. Please refresh the page and try again.', 'error');
        return;
    }
    
    const questionType = document.getElementById('question-type').value;
    const questionText = document.getElementById('question-text').value.trim();
    
    // Validation
    if (!questionType) {
        showNotification('Please select a question type.', 'error');
        return;
    }
    
    if (!questionText) {
        showNotification('Please enter a question.', 'error');
        return;
    }
    
    let question = {
        questionType: questionType,
        question: questionText
    };
    
    // Get answer based on type
    if (questionType === 'true-false') {
        const tfAnswer = document.querySelector('input[name="tf-answer"]:checked');
        if (!tfAnswer) {
            showNotification('Please select the correct answer (True/False).', 'error');
            return;
        }
        question.correctAnswer = tfAnswer.value;
    } else if (questionType === 'multiple-choice') {
        // Get all options
        const options = {};
        const mcqInputs = document.querySelectorAll('.mcq-input');
        let hasOptions = false;
        let hasCorrectAnswer = false;
        
        mcqInputs.forEach(input => {
            if (input.value.trim()) {
                options[input.dataset.option] = input.value.trim();
                hasOptions = true;
                
                // Check if this option is selected as correct
                const radioButton = input.parentElement.querySelector('input[name="mcq-correct"]');
                if (radioButton && radioButton.checked) {
                    hasCorrectAnswer = true;
                }
            }
        });
        
        if (!hasOptions) {
            showNotification('Please enter at least one answer option.', 'error');
            return;
        }
        
        if (!hasCorrectAnswer) {
            showNotification('Please select the correct answer for the options you have entered.', 'error');
            return;
        }
        
        const correctAnswer = document.querySelector('input[name="mcq-correct"]:checked');
        question.options = options;
        question.correctAnswer = correctAnswer.value;
    } else if (questionType === 'short-answer') {
        const saAnswer = document.getElementById('sa-answer').value.trim();
        if (!saAnswer) {
            showNotification('Please provide expected answer or key points.', 'error');
            return;
        }
        question.correctAnswer = saAnswer;
    }
    
    try {
        // Save question to MongoDB
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        const lectureName = currentWeek;
        
        // Debug logging
        console.log('🔍 [SAVE_QUESTION] Debug info:', {
            courseId,
            instructorId,
            lectureName,
            currentWeek
        });
        
        // Validation
        if (!courseId) {
            throw new Error('No course selected. Please select a course first.');
        }
        
        if (!instructorId) {
            throw new Error('Authentication error. Please refresh the page and try again.');
        }
        
        if (!lectureName) {
            throw new Error('No lecture selected. Please select a lecture first.');
        }
        
        const response = await fetch(`${API_BASE_URL}/api/questions`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: lectureName,
                instructorId: instructorId,
                questionType: question.questionType,
                question: question.question,
                options: question.options || {},
                correctAnswer: question.correctAnswer,
                explanation: '',
                difficulty: 'medium',
                tags: [],
                points: 1
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ [SAVE_QUESTION] API Error:', {
                status: response.status,
                statusText: response.statusText,
                errorText: errorText
            });
            
            // Check if it's an authentication error
            if (response.status === 401) {
                throw new Error('Authentication expired. Please refresh the page and try again.');
            }
            
            throw new Error(`Failed to save question: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        
        // Add the new question to local state immediately
        if (!assessmentQuestions[currentWeek]) {
            assessmentQuestions[currentWeek] = [];
        }
        
        const savedQuestion = {
            id: result.data.questionId,
            questionId: result.data.questionId,
            type: question.questionType,
            question: question.question,
            answer: question.correctAnswer,
            options: question.options || {}
        };
        
        assessmentQuestions[currentWeek].push(savedQuestion);
        
        // Update the display
        updateQuestionsDisplay(currentWeek);
        
        // Close modal
        closeQuestionModal();
        
        // Check if we should enable AI generation
        checkAIGenerationAvailability(currentWeek);
        
        showNotification('Question saved successfully!', 'success');
        
    } catch (error) {
        console.error('Error saving question:', error);
        showNotification(`Error saving question: ${error.message}`, 'error');
    }
}

/**
 * Reload questions for a specific unit from the database
 * @param {string} unitName - Unit name (e.g., 'Unit 1')
 */
async function reloadQuestionsForUnit(unitName) {
    try {
        const courseId = await getCurrentCourseId();
        
        const response = await fetch(`${API_BASE_URL}/api/questions/lecture?courseId=${courseId}&lectureName=${encodeURIComponent(unitName)}`);
        
        if (response.ok) {
            const result = await response.json();
            const questions = result.data.questions;
            
            // Store questions in the local assessmentQuestions object
            if (!assessmentQuestions[unitName]) {
                assessmentQuestions[unitName] = [];
            }
            
            // Clear existing questions and add new ones
            assessmentQuestions[unitName] = [];
            
            // Convert database questions to local format
            questions.forEach(dbQuestion => {
                const localQuestion = {
                    id: dbQuestion.questionId,
                    questionId: dbQuestion.questionId,
                    type: dbQuestion.questionType,
                    question: dbQuestion.question,
                    answer: dbQuestion.correctAnswer,
                    options: dbQuestion.options || {}
                };
                
                assessmentQuestions[unitName].push(localQuestion);
            });
            
        } else {
            console.error('Failed to reload questions for unit:', unitName);
        }
    } catch (error) {
        console.error('Error reloading questions for unit:', unitName, error);
    }
}

/**
 * Update the questions display for a week
 * @param {string} week - Week identifier
 */
function updateQuestionsDisplay(week) {
    const containerId = `assessment-questions-${week.toLowerCase().replace(/\s+/g, '-')}`;
    
    const questionsContainer = document.getElementById(containerId);
    if (!questionsContainer) {
        console.error(`Container not found for week: ${week}, ID: ${containerId}`);
        return;
    }
    
    const questions = assessmentQuestions[week] || [];
    
    if (questions.length === 0) {
        questionsContainer.innerHTML = `
            <div class="no-questions-message">
                <p>No assessment questions created yet. Click "Add Question" to get started.</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    questions.forEach((question, index) => {
        html += `
            <div class="question-item" data-question-id="${question.questionId || question.id}">
                <div class="question-header">
                    <span class="question-type-badge ${question.type}">${getQuestionTypeLabel(question.type)}</span>
                    <span class="question-number">Question ${index + 1}</span>
                    <button class="delete-question-btn" onclick="deleteQuestion('${week}', '${question.questionId || question.id}')">×</button>
                </div>
                <div class="question-content">
                    <p class="question-text">${question.question}</p>
                    ${getQuestionAnswerDisplay(question)}
                </div>
            </div>
        `;
    });
    
    questionsContainer.innerHTML = html;
    
    // Update pass threshold max value
    const weekId = week.toLowerCase().replace(/\s+/g, '-');
    const thresholdInput = document.getElementById(`pass-threshold-${weekId}`);
    
    if (thresholdInput) {
        thresholdInput.max = questions.length;
        // If there are no questions, always set threshold to 0
        if (questions.length === 0) {
            thresholdInput.value = 0;
        } else {
            // If threshold exceeds question count, adjust it
            if (parseInt(thresholdInput.value) > questions.length) {
                thresholdInput.value = questions.length;
            }
            // If threshold hasn't been set (is empty or invalid), default to 0
            if (thresholdInput.value === '' || thresholdInput.value === null || thresholdInput.value === undefined) {
                thresholdInput.value = 0;
            }
        }
    }
    
    // Event listeners for threshold input are handled by setupThresholdInputListeners()
    // No need to add them here to avoid duplicates
}

/**
 * Handle threshold input change events
 * @param {Event} event - The input event
 */
function handleThresholdInputChange(event) {
    const thresholdInput = event.target;
    const weekId = thresholdInput.id.replace('pass-threshold-', '');
    
    // Get the current total questions count for validation
    const questionsContainer = document.getElementById(`assessment-questions-${weekId}`);
    const totalQuestions = questionsContainer ? questionsContainer.querySelectorAll('.question-item').length : 0;
    
    console.log(`Threshold input changed: ${thresholdInput.value}/${totalQuestions}`);
}

/**
 * Get question type label for display
 * @param {string} type - Question type
 * @returns {string} Display label
 */
function getQuestionTypeLabel(type) {
    switch (type) {
        case 'true-false': return 'T/F';
        case 'multiple-choice': return 'MCQ';
        case 'short-answer': return 'SA';
        default: return type;
    }
}

/**
 * Get question answer display HTML
 * @param {object} question - Question object
 * @returns {string} HTML string
 */
function getQuestionAnswerDisplay(question) {
    if (question.type === 'true-false') {
        return `<p class="answer-preview"><strong>Answer:</strong> ${question.answer === 'true' ? 'True' : 'False'}</p>`;
    } else if (question.type === 'multiple-choice') {
        let optionsHtml = '';
        Object.entries(question.options).forEach(([key, value]) => {
            const isCorrect = key === question.answer;
            optionsHtml += `<span class="mcq-option-preview ${isCorrect ? 'correct' : ''}">${key}) ${value}</span>`;
        });
        return `<div class="mcq-preview">${optionsHtml}</div>`;
    } else if (question.type === 'short-answer') {
        return `<p class="answer-preview"><strong>Expected:</strong> ${question.answer}</p>`;
    }
    return '';
}

/**
 * Delete a question
 * @param {string} week - Week identifier
 * @param {string} questionId - Question ID
 */
async function deleteQuestion(week, questionId) {
    if (confirm('Are you sure you want to delete this question?')) {
        try {
            await deleteAssessmentQuestion(questionId, week);
            checkAIGenerationAvailability(week);
        } catch (error) {
            console.error('Error deleting question:', error);
        }
    }
}

/**
 * Generate AI questions for a week
 * @param {string} week - Week identifier
 */
// AI generation is now handled within the question modal via generateAIQuestionContent()

// createAIQuestion function removed - replaced by createAIQuestionContent for modal use

/**
 * Check if lecture notes are uploaded for a week
 * @param {string} week - Week identifier
 * @returns {boolean} True if lecture notes are uploaded
 */
function checkLectureNotesUploaded(week) {
    // Look for lecture notes status in the week
    const weekLower = week.toLowerCase().replace(' ', '');
    const lectureNotesElement = document.querySelector(`[onclick*="'${week}'"][onclick*="lecture-notes"]`);
    
    if (lectureNotesElement) {
        // Check if there's a "Processed" status nearby
        const parentItem = lectureNotesElement.closest('.file-item');
        if (parentItem) {
            const statusElement = parentItem.querySelector('.status-text');
            return statusElement && statusElement.textContent === 'Processed';
        }
    }
    
    return false; // Default to false for now
}

/**
 * Monitor lecture notes status changes and update AI button
 * This function should be called whenever file status changes
 */
function monitorLectureNotesStatus() {
    // Set up a mutation observer to watch for status changes
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'childList' || mutation.type === 'characterData') {
                // Check all weeks for status changes
                ['Week 1', 'Week 2', 'Week 3'].forEach(week => {
                    checkAIGenerationAvailability(week);
                });
            }
        });
    });
    
    // Observe the entire document for changes
    observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true
    });
}

/**
 * Check AI generation availability in the question modal
 */
function checkAIGenerationInModal() {
    console.log(`🔍 [AI_MODAL_CHECK] Starting check for currentWeek: ${currentWeek}`);
    
    const questionType = document.getElementById('question-type').value;
    const aiButton = document.getElementById('ai-generate-btn');
    
    console.log(`🔍 [AI_MODAL_CHECK] Question type: ${questionType}`);
    console.log(`🔍 [AI_MODAL_CHECK] AI button found: ${!!aiButton}`);
    
    if (!questionType) {
        // No question type selected, hide AI button
        console.log(`🔍 [AI_MODAL_CHECK] No question type selected, hiding AI button`);
        aiButton.style.display = 'none';
        return;
    }
    
    // Check if course materials are available for the current week
    const materialsAvailable = checkCourseMaterialsAvailable(currentWeek);
    console.log(`🔍 [AI_MODAL_CHECK] Course materials available: ${materialsAvailable}`);
    
    if (!materialsAvailable) {
        // No course materials available, disable AI button
        console.log(`🔍 [AI_MODAL_CHECK] No materials available, disabling AI button`);
        aiButton.style.display = 'flex';
        aiButton.disabled = true;
        aiButton.title = 'Please upload course materials (lecture notes, practice questions, etc.) before generating AI questions.';
        return;
    }
    
    // Course materials available and question type selected, enable AI button
    console.log(`🔍 [AI_MODAL_CHECK] Materials available, enabling AI button`);
    aiButton.style.display = 'flex';
    aiButton.disabled = false;
    aiButton.title = 'Generate AI question based on uploaded course materials.';
}

/**
 * Generate AI content for the current question in the modal
 */
async function generateAIQuestionContent() {
    const questionType = document.getElementById('question-type').value;
    
    if (!questionType) {
        showNotification('Please select a question type first.', 'error');
        return;
    }
    
    if (!checkCourseMaterialsAvailable(currentWeek)) {
        showNotification('Please upload course materials (lecture notes, practice questions, etc.) before generating AI questions.', 'error');
        return;
    }

    // Check if this is the second click with existing content
    if (aiGenerationCount > 0 && lastGeneratedContent && questionType === currentQuestionType) {
        // Show regenerate modal instead of generating new content
        openRegenerateModal();
        return;
    }

    // Reset tracking if question type changed
    if (questionType !== currentQuestionType) {
        aiGenerationCount = 0;
        lastGeneratedContent = null;
        currentQuestionType = questionType;
    }
    
    // Show loading state
    const aiButton = document.getElementById('ai-generate-btn');
    const originalText = aiButton.innerHTML;
    aiButton.innerHTML = '<span class="ai-icon">⏳</span> Generating...';
    aiButton.disabled = true;
    
    try {
        // Get current course ID and instructor ID
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        // Get course materials and learning objectives for the current week
        // Use data-unit-name attribute selector instead of folder-name text (which shows formatted name)
        const weekAccordionItem = document.querySelector(`.accordion-item[data-unit-name="${currentWeek}"]`);

        if (!weekAccordionItem) {
            throw new Error(`Could not find accordion item for week: ${currentWeek}`);
        }

        // Get materials
        const materials = [];
        const fileItems = weekAccordionItem.querySelectorAll('.course-materials-section .file-item');
        fileItems.forEach(item => {
            const title = item.querySelector('.file-info h3')?.textContent;
            const status = item.querySelector('.status-text')?.textContent;
            const docId = item.dataset.documentId;
            materials.push({ title, status, documentId: docId });
        });
        console.log('📚 [MATERIALS] Available materials for AI generation:', materials);

        // Get learning objectives
        const objectives = [];
        const objectivesList = weekAccordionItem.querySelector('.objectives-list');
        if (objectivesList) {
            objectivesList.querySelectorAll('.objective-text').forEach(obj => {
                const text = obj.textContent.trim();
                if (text) {
                    objectives.push(text);
                }
            });
        }
        console.log('📚 [OBJECTIVES] Learning objectives for AI generation:', objectives);

        // Call the AI question generation API
        const apiUrl = API_BASE_URL + '/api/questions/generate-ai';
        console.log('🔍 [API_CALL] Making request to:', apiUrl);
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: currentWeek,
                instructorId: instructorId,
                questionType: questionType,
                learningObjectives: objectives.length > 0 ? objectives : undefined
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
            throw new Error(errorData.message || `Failed to generate question: ${response.status}`);
        }
        
        const result = await response.json();
        console.log('🤖 [AI_RESPONSE] Raw response:', result);
        console.log('🤖 [AI_RESPONSE] Full data structure:', JSON.stringify(result, null, 2));
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to generate question');
        }
        
        const aiContent = result.data;
        console.log('🤖 [AI_CONTENT] Processed content to populate form:', aiContent);
        console.log('🤖 [AI_CONTENT] Content keys:', Object.keys(aiContent));
        console.log('🤖 [AI_CONTENT] Options structure:', aiContent.options ? JSON.stringify(aiContent.options, null, 2) : 'No options');
        
        // Store the generated content for potential regeneration
        lastGeneratedContent = aiContent;
        aiGenerationCount++;
        currentQuestionType = questionType;
        
        // Populate form fields with AI content
        populateFormWithAIContent(aiContent);
        
        // Update button text to indicate regeneration is available
        if (aiGenerationCount === 1) {
            aiButton.innerHTML = '<span class="ai-icon">🔄</span> Regenerate with AI';
        }
        
        // Show success notification
        showNotification('AI question generated successfully! You can now edit and save it.', 'success');
        
    } catch (error) {
        console.error('Error generating AI question:', error);
        showNotification(`Error generating AI question: ${error.message}`, 'error');
        
        // Show fallback content for demo purposes
        const fallbackContent = createFallbackAIContent(questionType, currentWeek);
        populateFormWithAIContent(fallbackContent);
        showNotification('Using fallback content due to generation error. Please edit before saving.', 'warning');
        
    } finally {
        // Restore button state
        aiButton.disabled = false;
        
        // If we have generated content, show regenerate button
        if (aiGenerationCount > 0) {
            aiButton.innerHTML = '<span class="ai-icon">🔄</span> Regenerate with AI';
        } else {
            aiButton.innerHTML = originalText;
        }
    }
}

/**
 * Create fallback AI content when the API fails
 * @param {string} type - Question type
 * @param {string} week - Week identifier
 * @returns {Object} Fallback content object
 */
function createFallbackAIContent(type, week) {
    if (type === 'true-false') {
        return {
            question: `Based on the ${week} lecture notes, this concept is essential for understanding the course material.`,
            answer: Math.random() > 0.5 ? 'true' : 'false'
        };
    } else if (type === 'multiple-choice') {
        return {
            question: `According to the ${week} lecture notes, which of the following is most accurate?`,
            options: {
                'A': 'Option A based on lecture content',
                'B': 'Option B based on lecture content', 
                'C': 'Option C based on lecture content',
                'D': 'Option D based on lecture content'
            },
            answer: ['A', 'B', 'C', 'D'][Math.floor(Math.random() * 4)]
        };
    } else if (type === 'short-answer') {
        return {
            question: `Explain a key concept from the ${week} lecture notes and its significance.`,
            answer: 'Students should demonstrate understanding by explaining the concept clearly and showing its relevance to the course material.'
        };
    }
}

/**
 * Populate the question modal form with AI-generated content
 * @param {Object} aiContent - The AI-generated question content
 */
function populateFormWithAIContent(aiContent) {
    console.log('🎯 [FORM_POPULATION] Starting to populate form with content:', aiContent);
    console.log('🎯 [FORM_POPULATION] Content structure:', {
        hasQuestion: 'question' in aiContent,
        hasOptions: 'options' in aiContent,
        optionsType: aiContent.options ? typeof aiContent.options : 'none',
        allKeys: Object.keys(aiContent)
    });
    
    // Set question text - check multiple possible locations
    const questionText = aiContent.question || aiContent.options?.question || aiContent.prompt || '';
    console.log('🎯 [FORM_POPULATION] Setting question text:', questionText);
    document.getElementById('question-text').value = questionText;
    
    // Set answer based on type
    const questionType = document.getElementById('question-type').value;
    console.log('🎯 [FORM_POPULATION] Question type:', questionType);
    
    if (questionType === 'true-false') {
        console.log('🎯 [FORM_POPULATION] Handling true-false question');
        console.log('🎯 [FORM_POPULATION] Answer value:', aiContent.answer);
        
        // Set radio button
        const radioButton = document.querySelector(`input[name="tf-answer"][value="${aiContent.answer}"]`);
        console.log('🎯 [FORM_POPULATION] Found radio button:', !!radioButton);
        if (radioButton) {
            radioButton.checked = true;
        }
    } else if (questionType === 'multiple-choice') {
        console.log('🎯 [FORM_POPULATION] Handling multiple-choice question');
        console.log('🎯 [FORM_POPULATION] Options:', aiContent.options);
        
        // Set MCQ options
        if (aiContent.options && typeof aiContent.options === 'object') {
            // Check if options are in the expected format or in choices array
            const choices = aiContent.options.choices || aiContent.options;
            console.log('🎯 [FORM_POPULATION] Processed choices:', choices);
            
            // Map choices to A, B, C, D if they're in an array
            if (Array.isArray(choices)) {
                choices.forEach((choice, index) => {
                    const option = String.fromCharCode(65 + index); // Convert 0 to 'A', 1 to 'B', etc.
                    console.log(`🎯 [FORM_POPULATION] Setting array option ${option}:`, choice);
                    const input = document.querySelector(`.mcq-input[data-option="${option}"]`);
                    if (input) {
                        input.value = choice;
                    }
                });
            } else {
                // Handle object format
                Object.keys(choices).forEach(option => {
                    console.log(`🎯 [FORM_POPULATION] Setting object option ${option}:`, choices[option]);
                    const input = document.querySelector(`.mcq-input[data-option="${option}"]`);
                    if (input) {
                        input.value = choices[option];
                    }
                });
            }
        }
        
        // Enable all radio buttons since we have content
        const radioButtons = document.querySelectorAll('input[name="mcq-correct"]');
        radioButtons.forEach(radio => {
            radio.disabled = false;
        });
        
        // Set correct answer - might be in different places in the response
        const correctAnswer = aiContent.options?.correctAnswer || aiContent.answer || '';
        console.log('🎯 [FORM_POPULATION] Correct answer:', correctAnswer);
        
        if (correctAnswer) {
            // Try both the original answer and uppercase version
            let correctRadio = document.querySelector(`input[name="mcq-correct"][value="${correctAnswer}"]`) ||
                             document.querySelector(`input[name="mcq-correct"][value="${correctAnswer.toUpperCase()}"]`);
            
            console.log('🎯 [FORM_POPULATION] Found correct answer radio:', !!correctRadio);
            if (correctRadio) {
                correctRadio.checked = true;
            }
        }
    } else if (questionType === 'short-answer') {
        console.log('🎯 [FORM_POPULATION] Handling short-answer question');
        console.log('🎯 [FORM_POPULATION] Full content:', aiContent);
        
        // For short answer, check both EXPECTED_ANSWER and answer fields
        const expectedAnswer = aiContent.EXPECTED_ANSWER || aiContent.answer || '';
        console.log('🎯 [FORM_POPULATION] Expected answer sources:', {
            fromExpectedAnswer: aiContent.EXPECTED_ANSWER,
            fromAnswer: aiContent.answer,
            final: expectedAnswer
        });
        
        // Set short answer
        document.getElementById('sa-answer').value = expectedAnswer;
    }
    
}

/**
 * Check AI generation availability and update button state
 * @param {string} week - Week identifier
 */
function checkAIGenerationAvailability(week) {
    // This function is now primarily used for external AI generation buttons
    // The modal AI generation is handled by checkAIGenerationInModal()
    const weekLower = week.toLowerCase().replace(' ', '');
    const aiButton = document.getElementById(`generate-ai-${weekLower}`);
    
    if (aiButton) {
        const lectureNotesUploaded = checkLectureNotesUploaded(week);
        aiButton.disabled = !lectureNotesUploaded;
        
        if (lectureNotesUploaded) {
            aiButton.title = 'Generate questions using AI based on uploaded lecture notes';
        } else {
            aiButton.title = 'Upload lecture notes first to enable AI generation';
        }
    }
}

/**
 * Save assessment settings for a week
 * @param {string} week - Week identifier
 */
function saveAssessment(week) {
    const weekLower = week.toLowerCase().replace(/\s+/g, '-');
    const thresholdInput = document.getElementById(`pass-threshold-${weekLower}`);
    
    if (!thresholdInput) {
        console.error(`Threshold input not found for week: ${week}, ID: pass-threshold-${weekLower}`);
        alert('Error: Could not find threshold input for this assessment.');
        return;
    }
    
    const threshold = parseInt(thresholdInput.value);
    const questions = assessmentQuestions[week] || [];
    
    if (questions.length === 0) {
        alert('Please add at least one question before saving the assessment.');
        return;
    }
    
    if (threshold > questions.length) {
        alert(`Pass threshold cannot be greater than the total number of questions (${questions.length}).`);
        return;
    }
    
    // Save the pass threshold to the backend
    savePassThreshold(week, threshold).then(() => {
        // Show success message
        alert(`Assessment saved for ${week}!\nTotal Questions: ${questions.length}\nPass Threshold: ${threshold}`);
    }).catch((error) => {
        console.error('Error saving assessment:', error);
        alert(`Error saving assessment: ${error.message}`);
    });
}

// Initialize assessment system - this will be called from the main DOMContentLoaded listener
function initializeAssessmentSystem() {
    // Initialize questions display for all units
    // Note: This will be updated dynamically based on actual course structure
    // The updateQuestionsDisplay function will be called for each unit as they are loaded
}

/**
 * Load onboarding data and populate the course upload page
 */
async function loadOnboardingData() {
    try {
        // Check if we have a courseId from URL parameters (onboarding redirect)
        const urlParams = new URLSearchParams(window.location.search);
        const courseId = urlParams.get('courseId');
        
        if (!courseId) {
            return;
        }
        
        // Fetch onboarding data from database
        const response = await fetch(`/api/onboarding/${courseId}`);
        
        if (!response.ok) {
            return;
        }
        
        const result = await response.json();
        const onboardingData = result.data;
        
        // Generate units dynamically based on course structure
        if (onboardingData.courseStructure && onboardingData.courseStructure.totalUnits > 0) {
            generateUnitsFromOnboarding(onboardingData);
        }
        
        // Load existing data for the units
        loadExistingUnitData(onboardingData);
        
        // Show success notification
        // Notification removed as per user request (was redundant)
        console.log('Onboarding data loaded successfully!');
        
    } catch (error) {
        console.error('Error loading onboarding data:', error);
        showNotification('Error loading onboarding data. Using default values.', 'warning');
    }
}

/**
 * Load course data (either from onboarding redirect or existing course)
 */
async function loadCourseData() {
    try {
        // First check if we have a courseId from URL parameters (onboarding redirect or course selection)
        const urlParams = new URLSearchParams(window.location.search);
        const courseIdFromUrl = urlParams.get('courseId');
        const courseIdFromStorage = localStorage.getItem('selectedCourseId');
        const selectedCourseId = courseIdFromUrl || courseIdFromStorage;
        
        if (selectedCourseId) {
            // Load specific course data
            console.log('Loading course from URL/localStorage:', selectedCourseId);
            await loadSpecificCourse(selectedCourseId);
            
            // Update URL if course ID is from localStorage
            if (courseIdFromStorage && !courseIdFromUrl) {
                urlParams.set('courseId', selectedCourseId);
                window.history.replaceState({}, '', `${window.location.pathname}?${urlParams.toString()}`);
            }
            return;
        }
        
        // If no courseId in URL or localStorage, check if instructor has any existing courses
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        const response = await fetch(`/api/onboarding/instructor/${instructorId}`);
        
        if (response.ok) {
            const result = await response.json();
            if (result.data && result.data.courses && result.data.courses.length > 0) {
                // Load the first available course
                const firstCourse = result.data.courses[0];
                console.log('Loading first available course:', firstCourse.courseId);
                await loadSpecificCourse(firstCourse.courseId);
                return;
            }
        }
        
        // If no existing course, show empty state
        showEmptyCourseState();
        
    } catch (error) {
        console.error('Error loading course data:', error);
        showNotification('Error loading course data. Using default values.', 'warning');
        showEmptyCourseState();
    }
}

/**
 * Load a specific course by ID
 */
async function loadSpecificCourse(courseId) {
    try {
        const response = await fetch(`/api/onboarding/${courseId}`);
        
        if (!response.ok) {
            showEmptyCourseState();
            return;
        }
        
        const result = await response.json();
        const courseData = result.data;
        
        // Update the course title in the header
        const courseTitleElement = document.getElementById('course-title');
        if (courseTitleElement && courseData.courseName) {
            courseTitleElement.textContent = courseData.courseName;
        }
        
        // Generate units dynamically based on course structure
        if (courseData.courseStructure && courseData.courseStructure.totalUnits > 0) {
            generateUnitsFromOnboarding(courseData);
            
            // Load existing data for the units (learning objectives, publish status, etc.)
            loadExistingUnitData(courseData);
        }
        
        // Show success notification
        showNotification('Course data loaded successfully!', 'success');
        
    } catch (error) {
        console.error('Error loading specific course:', error);
        showNotification('Error loading course data. Using default values.', 'warning');
        showEmptyCourseState();
    }
}

/**
 * Show empty course state when no course exists
 */
function showEmptyCourseState() {
    // Update the course title to show no course state
    const courseTitleElement = document.getElementById('course-title');
    if (courseTitleElement) {
        courseTitleElement.textContent = 'No Course Found';
    }
    
    const container = document.getElementById('dynamic-units-container');
    if (container) {
        container.innerHTML = `
            <div class="empty-course-state">
                <div class="empty-message">
                    <h3>No Course Found</h3>
                    <p>You haven't set up a course yet. Please complete the onboarding process first.</p>
                    <a href="/instructor/onboarding" class="btn-primary">Go to Onboarding</a>
                </div>
            </div>
        `;
    }
    
    // Show onboarding navigation item when no course exists
    const onboardingNavItem = document.getElementById('onboarding-nav-item');
    if (onboardingNavItem) {
        onboardingNavItem.style.display = 'block';
    }
}

/**
 * Generate units dynamically from onboarding data
 * @param {Object} onboardingData - Onboarding data with course structure
 */
function generateUnitsFromOnboarding(onboardingData) {
    const container = document.getElementById('dynamic-units-container');
    if (!container) {
        console.error('Dynamic units container not found');
        return;
    }
    
    // Hide onboarding navigation item when courses exist
    const onboardingNavItem = document.getElementById('onboarding-nav-item');
    if (onboardingNavItem) {
        onboardingNavItem.style.display = 'none';
    }
    
    // Clear existing content
    container.innerHTML = '';
    
    const { courseStructure, lectures } = onboardingData;
    const totalUnits = courseStructure.totalUnits;
    
    // Generate each unit
    for (let i = 1; i <= totalUnits; i++) {
        const unitName = `Unit ${i}`;
        const unitData = lectures ? lectures.find(l => l.name === unitName) : null;
        
        const unitElement = createUnitElement(unitName, unitData, i === 1); // First unit is expanded
        container.appendChild(unitElement);
    }

    // Add "Add Unit" button at the end
    const addUnitContainer = document.createElement('div');
    addUnitContainer.className = 'add-unit-container';
    addUnitContainer.style.marginTop = '20px';
    addUnitContainer.style.textAlign = 'center';
    
    // Check if adding unit is in progress
    const isAdding = container.dataset.addingUnit === 'true';
    
    addUnitContainer.innerHTML = `
        <button id="add-unit-btn" class="btn-secondary" onclick="addNewUnit()" ${isAdding ? 'disabled' : ''}>
            <span class="btn-icon">➕</span>
            ${isAdding ? 'Adding Unit...' : 'Add New Unit'}
        </button>
    `;
    container.appendChild(addUnitContainer);
    
    // Reinitialize event listeners for the new units
    initializeUnitEventListeners();
    
    // Load existing data for the units (learning objectives, publish status, etc.)
    loadExistingUnitData(onboardingData);
    
    // Load assessment questions after units are generated
    setTimeout(() => {
        loadAssessmentQuestionsFromCourseData(onboardingData);
    }, 100);
    
    // Load documents from course structure
    setTimeout(() => {
        loadDocuments().then(() => {
            // After documents are loaded (which creates the accordion items), load thresholds
            setTimeout(() => {
                console.log('🔄 [DELAYED_LOAD] Loading thresholds after documents rendered...');
                loadPassThresholds();
            }, 300);
            
            // Update published units summary
            updatePublishedSummary();
        });
    }, 100);
    
    // Also ensure buttons exist immediately (fallback)
    setTimeout(() => {
        ensureActionButtonsExist();
    }, 200); // Reduced timeout since buttons are already there

    // Focus a specific unit if requested via URL (e.g., ?unit=Unit%203)
    setTimeout(() => {
        focusUnitFromURL();
    }, 300);
}

/**
 * Create a unit element with all its sections
 * @param {string} unitName - Name of the unit (e.g., "Unit 1")
 * @param {Object} unitData - Existing unit data from database
 * @param {boolean} isExpanded - Whether the unit should be expanded by default
 * @returns {HTMLElement} The unit element
 */
function createUnitElement(unitName, unitData, isExpanded = false) {
    const unitDiv = document.createElement('div');
    unitDiv.className = 'accordion-item';
    unitDiv.setAttribute('data-unit-name', unitName);
    
    const unitId = unitName.toLowerCase().replace(/\s+/g, '-');
    
    // Extract unit number for display (e.g., "1" from "Unit 1")
    const unitNum = unitName.match(/\d+/)?.[0] || '';
    
    // Use displayName if available, otherwise just show the unit name
    const displayName = unitData?.displayName || '';
    const formattedName = displayName ? `${unitNum}. ${displayName}` : unitName;
    
    unitDiv.innerHTML = `
        <div class="accordion-header">
            <div class="unit-name-container">
                <span class="folder-name">${formattedName}</span>
                <button class="unit-rename-btn" onclick="event.stopPropagation(); openRenameUnitInput('${unitName}')" title="Rename unit">✏️</button>
                <div class="unit-rename-edit" style="display: none;">
                    <input type="text" class="unit-rename-input" placeholder="Enter unit title..." value="${displayName}" data-unit-name="${unitName}">
                    <button class="unit-save-btn" onclick="event.stopPropagation(); saveUnitDisplayName('${unitName}')" title="Save">✓</button>
                    <button class="unit-cancel-btn" onclick="event.stopPropagation(); cancelRenameUnit('${unitName}')" title="Cancel">✕</button>
                </div>
            </div>
            <div class="header-actions">
                <div class="publish-toggle">
                    <label class="toggle-switch">
                        <input type="checkbox" id="publish-${unitId}" onchange="togglePublish('${unitName}', this.checked)">
                        <span class="toggle-slider"></span>
                    </label>
                    <span class="toggle-label">Published</span>
                </div>

                <button class="delete-unit-btn" onclick="openDeleteUnitModal('${unitName}')" title="Delete Unit" style="background: none; border: none; cursor: pointer; font-size: 1.2rem; margin-right: 10px; color: #dc3545;">🗑️</button>

                <span class="accordion-toggle">${isExpanded ? '▼' : '▶'}</span>
            </div>
        </div>
        <div class="accordion-content ${isExpanded ? '' : 'collapsed'}">
            <!-- Learning Objectives Section -->
            <div class="unit-section learning-objectives-section">
                <div class="section-header">
                    <h3>Learning Objectives</h3>
                    <button class="toggle-section">▼</button>
                </div>
                <div class="section-content">
                    <p style="margin-bottom: 10px; color: #666; font-size: 0.9em;">Please provide 3 - 8 learning objectives that are covered by this unit</p>
                    <div class="objectives-list" id="objectives-list-${unitId}">
                        <!-- Objectives will be added here -->
                    </div>
                    <div class="objective-input-container">
                        <input type="text" id="objective-input-${unitId}" class="objective-input" placeholder="Enter learning objective...">
                        <button class="add-objective-btn-inline" onclick="addObjectiveFromInput('${unitName}')">+</button>
                    </div>
                    <div class="save-objectives">
                        <button class="save-btn" onclick="saveObjectives('${unitName}')">Save Learning Objectives</button>
                    </div>
                </div>
            </div>
            
            <!-- Course Materials Section -->
            <div class="unit-section course-materials-section">
                <div class="section-header">
                    <h3>Course Materials</h3>
                    <button class="toggle-section">▼</button>
                </div>
                <div class="section-content">
                    <div class="content-type-header">
                        <p><strong>Required Materials:</strong> *Lecture Notes and *Practice Questions/Tutorial are mandatory</p>
                    </div>
                    <div class="file-item placeholder-item">
                        <div class="file-info">
                            <h3>*Lecture Notes - ${unitName}</h3>
                            <p>Placeholder for required lecture notes. Please upload content.</p>
                            <span class="status-text">Not Uploaded</span>
                        </div>
                        <div class="file-actions">
                            <button class="action-button upload" onclick="openUploadModal('${unitName}', 'lecture-notes')">Upload</button>
                        </div>
                    </div>
                    <div class="file-item placeholder-item">
                        <div class="file-info">
                            <h3>*Practice Questions/Tutorial</h3>
                            <p>Placeholder for required practice questions. Please upload content.</p>
                            <span class="status-text">Not Uploaded</span>
                        </div>
                        <div class="file-actions">
                            <button class="action-button upload" onclick="openUploadModal('${unitName}', 'practice-quiz')">Upload</button>
                        </div>
                    </div>
                    <!-- Action buttons will be added dynamically by loadDocuments() -->
                    <!-- Expected order: Documents → Placeholders → Cleanup → Action Buttons -->
                    <!-- This ensures proper positioning below uploaded files -->
                </div>
            </div>
            
            <!-- Assessment Questions Section -->
            <div class="unit-section assessment-questions-section">
                <div class="section-header">
                    <h3>Assessment Questions</h3>
                    <button class="toggle-section">▼</button>
                </div>
                <div class="section-content">
                    <div class="assessment-info">
                        <p><strong>Assessment Settings:</strong> Assessment questions help BIOCBOT to determine whether to be in protégé or tutor mode. We recommend creating at least 3 questions.</p>
                    </div>
                    
                    <!-- Pass Threshold Setting -->
                    <div class="threshold-setting">
                        <label for="pass-threshold-${unitId}">Number of correct answers required for BIOCBOT to be in protégé mode:</label>
                        <input type="number" id="pass-threshold-${unitId}" min="0" max="10" value="0" class="threshold-input">
                        <span class="threshold-help">out of total questions</span>
                    </div>
                    
                    <!-- Questions List -->
                    <div class="questions-list" id="assessment-questions-${unitId}">
                        <!-- Assessment questions will be displayed here -->
                        <div class="no-questions-message">
                            <p>No assessment questions created yet. Click "Add Question" to get started.</p>
                        </div>
                    </div>
                    
                    <!-- Action Buttons -->
                    <div class="assessment-actions">
                        <button class="add-question-btn" onclick="openQuestionModal('${unitName}')">
                            <span class="btn-icon">➕</span>
                            Add Question
                        </button>
                    </div>
                    
                    <div class="save-assessment">
                        <button class="save-btn" onclick="saveAssessment('${unitName}')">Save Assessment</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    return unitDiv;
}

/**
 * Load existing data for the generated units
 * @param {Object} onboardingData - Onboarding data with existing unit information
 */
function loadExistingUnitData(onboardingData) {
    if (!onboardingData.lectures) return;
    
    onboardingData.lectures.forEach(unit => {
        const unitId = unit.name.toLowerCase().replace(/\s+/g, '-');
        
        // Load learning objectives
        if (unit.learningObjectives && unit.learningObjectives.length > 0) {
            const objectivesList = document.getElementById(`objectives-list-${unitId}`);
            if (objectivesList) {
                objectivesList.innerHTML = '';
                unit.learningObjectives.forEach(objective => {
                    const objectiveItem = document.createElement('div');
                    objectiveItem.className = 'objective-display-item';
                    objectiveItem.innerHTML = `
                        <span class="objective-text">${objective}</span>
                        <button class="remove-objective" onclick="removeObjective(this)">×</button>
                    `;
                    objectivesList.appendChild(objectiveItem);
                });
            } else {
                console.error(`Could not find objectives list element with ID: objectives-list-${unitId}`);
            }
        }
        
        // Load pass threshold
        const thresholdInput = document.getElementById(`pass-threshold-${unitId}`);
        if (thresholdInput) {
            if (unit.passThreshold) {
                thresholdInput.value = unit.passThreshold;
            } else {
                // If no threshold set, default to 0 but don't save it yet
                thresholdInput.value = 0;
            }
        }
        
        // Load assessment questions
        if (unit.assessmentQuestions && unit.assessmentQuestions.length > 0) {
            // Store questions in the local assessmentQuestions object
            if (!assessmentQuestions[unit.name]) {
                assessmentQuestions[unit.name] = [];
            }
            
            // Convert database questions to local format
            unit.assessmentQuestions.forEach(dbQuestion => {
                const localQuestion = {
                    id: dbQuestion.questionId,
                    questionId: dbQuestion.questionId,
                    type: dbQuestion.questionType,
                    question: dbQuestion.question,
                    answer: dbQuestion.correctAnswer,
                    options: dbQuestion.options || {}
                };
                
                assessmentQuestions[unit.name].push(localQuestion);
            });
            
            // Update the display for this unit
            updateQuestionsDisplay(unit.name);
        }
        
        // Load publish status
        if (unit.isPublished !== undefined) {
            const publishToggle = document.getElementById(`publish-${unitId}`);
            if (publishToggle) {
                publishToggle.checked = unit.isPublished;
            }
        }
        
        // Load documents from course structure
        if (unit.documents && unit.documents.length > 0) {
            // Find the course materials section for this unit
            const unitElement = document.querySelector(`[data-unit-name="${unit.name}"]`);
            if (unitElement) {
                const courseMaterialsSection = unitElement.querySelector('.course-materials-section .section-content');
                if (courseMaterialsSection) {
                    // Clear existing placeholder content
                    const placeholders = courseMaterialsSection.querySelectorAll('.file-item');
                    
                    placeholders.forEach(placeholder => {
                        placeholder.remove();
                    });
                    
                    // Add each document
                    unit.documents.forEach(doc => {
                        const documentItem = createDocumentItem(doc);
                        courseMaterialsSection.appendChild(documentItem);
                    });
                }
            }
        }
    });
}



/**
 * Initialize event listeners for dynamically generated units
 */
function initializeUnitEventListeners() {
    // Setup accordion toggling
    const accordionHeaders = document.querySelectorAll('.accordion-header');
    accordionHeaders.forEach(header => {
        header.addEventListener('click', (e) => {
            // Don't toggle if clicking on the toggle switch
            if (e.target.closest('.publish-toggle')) {
                return;
            }
            
            const accordionItem = header.parentElement;
            const content = accordionItem.querySelector('.accordion-content');
            const toggle = header.querySelector('.accordion-toggle');
            
            if (content.classList.contains('collapsed')) {
                content.classList.remove('collapsed');
                toggle.textContent = '▼';
            } else {
                content.classList.add('collapsed');
                toggle.textContent = '▶';
            }
        });
    });
    
    // Setup section toggling
    const sectionHeaders = document.querySelectorAll('.section-header');
    sectionHeaders.forEach(header => {
        header.addEventListener('click', (e) => {
            toggleSection(header, e);
        });
    });
    
    // Setup threshold input listeners
    setupThresholdInputListeners();
}

/**
 * Show document content in a modal
 * @param {Object} documentData - Document object with content and metadata
 */
function showDocumentModal(documentData) {
    // Remove any existing modal
    const existingModal = document.querySelector('.document-modal');
    if (existingModal) {
        existingModal.remove();
    }
    
    // Create modal HTML
    const modalHTML = `
        <div class="document-modal" style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        ">
            <div class="modal-content" style="
                background: white;
                padding: 20px;
                border-radius: 8px;
                max-width: 80%;
                max-height: 80%;
                overflow-y: auto;
                position: relative;
            ">
                <div class="modal-header" style="
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 20px;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                ">
                    <h2 style="margin: 0; color: #333;">${documentData.originalName}</h2>
                    <button class="close-modal" onclick="closeDocumentModal()" style="
                        background: none;
                        border: none;
                        font-size: 24px;
                        cursor: pointer;
                        color: #666;
                    ">&times;</button>
                </div>
                
                <div class="modal-body">
                    <div class="document-info" style="margin-bottom: 20px;">
                        <p><strong>Type:</strong> ${documentData.documentType}</p>
                        <p><strong>Size:</strong> ${documentData.size} bytes</p>
                        <p><strong>Uploaded:</strong> ${documentData.uploadDate ? new Date(documentData.uploadDate).toLocaleString() : 'Unknown'}</p>
                    </div>
                    
                    <div class="document-content" style="
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 4px;
                        border: 1px solid #e9ecef;
                        white-space: pre-wrap;
                        font-family: monospace;
                        max-height: 400px;
                        overflow-y: auto;
                    ">${documentData.content || 'No content available'}</div>
                </div>
                
                <div class="modal-footer" style="
                    margin-top: 20px;
                    text-align: right;
                    border-top: 1px solid #eee;
                    padding-top: 10px;
                ">
                    <button onclick="closeDocumentModal()" style="
                        background: #6c757d;
                        color: white;
                        border: none;
                        padding: 8px 16px;
                        border-radius: 4px;
                        cursor: pointer;
                    ">Close</button>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    
    // Add click outside to close functionality
    const modal = document.querySelector('.document-modal');
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeDocumentModal();
        }
    });
}

/**
 * Close the document modal
 */
function closeDocumentModal() {
    const modal = document.querySelector('.document-modal');
    if (modal) {
        modal.remove();
    }
}

/**
 * Add required placeholder items for lecture notes and practice questions
 * @param {HTMLElement} container - The container to add placeholders to
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 */
function addRequiredPlaceholders(container, unitName) {
    // Check if lecture notes and practice questions already exist as ACTUAL uploaded content
    let hasLectureNotes = false;
    let hasPracticeQuestions = false;
    
    container.querySelectorAll('.file-item').forEach(item => {
        const title = item.querySelector('h3');
        const statusText = item.querySelector('.status-text');
        
        if (title && statusText) {
            const titleText = title.textContent;
            const status = statusText.textContent;
            const isPlaceholder = item.classList.contains('placeholder-item');
            const documentType = item.dataset.documentType || '';
            
            console.log(`🔍 [PLACEHOLDERS] Checking item: "${titleText}" - Status: "${status}" - Type: "${documentType}" - IsPlaceholder: ${isPlaceholder}`);
            
            // Check for lecture notes - look for both document type and title patterns
            const isLectureNotes = documentType === 'lecture_notes' || 
                                  documentType === 'lecture-notes' ||
                                  titleText.includes('lecture-notes') ||
                                  (titleText.includes('Lecture Notes') && !isPlaceholder && status !== 'Not Uploaded');
            
            // Check for practice questions - look for both document type and title patterns  
            const isPracticeQuestions = documentType === 'practice_q_tutorials' || 
                                      documentType === 'practice-quiz' ||
                                      titleText.includes('practice-quiz') ||
                                      titleText.includes('practice_quiz') ||
                                      ((titleText.includes('Practice Questions') || titleText.includes('Practice Questions/Tutorial')) && !isPlaceholder && status !== 'Not Uploaded');
            
            console.log(`🔍 [PLACEHOLDERS] Item "${titleText}": isLectureNotes=${isLectureNotes}, isPracticeQuestions=${isPracticeQuestions}`);
            
            if (isLectureNotes) {
                hasLectureNotes = true;
                console.log(`✅ [PLACEHOLDERS] Found actual lecture notes with type: "${documentType}" and status: "${status}"`);
            }
            
            if (isPracticeQuestions) {
                hasPracticeQuestions = true;
                console.log(`✅ [PLACEHOLDERS] Found actual practice questions with type: "${documentType}" and status: "${status}"`);
            }
        }
    });
    
    console.log(`🔍 [PLACEHOLDERS] Status check for ${unitName}: Lecture Notes: ${hasLectureNotes}, Practice Questions: ${hasPracticeQuestions}`);
    
    // Remove any existing placeholders first to ensure clean state
    removeExistingPlaceholders(container);
    
    // Add lecture notes placeholder if it doesn't exist
    if (!hasLectureNotes) {
        console.log(`📝 [PLACEHOLDERS] Adding lecture notes placeholder for ${unitName} - no actual content found`);
        const lectureNotesItem = document.createElement('div');
        lectureNotesItem.className = 'file-item placeholder-item';
        lectureNotesItem.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-info">
                <h3>*Lecture Notes - ${unitName}</h3>
                <p>Placeholder for required lecture notes. Please upload content.</p>
                <span class="status-text">Not Uploaded</span>
            </div>
            <div class="file-actions">
                <button class="action-button upload" onclick="openUploadModal('${unitName}', 'lecture-notes')">Upload</button>
            </div>
        `;
        container.appendChild(lectureNotesItem);
        console.log(`✅ [PLACEHOLDERS] Lecture notes placeholder added for ${unitName}`);
    } else {
        console.log(`✅ [PLACEHOLDERS] No lecture notes placeholder needed for ${unitName} - actual content exists`);
    }
    
    // Add practice questions placeholder if it doesn't exist
    if (!hasPracticeQuestions) {
        console.log(`📝 [PLACEHOLDERS] Adding practice questions placeholder for ${unitName} - no actual content found`);
        const practiceQuestionsItem = document.createElement('div');
        practiceQuestionsItem.className = 'file-item placeholder-item';
        practiceQuestionsItem.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-info">
                <h3>*Practice Questions/Tutorial</h3>
                <p>Placeholder for required practice questions. Please upload content.</p>
                <span class="status-text">Not Uploaded</span>
            </div>
            <div class="file-actions">
                <button class="action-button upload" onclick="openUploadModal('${unitName}', 'practice-quiz')">Upload</button>
            </div>
        `;
        container.appendChild(practiceQuestionsItem);
        console.log(`✅ [PLACEHOLDERS] Practice questions placeholder added for ${unitName}`);
    } else {
        console.log(`✅ [PLACEHOLDERS] No practice questions placeholder needed for ${unitName} - actual content exists`);
    }
}



/**
 * Add action buttons only if they don't already exist (prevents duplicates)
 * @param {HTMLElement} container - The container to add buttons to
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 */
function addActionButtonsIfMissing(container, unitName) {
    // Check if action buttons already exist
    let hasAddContentSection = false;
    let hasConfirmButton = false;
    
    container.querySelectorAll('.add-content-section, .save-objectives').forEach(item => {
        if (item.classList.contains('add-content-section')) {
            hasAddContentSection = true;
        }
        if (item.textContent.includes('Confirm Course Materials')) {
            hasConfirmButton = true;
        }
    });
    
    // Add "Add Additional Material" button if it doesn't exist
    if (!hasAddContentSection) {
        const addContentSection = document.createElement('div');
        addContentSection.className = 'add-content-section';
        addContentSection.innerHTML = `
            <button class="add-content-btn additional-material" onclick="openUploadModal('${unitName}', 'additional')">
                <span class="btn-icon">➕</span>
                Add Additional Material
            </button>
        `;
        container.appendChild(addContentSection);
    }
    
    // Add "Confirm Course Materials" button if it doesn't exist
    if (!hasConfirmButton) {
        const confirmSection = document.createElement('div');
        confirmSection.className = 'save-objectives';
        confirmSection.innerHTML = `
            <button class="save-btn" onclick="confirmCourseMaterials('${unitName}')">Confirm Course Materials</button>
        `;
        container.appendChild(confirmSection);
    }
}



/**
 * Ensure action buttons exist for all units (fallback function)
 */
function ensureActionButtonsExist() {
    console.log('🔧 [FALLBACK] Ensuring action buttons exist for all units...');
    
    const accordionItems = document.querySelectorAll('.accordion-item');
    accordionItems.forEach(item => {
        // Use data-unit-name attribute for internal name (e.g., "Unit 1")
        const unitName = item.getAttribute('data-unit-name');
        if (!unitName) return;
        
        const courseMaterialsSection = item.querySelector('.course-materials-section .section-content');
        
        if (courseMaterialsSection) {
            // Check if action buttons already exist
            const hasActionButtons = courseMaterialsSection.querySelector('.add-content-section, .save-objectives');
            
            if (!hasActionButtons) {
                console.log(`🔧 [FALLBACK] Adding missing action buttons for ${unitName}`);
                addActionButtonsIfMissing(courseMaterialsSection, unitName);
            }
        }
    });
    
    console.log('✅ [FALLBACK] Action buttons check completed');
}

/**
 * Add cleanup button only if it doesn't already exist (prevents duplicates)
 * @param {HTMLElement} container - The container to add button to
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 * @param {string} courseId - The course ID
 */


/**
 * Clear all documents from a specific unit in the course structure
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 * @param {string} courseId - The course ID
 */




/**
 * Check if course materials are available for a specific week
 * This is a simplified check that looks for any non-placeholder file item.
 * @param {string} week - The week identifier (e.g., "Unit 1")
 * @returns {boolean} True if materials are detected, false otherwise.
 */
function checkCourseMaterialsAvailable(week) {
    if (!week) return false;

    // Find the accordion item using data-unit-name attribute (internal name like "Unit 1")
    const weekAccordionItem = document.querySelector(`.accordion-item[data-unit-name="${week}"]`);

    if (!weekAccordionItem) {
        console.warn(`Could not find accordion item for week: ${week}`);
        return false;
    }

    // Look for course materials in the section-content
    const courseMaterialsSection = weekAccordionItem.querySelector('.course-materials-section .section-content');
    if (!courseMaterialsSection) return false;

    // Check for any non-placeholder file items
    const fileItems = courseMaterialsSection.querySelectorAll('.file-item');
    console.log(`🔍 [MATERIALS_CHECK] Found ${fileItems.length} file items in ${week}`);
    
    for (const item of fileItems) {
        const status = item.querySelector('.status-text');
        if (status) {
            const statusText = status.textContent;
            // Consider both 'Processed' and 'Uploaded' as valid statuses
            if (statusText === 'Processed' || statusText === 'Uploaded' || statusText === 'uploaded') {
                console.log(`🔍 [MATERIALS_CHECK] Found valid material (${statusText}) in ${week}`);
                return true;
            }
        }
    }

    console.log(`🔍 [MATERIALS_CHECK] No processed materials found in ${week}`);
    return false;
}

/**
 * @param {Array} units - Array of units/lectures for the course
 */


document.addEventListener('DOMContentLoaded', async () => {
    console.log('📄 [DOCUMENTS] DOM fully loaded and parsed');
    
    // Wait for authentication to be ready
    await waitForAuth();
    
    // Check for onboarding completion first
    const instructorId = getCurrentInstructorId();
    if (!instructorId) {
        console.error('No instructor ID found.');
        // Optional: Redirect to login or show an error
        return;
    }

    // Initialize the main assessment system and load course structure from onboarding data
    // Only if we are on the dashboard
    const dashboardContainer = document.getElementById('dynamic-units-container') || document.getElementById('upload-drop-area');
    if (dashboardContainer) {
        await initializeAssessmentSystem();
        await loadOnboardingData();
    }

});
/**
 * Open the regenerate modal with current question content
 */
function openRegenerateModal() {
    const modal = document.getElementById('regenerate-modal');
    const currentQuestionDisplay = document.getElementById('current-question-display');
    const feedbackTextarea = document.getElementById('regenerate-feedback');
    
    if (!modal || !currentQuestionDisplay || !lastGeneratedContent) {
        console.error('Missing elements for regenerate modal');
        return;
    }
    
    // Clear previous feedback
    feedbackTextarea.value = '';
    
    // Display current question content
    displayCurrentQuestion(currentQuestionDisplay, lastGeneratedContent);
    
    // Show modal
    modal.classList.add('show');
    
    // Focus on textarea
    setTimeout(() => feedbackTextarea.focus(), 100);
}

/**
 * Close the regenerate modal
 */
function closeRegenerateModal() {
    const modal = document.getElementById('regenerate-modal');
    if (modal) {
        modal.classList.remove('show');
    }
}

/**
 * Display the current question in a readable format
 * @param {HTMLElement} container - The container element to display the question
 * @param {Object} questionContent - The question content object
 */
function displayCurrentQuestion(container, questionContent) {
    const questionType = document.getElementById('question-type').value;
    let html = '';
    
    // Question text
    html += `<div class="question-text">${questionContent.question || 'No question text'}</div>`;
    
    // Show options/answers based on type
    if (questionType === 'multiple-choice' && questionContent.options) {
        html += '<div class="question-options">';
        const options = questionContent.options;
        const correctAnswer = questionContent.answer;
        
        ['A', 'B', 'C', 'D'].forEach(letter => {
            if (options[letter]) {
                const isCorrect = letter === correctAnswer;
                html += `<div class="option ${isCorrect ? 'correct' : ''}">${letter}. ${options[letter]} ${isCorrect ? '(Correct)' : ''}</div>`;
            }
        });
        html += '</div>';
    } else if (questionType === 'true-false') {
        html += `<div class="question-answer">Correct Answer: ${questionContent.answer}</div>`;
    } else if (questionType === 'short-answer') {
        html += `<div class="question-answer">Expected Answer: ${questionContent.answer || 'No answer provided'}</div>`;
    }
    
    container.innerHTML = html;
}

/**
 * Submit regenerate request with feedback
 */
async function submitRegenerate() {
    const feedbackTextarea = document.getElementById('regenerate-feedback');
    const submitButton = document.getElementById('regenerate-submit-btn');
    const feedback = feedbackTextarea.value.trim();
    
    if (!feedback) {
        showNotification('Please provide feedback about what you\'d like to improve.', 'error');
        return;
    }
    
    // Show loading state
    const originalText = submitButton.innerHTML;
    submitButton.innerHTML = '⏳ Regenerating...';
    submitButton.disabled = true;
    
    try {
        // Get current form data
        const questionType = document.getElementById('question-type').value;
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        // Get learning objectives (same as original generation)
        const weekAccordionItem = Array.from(document.querySelectorAll('.accordion-item')).find(item => {
            const folderName = item.querySelector('.folder-name')?.textContent;
            return folderName === currentWeek;
        });

        const objectives = [];
        if (weekAccordionItem) {
            const objectivesList = weekAccordionItem.querySelector('.objectives-list');
            if (objectivesList) {
                objectivesList.querySelectorAll('.objective-text').forEach(obj => {
                    const text = obj.textContent.trim();
                    if (text) {
                        objectives.push(text);
                    }
                });
            }
        }
        
        // Call the regenerate API
        const response = await fetch(API_BASE_URL + '/api/questions/generate-ai', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: currentWeek,
                instructorId: instructorId,
                questionType: questionType,
                learningObjectives: objectives.length > 0 ? objectives : undefined,
                regenerate: true,
                feedback: feedback,
                previousQuestion: lastGeneratedContent
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ message: 'Unknown error' }));
            throw new Error(errorData.message || `Failed to regenerate question: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to regenerate question');
        }
        
        // Update the stored content
        lastGeneratedContent = result.data;
        
        // Populate form with new content
        populateFormWithAIContent(result.data);
        
        // Close modal
        closeRegenerateModal();
        
        // Show success notification
        showNotification('Question regenerated successfully based on your feedback!', 'success');
        
    } catch (error) {
        console.error('Error regenerating question:', error);
        showNotification(`Error regenerating question: ${error.message}`, 'error');
        
    } finally {
        // Restore button state
        submitButton.innerHTML = originalText;
        submitButton.disabled = false;
    }
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

/**
 * Update the published units summary text
 */
function updatePublishedSummary() {
    const summaryContainer = document.getElementById('published-units-summary');
    if (!summaryContainer) return;
    
    // Count total units and published units
    const unitSections = document.querySelectorAll('.accordion-item');
    const totalUnits = unitSections.length;
    
    let publishedCount = 0;
    unitSections.forEach(section => {
        const toggle = section.querySelector('.publish-toggle input');
        if (toggle && toggle.checked) {
            publishedCount++;
        }
    });
    
    // Update the text
    if (publishedCount === 0) {
        summaryContainer.innerHTML = `<strong style="color: #d9534f; font-size: 1.1em;">No units are currently published! Students cannot see any content. Please publish units to make them visible.</strong>`;
    } else {
        summaryContainer.textContent = `Currently, ${publishedCount} of the ${totalUnits} Units are Published.`;
    }
}

// Also update summary when a toggle is changed
document.addEventListener('change', (e) => {
    if (e.target.matches('.publish-toggle input')) {
        // Small delay to allow state to update
        setTimeout(updatePublishedSummary, 100);
    }
});

// ============================================
// Unit Renaming Functions
// ============================================

/**
 * Open the inline rename input for a unit
 * @param {string} unitName - Internal name of the unit (e.g., "Unit 1")
 */
function openRenameUnitInput(unitName) {
    const accordionItem = document.querySelector(`.accordion-item[data-unit-name="${unitName}"]`);
    if (!accordionItem) return;
    
    const folderName = accordionItem.querySelector('.folder-name');
    const renameBtn = accordionItem.querySelector('.unit-rename-btn');
    const editContainer = accordionItem.querySelector('.unit-rename-edit');
    const input = accordionItem.querySelector('.unit-rename-input');
    
    // Hide the folder name and pencil button, show the edit container
    if (folderName) folderName.style.display = 'none';
    if (renameBtn) renameBtn.style.display = 'none';
    if (editContainer) editContainer.style.display = 'flex';
    
    // Focus and select input
    if (input) {
        input.focus();
        input.select();
    }
    
    // Add Enter key handler
    if (input) {
        input.onkeydown = (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                saveUnitDisplayName(unitName);
            } else if (e.key === 'Escape') {
                e.preventDefault();
                cancelRenameUnit(unitName);
            }
        };
    }
}

/**
 * Save the unit display name
 * @param {string} unitName - Internal name of the unit (e.g., "Unit 1")
 */
async function saveUnitDisplayName(unitName) {
    const accordionItem = document.querySelector(`.accordion-item[data-unit-name="${unitName}"]`);
    if (!accordionItem) return;
    
    const input = accordionItem.querySelector('.unit-rename-input');
    const displayName = input ? input.value.trim() : '';
    
    try {
        const courseId = await getCurrentCourseId();
        const instructorId = getCurrentInstructorId();
        
        const response = await fetch(`/api/courses/${courseId}/units/${encodeURIComponent(unitName)}/rename`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ displayName, instructorId })
        });
        
        if (!response.ok) {
            throw new Error('Failed to rename unit');
        }
        
        const result = await response.json();
        
        // Update the folder name display
        const folderName = accordionItem.querySelector('.folder-name');
        const unitNum = unitName.match(/\d+/)?.[0] || '';
        const formattedName = displayName ? `${unitNum}. ${displayName}` : unitName;
        
        if (folderName) {
            folderName.textContent = formattedName;
        }
        
        showNotification(result.message || 'Unit renamed successfully', 'success');
        
    } catch (error) {
        console.error('Error renaming unit:', error);
        showNotification('Failed to rename unit: ' + error.message, 'error');
    }
    
    // Hide edit mode and restore normal display
    cancelRenameUnit(unitName);
}

/**
 * Cancel the rename operation and restore normal display
 * @param {string} unitName - Internal name of the unit (e.g., "Unit 1")
 */
function cancelRenameUnit(unitName) {
    const accordionItem = document.querySelector(`.accordion-item[data-unit-name="${unitName}"]`);
    if (!accordionItem) return;
    
    const folderName = accordionItem.querySelector('.folder-name');
    const renameBtn = accordionItem.querySelector('.unit-rename-btn');
    const editContainer = accordionItem.querySelector('.unit-rename-edit');
    
    // Show the folder name and pencil button, hide the edit container
    if (folderName) folderName.style.display = '';
    if (renameBtn) renameBtn.style.display = '';
    if (editContainer) editContainer.style.display = 'none';
}

// Make rename functions globally available
window.openRenameUnitInput = openRenameUnitInput;
window.saveUnitDisplayName = saveUnitDisplayName;
window.cancelRenameUnit = cancelRenameUnit;