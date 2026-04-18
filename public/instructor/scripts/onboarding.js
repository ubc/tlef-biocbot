/**
 * Onboarding Page JavaScript
 * Handles guided multi-step onboarding flow for instructors
 */

// Global state for onboarding
let onboardingState = {
    currentStep: 1,
    totalSteps: 3,
    currentSubstep: 'objectives',
    substeps: ['objectives', 'materials', 'questions'],
    courseData: {},
    uploadedFile: null,
    createdCourseId: null,
    isSubmitting: false, // Prevent multiple submissions
    existingCourseId: null // Store existing course ID if found
};

// Upload modal state
let uploadedFile = null;
let currentWeek = null;
let currentContentType = null;
let topicReviewResolve = null;
let canBypassOnboardingInstructorCourseCodes = false;

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
                <p class="topic-review-hint">Edit, add, or remove topics before saving this course-level list.</p>
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
        list.innerHTML = '<div class="topic-review-empty">No topics detected yet. Add topics manually for this course.</div>';
        return;
    }

    cleanTopics.forEach((topic) => addTopicReviewRow(topic));
}

function openTopicReviewModal(courseId, sourceName, existingTopics, suggestedTopics) {
    const modal = ensureTopicReviewModal();
    const mergedTopics = dedupeTopics([...(existingTopics || []), ...(suggestedTopics || [])]);
    const contextText = sourceName
        ? `Detected concepts after processing: ${sourceName}`
        : 'Detected concepts from the uploaded content.';

    modal.querySelector('#topic-review-context').textContent = contextText;
    modal.querySelector('#topic-review-new-input').value = '';
    populateTopicReviewRows(mergedTopics);

    modal.style.display = '';
    modal.classList.add('show');

    return new Promise((resolve) => {
        topicReviewResolve = resolve;
    });
}

// --- Inline Topic Review (inside upload modal) ---

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

    // Merge all topics for onboarding (existing + suggested)
    const mergedTopics = dedupeTopics([...(existingTopics || []), ...(suggestedTopics || [])]);

    // Store data for when Save is clicked
    pendingTopicReviewData = { courseId };

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
            ? `Detected concepts after processing: ${sourceName}`
            : 'Detected concepts from the uploaded content.';
    }

    // Populate topic rows
    const list = document.getElementById('upload-topic-review-list');
    if (list) {
        list.innerHTML = '';
        const cleanTopics = dedupeTopics(mergedTopics);
        if (cleanTopics.length === 0) {
            list.innerHTML = '<div class="topic-review-empty">No topics detected yet. Add topics manually for this course.</div>';
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

    const { courseId } = pendingTopicReviewData;
    const reviewedTopics = collectInlineTopicRows();

    try {
        const savedTopics = await saveCourseApprovedTopics(courseId, reviewedTopics);
        showNotification(`Saved ${savedTopics.length} approved course topic${savedTopics.length === 1 ? '' : 's'}.`, 'success');
    } catch (err) {
        console.error('Error saving topics:', err);
        showNotification('Could not save topics. Please try again.', 'error');
    }

    pendingTopicReviewData = null;
    closeUploadModal();
}

// --- End Inline Topic Review ---

document.addEventListener('DOMContentLoaded', async function() {
    // Initialize onboarding functionality
    initializeOnboarding();
    
    // Initialize guided substep functionality
    initializeGuidedSubsteps();
    
    // Wait for authentication to be ready before loading courses
    await waitForAuth();

    canBypassOnboardingInstructorCourseCodes = await checkCourseCodeBypassPermission();
    applyJoinCourseCodePermission();
    
    // Load available courses for course selection
    loadAvailableCourses();
});

async function checkCourseCodeBypassPermission() {
    try {
        const response = await fetch('/api/settings/can-delete-all', {
            credentials: 'include'
        });

        const result = await response.json();
        return !!(result.success && result.canDeleteAll);
    } catch (error) {
        console.error('Error checking onboarding instructor-code bypass permission:', error);
        return false;
    }
}

function applyJoinCourseCodePermission() {
    const codeHelp = document.getElementById('instructor-course-code-help');
    const codeGroup = document.getElementById('instructor-course-code-group');

    if (codeHelp) {
        codeHelp.textContent = canBypassOnboardingInstructorCourseCodes
            ? 'You have admin access, so no instructor code is required for you to join this course.'
            : 'Ask the course owner for the instructor course code.';
    }

    if (codeGroup && onboardingState.existingCourseId) {
        codeGroup.style.display = canBypassOnboardingInstructorCourseCodes ? 'none' : 'block';
    }

    if (canBypassOnboardingInstructorCourseCodes) {
        clearOnboardingJoinCourseCodeFeedback();
    }
}

/**
 * Check if onboarding is already complete for this instructor
 */
async function checkOnboardingStatus() {
    try {
        console.log('🔍 [ONBOARDING] Checking onboarding status...');
        
        // Check if there's a courseId in URL params (from redirect)
        const urlParams = new URLSearchParams(window.location.search);
        const courseId = urlParams.get('courseId');
        
        if (courseId) {
            console.log(`🔍 [ONBOARDING] Found courseId in URL params: ${courseId}`);
            // Check if this course has onboarding complete
            console.log(`📡 [MONGODB] Making API request to /api/onboarding/${courseId}`);
            const response = await authenticatedFetch(`/api/onboarding/${courseId}`);
            console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
            
            if (response.ok) {
                const courseData = await response.json();
                console.log('📡 [MONGODB] Course data retrieved:', courseData);
                if (courseData.data && courseData.data.isOnboardingComplete === true) {
                    console.log('✅ [ONBOARDING] Onboarding already complete for this course');
                    onboardingState.existingCourseId = courseId;
                    showOnboardingComplete();
                    return;
                } else {
                    // Course exists but onboarding is not complete - resume onboarding
                    console.log('⚠️ [ONBOARDING] Course exists but onboarding not complete, resuming...');
                    onboardingState.createdCourseId = courseId;
                    onboardingState.existingCourseId = courseId;
                    
                    // Check Unit 1 content to determine which step to resume at
                    const unit1 = courseData.data?.lectures?.find(lecture => lecture.name === 'Unit 1');
                    const hasObjectives = unit1?.learningObjectives && unit1.learningObjectives.length > 0;
                    const hasDocuments = unit1?.documents && unit1.documents.length > 0;
                    
                    if (!hasObjectives) {
                        console.log('📝 [ONBOARDING] Resuming at Step 3: Learning Objectives');
                        showOnboardingFlow();
                        showStep(3);
                        showSubstep('objectives');
                        return;
                    } else if (!hasDocuments) {
                        console.log('📁 [ONBOARDING] Resuming at Step 3: Course Materials');
                        showOnboardingFlow();
                        showStep(3);
                        showSubstep('materials');
                        return;
                    } else {
                        console.log('❓ [ONBOARDING] Resuming at Step 3: Assessment Questions');
                        showOnboardingFlow();
                        showStep(3);
                        showSubstep('questions');
                        return;
                    }
                }
            }
        }
        
        // Check if instructor has any completed courses
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        console.log(`🔍 [ONBOARDING] Checking for existing courses for instructor: ${instructorId}`);
        console.log(`📡 [MONGODB] Making API request to /api/onboarding/instructor/${instructorId}`);
        const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        
        if (response.ok) {
            const result = await response.json();
            console.log('📡 [MONGODB] Instructor courses data:', result);
            if (result.data && result.data.courses && result.data.courses.length > 0) {
                // Check if any course has onboarding complete
                const completedCourse = result.data.courses.find(course => course.isOnboardingComplete === true);
                if (completedCourse) {
                    console.log('✅ [ONBOARDING] Found completed course:', completedCourse);
                    // Store the course ID for potential redirect
                    onboardingState.existingCourseId = completedCourse.courseId;
                    showOnboardingComplete();
                    return;
                }
                
                // Check if there's an incomplete course (created but onboarding not finished)
                const incompleteCourse = result.data.courses.find(course => 
                    course.isOnboardingComplete === false || !course.isOnboardingComplete
                );
                
                if (incompleteCourse) {
                    console.log('⚠️ [ONBOARDING] Found incomplete course, resuming onboarding:', incompleteCourse.courseId);
                    // Store the course ID and resume onboarding
                    onboardingState.createdCourseId = incompleteCourse.courseId;
                    onboardingState.existingCourseId = incompleteCourse.courseId;
                    
                    // Check if Unit 1 has the required content to determine which step to resume at
                    const unit1 = incompleteCourse.lectures?.find(lecture => lecture.name === 'Unit 1');
                    const hasObjectives = unit1?.learningObjectives && unit1.learningObjectives.length > 0;
                    const hasDocuments = unit1?.documents && unit1.documents.length > 0;
                    
                    if (!hasObjectives) {
                        // Resume at Step 3, substep 1 (Learning Objectives)
                        console.log('📝 [ONBOARDING] Resuming at Step 3: Learning Objectives');
                        showOnboardingFlow();
                        showStep(3);
                        showSubstep('objectives');
                        return;
                    } else if (!hasDocuments) {
                        // Resume at Step 3, substep 2 (Course Materials)
                        console.log('📁 [ONBOARDING] Resuming at Step 3: Course Materials');
                        showOnboardingFlow();
                        showStep(3);
                        showSubstep('materials');
                        return;
                    } else {
                        // Resume at Step 3, substep 3 (Assessment Questions)
                        console.log('❓ [ONBOARDING] Resuming at Step 3: Assessment Questions');
                        showOnboardingFlow();
                        showStep(3);
                        showSubstep('questions');
                        return;
                    }
                }
            }
        }
        
        console.log('🔍 [ONBOARDING] No courses found, showing normal onboarding flow');
        // If we get here, onboarding is not complete, show normal flow
        showOnboardingFlow();
        
    } catch (error) {
        console.error('❌ [ONBOARDING] Error checking onboarding status:', error);
        // If there's an error, show normal onboarding flow
        showOnboardingFlow();
    }
}

/**
 * Show onboarding complete message
 */
function showOnboardingComplete() {
    // Hide all onboarding steps
    document.querySelectorAll('.onboarding-step').forEach(step => {
        step.style.display = 'none';
    });
    
    // Hide progress bar
    document.querySelector('.onboarding-progress').style.display = 'none';
    
    // Show completion message
    document.getElementById('onboarding-complete').style.display = 'block';
    
    // Update the course upload link to include the existing course ID
    if (onboardingState.existingCourseId) {
        const courseUploadLink = document.querySelector('#onboarding-complete .btn-primary');
        if (courseUploadLink) {
            courseUploadLink.href = `/instructor/documents?courseId=${onboardingState.existingCourseId}`;
        }
    }
    
    // Auto-redirect after 5 seconds to prevent users from staying on onboarding
    setTimeout(() => {
        if (onboardingState.existingCourseId) {
            window.location.href = `/instructor/documents?courseId=${onboardingState.existingCourseId}`;
        } else {
            window.location.href = '/instructor/documents';
        }
    }, 5000);
}

/**
 * Show normal onboarding flow
 */
function showOnboardingFlow() {
    // Hide completion message
    document.getElementById('onboarding-complete').style.display = 'none';
    
    // Show progress bar
    document.querySelector('.onboarding-progress').style.display = 'block';
    
    // Show first step
    showStep(1);
}

/**
 * Initialize all onboarding functionality
 */
function initializeOnboarding() {

    
    // Initialize form handlers
    initializeFormHandlers();
    
    // Initialize file upload handlers
    initializeFileUpload();
    
    // Initialize progress bar
    updateProgressBar();
    
    // Show first step (this will be overridden if onboarding is complete)
    showStep(1);
    
    // Add debugging for learning objectives
    setTimeout(() => {
        const addButton = document.querySelector('.add-objective-btn');
        if (addButton) {
            
            // Remove any existing onclick to avoid conflicts
            addButton.removeAttribute('onclick');
            
            addButton.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                addObjectiveForUnit('Unit 1');
            });
            
        } else {
            // Add objective button not found
        }
    }, 1000); // Wait a bit for DOM to be ready
}

/**
 * Initialize guided substep functionality
 */
function initializeGuidedSubsteps() {
    // Initialize progress card click handlers
    const progressCards = document.querySelectorAll('.progress-card');
    progressCards.forEach(card => {
        card.addEventListener('click', () => {
            const substep = card.dataset.substep;
            if (substep) {
                showSubstep(substep);
            }
        });
    });
    
    // Add click outside modal to close functionality
    document.addEventListener('click', (e) => {
        const uploadModal = document.getElementById('upload-modal');
        const questionModal = document.getElementById('question-modal');
        const questionLearningObjectiveModal = document.getElementById('question-learning-objective-modal');
        const autoLinkConfirmationModal = document.getElementById('auto-link-confirmation-modal');
        
        // Close upload modal if clicking outside
        if (uploadModal && uploadModal.classList.contains('show') && e.target === uploadModal) {
            closeUploadModal();
        }

        if (questionModal && questionModal.classList.contains('show') && e.target === questionModal) {
            closeQuestionModal();
        }

        if (questionLearningObjectiveModal && questionLearningObjectiveModal.classList.contains('show') && e.target === questionLearningObjectiveModal) {
            closeQuestionLearningObjectiveModal();
        }

        if (autoLinkConfirmationModal && autoLinkConfirmationModal.classList.contains('show') && e.target === autoLinkConfirmationModal) {
            closeAutoLinkConfirmationModal();
        }
    });
}

/**
 * Initialize form event handlers
 */
function initializeFormHandlers() {
    // Course selection handler
    const courseSelect = document.getElementById('course-select');
    if (courseSelect) {
        courseSelect.addEventListener('change', handleCourseSelection);
    }
    
    // Custom course name handler
    const customCourseSection = document.getElementById('custom-course-section');
    const customCourseName = document.getElementById('custom-course-name');
    if (customCourseName) {
        customCourseName.addEventListener('input', handleCustomCourseInput);
    }

    const instructorCourseCode = document.getElementById('instructor-course-code');
    if (instructorCourseCode) {
        instructorCourseCode.addEventListener('input', clearOnboardingJoinCourseCodeFeedback);
    }
    
    // Course setup form handler
    const courseSetupForm = document.getElementById('course-setup-form');
    if (courseSetupForm) {
        courseSetupForm.addEventListener('submit', handleCourseSetup);
    }
}

/**
 * Initialize file upload functionality
 */
function initializeFileUpload() {
    const fileInput = document.getElementById('file-input');
    
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }
}

/**
 * Handle course selection change
 */
function handleCourseSelection(event) {
    const courseSelect = event.target;
    const customCourseSection = document.getElementById('custom-course-section');
    const courseStructureSection = document.getElementById('course-structure-section');
    const joinCourseSection = document.getElementById('join-course-section');
    const continueBtn = document.getElementById('continue-btn');
    const joinCourseBtn = document.getElementById('join-course-btn');
    const codeGroup = document.getElementById('instructor-course-code-group');
    const codeInput = document.getElementById('instructor-course-code');
    clearOnboardingJoinCourseCodeFeedback();
    
    if (courseSelect.value === 'custom') {
        // Show custom course input and course structure
        customCourseSection.style.display = 'block';
        courseStructureSection.style.display = 'block';
        joinCourseSection.style.display = 'none';
        continueBtn.style.display = 'inline-block';
        joinCourseBtn.style.display = 'none';
        
        // Clear course data
        onboardingState.courseData.course = null;
        onboardingState.existingCourseId = null;
        if (codeGroup) codeGroup.style.display = 'none';
        if (codeInput) codeInput.value = '';
    } else if (courseSelect.value === '') {
        // No course selected
        customCourseSection.style.display = 'none';
        courseStructureSection.style.display = 'block';
        joinCourseSection.style.display = 'none';
        continueBtn.style.display = 'inline-block';
        joinCourseBtn.style.display = 'none';
        
        // Clear course data
        onboardingState.courseData.course = null;
        onboardingState.existingCourseId = null;
        if (codeGroup) codeGroup.style.display = 'none';
        if (codeInput) codeInput.value = '';
    } else {
        // Existing course selected
        customCourseSection.style.display = 'none';
        courseStructureSection.style.display = 'none';
        joinCourseSection.style.display = 'block';
        continueBtn.style.display = 'none';
        joinCourseBtn.style.display = 'inline-block';
        if (codeGroup) {
            codeGroup.style.display = canBypassOnboardingInstructorCourseCodes ? 'none' : 'block';
        }
        if (codeInput) codeInput.value = '';
        
        // Store course data and populate course details
        onboardingState.courseData.course = courseSelect.value;
        populateSelectedCourseDetails(courseSelect.value);
    }
}

/**
 * Handle custom course name input
 */
function handleCustomCourseInput(event) {
    onboardingState.courseData.course = event.target.value;
}

/**
 * Populate selected course details for joining
 */
function populateSelectedCourseDetails(courseId) {
    const courseDetailsContainer = document.getElementById('selected-course-details');
    
    // Find the course data from the available courses
    const courseSelect = document.getElementById('course-select');
    const selectedOption = courseSelect.querySelector(`option[value="${courseId}"]`);
    
    if (selectedOption) {
        const courseName = selectedOption.textContent;
        courseDetailsContainer.innerHTML = `
            <div class="course-info">
                <h4>${courseName}</h4>
                <p><strong>Course ID:</strong> ${courseId}</p>
                <p>${canBypassOnboardingInstructorCourseCodes
                    ? 'You have admin access, so you can join this course without entering an instructor code.'
                    : 'Enter the instructor course code to join this course.'}</p>
            </div>
        `;
        
        // Store the course ID for joining
        onboardingState.existingCourseId = courseId;
    }
}

function animateOnboardingJoinCourseCodeError(field) {
    if (!field) {
        return;
    }

    field.classList.remove('field-error-shake');
    void field.offsetWidth;
    field.classList.add('field-error-shake');
}

function setOnboardingJoinCourseCodeFeedback(message) {
    const codeInput = document.getElementById('instructor-course-code');
    const errorElement = document.getElementById('instructor-course-code-error');

    if (codeInput) {
        codeInput.classList.add('input-error');
        codeInput.setAttribute('aria-invalid', 'true');
        animateOnboardingJoinCourseCodeError(codeInput);
        codeInput.focus();
    }

    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
}

function clearOnboardingJoinCourseCodeFeedback() {
    const codeInput = document.getElementById('instructor-course-code');
    const errorElement = document.getElementById('instructor-course-code-error');

    if (codeInput) {
        codeInput.classList.remove('input-error', 'field-error-shake');
        codeInput.removeAttribute('aria-invalid');
    }

    if (errorElement) {
        errorElement.textContent = '';
        errorElement.style.display = 'none';
    }
}

/**
 * Join an existing course
 */
async function joinExistingCourse() {
    if (!onboardingState.existingCourseId) {
        showNotification('No course selected to join.', 'error');
        return;
    }

    const codeInput = document.getElementById('instructor-course-code');
    const code = codeInput ? codeInput.value.trim().toUpperCase() : '';
    if (!canBypassOnboardingInstructorCourseCodes && !code) {
        setOnboardingJoinCourseCodeFeedback('Instructor course code is required to join this course.');
        return;
    }

    clearOnboardingJoinCourseCodeFeedback();
    
    try {
        console.log(`🚀 [ONBOARDING] Joining existing course: ${onboardingState.existingCourseId}`);
        
        // Show loading state
        const joinBtn = document.getElementById('join-course-btn');
        const originalText = joinBtn.textContent;
        joinBtn.textContent = 'Joining Course...';
        joinBtn.disabled = true;
        
        // Call the join course API
        const response = await fetch(`/api/courses/${onboardingState.existingCourseId}/instructors`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                instructorId: getCurrentInstructorId(),
                code
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to join course');
        }
        
        const result = await response.json();
        console.log('✅ [ONBOARDING] Successfully joined course:', result);
        
        // Mark instructor's onboarding as complete since they joined an existing course
        await markInstructorOnboardingComplete(onboardingState.existingCourseId);
        
        // Show success message
        showNotification('Successfully joined the course!', 'success');
        
        // Redirect to the course page after a short delay
        setTimeout(() => {
            window.location.href = `/instructor/documents?courseId=${onboardingState.existingCourseId}`;
        }, 2000);
        
    } catch (error) {
        console.error('❌ [ONBOARDING] Error joining course:', error);
        if (codeInput && /course code|required|invalid/i.test(error.message)) {
            setOnboardingJoinCourseCodeFeedback(error.message);
        } else {
            showNotification(`Error joining course: ${error.message}`, 'error');
        }
        
        // Reset button state
        const joinBtn = document.getElementById('join-course-btn');
        joinBtn.textContent = 'Join Course';
        joinBtn.disabled = false;
    }
}

/**
 * Handle course setup form submission
 */
async function handleCourseSetup(event) {
    event.preventDefault();
    
    // Prevent multiple submissions
    if (onboardingState.isSubmitting) {
        return;
    }
    
    const form = event.target;
    const submitButton = form.querySelector('button[type="submit"]');
    
    // Validate form
    if (!validateCourseSetup()) {
        return;
    }
    
    // Collect form data
    const formData = new FormData(form);
    const weeks = parseInt(formData.get('weeks'));
    const lecturesPerWeek = parseInt(formData.get('lecturesPerWeek'));
    
    onboardingState.courseData = {
        course: formData.get('course') === 'custom' ? 
            document.getElementById('custom-course-name').value : 
            formData.get('course'),
        weeks: weeks,
        lecturesPerWeek: lecturesPerWeek,
        totalUnits: weeks * lecturesPerWeek // Calculate total units
    };
    

    
    // Set submitting flag and disable submit button
    onboardingState.isSubmitting = true;
    submitButton.disabled = true;
    submitButton.textContent = 'Creating course...';
    
    try {
        // Only check for existing courses if not creating a custom course
        const courseSelect = document.getElementById('course-select');
        const isCustomCourse = courseSelect && courseSelect.value === 'custom';
        
        if (!isCustomCourse) {
            // Check if course already exists (either for this instructor or globally)
            const existingCourse = await checkExistingCourse();
            if (existingCourse) {
                // If course exists, set the existing course ID and join it
                onboardingState.existingCourseId = existingCourse.courseId;
                onboardingState.createdCourseId = existingCourse.courseId;
                await joinExistingCourse();
                return;
            }
        } else {
            // For custom courses, check if instructor already has an incomplete course
            // If so, use that course instead of creating a new one
            const instructorId = getCurrentInstructorId();
            if (instructorId) {
                const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);
                if (response.ok) {
                    const result = await response.json();
                    if (result.data && result.data.courses && result.data.courses.length > 0) {
                        // Check for incomplete course (isOnboardingComplete is false)
                        const incompleteCourse = result.data.courses.find(course => 
                            !course.isOnboardingComplete || course.isOnboardingComplete === false
                        );
                        if (incompleteCourse) {
                            // Use the existing incomplete course
                            onboardingState.createdCourseId = incompleteCourse.courseId;
                            onboardingState.existingCourseId = incompleteCourse.courseId;
                            console.log('Using existing incomplete course:', incompleteCourse.courseId);
                            // Continue to next step with existing course
                            nextStep();
                            return;
                        }
                    }
                }
            }
        }
        
        // Create course and save to database
        const response = await createCourse(onboardingState.courseData);
        onboardingState.createdCourseId = response.courseId;
        
        // Move to next step (guided unit setup)
        nextStep();
        
    } catch (error) {
        console.error('Error creating course:', error);
        showNotification('Error creating course. Please try again.', 'error');
    } finally {
        // Reset submitting flag and re-enable submit button
        onboardingState.isSubmitting = false;
        submitButton.disabled = false;
        submitButton.textContent = 'Continue to Unit Setup';
    }
}

/**
 * Check if course already exists (either for this instructor or globally by name)
 */
async function checkExistingCourse() {
    try {
        const courseSelect = document.getElementById('course-select');
        const selectedCourseId = courseSelect ? courseSelect.value : '';
        if (selectedCourseId && selectedCourseId !== 'custom') {
            const selectedOption = courseSelect.options[courseSelect.selectedIndex];
            return {
                courseId: selectedCourseId,
                courseName: selectedOption ? selectedOption.textContent : selectedCourseId
            };
        }

        const courseName = onboardingState.courseData.course;
        if (!courseName) {
            return null;
        }

        const instructorId = getCurrentInstructorId();
        if (instructorId) {
            const response = await authenticatedFetch(`/api/onboarding/instructor/${instructorId}`);

            if (response.ok) {
                const result = await response.json();
                if (result.data && result.data.courses) {
                    const existingInstructorCourse = result.data.courses.find(course =>
                        course.courseName && course.courseName.toLowerCase() === courseName.toLowerCase()
                    );

                    if (existingInstructorCourse) {
                        return existingInstructorCourse;
                    }
                }
            }
        }

        const joinableCoursesResponse = await authenticatedFetch('/api/courses/available/joinable');
        if (joinableCoursesResponse.ok) {
            const joinableCoursesResult = await joinableCoursesResponse.json();
            if (joinableCoursesResult.success && joinableCoursesResult.data) {
                const existingCourse = joinableCoursesResult.data.find(course =>
                    course.courseName.toLowerCase() === courseName.toLowerCase()
                );
                if (existingCourse) {
                    return existingCourse;
                }
            }
        }
        
        return null;
    } catch (error) {
        console.error('Error checking existing course:', error);
        return null;
    }
}

// Removed duplicate joinExistingCourse function - using the one without parameters

/**
 * Mark instructor's onboarding as complete
 */
async function markInstructorOnboardingComplete(courseId) {
    try {
        console.log(`🔧 [ONBOARDING] Marking instructor onboarding as complete for course: ${courseId}`);
        
        const response = await authenticatedFetch('/api/onboarding/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                instructorId: getCurrentInstructorId()
            })
        });
        
        if (response.ok) {
            console.log('✅ [ONBOARDING] Successfully marked onboarding as complete');
        } else {
            console.warn('⚠️ [ONBOARDING] Failed to mark onboarding as complete, but continuing...');
        }
    } catch (error) {
        console.error('❌ [ONBOARDING] Error marking onboarding as complete:', error);
        // Don't throw error here as it's not critical for the join process
    }
}

/**
 * Get detailed course information
 */
async function getCourseDetails(courseId) {
    try {
        const response = await authenticatedFetch(`/api/onboarding/${courseId}`);
        if (response.ok) {
            const result = await response.json();
            return result.data;
        }
        return null;
    } catch (error) {
        console.error('Error getting course details:', error);
        return null;
    }
}

/**
 * Create course and save onboarding data to database
 */
async function createCourse(courseData) {
    try {
        console.log('🚀 [ONBOARDING] Starting course creation process...');
        console.log('📋 [ONBOARDING] Course data:', courseData);
        
        // Generate a course ID based on the course name
        let courseId = courseData.course.replace(/\s+/g, '-').toUpperCase();
        
        // Ensure the course ID is valid (no special characters, reasonable length)
        courseId = courseId.replace(/[^A-Z0-9-]/g, '');
        if (courseId.length > 20) {
            courseId = courseId.substring(0, 20);
        }
        
        // Add timestamp to ensure uniqueness
        courseId = `${courseId}-${Date.now()}`;
        console.log(`🆔 [ONBOARDING] Generated course ID: ${courseId}`);
        
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        console.log(`👤 [ONBOARDING] Using instructor ID: ${instructorId}`);
        
        // Get learning objectives from the UI
        const learningObjectives = getLearningObjectivesFromUI();
        console.log('📚 [ONBOARDING] Learning objectives from UI:', learningObjectives);
        
        // If no objectives found, show error
        if (learningObjectives.length === 0) {            
            console.warn('⚠️ [ONBOARDING] No learning objectives found in UI');
            // Try to find objectives manually
            const objectivesList = document.getElementById('objectives-list');
            if (objectivesList) {
                const items = objectivesList.querySelectorAll('.objective-display-item');
                items.forEach((item, index) => {
                    const text = item.querySelector('.objective-text')?.textContent;
                });
            }
        }
        
        // Prepare onboarding data with unit structure
        const onboardingData = {
            courseId: courseId,
            courseName: courseData.course,
            instructorId: instructorId,
            courseDescription: '',
            learningOutcomes: learningObjectives,
            assessmentCriteria: '',
            courseMaterials: [],
            unitFiles: {},
            courseStructure: {
                weeks: courseData.weeks,
                lecturesPerWeek: courseData.lecturesPerWeek,
                totalUnits: courseData.totalUnits
            }
        };
        
        console.log('📋 [ONBOARDING] Prepared onboarding data:', onboardingData);
        
        // Initialize unit structure with Unit 1 learning objectives
        for (let i = 1; i <= courseData.totalUnits; i++) {
            const unitName = `Unit ${i}`;
            onboardingData.unitFiles[unitName] = [];
            
            // Add learning objectives to Unit 1
            if (i === 1 && learningObjectives.length > 0) {
                onboardingData.lectures = [{
                    name: unitName,
                    learningObjectives: learningObjectives,
                    isPublished: false,
                    passThreshold: 2,
                    createdAt: new Date(),
                    updatedAt: new Date()
                }];
            }
        }
        
        console.log('📋 [ONBOARDING] Final onboarding data with unit structure:', onboardingData);
        console.log(`📡 [MONGODB] Making API request to /api/onboarding (POST)`);
        console.log(`📡 [MONGODB] Request body size: ${JSON.stringify(onboardingData).length} characters`);
        
        const response = await authenticatedFetch('/api/onboarding', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(onboardingData)
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to create course: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Course created successfully:', result);
        
        // After successfully creating the course, save Unit 1 data using the same APIs
        // that the course upload functionality expects
        // Note: Learning objectives will be saved together when onboarding is completed
        // to avoid overwriting issues
        
        return {
            courseId: courseId,
            name: courseData.course,
            weeks: courseData.weeks,
            lecturesPerWeek: courseData.lecturesPerWeek,
            createdAt: new Date().toISOString(),
            status: 'active'
        };
        
    } catch (error) {
        console.error('❌ [ONBOARDING] Error creating course:', error);
        throw error;
    }
}

/**
 * Save Unit 1 learning objectives using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {Array} objectives - Array of learning objectives
 * @param {string} instructorId - The instructor ID
 */
async function saveUnit1LearningObjectives(courseId, lectureName, objectives, instructorId) {
    try {        
        const requestBody = {
            lectureName: lectureName,
            objectives: objectives,
            instructorId: instructorId,
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
            throw new Error(`Failed to save learning objectives: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        
    } catch (error) {
        // Don't throw here - we want the course creation to succeed even if this fails
        showNotification('Warning: Learning objectives saved to course but not to learning objectives API. They may not appear in the course upload interface.', 'warning');
    }
}

/**
 * Get learning objectives from the UI
 * @returns {Array} Array of learning objectives
 */
function getLearningObjectivesFromUI() {
    const objectivesList = document.getElementById('objectives-list');
    if (!objectivesList) {
        return [];
    }
    
    const objectives = [];
    const objectiveItems = objectivesList.querySelectorAll('.objective-display-item');    
    objectiveItems.forEach((item, index) => {
        const objectiveText = item.querySelector('.objective-text');
        if (objectiveText && objectiveText.textContent.trim()) {
            const text = objectiveText.textContent.trim();
            objectives.push(text);
            console.log(`Objective ${index + 1}:`, text);
        }
    });
    return objectives;
}

/**
 * Add a new learning objective for a unit (used in onboarding)
 * @param {string} unitName - The unit name (e.g., 'Unit 1')
 */
async function addObjectiveForUnit(unitName) {
    console.log('addObjectiveForUnit called with:', unitName);
    
    const inputField = document.getElementById('objective-input');
    const objectivesList = document.getElementById('objectives-list');
    
    console.log('Input field found:', !!inputField);
    console.log('Objectives list found:', !!objectivesList);
    
    if (!inputField || !objectivesList) {
        console.error('Could not find objective input or list elements');
        showNotification('Error: Could not find objective elements', 'error');
        return;
    }
    
    const objectiveText = inputField.value.trim();
    console.log('Objective text:', objectiveText);
    
    if (!objectiveText) {
        showNotification('Please enter a learning objective.', 'error');
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
    
    // Don't save immediately - just add to UI
    // The objectives will be saved together when onboarding is completed
    console.log('Objective added to UI:', objectiveText);
    console.log('Total objectives now:', objectivesList.querySelectorAll('.objective-display-item').length);
    showNotification('Learning objective added successfully!', 'success');
}

/**
 * Remove a learning objective (used in onboarding)
 * @param {HTMLElement} button - The remove button element
 */
async function removeObjective(button) {
    const objectiveItem = button.closest('.objective-display-item');
    const objectiveText = objectiveItem.querySelector('.objective-text').textContent.trim();
    
    // Remove from UI
    objectiveItem.remove();
    
    // Don't remove from API immediately - the final state will be saved
    // when onboarding is completed
    console.log('Learning objective removed from UI:', objectiveText);
    console.log('Removal will be reflected when onboarding is completed');
    
    showNotification('Learning objective removed.', 'info');
}

/**
 * Validate course setup form
 */
function validateCourseSetup() {
    const courseSelect = document.getElementById('course-select');
    const weeksInput = document.getElementById('weeks-count');
    const lecturesInput = document.getElementById('lectures-per-week');
    
    let isValid = true;
    
    // Validate course selection
    if (!courseSelect.value) {
        showFieldError(courseSelect, 'Please select a course');
        isValid = false;
    }
    
    // Validate custom course name if selected
    if (courseSelect.value === 'custom') {
        const customName = document.getElementById('custom-course-name').value.trim();
        if (!customName) {
            showFieldError(document.getElementById('custom-course-name'), 'Please enter a course name');
            isValid = false;
        }
    }
    
    // Only validate course structure fields if creating a new course (custom or no existing course)
    if (courseSelect.value === 'custom' || courseSelect.value === '') {
        // Validate weeks input
        const weeks = parseInt(weeksInput.value);
        if (!weeks || weeks < 1 || weeks > 20) {
            showFieldError(weeksInput, 'Please enter a valid number of weeks (1-20)');
            isValid = false;
        }
        
        // Validate lectures per week input
        const lectures = parseInt(lecturesInput.value);
        if (!lectures || lectures < 1 || lectures > 5) {
            showFieldError(lecturesInput, 'Please enter a valid number of lectures per week (1-5)');
            isValid = false;
        }
    }
    
    return isValid;
}

/**
 * Handle file selection
 */
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        processSelectedFile(file);
    }
}

/**
 * Process selected file
 */
function processSelectedFile(file) {
    // Validate file type
    const allowedTypes = ['.pdf', '.docx', '.txt', '.ppt', '.pptx'];
    const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
        showErrorMessage('Please select a valid file type (PDF, DOCX, TXT, PPT, PPTX)');
        return;
    }
    
    // Store file info
    uploadedFile = file;
    
    // Update UI
    const fileInfo = document.getElementById('file-info');
    const fileName = document.getElementById('file-name');
    const fileSize = document.getElementById('file-size');
    
    if (fileInfo && fileName && fileSize) {
        fileName.textContent = file.name;
        fileSize.textContent = formatFileSize(file.size);
        fileInfo.style.display = 'flex';
    }
    
    showNotification(`File "${file.name}" selected successfully`, 'success');
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Navigate to next step
 */
function nextStep() {
    if (onboardingState.currentStep < onboardingState.totalSteps) {
        onboardingState.currentStep++;
        showStep(onboardingState.currentStep);
        updateProgressBar();
    }
}

function previousStep() {
    if (onboardingState.currentStep > 1) {
        onboardingState.currentStep--;
        showStep(onboardingState.currentStep);
        updateProgressBar();
    }
}

/**
 * Show specific step
 */
function showStep(stepNumber) {
    // Hide all steps
    const steps = document.querySelectorAll('.onboarding-step');
    steps.forEach(step => step.classList.remove('active'));
    
    // Show current step
    const currentStep = document.getElementById(`step-${stepNumber}`);
    if (currentStep) {
        currentStep.classList.add('active');
    }
    
    // Update step indicators
    const indicators = document.querySelectorAll('.step-indicator');
    indicators.forEach((indicator, index) => {
        indicator.classList.remove('active', 'completed');
        if (index + 1 < stepNumber) {
            indicator.classList.add('completed');
        } else if (index + 1 === stepNumber) {
            indicator.classList.add('active');
        }
    });
    
    // If we're on step 3, show the first substep
    if (stepNumber === 3) {
        showSubstep('objectives');
    }
}

/**
 * Show specific substep
 */
function showSubstep(substepName) {
    // Hide all substeps
    const substeps = document.querySelectorAll('.guided-substep');
    substeps.forEach(substep => substep.classList.remove('active'));
    
    // Show current substep
    const currentSubstep = document.getElementById(`substep-${substepName}`);
    if (currentSubstep) {
        currentSubstep.classList.add('active');
    }
    
    // Update progress cards
    const progressCards = document.querySelectorAll('.progress-card');
    progressCards.forEach(card => {
        card.classList.remove('active', 'completed');
        const cardSubstep = card.dataset.substep;
        const substepIndex = onboardingState.substeps.indexOf(cardSubstep);
        const currentIndex = onboardingState.substeps.indexOf(substepName);
        
        if (substepIndex < currentIndex) {
            card.classList.add('completed');
        } else if (substepIndex === currentIndex) {
            card.classList.add('active');
        }
    });
    
    // Update current substep in state
    onboardingState.currentSubstep = substepName;
}

/**
 * Navigate to next substep
 */
function nextSubstep(substepName) {
    showSubstep(substepName);
}

/**
 * Navigate to previous substep
 */
function previousSubstep(substepName) {
    showSubstep(substepName);
}

/**
 * Update progress bar
 */
function updateProgressBar() {
    const progressFill = document.getElementById('progress-fill');
    if (progressFill) {
        const progress = (onboardingState.currentStep / onboardingState.totalSteps) * 100;
        progressFill.style.width = `${progress}%`;
    }
}

/**
 * Add learning objective
 */
async function addObjective() {
    const input = document.getElementById('objective-input');
    const objectiveText = input.value.trim();
    
    if (!objectiveText) {
        showNotification('Please enter a learning objective.', 'error');
        return;
    }
    
    const objectivesList = document.getElementById('objectives-list');
    
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
    input.value = '';
    input.focus();
    
    // Don't save immediately - just add to UI
    // The objectives will be saved together when onboarding is completed
    showNotification('Learning objective added successfully!', 'success');
}

/**
 * Remove learning objective
 */
function removeObjective(button) {
    const objectiveItem = button.closest('.objective-display-item');
    objectiveItem.remove();
    showNotification('Learning objective removed.', 'info');
}

/**
 * Add probing question
 */
async function addQuestion() {
    console.log('=== ADDING PROBING QUESTION ===');
    const input = document.getElementById('question-input');
    const questionText = input.value.trim();
    
    console.log('Question input value:', questionText);
    console.log('Question input element found:', !!input);
    
    if (!questionText) {
        showNotification('Please enter a probing question.', 'error');
        return;
    }
    
    const questionsList = document.getElementById('assessment-questions-onboarding');
    console.log('Questions list element found:', !!questionsList);
    console.log('Questions list ID:', questionsList?.id);
    
    if (!questionsList) {
        console.error('Questions list not found!');
        showNotification('Error: Questions list not found', 'error');
        return;
    }
    
    // Create new question display item
    const questionItem = document.createElement('div');
    questionItem.className = 'objective-display-item';
    questionItem.innerHTML = `
        <span class="objective-text">${questionText}</span>
        <button class="remove-objective" onclick="removeQuestion(this)">×</button>
    `;
    
    console.log('Created question item:', questionItem);
    console.log('Question item HTML:', questionItem.innerHTML);
    
    // Add to the list
    questionsList.appendChild(questionItem);
    
    console.log('Question added to DOM. Total questions now:', questionsList.querySelectorAll('.objective-display-item').length);
    console.log('All questions in DOM:', Array.from(questionsList.querySelectorAll('.objective-display-item .objective-text')).map(q => q.textContent.trim()));
    
    // Clear the input field
    input.value = '';
    input.focus();
    
    // Don't save immediately - just add to UI
    // The questions will be saved together when onboarding is completed
    console.log('Probing question added to UI:', questionText);
    showNotification('Probing question added successfully!', 'success');
}

/**
 * Remove probing question
 */
async function removeQuestion(button) {
    console.log('=== REMOVING PROBING QUESTION ===');
    const questionItem = button.closest('.objective-display-item');
    const questionText = questionItem.querySelector('.objective-text').textContent.trim();
    
    console.log('Removing question:', questionText);
    console.log('Question item found:', !!questionItem);
    
    // Remove from UI
    questionItem.remove();
    
    const questionsList = document.getElementById('assessment-questions-onboarding');
    console.log('Question removed from DOM. Total questions now:', questionsList?.querySelectorAll('.objective-display-item').length || 0);
    console.log('Remaining questions:', Array.from(questionsList?.querySelectorAll('.objective-display-item .objective-text') || []).map(q => q.textContent.trim()));
    
    // Don't remove from API immediately - the final state will be saved
    // when onboarding is completed
    console.log('Probing question removed from UI:', questionText);
    console.log('Removal will be reflected when onboarding is completed');
    
    showNotification('Probing question removed.', 'info');
}



// Assessment Questions Functionality
// Global variables for assessment questions
let assessmentQuestions = {
    'Onboarding': []
};
let editingQuestionObjectiveContext = null;
let autoLinkConfirmationContext = null;

function getOnboardingLearningObjectives() {
    const objectives = [];
    document.querySelectorAll('#objectives-list .objective-text').forEach(item => {
        const text = item.textContent.trim();
        if (text) {
            objectives.push(text);
        }
    });

    return objectives;
}

function populateLearningObjectiveOptions(selectElement, objectives = [], selectedObjective = '') {
    if (!selectElement) {
        return;
    }

    const normalizedSelected = (selectedObjective || '').trim();
    const uniqueObjectives = [...new Set(objectives.map(objective => objective.trim()).filter(Boolean))];

    selectElement.innerHTML = '<option value="">Leave unassigned</option>';

    uniqueObjectives.forEach(objective => {
        const option = document.createElement('option');
        option.value = objective;
        option.textContent = objective;
        selectElement.appendChild(option);
    });

    if (normalizedSelected && !uniqueObjectives.includes(normalizedSelected)) {
        const savedOption = document.createElement('option');
        savedOption.value = normalizedSelected;
        savedOption.textContent = `${normalizedSelected} (saved)`;
        selectElement.appendChild(savedOption);
    }

    selectElement.value = normalizedSelected;
}

function setLearningObjectiveNote(message = '') {
    const note = document.getElementById('learning-objective-note');
    if (!note) {
        return;
    }

    if (message) {
        note.textContent = message;
        note.style.display = 'block';
        return;
    }

    note.textContent = '';
    note.style.display = 'none';
}

function populateQuestionLearningObjectiveDropdown(selectedObjective = '', noteMessage = '') {
    const select = document.getElementById('learning-objective-select');
    populateLearningObjectiveOptions(select, getOnboardingLearningObjectives(), selectedObjective);
    setLearningObjectiveNote(noteMessage);
}

function getStoredQuestion(week, questionId) {
    return (assessmentQuestions[week] || []).find(question => String(question.id) === String(questionId)) || null;
}

function renderLearningObjectiveDisplay(learningObjective) {
    const value = (learningObjective || '').trim();
    const className = value
        ? 'question-learning-objective-value'
        : 'question-learning-objective-value unassigned';
    const label = value || 'Unassigned';

    return `
        <div class="question-learning-objective">
            <span class="question-learning-objective-label">Learning Objective</span>
            <span class="${className}">${label}</span>
        </div>
    `;
}

function setAutoLinkButtonLoading(button, isLoading) {
    if (!button) {
        return;
    }

    if (isLoading) {
        button.dataset.originalHtml = button.innerHTML;
        button.disabled = true;
        button.classList.add('is-loading');
        button.innerHTML = '<span class="btn-icon">⏳</span> Auto-linking...';
        return;
    }

    button.disabled = false;
    button.classList.remove('is-loading');
    if (button.dataset.originalHtml) {
        button.innerHTML = button.dataset.originalHtml;
        delete button.dataset.originalHtml;
    }
}

function openAutoLinkConfirmationModal(week, buttonElement = null) {
    const weekKey = week || 'Onboarding';
    const questions = assessmentQuestions[weekKey] || [];
    if (questions.length === 0) {
        showNotification('There are no questions to auto-link yet.', 'warning');
        return;
    }

    const learningObjectives = getOnboardingLearningObjectives();
    if (learningObjectives.length === 0) {
        showNotification('Add learning objectives before auto-linking questions.', 'warning');
        return;
    }

    const modal = document.getElementById('auto-link-confirmation-modal');
    const unitLabel = document.getElementById('auto-link-confirmation-unit-label');
    if (!modal) {
        autoLinkQuestionsToLearningObjectives(weekKey, buttonElement);
        return;
    }

    autoLinkConfirmationContext = { week: weekKey, buttonElement };
    if (unitLabel) {
        unitLabel.textContent = weekKey === 'Onboarding' ? 'Unit 1' : weekKey;
    }
    modal.classList.add('show');
}

function closeAutoLinkConfirmationModal() {
    autoLinkConfirmationContext = null;
    const modal = document.getElementById('auto-link-confirmation-modal');
    if (modal) {
        modal.classList.remove('show');
    }
}

function confirmAutoLinkQuestions() {
    if (!autoLinkConfirmationContext) {
        closeAutoLinkConfirmationModal();
        return;
    }

    const { week, buttonElement } = autoLinkConfirmationContext;
    closeAutoLinkConfirmationModal();
    autoLinkQuestionsToLearningObjectives(week, buttonElement);
}

/**
 * Open question modal for adding assessment questions
 */
function openQuestionModal(week) {
    currentWeek = week;
    const modal = document.getElementById('question-modal');
    if (modal) {
        modal.classList.add('show');
        // Reset form
        resetQuestionForm();
        populateQuestionLearningObjectiveDropdown();
        
        // Check if AI generation should be enabled
        checkAIGenerationInModal();
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
    const learningObjectiveSelect = document.getElementById('learning-objective-select');
    if (learningObjectiveSelect) {
        learningObjectiveSelect.innerHTML = '<option value="">Leave unassigned</option>';
        learningObjectiveSelect.value = '';
    }
    setLearningObjectiveNote('');
    
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
}

/**
 * Update question form based on selected question type
 */
function updateQuestionForm() {
    const questionType = document.getElementById('question-type').value;
    
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
    
    // Check if AI generation is available for this question type
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
 * Save the question from the modal
 */
function saveQuestion() {
    const questionType = document.getElementById('question-type').value;
    const questionText = document.getElementById('question-text').value.trim();
    const learningObjective = document.getElementById('learning-objective-select')?.value?.trim() || '';
    
    if (!questionType) {
        showNotification('Please select a question type.', 'error');
        return;
    }
    
    if (!questionText) {
        showNotification('Please enter a question.', 'error');
        return;
    }
    
    let question = {
        id: Date.now(),
        type: questionType,
        question: questionText,
        learningObjective
    };
    
    // Get answer based on question type
    if (questionType === 'true-false') {
        const selectedAnswer = document.querySelector('input[name="tf-answer"]:checked');
        if (!selectedAnswer) {
            showNotification('Please select the correct answer.', 'error');
            return;
        }
        question.correctAnswer = selectedAnswer.value === 'true';
    } else if (questionType === 'multiple-choice') {
        const options = [];
        const mcqInputs = document.querySelectorAll('.mcq-input');
        let hasCorrectAnswer = false;
        
        mcqInputs.forEach(input => {
            if (input.value.trim()) {
                const option = input.dataset.option;
                const isCorrect = document.querySelector(`input[name="mcq-correct"][value="${option}"]`).checked;
                options.push(input.value.trim());
                
                if (isCorrect) {
                    question.correctAnswer = options.length - 1;
                    hasCorrectAnswer = true;
                }
            }
        });
        
        if (options.length < 2) {
            showNotification('Please provide at least 2 answer options.', 'error');
            return;
        }
        
        if (!hasCorrectAnswer) {
            showNotification('Please select the correct answer.', 'error');
            return;
        }
        
        question.options = options;
    } else if (questionType === 'short-answer') {
        const expectedAnswer = document.getElementById('sa-answer').value.trim();
        if (!expectedAnswer) {
            showNotification('Please provide the expected answer or key points.', 'error');
            return;
        }
        question.correctAnswer = expectedAnswer;
    }
    
    // Add question to the assessment
    // During onboarding, we're always working with 'Onboarding' as the week
    const weekKey = currentWeek || 'Onboarding';
    
    if (!assessmentQuestions[weekKey]) {
        assessmentQuestions[weekKey] = [];
    }
    
    assessmentQuestions[weekKey].push(question);
    
    console.log(`Question added to assessmentQuestions['${weekKey}']:`, question);
    console.log(`Total questions for ${weekKey}:`, assessmentQuestions[weekKey].length);
    
    // Update the display
    displayAssessmentQuestions(weekKey);
    
    // Close modal and show success
    closeQuestionModal();
    const learningObjectiveMessage = question.learningObjective
        ? ` Linked to "${question.learningObjective}".`
        : '';
    showNotification(`Question added successfully!${learningObjectiveMessage}`, 'success');
}



/**
 * Display assessment questions
 */
function displayAssessmentQuestions(week) {
    // During onboarding, we need to handle the 'Onboarding' week specially
    let containerId;
    if (week === 'Onboarding') {
        containerId = 'assessment-questions-onboarding';
    } else {
        containerId = `assessment-questions-${week.toLowerCase()}`;
    }
    
    const questionsContainer = document.getElementById(containerId);
    
    if (!questionsContainer) {
        console.error(`Questions container not found for week '${week}' with ID '${containerId}'`);
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
    
    // Clear container and add questions
    questionsContainer.innerHTML = '';
    
    questions.forEach((question, index) => {
        const questionElement = createQuestionElement(question, index + 1, week);
        questionsContainer.appendChild(questionElement);
    });
}

/**
 * Create question element
 */
function createQuestionElement(question, questionNumber, week) {
    const questionDiv = document.createElement('div');
    questionDiv.className = 'question-item';
    
    const typeBadgeClass = question.type === 'multiple-choice' ? 'multiple-choice' : 
                          question.type === 'true-false' ? 'true-false' : 'short-answer';
    
    let answerPreview = '';
    
    if (question.type === 'multiple-choice') {
        answerPreview = '<div class="mcq-preview">';
        question.options.forEach((option, index) => {
            const isCorrect = index === question.correctAnswer;
            answerPreview += `<div class="mcq-option-preview ${isCorrect ? 'correct' : ''}">${option}</div>`;
        });
        answerPreview += '</div>';
    } else if (question.type === 'true-false') {
        answerPreview = `<div class="answer-preview">Correct Answer: ${question.correctAnswer ? 'True' : 'False'}</div>`;
    } else {
        answerPreview = `<div class="answer-preview">Sample Answer: ${question.correctAnswer}</div>`;
    }
    
    questionDiv.innerHTML = `
        <div class="question-header">
            <span class="question-type-badge ${typeBadgeClass}">${question.type.replace('-', ' ')}</span>
            <span class="question-number">Question ${questionNumber}</span>
            <div class="question-action-buttons">
                <button class="edit-question-btn" onclick="openQuestionLearningObjectiveModal('${week}', ${question.id})" title="Edit learning objective">✎</button>
                <button class="delete-question-btn" onclick="deleteAssessmentQuestion('${week}', ${question.id})" title="Delete question">×</button>
            </div>
        </div>
        <div class="question-content">
            ${renderLearningObjectiveDisplay(question.learningObjective)}
            <div class="question-text">${question.question}</div>
            ${answerPreview}
        </div>
    `;
    
    return questionDiv;
}

function openQuestionLearningObjectiveModal(week, questionId) {
    const question = getStoredQuestion(week || 'Onboarding', questionId);
    const modal = document.getElementById('question-learning-objective-modal');
    const questionText = document.getElementById('edit-learning-objective-question-text');
    const select = document.getElementById('edit-learning-objective-select');

    if (!question || !modal || !questionText || !select) {
        showNotification('Could not open the learning objective editor.', 'error');
        return;
    }

    editingQuestionObjectiveContext = { week: week || 'Onboarding', questionId: String(questionId) };
    questionText.textContent = question.question || '';
    populateLearningObjectiveOptions(select, getOnboardingLearningObjectives(), question.learningObjective || '');
    modal.classList.add('show');
}

function closeQuestionLearningObjectiveModal() {
    const modal = document.getElementById('question-learning-objective-modal');
    const questionText = document.getElementById('edit-learning-objective-question-text');
    const select = document.getElementById('edit-learning-objective-select');

    editingQuestionObjectiveContext = null;

    if (questionText) {
        questionText.textContent = '';
    }

    if (select) {
        select.innerHTML = '<option value="">Leave unassigned</option>';
        select.value = '';
    }

    if (modal) {
        modal.classList.remove('show');
    }
}

function saveQuestionLearningObjective() {
    if (!editingQuestionObjectiveContext) {
        showNotification('No question selected for editing.', 'error');
        return;
    }

    const { week, questionId } = editingQuestionObjectiveContext;
    const question = getStoredQuestion(week, questionId);
    if (!question) {
        showNotification('Could not find the selected question.', 'error');
        return;
    }

    question.learningObjective = document.getElementById('edit-learning-objective-select')?.value?.trim() || '';
    displayAssessmentQuestions(week);
    closeQuestionLearningObjectiveModal();
    showNotification('Learning objective updated successfully.', 'success');
}

async function autoLinkQuestionsToLearningObjectives(week, buttonElement = null) {
    const weekKey = week || 'Onboarding';
    const questions = assessmentQuestions[weekKey] || [];
    if (questions.length === 0) {
        showNotification('There are no questions to auto-link yet.', 'warning');
        return;
    }

    const learningObjectives = getOnboardingLearningObjectives();
    if (learningObjectives.length === 0) {
        showNotification('Add learning objectives before auto-linking questions.', 'warning');
        return;
    }

    try {
        setAutoLinkButtonLoading(buttonElement, true);
        showNotification('Auto-linking questions to learning objectives...', 'info');

        const courseId = onboardingState.createdCourseId || onboardingState.existingCourseId;
        const instructorId = getCurrentInstructorId();

        if (!courseId) {
            throw new Error('Course ID not found. Please complete course setup first.');
        }

        const response = await authenticatedFetch(`${API_BASE_URL}/api/questions/auto-link-learning-objectives`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                courseId,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives,
                questions: questions.map(question => ({
                    questionId: question.questionId || String(question.id),
                    questionType: question.type,
                    question: question.question,
                    options: Array.isArray(question.options)
                        ? question.options.reduce((acc, optionText, index) => {
                            acc[String.fromCharCode(65 + index)] = optionText;
                            return acc;
                        }, {})
                        : (question.options || {}),
                    correctAnswer: question.correctAnswer,
                    learningObjective: question.learningObjective || ''
                }))
            })
        });

        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to auto-link questions');
        }

        const matchesById = new Map((result.data.matchedQuestions || []).map(question => [
            String(question.questionId || question.id),
            question.learningObjective || ''
        ]));

        assessmentQuestions[weekKey] = questions.map(question => ({
            ...question,
            learningObjective: matchesById.get(String(question.questionId || question.id)) || question.learningObjective || ''
        }));

        displayAssessmentQuestions(weekKey);
        const fallbackMessage = result.data?.unassignedCount > 0
            ? `Auto-link complete: ${result.data.linkedCount || 0} linked, ${result.data.unassignedCount} left unassigned.`
            : (result.message || 'Questions auto-linked successfully.');
        showNotification(result.message || fallbackMessage, 'success');
    } catch (error) {
        console.error('Error auto-linking onboarding questions:', error);
        showNotification(`Error auto-linking questions: ${error.message}`, 'error');
    } finally {
        setAutoLinkButtonLoading(buttonElement, false);
    }
}

/**
 * Delete assessment question
 */
function deleteAssessmentQuestion(week, questionId) {
    if (confirm('Are you sure you want to delete this question?')) {
        // During onboarding, we're always working with 'Onboarding' as the week
        const weekKey = week || 'Onboarding';
        
        if (assessmentQuestions[weekKey]) {
            assessmentQuestions[weekKey] = assessmentQuestions[weekKey].filter(q => q.id !== questionId);
            console.log(`Question ${questionId} deleted from assessmentQuestions['${weekKey}']`);
            console.log(`Remaining questions for ${weekKey}:`, assessmentQuestions[weekKey].length);
            displayAssessmentQuestions(weekKey);
            showNotification('Question deleted successfully!', 'success');
        } else {
            console.error(`No assessment questions found for week '${weekKey}'`);
            showNotification('No questions found to delete.', 'error');
        }
    }
}

/**
 * Save assessment
 */
async function saveAssessment(week) {
    console.log(`=== SAVING ASSESSMENT FOR ${week} ===`);
    
    const questions = assessmentQuestions[week] || [];
    const thresholdInput = document.getElementById(`pass-threshold-${week.toLowerCase()}`);
    const threshold = thresholdInput ? parseInt(thresholdInput.value) : 2;
    
    console.log('Questions to save:', questions);
    console.log('Pass threshold:', threshold);
    
    if (questions.length === 0) {
        showNotification('Please add at least one assessment question before saving.', 'error');
        return;
    }
    
    try {
        // Get the current course ID and instructor ID
        const courseId = onboardingState.createdCourseId;
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        
        if (!courseId) {
            throw new Error('No course ID available. Please complete course setup first.');
        }
        
        console.log(`Saving ${questions.length} questions for course ${courseId}...`);
        
        // Save each question individually to the backend
        const savedQuestions = [];
        for (let i = 0; i < questions.length; i++) {
            const question = questions[i];
            console.log(`Saving question ${i + 1}/${questions.length}:`, question);
            
            try {
                // Pass the full question object instead of just the question text
                const result = await saveUnit1AssessmentQuestion(courseId, 'Unit 1', question, instructorId);
                question.saved = true; // Mark as saved to prevent duplicates
                savedQuestions.push(result);
                console.log(`Question ${i + 1} saved successfully:`, result);
            } catch (error) {
                console.error(`Failed to save question ${i + 1}:`, error);
                // Continue with other questions even if one fails
            }
        }
        
        // Save the pass threshold
        try {
            await saveUnit1PassThreshold(courseId, 'Unit 1', threshold, instructorId);
            console.log('Pass threshold saved successfully');
        } catch (error) {
            console.error('Failed to save pass threshold:', error);
        }
        
        console.log(`Assessment saved successfully! ${savedQuestions.length}/${questions.length} questions saved.`);
        showNotification(`Assessment saved for ${week}!\nTotal Questions: ${savedQuestions.length}/${questions.length}\nPass Threshold: ${threshold}`, 'success');
        
    } catch (error) {
        console.error('Error saving assessment:', error);
        showNotification(`Failed to save assessment: ${error.message}`, 'error');
    }
}


/**
 * Save onboarding data to database
 */
async function saveOnboardingData() {
    try {
        const courseId = onboardingState.createdCourseId;
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        
        // Collect learning objectives
        const objectivesList = document.getElementById('objectives-list');
        const objectives = Array.from(objectivesList.querySelectorAll('.objective-display-item .objective-text'))
            .map(obj => obj.textContent.trim());
        
        // Collect unit files (materials uploaded during onboarding)
        const unitFiles = {};
        
        // Get lecture notes status and content
        const lectureStatus = document.getElementById('lecture-status');
        if (lectureStatus.textContent !== 'Not Uploaded') {
            unitFiles['Unit 1'] = [{
                name: 'Lecture Notes - Unit 1',
                type: 'lecture-notes',
                status: 'uploaded',
                uploadedAt: new Date().toISOString()
            }];
        }
        
        // Get practice questions status and content
        const practiceStatus = document.getElementById('practice-status');
        if (practiceStatus.textContent !== 'Not Uploaded') {
            if (!unitFiles['Unit 1']) {
                unitFiles['Unit 1'] = [];
            }
            unitFiles['Unit 1'].push({
                name: 'Practice Questions/Tutorial',
                type: 'practice-quiz', // Keep consistent with course upload functionality
                status: 'uploaded',
                uploadedAt: new Date().toISOString()
            });
        }
        
        // Get additional materials
        const additionalMaterials = document.querySelectorAll('.additional-material-item');
        additionalMaterials.forEach(material => {
            const materialName = material.querySelector('.material-name').textContent;
            if (!unitFiles['Unit 1']) {
                unitFiles['Unit 1'] = [];
            }
            unitFiles['Unit 1'].push({
                name: materialName,
                type: 'additional',
                status: 'uploaded',
                uploadedAt: new Date().toISOString()
            });
        });
        
        // Prepare onboarding data
        const onboardingData = {
            courseId: courseId,
            courseName: onboardingState.courseData.course,
            instructorId: instructorId,
            learningOutcomes: objectives,
            unitFiles: unitFiles
        };
        
        // Update the onboarding data in the database
        const response = await authenticatedFetch(`/api/onboarding/${courseId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(onboardingData)
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to save onboarding data: ${response.status} ${errorText}`);
        }
        
        console.log('Onboarding data saved successfully');
        
    } catch (error) {
        console.error('Error saving onboarding data:', error);
        throw error;
    }
}

/**
 * Complete Unit 1 setup
 */
async function completeUnit1Setup() {
    if (onboardingState.isSubmitting) return;
    onboardingState.isSubmitting = true;
    
    console.log('%c--- Starting Final Onboarding Step ---', 'font-weight: bold; color: blue;');

    // Validate that required content has been set up
    const objectivesList = document.getElementById('objectives-list');
    const objectives = objectivesList.querySelectorAll('.objective-display-item');
    
    if (objectives.length === 0) {
        showNotification('Please add at least one learning objective before continuing.', 'error');
        return;
    }
    
    // Check if required materials are uploaded
    const lectureStatus = document.getElementById('lecture-status');
    const practiceStatus = document.getElementById('practice-status');
    
    if (lectureStatus.textContent === 'Not Uploaded' || practiceStatus.textContent === 'Not Uploaded') {
        showNotification('Please upload required materials (Lecture Notes and Practice Questions) before continuing.', 'error');
        return;
    }
    
    try {
        // Save onboarding data to database before redirecting
        console.log('Step 1: Calling saveOnboardingData...');
        await saveOnboardingData();
        console.log('Step 1: saveOnboardingData completed.');
        
        // Also ensure all Unit 1 data is saved using the same APIs that course upload expects
        console.log('Step 2: Calling saveAllUnit1Data...');
        await saveAllUnit1Data();
        console.log('Step 2: saveAllUnit1Data completed.');
        
        // Mark onboarding as complete only after all Unit 1 data is saved
        console.log('Step 3: Marking onboarding as complete...');
        await markInstructorOnboardingComplete(onboardingState.createdCourseId);
        console.log('Step 3: Onboarding marked as complete.');
        
        // Show success message and redirect
        console.log('Step 4: Onboarding save process complete. Redirecting...');
        showNotification('Unit 1 setup completed successfully! Redirecting to course upload...', 'success');
        
        // Wait a moment for the notification to be seen, then redirect with course ID
        setTimeout(() => {
            window.location.href = `/instructor/index.html?courseId=${onboardingState.createdCourseId}`;
        }, 1500);
        
    } catch (error) {
        console.error('Error saving onboarding data:', error);
        showNotification('Error saving onboarding data. Please try again.', 'error');
        onboardingState.isSubmitting = false;
    }
}

/**
 * Save all Unit 1 data using the same APIs that course upload expects
 * This ensures that all data created during onboarding is properly stored
 * and can be loaded by the course upload functionality
 * 
 * IMPORTANT: We save all data together at the end rather than individually
 * to avoid overwriting issues where only the last item gets saved.
 */
async function saveAllUnit1Data() {
    try {
        const courseId = onboardingState.createdCourseId;
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        
        if (!courseId) {
            console.error('No course ID available for saving Unit 1 data');
            return;
        }
        
        console.log('Saving all Unit 1 data for course:', courseId);
        
        // 1. Save all learning objectives together as a batch
        const objectivesList = document.getElementById('objectives-list');
        const objectives = Array.from(objectivesList.querySelectorAll('.objective-display-item .objective-text'))
            .map(obj => obj.textContent.trim())
            .filter(obj => obj.length > 0);
        
        if (objectives.length > 0) {
            console.log('Saving all learning objectives together:', objectives);
            await saveUnit1LearningObjectives(courseId, 'Unit 1', objectives, instructorId);
        }
        
        // 2. Save all assessment questions
        // Use the memory state instead of scraping DOM, and avoid duplicates
        const weekKey = 'Onboarding';
        const questions = assessmentQuestions[weekKey] || [];
        
        console.log(`Checking ${questions.length} questions for saving...`);
        
        if (questions.length > 0) {
            let savedCount = 0;
            let skippedCount = 0;
            
            for (let i = 0; i < questions.length; i++) {
                const question = questions[i];
                
                // Skip if already saved
                if (question.saved) {
                    console.log(`Skipping question ${i + 1} (already saved)`);
                    skippedCount++;
                    continue;
                }
                
                console.log(`Saving question ${i + 1}/${questions.length}:`, question);
                try {
                    const result = await saveUnit1AssessmentQuestion(courseId, 'Unit 1', question, instructorId);
                    question.saved = true; // Mark as saved
                    savedCount++;
                    console.log(`Question ${i + 1} saved successfully`);
                } catch (error) {
                    console.error(`Failed to save question ${i + 1}:`, error);
                }
            }
            console.log(`Assessment questions save complete. Saved: ${savedCount}, Skipped: ${skippedCount}`);
        } else {
            console.log('No assessment questions to save.');
        }
        
        // 3. Save pass threshold setting
        const passThresholdInput = document.getElementById('pass-threshold-onboarding');
        if (passThresholdInput) {
            const passThreshold = parseInt(passThresholdInput.value) || 2;
            console.log('Saving pass threshold:', passThreshold);
            try {
                await saveUnit1PassThreshold(courseId, 'Unit 1', passThreshold, instructorId);
                console.log('Pass threshold saved successfully');
            } catch (error) {
                console.error('Failed to save pass threshold:', error);
            }
        } else {
            console.log('Pass threshold input not found');
        }
        
        // 4. Save all uploaded documents (this should already be done during upload, but ensure it's complete)
        console.log('Unit 1 documents should already be saved from upload process');
        
        console.log('All Unit 1 data saved successfully');
        
    } catch (error) {
        console.error('Error saving all Unit 1 data:', error);
        // Don't throw here - we want the onboarding to complete successfully
        // Just log the error for debugging
        showNotification('Warning: Some Unit 1 data may not have been saved properly. Please check the course upload interface.', 'warning');
    }
}

/**
 * Open upload modal
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
    
    // Show/hide name input section based on content type
    // Always hide name input section to enforce standardized naming
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
 * Close upload modal
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
}

/**
 * Trigger file input when upload button is clicked
 */
function triggerFileInput() {
    const fileInput = document.getElementById('file-input');
    fileInput.click();
}

/**
 * Handle the main upload action
 */
async function handleUpload() {
    const textInput = document.getElementById('text-input').value.trim();
    const materialNameInput = document.getElementById('material-name').value.trim();
    const uploadBtn = document.getElementById('upload-btn');
    
    // Add debugging
    console.log('handleUpload called with:', {
        currentContentType,
        uploadedFile: !!uploadedFile,
        textInput: textInput.length,
        materialNameInput: materialNameInput.length
    });
    
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
        // Get the current course ID and instructor ID
        const courseId = onboardingState.createdCourseId;
        const instructorId = getCurrentInstructorId();
        if (!instructorId) {
            console.error('No instructor ID found. User not authenticated.');
            return;
        }
        
        console.log('Course creation state:', {
            createdCourseId: onboardingState.createdCourseId,
            courseData: onboardingState.courseData,
            courseId
        });
        
        if (!courseId) {
            throw new Error('No course ID available. Please complete course setup first.');
        }
        
        // Determine document type based on content type
        let documentType = 'additional';
        switch (currentContentType) {
            case 'lecture-notes':
                documentType = 'lecture-notes';
                break;
            case 'practice-quiz':
                documentType = 'practice-quiz'; // Keep consistent with course upload functionality
                break;
            case 'additional':
                documentType = 'additional';
                break;
        }
        
        console.log('Document type determined:', documentType);
        let uploadResult = null;
        
        // Check if this document type already exists for Unit 1
        const documentTypeExists = await checkDocumentTypeExists(courseId, 'Unit 1', documentType);
        if (documentTypeExists) {
            const replace = confirm(`${documentType.replace('-', ' ')} already exists for Unit 1. Would you like to replace the existing content?`);
            if (replace) {
                // Remove existing documents of this type
                await removeExistingDocumentType(courseId, 'Unit 1', documentType, instructorId);
                console.log(`Removed existing ${documentType} documents for Unit 1`);
            } else {
                throw new Error(`${documentType.replace('-', ' ')} already exists for Unit 1. Please remove the existing content first or use a different type.`);
            }
        }
        
        // Save the uploaded content using the same API that course upload expects
        if (uploadedFile) {
            // Pass the standardized title to the save function
            const title = getDefaultTitle(documentType);
            uploadResult = await saveUnit1Document(courseId, 'Unit 1', documentType, uploadedFile, instructorId, title);
        } else if (textInput) {
            const title = getDefaultTitle(documentType, 'Text Content');
            console.log('Saving text content with title:', title);
            console.log('Request details:', {
                courseId,
                lectureName: 'Unit 1',
                documentType,
                content: textInput,
                title,
                instructorId
            });
            uploadResult = await saveUnit1Text(courseId, 'Unit 1', documentType, textInput, title, instructorId);
        }

        const uploadedDocumentId = uploadResult?.data?.documentId || null;
        
        // Update status badge based on content type
        let statusBadge = null;
        let statusText = 'Uploaded';
        
        switch (currentContentType) {
            case 'lecture-notes':
                statusBadge = document.getElementById('lecture-status');
                break;
            case 'practice-quiz':
                statusBadge = document.getElementById('practice-status');
                break;
            case 'additional':
                statusBadge = document.getElementById('additional-status');
                statusText = 'Added';
                break;
        }
        
        if (statusBadge) {
            statusBadge.textContent = statusText;
            statusBadge.style.background = 'rgba(40, 167, 69, 0.1)';
            statusBadge.style.color = '#28a745';
        }
        
        showNotification('Content uploaded and processed successfully!', 'success');

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
                suggestedTopics = await extractTopicsForUploadedDocument(courseId, uploadedDocumentId);
            } catch (e) {
                console.warn('Could not extract topics from uploaded document:', e);
            }

            showInlineTopicReview(courseId, getDefaultTitle(documentType), existingTopics, suggestedTopics);
        } catch (topicError) {
            console.error('Error during topic review flow:', topicError);
            showNotification('Upload succeeded, but topic review could not be completed.', 'warning');
            closeUploadModal();
        }

    } catch (error) {
        console.error('Error uploading content:', error);
        showNotification(`Error uploading content: ${error.message}. Please try again.`, 'error');

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
 * Get default title for content based on document type
 * @param {string} documentType - The type of document
 * @param {string} fallback - Fallback text if no specific title is found
 * @returns {string} Default title for the content
 */
function getDefaultTitle(documentType, fallback) {
    switch (documentType) {
        case 'lecture-notes':
            return 'Lecture Notes - Unit 1';
        case 'practice-quiz':
            return 'Practice Questions/Tutorial - Unit 1';
        case 'additional':
            return 'Additional Material - Unit 1';
        default:
            return fallback || 'Content - Unit 1';
    }
}

/**
 * Save Unit 1 document using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} documentType - The type of document
 * @param {File} file - The uploaded file
 * @param {string} instructorId - The instructor ID
 */
async function saveUnit1Document(courseId, lectureName, documentType, file, instructorId, title) {
    try {
        console.log(`📁 [DOCUMENT] Starting document upload process...`);
        console.log(`📁 [DOCUMENT] Course ID: ${courseId}`);
        console.log(`📁 [DOCUMENT] Lecture/Unit: ${lectureName}`);
        console.log(`📁 [DOCUMENT] Document type: ${documentType}`);
        console.log(`📁 [DOCUMENT] File details:`, {
            name: file.name,
            size: file.size,
            type: file.type,
            lastModified: new Date(file.lastModified)
        });
        console.log(`📁 [DOCUMENT] Instructor ID: ${instructorId}`);
        
        const formData = new FormData();
        formData.append('file', file);
        formData.append('courseId', courseId);
        formData.append('lectureName', lectureName);
        formData.append('documentType', documentType);
        formData.append('instructorId', instructorId);
        // Add the standardized title to the form data
        if (title) {
            formData.append('title', title);
        }
        
        console.log(`📡 [MONGODB] Making API request to /api/documents/upload (POST)`);
        console.log(`📡 [MONGODB] FormData contents:`, {
            courseId: formData.get('courseId'),
            lectureName: formData.get('lectureName'),
            documentType: formData.get('documentType'),
            instructorId: formData.get('instructorId'),
            fileName: formData.get('file')?.name,
            fileSize: formData.get('file')?.size
        });
        
        const response = await fetch('/api/documents/upload', {
            method: 'POST',
            body: formData
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to save document: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Document saved successfully:', result);
        console.log('📁 [DOCUMENT] Document ID from response:', result.data?.documentId);
        
        // Document linking is already handled by the upload API, no need for separate call
        console.log(`✅ [DOCUMENT] Document upload completed successfully (already linked to course structure)`);
        return result;
        
    } catch (error) {
        console.error('❌ [DOCUMENT] Error saving Unit 1 document:', error);
        throw error;
    }
}

/**
 * Save Unit 1 URL content using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} documentType - The type of document
 * @param {string} url - The URL content
 * @param {string} name - The name for the content
 * @param {string} instructorId - The instructor ID
 */
async function saveUnit1URL(courseId, lectureName, documentType, url, name, instructorId) {
    try {
        console.log(`Saving Unit 1 URL content for course ${courseId}:`, { documentType, url, name });
        
        // For URL content, we'll create a text document with the URL
        const textContent = `URL: ${url}\n\nContent from: ${name}`;
        
        const response = await fetch('/api/documents/text', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId,
                lectureName,
                documentType,
                content: textContent,
                title: name,
                instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to save URL content: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('Unit 1 URL content saved successfully:', result);
        return result;
        
    } catch (error) {
        console.error('Error saving Unit 1 URL content:', error);
        throw error;
    }
}

/**
 * Save Unit 1 text content using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} documentType - The type of document
 * @param {string} text - The text content
 * @param {string} name - The name for the content
 * @param {string} instructorId - The instructor ID
 */
async function saveUnit1Text(courseId, lectureName, documentType, text, name, instructorId) {
    try {
        console.log(`📝 [TEXT] Starting text content upload process...`);
        console.log(`📝 [TEXT] Course ID: ${courseId}`);
        console.log(`📝 [TEXT] Lecture/Unit: ${lectureName}`);
        console.log(`📝 [TEXT] Document type: ${documentType}`);
        console.log(`📝 [TEXT] Content name: ${name}`);
        console.log(`📝 [TEXT] Text content length: ${text.length} characters`);
        console.log(`📝 [TEXT] Text content preview: ${text.substring(0, 100)}${text.length > 100 ? '...' : ''}`);
        console.log(`📝 [TEXT] Instructor ID: ${instructorId}`);
        
        const requestBody = {
            courseId,
            lectureName,
            documentType,
            content: text,
            title: name,
            instructorId
        };
        
        console.log(`📡 [MONGODB] Making API request to /api/documents/text (POST)`);
        console.log(`📡 [MONGODB] Request endpoint: /api/documents/text`);
        console.log(`📡 [MONGODB] Request body:`, requestBody);
        console.log(`📡 [MONGODB] Request body size: ${JSON.stringify(requestBody).length} characters`);
        
        const response = await fetch('/api/documents/text', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to save text content: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Text content saved successfully:', result);
        console.log('📝 [TEXT] Document ID from response:', result.data?.documentId);
        return result;
        
    } catch (error) {
        console.error('❌ [TEXT] Error saving Unit 1 text content:', error);
        throw error;
    }
}

/**
 * Save Unit 1 probing question using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} questionText - The probing question text
 * @param {string} instructorId - The instructor ID
 */
async function saveUnit1ProbingQuestion(courseId, lectureName, questionText, instructorId) {
    try {
        console.log(`Saving Unit 1 probing question for course ${courseId}:`, { lectureName, questionText });
        
        // Since there's no dedicated probing questions API, we'll save this as a text document
        // with a special type that can be identified later
        const response = await fetch('/api/documents/text', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId,
                lectureName,
                documentType: 'probing-question',
                content: questionText,
                title: `Probing Question - Unit 1: ${questionText.substring(0, 50)}${questionText.length > 50 ? '...' : ''}`,
                instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to save probing question: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('Unit 1 probing question saved successfully:', result);
        
    } catch (error) {
        console.error('Error saving Unit 1 probing question:', error);
        // Don't throw here - we want the question to be added to the UI
        // and the course to be created successfully even if this fails
    }
}



/**
 * Remove Unit 1 probing question using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} questionText - The probing question text
 * @param {string} instructorId - The instructor ID
 */
async function removeUnit1ProbingQuestion(courseId, lectureName, questionText, instructorId) {
    try {
        console.log(`Removing Unit 1 probing question for course ${courseId}:`, { lectureName, questionText });
        
        // Note: We don't have a DELETE endpoint for probing questions by content
        // The removal will be handled when the user completes onboarding and the final state is saved
        console.log('Probing question removal logged - will be updated when onboarding is completed');
        
    } catch (error) {
        console.error('Error removing probing question from API:', error);
        // Don't throw here - we want the question to be removed from the UI
        // and the course to be created successfully even if this fails
    }
}

/**
 * Save Unit 1 learning objective using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} objectiveText - The learning objective text
 * @param {string} instructorId - The instructor ID
 */
async function saveUnit1LearningObjective(courseId, lectureName, objectiveText, instructorId) {
    try {
        console.log(`Saving Unit 1 learning objective for course ${courseId}:`, { lectureName, objectiveText });
        
        const response = await fetch('/api/learning-objectives', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                lectureName: lectureName,
                objectives: [objectiveText], // Send as array for consistency
                instructorId: instructorId,
                courseId: courseId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to save learning objective: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('Unit 1 learning objective saved successfully:', result);
        
    } catch (error) {
        console.error('Error saving Unit 1 learning objective:', error);
        // Don't throw here - we want the objective to be added to the UI
        // and the course to be created successfully even if this fails
    }
}

/**
 * Remove Unit 1 learning objective using the same API that course upload expects
 * @param {string} courseId - The course ID
 * @param {string} lectureName - The lecture/unit name (e.g., 'Unit 1')
 * @param {string} objectiveText - The learning objective text
 * @param {string} instructorId - The instructor ID
 */
async function removeUnit1LearningObjective(courseId, lectureName, objectiveText, instructorId) {
    try {
        console.log(`Removing Unit 1 learning objective for course ${courseId}:`, { lectureName, objectiveText });
        
        // Note: We don't have a DELETE endpoint for learning objectives by content
        // The removal will be handled when the user completes onboarding and the final state is saved
        console.log('Learning objective removal logged - will be updated when onboarding is completed');
        
    } catch (error) {
        console.error('Error removing learning objective from API:', error);
        // Don't throw here - we want the objective to be removed from the UI
        // and the course to be created successfully even if this fails
    }
}


/**
 * Check if a document type already exists for a unit
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Unit name
 * @param {string} documentType - Type of document to check
 * @returns {Promise<boolean>} True if document type already exists
 */
async function checkDocumentTypeExists(courseId, lectureName, documentType) {
    try {
        const response = await fetch(`/api/courses/${courseId}?instructorId=${getCurrentInstructorId()}`);
        if (response.ok) {
            const result = await response.json();
            const course = result.data;
            
            if (course && course.lectures) {
                const unit = course.lectures.find(l => l.name === lectureName);
                if (unit && unit.documents) {
                    return unit.documents.some(doc => doc.documentType === documentType);
                }
            }
        }
        return false;
    } catch (error) {
        console.error('Error checking document type existence:', error);
        return false;
    }
}

/**
 * Utility functions
 */
function showFieldError(field, message) {
    const formGroup = field.closest('.form-group');
    
    // Remove existing error
    formGroup.classList.remove('success');
    const existingError = formGroup.querySelector('.error-message');
    if (existingError) {
        existingError.remove();
    }
    
    // Add error state
    formGroup.classList.add('error');
    
    // Create error message element
    const errorElement = document.createElement('div');
    errorElement.className = 'error-message';
    errorElement.textContent = message;
    
    // Insert error message after the field
    field.parentNode.insertBefore(errorElement, field.nextSibling);
}

function showSuccessMessage(message) {
    showNotification(message, 'success');
}

function showErrorMessage(message) {
    showNotification(message, 'error');
}

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    // Add styles
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
        ${type === 'success' ? 'background-color: var(--success-color);' : 'background-color: var(--danger-color);'}
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
 * Remove existing document of a specific type for a unit
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Unit name
 * @param {string} documentType - Type of document to remove
 * @param {string} instructorId - Instructor ID
 * @returns {Promise<boolean>} True if document was removed
 */
async function removeExistingDocumentType(courseId, lectureName, documentType, instructorId) {
    try {
        const response = await fetch(`/api/courses/${courseId}?instructorId=${instructorId}`);
        if (response.ok) {
            const result = await response.json();
            const course = result.data;
            
            if (course && course.lectures) {
                const unit = course.lectures.find(l => l.name === lectureName);
                if (unit && unit.documents) {
                    const documentsToRemove = unit.documents.filter(doc => doc.documentType === documentType);
                    
                    if (documentsToRemove.length > 0) {
                        // Remove each document of this type
                        for (const doc of documentsToRemove) {
                            await fetch(`/api/documents/${doc.documentId}`, {
                                method: 'DELETE',
                                headers: {
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify({
                                    instructorId: instructorId
                                })
                            });
                        }
                        
                        // Update the course structure to remove these documents
                        const updateResponse = await fetch(`/api/courses/${courseId}/lectures/${lectureName}/documents`, {
                            method: 'DELETE',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                documentTypes: [documentType],
                                instructorId: instructorId
                            })
                        });
                        
                        return updateResponse.ok;
                    }
                }
            }
        }
        return false;
    } catch (error) {
        console.error('Error removing existing document type:', error);
        return false;
    }
}

/**
 * Save an assessment question using the questions API
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Unit name
 * @param {Object|string} questionObjOrText - The full question object with question, options, correctAnswer, type, etc., OR just a question text string (for probing questions)
 * @param {string} instructorId - Instructor ID
 * @returns {Promise<Object>} API response
 */
async function saveUnit1AssessmentQuestion(courseId, lectureName, questionObjOrText, instructorId) {
    try {
        console.log(`❓ [ASSESSMENT] Starting assessment question creation process...`);
        console.log(`❓ [ASSESSMENT] Course ID: ${courseId}`);
        console.log(`❓ [ASSESSMENT] Lecture/Unit: ${lectureName}`);
        console.log(`❓ [ASSESSMENT] Question data (type: ${typeof questionObjOrText}):`, questionObjOrText);
        console.log(`❓ [ASSESSMENT] Instructor ID: ${instructorId}`);
        
        // Handle case where only question text is provided (probing questions)
        // Convert string to question object format
        let questionObj;
        if (typeof questionObjOrText === 'string') {
            // This is a probing question - just text, no options
            questionObj = {
                question: questionObjOrText,
                type: 'multiple-choice',
                options: [],
                correctAnswer: 0
            };
        } else {
            // This is a full question object
            questionObj = questionObjOrText;
        }
        
        // Determine question type - use from question object or default to multiple-choice
        const questionType = questionObj.type || questionObj.questionType || 'multiple-choice';
        
        // Convert options from array format to object format if needed
        // In onboarding, options are stored as an array: ['Option 1', 'Option 2', ...]
        // Backend expects object format: {A: 'Option 1', B: 'Option 2', ...}
        let options = {};
        let correctAnswer = questionObj.correctAnswer;
        
        if (questionType === 'multiple-choice') {
            // Check if options is an array (onboarding format) or object (instructor.js format)
            if (Array.isArray(questionObj.options)) {
                // Convert array to object format: ['text1', 'text2', ...] -> {A: 'text1', B: 'text2', ...}
                const optionLetters = ['A', 'B', 'C', 'D', 'E', 'F'];
                questionObj.options.forEach((optionText, index) => {
                    if (optionText && optionText.trim()) {
                        options[optionLetters[index]] = optionText.trim();
                    }
                });
                
                // Convert index-based correctAnswer (0, 1, 2, 3) to letter format ('A', 'B', 'C', 'D')
                if (typeof correctAnswer === 'number' && correctAnswer >= 0 && correctAnswer < questionObj.options.length) {
                    correctAnswer = optionLetters[correctAnswer];
                }
            } else if (questionObj.options && typeof questionObj.options === 'object') {
                // Already in object format, use as is
                options = questionObj.options;
                // correctAnswer should already be in letter format ('A', 'B', etc.)
            } else {
                // Fallback: create default options if none provided
                options = {
                    A: 'Option A',
                    B: 'Option B',
                    C: 'Option C',
                    D: 'Option D'
                };
                correctAnswer = 'A';
            }
        } else if (questionType === 'true-false') {
            // True/false questions don't need options object
            options = {};
            // correctAnswer should be 'true' or 'false' as a string
            if (typeof correctAnswer === 'boolean') {
                correctAnswer = correctAnswer.toString();
            }
        } else if (questionType === 'short-answer') {
            // Short answer questions don't need options object
            options = {};
            // correctAnswer should be the expected answer text
        }
        
        const requestBody = {
            courseId,
            lectureName,
            instructorId,
            questionType: questionType,
            question: questionObj.question || questionObj.questionText || '',
            options: options,
            correctAnswer: correctAnswer || 'A',
            explanation: questionObj.explanation || '',
            difficulty: questionObj.difficulty || 'medium',
            tags: questionObj.tags || [],
            learningObjective: questionObj.learningObjective || '',
            points: questionObj.points || 1
        };
        
        console.log(`📡 [MONGODB] Making API request to /api/questions (POST)`);
        console.log(`📡 [MONGODB] Request endpoint: /api/questions`);
        console.log(`📡 [MONGODB] Request method: POST`);
        console.log(`📡 [MONGODB] Request headers: { 'Content-Type': 'application/json' }`);
        console.log(`📡 [MONGODB] Request body:`, JSON.stringify(requestBody, null, 2));
        console.log(`📡 [MONGODB] Request body size: ${JSON.stringify(requestBody).length} characters`);
        
        const response = await fetch('/api/questions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        console.log(`📡 [MONGODB] API response status text: ${response.statusText}`);
        console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] API error response: ${response.status} ${errorText}`);
            throw new Error(`Failed to save assessment question: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] API success response:', result);
        console.log('✅ [ASSESSMENT] Assessment question saved successfully!');
        return result;
        
    } catch (error) {
        console.error('❌ [ASSESSMENT] Error saving assessment question:', error);
        throw error;
    }
}

/**
 * Save pass threshold setting for a unit
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Unit name
 * @param {number} passThreshold - Pass threshold value
 * @param {string} instructorId - Instructor ID
 * @returns {Promise<Object>} API response
 */
async function saveUnit1PassThreshold(courseId, lectureName, passThreshold, instructorId) {
    try {
        console.log(`🎯 [THRESHOLD] Starting pass threshold update process...`);
        console.log(`🎯 [THRESHOLD] Course ID: ${courseId}`);
        console.log(`🎯 [THRESHOLD] Lecture/Unit: ${lectureName}`);
        console.log(`🎯 [THRESHOLD] Pass threshold value: ${passThreshold}`);
        console.log(`🎯 [THRESHOLD] Instructor ID: ${instructorId}`);
        
        const requestBody = {
            courseId,
            lectureName,
            passThreshold,
            instructorId
        };
        
        console.log(`📡 [MONGODB] Making API request to /api/lectures/pass-threshold (POST)`);
        console.log(`📡 [MONGODB] Request endpoint: /api/lectures/pass-threshold`);
        console.log(`📡 [MONGODB] Request body:`, requestBody);
        console.log(`📡 [MONGODB] Request body size: ${JSON.stringify(requestBody).length} characters`);
        
        // Use the lectures API to update the pass threshold
        const response = await fetch(`/api/lectures/pass-threshold`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        console.log(`📡 [MONGODB] API response headers:`, Object.fromEntries(response.headers.entries()));
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`❌ [MONGODB] Error saving pass threshold: ${response.status} ${errorText}`);
            throw new Error(`Failed to save pass threshold: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        console.log('✅ [MONGODB] Pass threshold saved successfully:', result);
        console.log('🎯 [THRESHOLD] Pass threshold update completed successfully!');
        return result;
        
    } catch (error) {
        console.error('❌ [THRESHOLD] Error saving pass threshold:', error);
        throw error;
    }
}

function isCourseDeactive(course = {}) {
    return (course.status || 'active') === 'inactive';
}

function getCourseDisplayName(course = {}) {
    const courseName = course.courseName || course.courseId || 'Untitled Course';
    return isCourseDeactive(course) ? `${courseName} (deactive)` : courseName;
}

function dedupeCourses(courses = []) {
    return courses.filter((course, index, self) =>
        index === self.findIndex(candidate => candidate.courseId === course.courseId)
    );
}

function appendCourseGroup(selectElement, label, courses) {
    if (!courses.length) {
        return;
    }

    const optgroup = document.createElement('optgroup');
    optgroup.label = label;

    courses.forEach(course => {
        const option = document.createElement('option');
        option.value = course.courseId;
        option.textContent = getCourseDisplayName(course);
        option.dataset.status = course.status || 'active';
        optgroup.appendChild(option);
    });

    selectElement.appendChild(optgroup);
}

function populateAvailableCourses(selectElement, courses) {
    selectElement.innerHTML = '<option value="">Choose a course...</option>';

    const uniqueCourses = dedupeCourses(courses);
    const activeCourses = uniqueCourses.filter(course => !isCourseDeactive(course));
    const inactiveCourses = uniqueCourses.filter(isCourseDeactive);

    appendCourseGroup(selectElement, 'Active Courses', activeCourses);
    appendCourseGroup(selectElement, 'Deactive Courses', inactiveCourses);
}

/**
 * Load available courses for the instructor
 */
async function loadAvailableCourses() {
    try {
        const courseSelect = document.getElementById('course-select');
        
        if (!courseSelect) return;
        
        // Fetch courses from the API
        const response = await fetch('/api/courses/available/joinable');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch courses');
        }
        
        const courses = result.data || [];
        
        console.log('All available courses from API:', courses);

        populateAvailableCourses(courseSelect, courses);
        
        // Add custom course option
        const customOption = document.createElement('option');
        customOption.value = 'custom';
        customOption.textContent = 'Enter custom course name...';
        courseSelect.appendChild(customOption);
        
        console.log('Available courses loaded and deduplicated:', dedupeCourses(courses));
        
    } catch (error) {
        console.error('Error loading available courses:', error);
        // Keep the placeholder option if API fails
        const courseSelect = document.getElementById('course-select');
        if (courseSelect) {
            courseSelect.innerHTML = '<option value="">Choose a course...</option>';
            // Add custom course option even if API fails
            const customOption = document.createElement('option');
            customOption.value = 'custom';
            customOption.textContent = 'Enter custom course name...';
            courseSelect.appendChild(customOption);
        }
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

// ==========================================
// AI Question Generation Logic
// ==========================================

const API_BASE_URL = '';
// AI Generation State
let aiGenerationCount = 0;
let lastGeneratedContent = null;
let currentQuestionType = null;

/**
 * Check AI generation availability in the question modal
 */
function checkAIGenerationInModal() {
    console.log(`🔍 [AI_MODAL_CHECK] Starting check for AI generation`);
    
    const questionType = document.getElementById('question-type').value;
    const aiButton = document.getElementById('ai-generate-btn');
    
    if (!aiButton) return;
    
    if (!questionType) {
        // No question type selected, hide AI button
        aiButton.style.display = 'none';
        return;
    }
    
    // Check if course materials or objectives are available for Unit 1
    // In onboarding, we check the status badges or the objectives list
    const materialsAvailable = checkOnboardingCourseMaterialsAvailable();
    const objectivesAvailable = checkOnboardingObjectivesAvailable();
    
    if (!materialsAvailable && !objectivesAvailable) {
        // No materials/objectives available, disable AI button
        aiButton.style.display = 'flex';
        aiButton.disabled = true;
        aiButton.title = 'Please upload course materials or add learning objectives before generating AI questions.';
        return;
    }
    
    // Materials available and question type selected, enable AI button
    aiButton.style.display = 'flex';
    aiButton.disabled = false;
    aiButton.title = 'Generate AI question based on uploaded course materials and learning objectives.';
}

/**
 * Check if course materials are uploaded/processed in onboarding
 */
function checkOnboardingCourseMaterialsAvailable() {
    const lectureStatus = document.getElementById('lecture-status');
    const practiceStatus = document.getElementById('practice-status');
    
    // Check if status text indicates uploaded/processed
    // The text is usually 'Not Uploaded', 'Uploading...', 'Uploaded', 'Processed', 'Added'
    const isAvailable = (status) => {
        if (!status) return false;
        const text = status.textContent;
        return text === 'Uploaded' || text === 'Processed' || text === 'Added';
    };
    
    return isAvailable(lectureStatus) || isAvailable(practiceStatus);
}

/**
 * Check if learning objectives are available in onboarding
 */
function checkOnboardingObjectivesAvailable() {
    const objectivesList = document.getElementById('objectives-list');
    if (!objectivesList) return false;
    
    // Check if there are any objective items
    return objectivesList.querySelectorAll('.objective-display-item').length > 0;
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
    
    if (!checkOnboardingCourseMaterialsAvailable() && !checkOnboardingObjectivesAvailable()) {
        showNotification('Please upload course materials or add learning objectives before generating AI questions.', 'error');
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
        // Get course ID from onboarding state
        const courseId = onboardingState.createdCourseId || onboardingState.existingCourseId;
        const instructorId = getCurrentInstructorId();
        const lectureName = 'Unit 1'; // Always Unit 1 for onboarding
        
        if (!courseId) {
            throw new Error('Course ID not found. Please ensure course is created.');
        }

        // Get learning objectives from UI
        const objectives = [];
        document.querySelectorAll('#objectives-list .objective-text').forEach(el => {
            const text = el.textContent.trim();
            if (text) objectives.push(text);
        });
        
        console.log('📚 [OBJECTIVES] Learning objectives for AI generation:', objectives);

        // Call the AI question generation API
        const apiUrl = API_BASE_URL + '/api/questions/generate-ai';
        console.log('🔍 [API_CALL] Making request to:', apiUrl);
        const response = await authenticatedFetch(apiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: lectureName,
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
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to generate question');
        }
        
        const aiContent = result.data;
        
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
        const fallbackContent = createFallbackAIContent(questionType, 'Unit 1');
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
 * Open the regenerate modal
 */
function openRegenerateModal() {
    const modal = document.getElementById('regenerate-modal');
    if (!modal) return;
    
    // Display current question for reference
    const displayContainer = document.getElementById('current-question-display');
    if (displayContainer && lastGeneratedContent) {
        let contentHtml = `<p><strong>Question:</strong> ${lastGeneratedContent.question || ''}</p>`;
        
        if (lastGeneratedContent.options) {
            contentHtml += '<div class="preview-options">';
            const options = lastGeneratedContent.options.choices || lastGeneratedContent.options;
            if (Array.isArray(options)) {
                options.forEach((opt, idx) => {
                    contentHtml += `<div>${String.fromCharCode(65+idx)}) ${opt}</div>`;
                });
            } else {
                Object.entries(options).forEach(([key, val]) => {
                    contentHtml += `<div>${key}) ${val}</div>`;
                });
            }
            contentHtml += '</div>';
        }
        
        if (lastGeneratedContent.answer) {
            contentHtml += `<p><strong>Answer:</strong> ${lastGeneratedContent.answer}</p>`;
        }
        
        displayContainer.innerHTML = contentHtml;
    }
    
    modal.classList.add('show');
}

/**
 * Close the regenerate modal
 */
function closeRegenerateModal() {
    const modal = document.getElementById('regenerate-modal');
    if (modal) {
        modal.classList.remove('show');
        // Reset feedback
        const feedback = document.getElementById('regenerate-feedback');
        if (feedback) feedback.value = '';
    }
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
        const courseId = onboardingState.createdCourseId || onboardingState.existingCourseId;
        const instructorId = getCurrentInstructorId();
        const lectureName = 'Unit 1';
        
        // Get learning objectives
        const objectives = [];
        document.querySelectorAll('#objectives-list .objective-text').forEach(el => {
            const text = el.textContent.trim();
            if (text) objectives.push(text);
        });
        
        // Call the regenerate API
        const response = await authenticatedFetch(API_BASE_URL + '/api/questions/generate-ai', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: lectureName,
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
 * Populate the question modal form with AI-generated content
 */
function populateFormWithAIContent(aiContent) {
    if (!aiContent) return;
    
    // Set question text
    const questionText = aiContent.question || aiContent.options?.question || aiContent.prompt || '';
    document.getElementById('question-text').value = questionText;
    
    // Set answer based on type
    const questionType = document.getElementById('question-type').value;
    
    if (questionType === 'true-false') {
        const answer = String(aiContent.answer).toLowerCase();
        const radioButton = document.querySelector(`input[name="tf-answer"][value="${answer}"]`);
        if (radioButton) {
            radioButton.checked = true;
        }
    } else if (questionType === 'multiple-choice') {
        // Set MCQ options
        if (aiContent.options) {
            const choices = aiContent.options.choices || aiContent.options;
            
            if (Array.isArray(choices)) {
                choices.forEach((choice, index) => {
                    const option = String.fromCharCode(65 + index);
                    const input = document.querySelector(`.mcq-input[data-option="${option}"]`);
                    if (input) input.value = choice;
                });
            } else if (typeof choices === 'object') {
                Object.keys(choices).forEach(option => {
                    const input = document.querySelector(`.mcq-input[data-option="${option}"]`);
                    if (input) input.value = choices[option];
                });
            }
        }
        
        // Enable radio buttons
        const radioButtons = document.querySelectorAll('input[name="mcq-correct"]');
        radioButtons.forEach(radio => radio.disabled = false);
        
        // Set correct answer
        const correctAnswer = aiContent.options?.correctAnswer || aiContent.answer || '';
        if (correctAnswer) {
            let correctRadio = document.querySelector(`input[name="mcq-correct"][value="${correctAnswer}"]`) ||
                             document.querySelector(`input[name="mcq-correct"][value="${correctAnswer.toUpperCase()}"]`);
            if (correctRadio) correctRadio.checked = true;
        }
    } else if (questionType === 'short-answer') {
        const expectedAnswer = aiContent.EXPECTED_ANSWER || aiContent.answer || '';
        document.getElementById('sa-answer').value = expectedAnswer;
    }

    if (Object.prototype.hasOwnProperty.call(aiContent, 'selectedLearningObjective')) {
        const selectedLearningObjective = (aiContent.selectedLearningObjective || '').trim();
        let learningObjectiveNote = '';

        if (aiContent.wasRegenerated) {
            learningObjectiveNote = selectedLearningObjective
                ? 'The regenerated question was re-linked to this learning objective. Review it before saving if you want a different one.'
                : 'No clear learning objective match was found for the regenerated question. It is currently unassigned until you choose one.';
        } else if (selectedLearningObjective) {
            learningObjectiveNote = 'AI selected this learning objective for the generated question. Saving will keep this link unless you change it.';
        }

        populateQuestionLearningObjectiveDropdown(
            selectedLearningObjective,
            learningObjectiveNote
        );
    }
}

/**
 * Create fallback AI content when the API fails
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
