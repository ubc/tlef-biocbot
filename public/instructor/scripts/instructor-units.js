/**
 * Instructor: unit rendering, accordion, rename, and placeholder management.
 * (Add/delete-unit handlers live in the boot file's first DOMContentLoaded
 * listener in instructor.js.)
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
 * Helper function to find elements containing specific text
 * @param {string} selector - CSS selector for elements to search within
 * @param {string} text - Text to search for
 * @param {boolean} caseSensitive - Whether the search should be case sensitive
 * @returns {Array} - Array of matching elements
 */
function findElementsContainingText(selector, text, caseSensitive = false) {
    const elements = Array.from(document.querySelectorAll(selector));
    return elements.filter(element => {
        const elementText = element.textContent;
        if (caseSensitive) {
            return elementText.includes(text);
        } else {
            return elementText.toUpperCase().includes(text.toUpperCase());
        }
    });
}

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
        <div class="accordion-header" role="button" tabindex="0" aria-expanded="${isExpanded}">
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
                        <input type="checkbox" id="publish-${unitId}" aria-label="Publish ${unitName} to students" onchange="togglePublish('${unitName}', this.checked)">
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
                        <button class="auto-link-btn" onclick="openAutoLinkConfirmationModal('${unitName}', this)">
                            <span class="btn-icon">🪄</span>
                            Auto-link Questions
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
                    options: dbQuestion.options || {},
                    learningObjective: dbQuestion.learningObjective || ''
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
        const toggleAccordion = (e) => {
            // Keep the unit's own controls independent from the accordion.
            if (e.target.closest('button, input, label, select, textarea, a')) {
                return;
            }
            
            const accordionItem = header.parentElement;
            const content = accordionItem.querySelector('.accordion-content');
            const toggle = header.querySelector('.accordion-toggle');
            
            if (content.classList.contains('collapsed')) {
                content.classList.remove('collapsed');
                toggle.textContent = '▼';
                header.setAttribute('aria-expanded', 'true');
            } else {
                content.classList.add('collapsed');
                toggle.textContent = '▶';
                header.setAttribute('aria-expanded', 'false');
            }
        };

        header.addEventListener('click', toggleAccordion);
        header.addEventListener('keydown', (e) => {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            if (e.target !== header) return;
            e.preventDefault();
            toggleAccordion(e);
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
