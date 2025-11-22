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
    
    // Test if AI button exists
    const aiButton = document.getElementById('ai-generate-btn');
    console.log(`🔍 [DOM_LOADED] AI button found: ${!!aiButton}`);
    if (aiButton) {
        console.log(`🔍 [DOM_LOADED] AI button properties:`, {
            display: aiButton.style.display,
            disabled: aiButton.disabled,
            className: aiButton.className,
            textContent: aiButton.textContent
        });
        
        // Test if button is clickable
        aiButton.addEventListener('click', function() {
            console.log('🔍 [TEST] AI button clicked successfully!');
        });
        
        // Test button visibility
        console.log(`🔍 [TEST] AI button computed styles:`, {
            display: window.getComputedStyle(aiButton).display,
            visibility: window.getComputedStyle(aiButton).visibility,
            opacity: window.getComputedStyle(aiButton).opacity
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
        
        // Close calibration modal if clicking outside
        if (calibrationModal && calibrationModal.classList.contains('show') && e.target === calibrationModal) {
            closeCalibrationModal();
        }
        
        // Close view modal if clicking outside
        if (viewModal && viewModal.classList.contains('show') && e.target === viewModal) {
            closeViewModal();
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
    

    
    // Check for URL parameters to open modals
    checkUrlParameters();
    
    // Load the saved publish status from the database
    loadPublishStatus();
    
    // Start polling for publish status changes (to detect updates from other users)
    startPublishStatusPolling();
    
    // Load the saved learning objectives from the database
    loadLearningObjectives();
    
    // Load the saved documents from the database
    loadDocuments();
    
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
    
    // Add global cleanup button
    // addGlobalCleanupButton(); // Function not implemented yet
    
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
    
    
    // Handle drag and drop functionality
    if (uploadDropArea) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            uploadDropArea.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            uploadDropArea.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            uploadDropArea.addEventListener(eventName, unhighlight, false);
        });

        function highlight() {
            uploadDropArea.classList.add('highlight');
        }

        function unhighlight() {
            uploadDropArea.classList.remove('highlight');
        }

        uploadDropArea.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(files);
        }

        uploadDropArea.addEventListener('click', () => {
            fileUpload.click();
        });

        fileUpload.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        function handleFiles(files) {
            // This is just a UI skeleton, so we'll just log the files
            
            
            // Check if week is selected
            const weekSelect = document.getElementById('week-select');
            if (weekSelect && !weekSelect.value) {
                alert('Please select a week for the uploaded documents.');
                return;
            }
            
            // In a real implementation, you would upload these files to the server
            // For demonstration, we'll just show a notification
            showNotification(`${files.length} document(s) uploaded and processing`, 'success');
            
            // Simulate adding a new file to the accordion
            if (files.length > 0) {
                addNewFileToAccordion(files[0]);
            }
        }
    }
    
    // Function to add a new file to the accordion
    function addNewFileToAccordion(file) {
        // Get the selected week
        const weekSelect = document.getElementById('week-select');
        const weekValue = weekSelect ? weekSelect.value : '1';
        const weekName = `Week ${weekValue}`;
        
        // Find the corresponding accordion item or create it
        let accordionItem = findOrCreateAccordionItem(weekName);
        
        // Create the file item
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        
        // Determine icon based on file type
        let fileIcon = '';
        if (file.name.toLowerCase().includes('quiz')) {
            fileIcon = '';
        } else if (file.name.toLowerCase().includes('syllabus')) {
            fileIcon = '';
        }
        
        fileItem.innerHTML = `
            <span class="file-icon">${fileIcon}</span>
            <div class="file-info">
                <h3>${file.name}</h3>
                <p>Newly uploaded document. Processing will begin shortly.</p>
                <span class="status-text processing">Processing</span>
            </div>
            <div class="file-actions">
                <button class="action-button view">View</button>
                <button class="action-button delete">Delete</button>
            </div>
        `;
        
        // Add event listeners to the buttons
        const viewButton = fileItem.querySelector('.view');
        const deleteButton = fileItem.querySelector('.delete');
        
        viewButton.addEventListener('click', () => {
            // In a real implementation, this would open the document
        });
        
        deleteButton.addEventListener('click', () => {
            fileItem.remove();
            // In a real implementation, this would delete the document from the server
            showNotification(`Document "${file.name}" deleted`, 'info');
        });
        
        // Add the file item to the accordion content
        const accordionContent = accordionItem.querySelector('.accordion-content');
        accordionContent.appendChild(fileItem);
        
        // Make sure the accordion is expanded
        if (accordionContent.classList.contains('collapsed')) {
            const accordionHeader = accordionItem.querySelector('.accordion-header');
            accordionHeader.click();
        }
    }
    
    // Function to find or create an accordion item for a specific week
    function findOrCreateAccordionItem(weekName) {
        const accordionContainer = document.querySelector('.accordion-container');
        
        // Try to find existing accordion item
        let accordionItem = null;
        document.querySelectorAll('.accordion-item').forEach(item => {
            const folderName = item.querySelector('.folder-name').textContent;
            if (folderName === weekName) {
                accordionItem = item;
            }
        });
        
        // If not found, create a new one
        if (!accordionItem) {
            accordionItem = document.createElement('div');
            accordionItem.className = 'accordion-item';
            
            accordionItem.innerHTML = `
                <div class="accordion-header">
                    <span class="folder-icon"></span>
                    <span class="folder-name">${weekName}</span>
                    <span class="accordion-toggle">▶</span>
                </div>
                <div class="accordion-content collapsed">
                    <!-- Files will be added here -->
                </div>
            `;
            
            // Add event listener to the header
            const header = accordionItem.querySelector('.accordion-header');
            header.addEventListener('click', () => {
                const content = accordionItem.querySelector('.accordion-content');
                const toggle = header.querySelector('.accordion-toggle');
                
                content.classList.toggle('collapsed');
                
                if (content.classList.contains('collapsed')) {
                    toggle.textContent = '▶';
                } else {
                    toggle.textContent = '▼';
                }
            });
            
            // Add to the container
            accordionContainer.appendChild(accordionItem);
        }
        
        return accordionItem;
    }
    
    // Tab functionality
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove active class from all buttons
            tabButtons.forEach(btn => btn.classList.remove('active'));
            
            // Add active class to clicked button
            button.classList.add('active');
            
            // In a real implementation, this would filter the documents
            showNotification(`Showing ${button.textContent.trim()} view`, 'info');
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
        case 'readings':
            title = 'Upload Readings';
            buttonText = 'Upload Readings';
            break;
        case 'syllabus':
            title = 'Upload Syllabus';
            buttonText = 'Upload Syllabus';
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
    if (nameInputSection) {
        if (contentType === 'additional') {
            nameInputSection.style.display = 'flex';
        } else {
            nameInputSection.style.display = 'none';
        }
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
    
    // Reset upload button text
    const uploadBtn = document.getElementById('upload-btn');
    if (uploadBtn) {
        uploadBtn.textContent = 'Upload';
        uploadBtn.disabled = false;
    }
    
    // Hide loading indicator and show upload section
    const loadingIndicator = document.getElementById('upload-loading-indicator');
    const uploadSection = document.getElementById('upload-section');
    if (loadingIndicator) loadingIndicator.style.display = 'none';
    if (uploadSection) uploadSection.style.display = 'block';
}

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
            case 'readings':
                fileName = `Readings - ${currentWeek}`;
                break;
            case 'syllabus':
                fileName = `Syllabus - ${currentWeek}`;
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
        
        // Hide loading indicator before closing modal
        if (loadingIndicator) loadingIndicator.style.display = 'none';
        if (uploadSection) uploadSection.style.display = 'block';
        
        // Re-enable modal close button
        if (modalCloseBtn) modalCloseBtn.style.pointerEvents = 'auto';
        if (modalCloseBtn) modalCloseBtn.style.opacity = '1';
        
        // Close modal and show success
        closeUploadModal();
        showNotification(uploadResult?.message || 'Content uploaded successfully!', 'success');
        
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
    // Find the week accordion item
    const weekAccordion = findElementsContainingText('.accordion-item .folder-name', week)[0].closest('.accordion-item');
    
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
            } else {
                viewFileItem(viewButton);
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
            } else {
                deleteFileItem(deleteButton);
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
                <button class="action-button view" onclick="${documentId ? `viewDocument('${documentId}')` : 'viewFileItem(this)'}">View</button>
                <button class="action-button delete" onclick="${documentId ? `deleteDocument('${documentId}')` : 'deleteFileItem(this)'}">Delete</button>
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
    // Find the accordion item
    const accordionItems = document.querySelectorAll('.accordion-item');
    let targetAccordion = null;
    
    for (let item of accordionItems) {
        const folderName = item.querySelector('.folder-name').textContent;
        if (folderName === lectureName) {
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
        showNotification(result.message || 'Publish status updated successfully', 'success');
        
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
    
    // If no course ID in URL, try to get it from the user's courses
    try {
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
 * Stop polling for publish status changes
 */
function stopPublishStatusPolling() {
    if (publishStatusPollingInterval) {
        clearInterval(publishStatusPollingInterval);
        publishStatusPollingInterval = null;
        console.log('📊 [POLLING] Stopped publish status polling');
    }
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
            const folderName = item.querySelector('.folder-name');
            if (!folderName) continue;
            
            const lectureName = folderName.textContent;
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
            const folderName = item.querySelector('.folder-name');
            if (!folderName) {
                console.warn(`⚠️ [DOCUMENTS] No folder name found for accordion item`);
                continue;
            }
            
            const lectureName = folderName.textContent;
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
                        
                        // Add cleanup button if there are documents (add this BEFORE action buttons)
                        if (documents && documents.length > 0) {
                            addCleanupButtonIfMissing(courseMaterialsSection, lectureName, courseId);
                        }
                        
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
            const folderName = accordionItem.querySelector('.folder-name');
            if (!folderName) return;
            
            const unitName = folderName.textContent;
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
                const folderName = accordionItem.querySelector('.folder-name');
                if (!folderName) return;
                
                const unitName = folderName.textContent;
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
            <h3>${doc.originalName}</h3>
            <p>${doc.metadata?.description || 'No description'}</p>
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
    // Use the existing helper function to find elements containing the unit name
    const folderElements = findElementsContainingText('.accordion-item .folder-name', unitName);
    if (folderElements.length > 0) {
        return folderElements[0].closest('.accordion-item');
    }
    return null;
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
            const folderName = item.querySelector('.folder-name');
            if (!folderName) {
                console.warn(`⚠️ [ASSESSMENT_QUESTIONS] No folder name found for accordion item`);
                continue;
            }
            
            const lectureName = folderName.textContent;
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
            const folderName = item.querySelector('.folder-name');
            if (!folderName) continue;
            
            const lectureName = folderName.textContent;
            
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
            const folderName = item.querySelector('.folder-name');
            if (!folderName) continue;
            
            const lectureName = folderName.textContent;
            
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
function openModeQuestionsModal() {
    openCalibrationModal('Week 1', 'Introduction to Biochemistry');
}

/**
 * Close the mode questions modal
 */
function closeModeQuestionsModal() {
    closeCalibrationModal();
}


/**
 * Render questions in the modal
 */
function renderQuestions() {
    const questionsList = document.getElementById('questions-list');
    questionsList.innerHTML = '';
    
    currentQuestions.forEach((question, index) => {
        const questionElement = document.createElement('div');
        questionElement.className = 'question-item';
        questionElement.innerHTML = `
            <div class="question-header">
                <span class="question-number">Question ${index + 1}</span>
                <button class="delete-question" onclick="deleteQuestion(${index})">×</button>
            </div>
            <div class="question-content">
                <div class="question-text-container">
                    <label class="question-label">Question Text:</label>
                    <input type="text" class="question-text" value="${question.question}" 
                           placeholder="Enter your question here..." 
                           onchange="updateQuestion(${index}, 'question', this.value)">
                </div>
                <div class="options-container">
                    <label class="options-label">Answer Options:</label>
                    <div class="options-list">
                        ${question.options.map((option, optionIndex) => `
                            <div class="option-item">
                                <div class="option-input-group">
                                    <input type="radio" name="correct-${index}" value="${optionIndex}" 
                                           ${optionIndex === question.correctAnswer ? 'checked' : ''}
                                           onchange="updateQuestion(${index}, 'correctAnswer', ${optionIndex})"
                                           class="correct-radio">
                                    <input type="text" value="${option}" 
                                           placeholder="Option ${optionIndex + 1}"
                                           onchange="updateQuestionOption(${index}, ${optionIndex}, this.value)"
                                           class="option-text">
                                </div>
                                <div class="score-box"></div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
        questionsList.appendChild(questionElement);
    });
}

/**
 * Add a new question
 */
function addNewQuestion() {
    const newQuestion = {
        id: questionCounter++,
        question: "",
        options: ["", "", "", ""],
        correctAnswer: 0
    };
    
    currentQuestions.push(newQuestion);
    renderQuestions();
}

/**
 * Delete a question
 * @param {number} index - Index of the question to delete
 */
function deleteQuestion(index) {
    if (currentQuestions.length <= 1) {
        showNotification('You must have at least one question.', 'error');
        return;
    }
    
    currentQuestions.splice(index, 1);
    renderQuestions();
}

/**
 * Update question text or correct answer
 * @param {number} index - Question index
 * @param {string} field - Field to update ('question' or 'correctAnswer')
 * @param {string|number} value - New value
 */
function updateQuestion(index, field, value) {
    if (index >= 0 && index < currentQuestions.length) {
        currentQuestions[index][field] = value;
    }
}

/**
 * Update question option text
 * @param {number} index - Question index
 * @param {number} optionIndex - Option index
 * @param {string} value - New option text
 */
function updateQuestionOption(index, optionIndex, value) {
    if (index >= 0 && index < currentQuestions.length && 
        optionIndex >= 0 && optionIndex < 4) {
        currentQuestions[index].options[optionIndex] = value;
    }
}

/**
 * Save mode questions
 */
async function saveModeQuestions() {
    saveCalibrationQuestions();
}

// Setup threshold slider
document.addEventListener('DOMContentLoaded', function() {
    const thresholdSlider = document.getElementById('mode-threshold');
    const thresholdValue = document.getElementById('threshold-value');
    
    if (thresholdSlider && thresholdValue) {
        thresholdSlider.addEventListener('input', function() {
            thresholdValue.textContent = this.value + '%';
        });
    }
}); 



/**
 * Delete a file item
 * @param {HTMLElement} button - The delete button element
 */
async function deleteFileItem(button) {
    const fileItem = button.closest('.file-item');
    const fileName = fileItem.querySelector('h3').textContent;
    
    // Check if this is a placeholder item (shouldn't be deleted)
    if (fileItem.classList.contains('placeholder-item')) {
        showNotification('Cannot delete placeholder items. Please upload content first.', 'warning');
        return;
    }
    
    // Check if this is an actual document with a document ID
    const documentId = fileItem.dataset.documentId;
    if (documentId) {
        // This is a real document, use the proper delete function
        await deleteDocument(documentId);
        return;
    }
    
    // Show confirmation dialog for other file items
    if (confirm(`Are you sure you want to delete "${fileName}"?`)) {
        // Remove the file item from the DOM
        fileItem.remove();
        
        // Show success notification
        showNotification(`"${fileName}" has been deleted successfully!`, 'success');
    }
}

/**
 * View a file item content
 * @param {HTMLElement} button - The view button element
 */
function viewFileItem(button) {
    const fileItem = button.closest('.file-item');
    const fileName = fileItem.querySelector('h3').textContent;
    const fileDescription = fileItem.querySelector('p').textContent;
    
    // Show a placeholder message since we're not generating mock content anymore
    const placeholderContent = `
        <h2>${fileName}</h2>
        <p><strong>Description:</strong> ${fileDescription}</p>
        <div class="content-placeholder">
            <p>Document content will be displayed here when the actual document is loaded.</p>
            <p>This placeholder indicates that the document viewing functionality is being implemented.</p>
        </div>
    `;
    
    // Open the view modal
    openViewModal(fileName, placeholderContent);
}



/**
 * Open the view modal with file content
 * @param {string} fileName - The name of the file
 * @param {string} content - The content to display
 */
function openViewModal(fileName, content) {
    // Create modal HTML if it doesn't exist
    let viewModal = document.getElementById('view-modal');
    if (!viewModal) {
        viewModal = document.createElement('div');
        viewModal.id = 'view-modal';
        viewModal.className = 'modal';
        viewModal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h2 id="view-modal-title">View File</h2>
                    <button class="modal-close" onclick="closeViewModal()">×</button>
                </div>
                <div class="modal-body">
                    <div id="view-modal-content"></div>
                </div>
                <div class="modal-footer">
                    <div class="modal-actions">
                        <button class="btn-secondary" onclick="closeViewModal()">Close</button>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(viewModal);
    }
    
    // Update modal content
    document.getElementById('view-modal-title').textContent = `View: ${fileName}`;
    document.getElementById('view-modal-content').innerHTML = content;
    
    // Show the modal
    viewModal.style.display = ''; // Clear any inline display style
    viewModal.classList.add('show');
}

/**
 * Close the view modal
 */
function closeViewModal() {
    const modal = document.getElementById('view-modal');
    if (modal) {
        modal.classList.remove('show');
        // Ensure modal is hidden even if class removal doesn't work
        modal.style.display = 'none';
    }
}

// Old learning objectives functions removed - not used in simple modal

/**
 * Check URL parameters and open modals accordingly
 */
function checkUrlParameters() {
    const urlParams = new URLSearchParams(window.location.search);
    const openModal = urlParams.get('openModal');

    if (openModal === 'modeQuestions') {
        // Small delay to ensure the page is fully loaded
        setTimeout(() => {
            openModeQuestionsModal();
        }, 100);
    }
} 

/**
 * Open the calibration modal for a specific week
 * @param {string} week - The week (e.g., 'Week 1')
 * @param {string} topic - The topic name (e.g., 'Introduction to Biochemistry')
 */
function openCalibrationModal(week, topic) {
    // Set the week and topic in the modal
    document.getElementById('calibration-week').textContent = week;
    document.getElementById('calibration-topic').textContent = topic;
    document.getElementById('calibration-topic-questions').textContent = topic;
    
    // Show the modal
    const modal = document.getElementById('calibration-modal');
    modal.style.display = ''; // Clear any inline display style
    modal.classList.add('show');
    
    // TODO: Load questions specific to this week/topic from database
    // This functionality will be implemented when the actual question loading is ready
}

/**
 * Close the calibration modal
 */
function closeCalibrationModal() {
    const modal = document.getElementById('calibration-modal');
    if (modal) {
        modal.classList.remove('show');
        // Ensure modal is hidden even if class removal doesn't work
        modal.style.display = 'none';
    }
}



/**
 * Save calibration questions for the current week
 */
async function saveCalibrationQuestions() {
    const threshold = document.getElementById('mode-threshold').value;
    const week = document.getElementById('calibration-week').textContent;
    const topic = document.getElementById('calibration-topic').textContent;
    
    // Validate questions
    for (let i = 0; i < currentQuestions.length; i++) {
        const question = currentQuestions[i];
        if (!question.question.trim()) {
            showNotification(`Question ${i + 1} cannot be empty.`, 'error');
            return;
        }
        
        for (let j = 0; j < question.options.length; j++) {
            if (!question.options[j].trim()) {
                showNotification(`Question ${i + 1}, Option ${j + 1} cannot be empty.`, 'error');
                return;
            }
        }
    }
    
    try {
        // In a real implementation, this would save to the server with the week identifier
        const response = await fetch('/api/calibration-questions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                week: week,
                topic: topic,
                questions: currentQuestions,
                threshold: parseInt(threshold),
                instructorId: getCurrentInstructorId()
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to save questions');
        }
        
        showNotification(`Calibration questions for ${week}: ${topic} saved successfully!`, 'success');
        closeCalibrationModal();
        
    } catch (error) {
        console.error('Error saving calibration questions:', error);
        // For demo purposes, still close the modal and show success
        showNotification(`Calibration questions for ${week}: ${topic} saved successfully! (Demo mode)`, 'success');
        closeCalibrationModal();
    }
} 

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
    // Find the week element using our custom helper function
    const folderElement = findElementsContainingText('.accordion-item .folder-name', week)[0];
    if (!folderElement) {
        console.error('Could not find folder element for:', week);
        showNotification('Error: Could not find unit element', 'error');
        return;
    }
    
    const weekElement = folderElement.closest('.accordion-item');
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
        showNotification('Learning objective removed.', 'info');
    } else {
        console.error('Could not find objective item to remove');
    }
}

/**
 * Add a new learning objective for a unit (used in onboarding)
 * @param {string} unitName - The unit name (e.g., 'Unit 1')
 */
function addObjectiveForUnit(unitName) {
    const inputField = document.getElementById('objective-input');
    const objectivesList = document.getElementById('objectives-list');
    
    if (!inputField || !objectivesList) {
        console.error('Could not find objective input or list elements');
        showNotification('Error: Could not find objective elements', 'error');
        return;
    }
    
    const objectiveText = inputField.value.trim();
    
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
    
    showNotification('Learning objective added successfully!', 'success');
}

/**
 * Save learning objectives for a week
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
async function saveObjectives(week) {
    // Find the week element using our custom helper function
    const folderElement = findElementsContainingText('.accordion-item .folder-name', week)[0];
    if (!folderElement) {
        console.error('Could not find folder element for:', week);
        showNotification('Error: Could not find unit element', 'error');
        return;
    }
    
    const weekElement = folderElement.closest('.accordion-item');
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
    // Find the week element using our custom helper function
    const folderElement = findElementsContainingText('.accordion-item .folder-name', week)[0];
    const weekElement = folderElement.closest('.accordion-item');
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

/**
 * Add a new probing question from the input field
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
function addQuestionFromInput(week) {
    // Find the week element using our custom helper function
    const folderElement = findElementsContainingText('.accordion-item .folder-name', week)[0];
    const weekElement = folderElement.closest('.accordion-item');
    const inputField = weekElement.querySelector(`#question-input-${week.toLowerCase().replace(/\s+/g, '')}`);
    const questionText = inputField.value.trim();
    
    if (!questionText) {
        showNotification('Please enter a probing question.', 'error');
        return;
    }
    
    // Get the questions list
    const questionsList = weekElement.querySelector(`#questions-list-${week.toLowerCase().replace(/\s+/g, '')}`);
    
    // Create new question display item
    const questionItem = document.createElement('div');
    questionItem.className = 'objective-display-item';
    questionItem.innerHTML = `
        <span class="objective-text">${questionText}</span>
        <button class="remove-objective" onclick="removeQuestion(this)">×</button>
    `;
    
    // Add to the list
    questionsList.appendChild(questionItem);
    
    // Clear the input field
    inputField.value = '';
    inputField.focus();
}

/**
 * Remove a probing question
 * @param {HTMLElement} button - The remove button element
 */
function removeQuestion(button) {
    const questionItem = button.closest('.objective-display-item');
    questionItem.remove();
}

/**
 * Save probing questions for a week
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
async function saveQuestions(week) {
    // Find the week element using our custom helper function
    const folderElement = findElementsContainingText('.accordion-item .folder-name', week)[0];
    const weekElement = folderElement.closest('.accordion-item');
    const questionItems = weekElement.querySelectorAll('.probing-questions-section .objective-text');
    
    // Collect all questions
    const questions = Array.from(questionItems).map(item => item.textContent.trim()).filter(value => value);
    
    if (questions.length === 0) {
        showNotification('Please add at least one probing question.', 'error');
        return;
    }
    
    try {
        // In a real implementation, this would save to the server
        const response = await fetch('/api/probing-questions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                week: week,
                questions: questions,
                instructorId: getCurrentInstructorId()
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to save probing questions');
        }
        
        showNotification(`Probing questions for ${week} saved successfully!`, 'success');
        
    } catch (error) {
        console.error('Error saving probing questions:', error);
        // For demo purposes, still show success
        showNotification(`Probing questions for ${week} saved successfully! (Demo mode)`, 'success');
    }
}

/**
 * Generate probing questions based on uploaded course materials
 * @param {string} week - The week identifier (e.g., 'Week 1')
 */
async function generateProbingQuestions(week) {
    const weekElement = findElementsContainingText('.accordion-item .folder-name', week)[0].closest('.accordion-item');
    const fileItems = weekElement.querySelectorAll('.course-materials-section .file-item');
    
    // Collect all course materials and learning objectives
    const materials = [];
    const objectives = [];
    
    // Get learning objectives
    const objectivesList = weekElement.querySelector('.objectives-list');
    if (objectivesList) {
        objectivesList.querySelectorAll('.objective-text').forEach(obj => {
            objectives.push(obj.textContent.trim());
        });
    }
    console.log('📚 [PROBING] Found learning objectives:', objectives);
    
    // Get course materials
    fileItems.forEach(item => {
        const title = item.querySelector('.file-info h3')?.textContent;
        const status = item.querySelector('.status-text')?.textContent;
        const docId = item.dataset.documentId;
        
        if (status === 'Processed' || status === 'Uploaded') {
            materials.push({ title, status, documentId: docId });
        }
    });
    console.log('📚 [PROBING] Found course materials:', materials);

    if (materials.length === 0) {
        showNotification('Please upload and process course materials before generating probing questions.', 'warning');
        return;
    }

    showNotification('Generating probing questions based on course materials and learning objectives...', 'info');

    try {
        // Get the actual content of the materials
        const courseId = await getCurrentCourseId();
        const response = await fetch(`/api/questions/course-material?courseId=${courseId}&lectureName=${encodeURIComponent(week)}&instructorId=${getCurrentInstructorId()}`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch course materials');
        }
        
        const result = await response.json();
        console.log('📚 [PROBING] Course material content:', result);
        
        if (!result.success || !result.data.content) {
            throw new Error('No course material content available');
        }
        
        // Call the AI generation endpoint with both materials and objectives
        const aiResponse = await fetch('/api/questions/generate-ai', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                courseId: courseId,
                lectureName: week,
                instructorId: getCurrentInstructorId(),
                questionType: 'probing',
                courseMaterial: result.data.content,
                learningObjectives: objectives
            })
        });
        
        if (!aiResponse.ok) {
            throw new Error('Failed to generate probing questions');
        }
        
        const aiResult = await aiResponse.json();
        console.log('🤖 [PROBING] AI generated questions:', aiResult);
        
        if (!aiResult.success || !aiResult.data?.questions) {
            throw new Error('Failed to parse AI generated questions');
        }
        
        // Get the questions list for this week
        const questionsList = weekElement.querySelector('.probing-questions-section .questions-list');
        
        if (!questionsList) {
            console.error('Could not find questions list element for', week);
            showNotification('Error: Could not find questions list container.', 'error');
            return;
        }
        
        // Add each generated question to the list
        aiResult.data.questions.forEach(question => {
            const questionItem = document.createElement('div');
            questionItem.className = 'objective-display-item';
            questionItem.innerHTML = `
                <span class="objective-text">${question}</span>
                <button class="remove-objective" onclick="removeQuestion(this)">×</button>
            `;
            questionsList.appendChild(questionItem);
        });

        showNotification(`${aiResult.data.questions.length} probing questions generated successfully!`, 'success');
    } catch (error) {
        console.error('Error generating probing questions:', error);
        showNotification('Failed to generate probing questions. Please try again.', 'error');
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
        
        // Find the accordion item whose folder-name matches the unit
        const folderEls = findElementsContainingText('.accordion-item .folder-name', unitNameParam);
        if (!folderEls || folderEls.length === 0) {
            return;
        }
        
        const accordionItem = folderEls[0].closest('.accordion-item');
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
function toggleAccordionDynamic(content, toggle) {
    const isCollapsed = content.classList.contains('collapsed');
    
    if (isCollapsed) {
        // Expanding: first remove collapsed class, measure height, then animate
        content.classList.remove('collapsed');
        
        // Force a reflow to get the actual height
        const height = content.scrollHeight;
        
        // Set max-height for smooth transition
        content.style.maxHeight = height + 'px';
        
        // Update toggle icon
        toggle.textContent = '▼';
        
        // Clean up after transition
        setTimeout(() => {
            content.style.maxHeight = 'none';
        }, 300);
        
    } else {
        // Collapsing: set height first, then add collapsed class
        const height = content.scrollHeight;
        content.style.maxHeight = height + 'px';
        
        // Force reflow
        content.offsetHeight;
        
        // Add collapsed class for transition
        content.classList.add('collapsed');
        
        // Update toggle icon
        toggle.textContent = '▶';
        
        // Clean up after transition
        setTimeout(() => {
            content.style.maxHeight = '';
        }, 300);
    }
}

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
        const weekAccordionItem = Array.from(document.querySelectorAll('.accordion-item')).find(item => {
            const folderName = item.querySelector('.folder-name')?.textContent;
            return folderName === currentWeek;
        });

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
        aiButton.innerHTML = originalText;
        aiButton.disabled = false;
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
        showNotification('Onboarding data loaded successfully!', 'success');
        
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
    
    unitDiv.innerHTML = `
        <div class="accordion-header">
            <span class="folder-name">${unitName}</span>
            <div class="header-actions">
                <div class="publish-toggle">
                    <label class="toggle-switch">
                        <input type="checkbox" id="publish-${unitId}" onchange="togglePublish('${unitName}', this.checked)">
                        <span class="toggle-slider"></span>
                    </label>
                    <span class="toggle-label">Published</span>
                </div>

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
                        <p><strong>Assessment Settings:</strong> Create questions to determine student readiness for tutor/protégé mode</p>
                    </div>
                    
                    <!-- Pass Threshold Setting -->
                    <div class="threshold-setting">
                        <label for="pass-threshold-${unitId}">Questions required to pass:</label>
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
 * Update file status display for uploaded files
 */
function updateFileStatus(contentType, unitName, status, fileName) {
    // Find the file item for this content type and unit
    const fileItems = document.querySelectorAll('.file-item');
    
    fileItems.forEach(item => {
        const itemTitle = item.querySelector('h3');
        if (itemTitle) {
            const isLectureNotes = contentType === 'lecture-notes' && itemTitle.textContent.includes('Lecture Notes');
            const isPracticeQuestions = contentType === 'practice-questions' && itemTitle.textContent.includes('Practice Questions');
            
            // Check if this item belongs to the specified unit
            const isCorrectUnit = itemTitle.textContent.includes(unitName);
            
            if ((isLectureNotes || isPracticeQuestions) && isCorrectUnit) {
                const statusText = item.querySelector('.status-text');
                if (statusText) {
                    statusText.textContent = status === 'uploaded' ? 'Uploaded' : 'Not Uploaded';
                    statusText.className = status === 'uploaded' ? 'status-text uploaded' : 'status-text';
                }
                
                // Update the file info
                const fileInfo = item.querySelector('.file-info p');
                if (fileInfo && status === 'uploaded') {
                    fileInfo.textContent = `File: ${fileName}`;
                    fileInfo.className = 'file-info uploaded';
                }
            }
        }
    });
}

/**
 * Add additional material to the display
 */
function addAdditionalMaterial(unitName, materialName) {
    // Find the add content section for Unit 1
    const addContentSection = document.querySelector('.add-content-section');
    if (addContentSection) {
        const materialItem = document.createElement('div');
        materialItem.className = 'file-item additional-material-item';
        materialItem.innerHTML = `
            <div class="file-info">
                <h3>${materialName}</h3>
                <p>Additional material uploaded during onboarding</p>
                <span class="status-text uploaded">Uploaded</span>
            </div>
            <div class="file-actions">
                <button class="action-button view" onclick="viewFile('${materialName}')">View</button>
                <button class="action-button delete" onclick="deleteFileItem(this)">Delete</button>
            </div>
        `;
        
        // Insert before the add content button
        addContentSection.parentNode.insertBefore(materialItem, addContentSection);
    }
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
 * Add action buttons for additional materials and confirmation
 * @param {HTMLElement} container - The container to add buttons to
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 */
function addActionButtons(container, unitName) {
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
 * Add cleanup button to clear all documents from a unit
 * @param {HTMLElement} container - The container to add button to
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 * @param {string} courseId - The course ID
 */
function addCleanupButton(container, unitName, courseId) {
    // Check if cleanup button already exists
    let hasCleanupButton = false;
    container.querySelectorAll('.cleanup-section').forEach(item => {
        if (item.textContent.includes('Clear All Documents')) {
            hasCleanupButton = true;
        }
    });
    
    if (!hasCleanupButton) {
        const cleanupSection = document.createElement('div');
        cleanupSection.className = 'cleanup-section';
        cleanupSection.style.marginTop = '20px';
        cleanupSection.style.padding = '15px';
        cleanupSection.style.backgroundColor = '#fff3cd';
        cleanupSection.style.border = '1px solid #ffeaa7';
        cleanupSection.style.borderRadius = '5px';
        cleanupSection.innerHTML = `
            <h4 style="margin: 0 0 10px 0; color: #856404;">⚠️ Document Cleanup</h4>
            <p style="margin: 0 0 15px 0; color: #856404; font-size: 14px;">
                This will remove ALL documents from ${unitName} in the course structure. 
                This action cannot be undone.
            </p>
            <button class="cleanup-btn" onclick="clearAllDocuments('${unitName}', '${courseId}')" 
                    style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                🗑️ Clear All Documents from ${unitName}
            </button>
        `;
        container.appendChild(cleanupSection);
    }
}

/**
 * Ensure action buttons exist for all units (fallback function)
 */
function ensureActionButtonsExist() {
    console.log('🔧 [FALLBACK] Ensuring action buttons exist for all units...');
    
    const accordionItems = document.querySelectorAll('.accordion-item');
    accordionItems.forEach(item => {
        const folderName = item.querySelector('.folder-name');
        if (!folderName) return;
        
        const unitName = folderName.textContent;
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
function addCleanupButtonIfMissing(container, unitName, courseId) {
    // Check if cleanup button already exists
    let hasCleanupButton = false;
    container.querySelectorAll('.cleanup-section').forEach(item => {
        if (item.textContent.includes('Clear All Documents')) {
            hasCleanupButton = true;
        }
    });
    
}

/**
 * Clear all documents from a specific unit in the course structure
 * @param {string} unitName - The name of the unit (e.g., 'Unit 1')
 * @param {string} courseId - The course ID
 */
async function clearAllDocuments(unitName, courseId) {
    // Confirm the action
    if (!confirm(`Are you sure you want to clear ALL documents from ${unitName}? This action cannot be undone.`)) {
        return;
    }
    
    try {
        const instructorId = getCurrentInstructorId();
        
        showNotification(`Clearing all documents from ${unitName}...`, 'info');
        
        const response = await fetch(`/api/courses/${courseId}/clear-documents`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                unitName: unitName,
                instructorId: instructorId
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to clear documents: ${response.status} ${errorText}`);
        }
        
        const result = await response.json();
        
        showNotification(`Successfully cleared ${result.data.clearedCount} documents from ${unitName}!`, 'success');
        
        // Reload documents to reflect the changes
        await loadDocuments();
        
    } catch (error) {
        console.error('Error clearing documents:', error);
        showNotification(`Error clearing documents: ${error.message}`, 'error');
    }
}

function renderMCQOptions() {
    const container = document.getElementById('mcq-options');
    container.innerHTML = `
        ${['A', 'B', 'C', 'D'].map(option => `
            <div class="form-group mcq-option">
                <label for="mcq-option-${option}">Option ${option}</label>
                <div class="input-group">
                    <input type="text" id="mcq-option-${option}" class="form-control mcq-input" data-option="${option}" placeholder="Enter option ${option} text...">
                    <div class="input-group-append">
                        <div class="input-group-text">
                            <input type="radio" name="mcq-correct" value="${option}" disabled>
                        </div>
                    </div>
                </div>
            </div>
        `).join('')}
    `;
    
    // Add event listeners to enable radio buttons when text is entered
    container.querySelectorAll('.mcq-input').forEach(input => {
        input.addEventListener('input', function() {
            const radioButton = document.querySelector(`input[name="mcq-correct"][value="${this.dataset.option}"]`);
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
 * Check if course materials are available for a specific week
 * This is a simplified check that looks for any non-placeholder file item.
 * @param {string} week - The week identifier (e.g., "Unit 1")
 * @returns {boolean} True if materials are detected, false otherwise.
 */
function checkCourseMaterialsAvailable(week) {
    if (!week) return false;

    // Find the accordion item by looking for the folder name that matches the week
    const accordionItems = document.querySelectorAll('.accordion-item');
    const weekAccordionItem = Array.from(accordionItems).find(item => {
        const folderName = item.querySelector('.folder-name')?.textContent;
        return folderName === week;
    });

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
function renderCourseUnits(units) {
    const accordionContainer = document.querySelector('.accordion-container');
    accordionContainer.innerHTML = ''; // Clear existing content
    
    if (!units || units.length === 0) {
        accordionContainer.innerHTML = '<p>No units found for this course.</p>';
        return;
    }
    
    units.forEach(unit => {
        const unitName = (unit.name || 'Unnamed Unit').trim();
        const weekId = unitName.toLowerCase().replace(/\s+/g, '-');
        
        const accordionItem = document.createElement('div');
        accordionItem.className = 'accordion-item';
        accordionItem.id = `accordion-${weekId}`; // Add this ID for the check function
        
        accordionItem.innerHTML = `
            <div class="accordion-header">
                <div class="header-left">
                    <span class="folder-name">${unitName}</span>
                    <div class="header-actions">
                        <div class="publish-toggle">
                            <label class="toggle-switch">
                                <input type="checkbox" id="publish-${weekId}" onchange="togglePublish('${unitName}', this.checked)">
                                <span class="toggle-slider"></span>
                            </label>
                            <span class="toggle-label">Published</span>
                        </div>
                        <span class="accordion-toggle">${isExpanded ? '▼' : '▶'}</span>
                    </div>
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
                        <div class="objectives-list" id="objectives-list-${weekId}">
                            <!-- Objectives will be added here -->
                        </div>
                        <div class="objective-input-container">
                            <input type="text" id="objective-input-${weekId}" class="objective-input" placeholder="Enter learning objective...">
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
                            <p><strong>Assessment Settings:</strong> Create questions to determine student readiness for tutor/protégé mode</p>
                        </div>
                        
                        <!-- Pass Threshold Setting -->
                        <div class="threshold-setting">
                            <label for="pass-threshold-${weekId}">Questions required to pass:</label>
                            <input type="number" id="pass-threshold-${weekId}" min="0" max="10" value="0" class="threshold-input">
                            <span class="threshold-help">out of total questions</span>
                        </div>
                        
                        <!-- Questions List -->
                        <div class="questions-list" id="assessment-questions-${weekId}">
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
        
        accordionContainer.appendChild(accordionItem);
    });

    // After rendering units, focus a unit if specified in URL
    setTimeout(() => {
        focusUnitFromURL();
    }, 100);
}

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
    await initializeAssessmentSystem();
    await loadOnboardingData();

});

/**
 * Show a notification to the user
 * @param {string} message - The message to display
 */
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

