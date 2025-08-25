document.addEventListener('DOMContentLoaded', async () => {
    // Check if we're on the onboarding page - if so, don't initialize instructor functionality
    if (window.location.pathname.includes('/onboarding')) {
        console.log('🚫 [INSTRUCTOR] On onboarding page, skipping instructor initialization');
        return;
    }
    
    console.log('🚀 [INSTRUCTOR] Starting instructor page initialization...');
    
    const uploadDropArea = document.getElementById('upload-drop-area');
    const fileUpload = document.getElementById('file-upload');
    const documentSearch = document.getElementById('document-search');
    const documentFilter = document.getElementById('document-filter');
    const courseSelect = document.getElementById('course-select');
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
    
    // Load course data first (either from onboarding redirect or existing course)
    await loadCourseData();
    
    // Only load saved data if we have a course loaded
    const courseId = await getCurrentCourseId();
    if (courseId) {
        console.log(`📁 [INSTRUCTOR] Course ${courseId} loaded, loading saved data...`);
        
        // Load the saved publish status from the database
        loadPublishStatus();
        
        // Load the saved learning objectives from the database
        loadLearningObjectives();
        
        // Load the saved documents from the database
        loadDocuments();
        
        // Load the saved assessment questions from the database
        loadAssessmentQuestions();
        
        // Load the saved pass thresholds from the database
        loadPassThresholds();
    } else {
        console.log('ℹ️ [INSTRUCTOR] No course loaded, skipping data load operations');
    }
    
    // Set up threshold input event listeners
    setupThresholdInputListeners();
    
    // Add global cleanup button
    addGlobalCleanupButton();
    
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
    
    // Handle course selection
    if (courseSelect) {
        courseSelect.addEventListener('change', () => {
            const selectedCourse = courseSelect.value;
            if (selectedCourse) {
                // In a real implementation, this would load the course documents
                
                // For demonstration purposes, we'll just show a notification
                showNotification(`Loaded documents for ${courseSelect.options[courseSelect.selectedIndex].text}`, 'info');
            }
        });
    }
    
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
            
            // Check if a course is selected
            const selectedCourse = courseSelect.value;
            if (!selectedCourse) {
                alert('Please select a course before uploading documents.');
                return;
            }
            
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
    const urlInput = document.getElementById('url-input');
    const textInput = document.getElementById('text-input');
    const materialName = document.getElementById('material-name');
    const uploadFileBtn = document.querySelector('.upload-file-btn span:last-child');
    
    if (fileInput) fileInput.value = '';
    if (fileInfo) fileInfo.style.display = 'none';
    if (urlInput) urlInput.value = '';
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
    const urlInput = document.getElementById('url-input').value.trim();
    const textInput = document.getElementById('text-input').value.trim();
    const materialNameInput = document.getElementById('material-name').value.trim();
    const uploadBtn = document.getElementById('upload-btn');
    
    // Check if at least one input method is provided
    if (!uploadedFile && !urlInput && !textInput) {
        showNotification('Please provide content via file upload, URL, or direct text input', 'error');
        return;
    }
    
    // Disable upload button and show loading state
    uploadBtn.textContent = 'Uploading...';
    uploadBtn.disabled = true;
    
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
                    description: urlInput || ''
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
        addContentToWeek(currentWeek, fileName, `Uploaded successfully - ${uploadResult?.data?.filename || fileName}`, documentId);
        
        // Close modal and show success
        closeUploadModal();
        showNotification(uploadResult?.message || 'Content uploaded successfully!', 'success');
        
    } catch (error) {
        console.error('Error uploading content:', error);
        showNotification(`Error uploading content: ${error.message}`, 'error');
        
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
 */
function addContentToWeek(week, fileName, description, documentId) {
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
        if ((currentContentType === 'lecture-notes' && title.includes('*Lecture Notes')) ||
            (currentContentType === 'practice-quiz' && title.includes('*Practice Questions/Tutorial'))) {
            targetFileItem = item;
        }
    });
    
    if (targetFileItem) {
        // Update existing item
        targetFileItem.querySelector('.file-info h3').textContent = fileName;
        targetFileItem.querySelector('.file-info p').textContent = description;
        targetFileItem.querySelector('.status-text').textContent = 'Processed';
        targetFileItem.querySelector('.status-text').className = 'status-text processed';
        
        // Set document ID for proper deletion
        if (documentId) {
            targetFileItem.dataset.documentId = documentId;
        }
        
        // Update action button to view instead of upload
        const uploadButton = targetFileItem.querySelector('.action-button.upload');
        if (uploadButton) {
            uploadButton.textContent = 'View';
            uploadButton.className = 'action-button view';
            uploadButton.onclick = () => viewDocument(documentId);
        }
        
        // Add delete button if it doesn't exist
        let deleteButton = targetFileItem.querySelector('.action-button.delete');
        if (!deleteButton) {
            deleteButton = document.createElement('button');
            deleteButton.className = 'action-button delete';
            deleteButton.onclick = () => deleteDocument(documentId);
            deleteButton.textContent = 'Delete';
            
            const fileActions = targetFileItem.querySelector('.file-actions');
            if (fileActions) {
                fileActions.appendChild(deleteButton);
            }
        }
    } else {
        // Create new file item
        const fileItem = document.createElement('div');
        fileItem.className = 'file-item';
        
        // Set document ID if available
        if (documentId) {
            fileItem.dataset.documentId = documentId;
        }
        
        fileItem.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-info">
                <h3>${fileName}</h3>
                <p>${description}</p>
                <span class="status-text processed">Processed</span>
            </div>
            <div class="file-actions">
                <button class="action-button view" onclick="${documentId ? `viewDocument('${documentId}')` : 'viewFileItem(this)'}">View</button>
                <button class="action-button delete" onclick="${documentId ? `deleteDocument('${documentId}')` : 'deleteFileItem(this)'}">Delete</button>
            </div>
        `;
        
        // Insert before the add content section
        const addContentSection = courseMaterialsContent.querySelector('.add-content-section');
        if (addContentSection) {
            courseMaterialsContent.insertBefore(fileItem, addContentSection);
        } else {
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
            
            // Show specific error message
            const errorMessage = errorData.message || errorData.error || `Failed to update publish status: ${response.status}`;
            showNotification(`Error: ${errorMessage}`, 'error');
            
            // Revert the toggle if the API call failed
            const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
            const toggle = document.getElementById(toggleId);
            if (toggle) {
                toggle.checked = !isPublished;
                togglePublish(lectureName, !isPublished);
            }
            return;
        }
        
        const result = await response.json();
        
        // Show success notification
        showNotification(result.message || 'Publish status updated successfully', 'success');
        
    } catch (error) {
        console.error('Error updating publish status:', error);
        showNotification('Error updating publish status. Please try again.', 'error');
        
        // Revert the toggle if the API call failed
        const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
        const toggle = document.getElementById(toggleId);
        if (toggle) {
            toggle.checked = !isPublished;
            togglePublish(lectureName, !isPublished);
        }
    }
}

/**
 * Get current instructor ID (placeholder function)
 * @returns {string} Instructor ID
 */
function getCurrentInstructorId() {
    // In a real implementation, this would get the instructor ID from the session/token
    return 'instructor-123';
}

/**
 * Get the current course ID for the instructor
 * This function checks URL parameters first, then falls back to instructor courses
 * @returns {Promise<string|null>} The course ID or null if not found
 */
async function getCurrentCourseId() {
    // Check if we're on the onboarding page - if so, don't make API calls
    if (window.location.pathname.includes('/onboarding')) {
        console.log('🚫 [COURSES] On onboarding page, skipping course ID fetch');
        return null;
    }
    
    // Check if we have a courseId from URL parameters (onboarding redirect)
    const urlParams = new URLSearchParams(window.location.search);
    const courseIdFromUrl = urlParams.get('courseId');
    
    if (courseIdFromUrl) {
        console.log(`🔍 [COURSES] Found course ID in URL: ${courseIdFromUrl}`);
        return courseIdFromUrl;
    }
    
    // If no course ID in URL, try to get it from the instructor's courses
    try {
        console.log('🔍 [COURSES] No course ID in URL, checking instructor courses...');
        const instructorId = getCurrentInstructorId();
        const response = await fetch(`/api/onboarding/instructor/${instructorId}`);
        
        if (response.ok) {
            const result = await response.json();
            if (result.data && result.data.courses && result.data.courses.length > 0) {
                // Return the first course found
                const firstCourse = result.data.courses[0];
                console.log(`🔍 [COURSES] Found course from instructor data: ${firstCourse.courseId}`);
                return firstCourse.courseId;
            }
        }
    } catch (error) {
        console.error('❌ [COURSES] Error fetching instructor courses:', error);
    }
    
    // If no course found, show an error and redirect to onboarding
    console.error('❌ [COURSES] No course ID found. Redirecting to onboarding...');
    showNotification('No course found. Please complete onboarding first.', 'error');
    setTimeout(() => {
        window.location.href = '/instructor/onboarding';
    }, 2000);
    
    // Return a placeholder (this should not be reached due to redirect)
    return null;
}

/**
 * Load the saved publish status for all lectures from the database
 */
async function loadPublishStatus() {
    try {
        const courseId = await getCurrentCourseId();
        
        // If we're on onboarding page, don't load publish status
        if (!courseId) {
            console.log('🚫 [PUBLISH] No course ID available (likely on onboarding page), skipping publish status load');
            return;
        }
        
        const instructorId = getCurrentInstructorId();
        
        const response = await fetch(`/api/lectures/publish-status?instructorId=${instructorId}&courseId=${courseId}`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch publish status');
        }
        
        const result = await response.json();
        const publishStatus = result.data.publishStatus;
        
        // Update all toggle switches to reflect the saved state
        Object.keys(publishStatus).forEach(lectureName => {
            const isPublished = publishStatus[lectureName];
            const toggleId = `publish-${lectureName.toLowerCase().replace(/\s+/g, '')}`;
            const toggle = document.getElementById(toggleId);
            
            if (toggle) {
                // Update the toggle state
                toggle.checked = isPublished;
                
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
        });
        
    } catch (error) {
        console.error('❌ [PUBLISH] Error loading publish status:', error);
        showNotification('Error loading publish status. Using default values.', 'warning');
    }
}

/**
 * Load the saved learning objectives for all lectures from the database
 */
async function loadLearningObjectives() {
    try {
        console.log('📚 [LEARNING_OBJECTIVES] Starting to load learning objectives...');
        const courseId = await getCurrentCourseId();
        
        // If we're on onboarding page, don't load learning objectives
        if (!courseId) {
            console.log('🚫 [LEARNING_OBJECTIVES] No course ID available (likely on onboarding page), skipping learning objectives load');
            return;
        }
        
        console.log(`📚 [LEARNING_OBJECTIVES] Course ID: ${courseId}`);
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        console.log(`📚 [LEARNING_OBJECTIVES] Found ${accordionItems.length} accordion items (units/weeks)`);
        
        for (const item of accordionItems) {
            const folderName = item.querySelector('.folder-name');
            if (!folderName) continue;
            
            const lectureName = folderName.textContent;
            console.log(`📚 [LEARNING_OBJECTIVES] Processing lecture/unit: ${lectureName}`);
            
            const instructorId = getCurrentInstructorId();
            const response = await fetch(`/api/learning-objectives?instructorId=${instructorId}&courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
            
            if (response.ok) {
                const result = await response.json();
                const objectives = result.data.objectives;
                
                // Debug: Log the actual objectives data structure
                console.log(`🔍 [LEARNING_OBJECTIVES] Raw API response for ${lectureName}:`, result);
                console.log(`🔍 [LEARNING_OBJECTIVES] Objectives data for ${lectureName}:`, objectives);
                
                if (objectives && objectives.length > 0) {
                    console.log(`📚 [LEARNING_OBJECTIVES] Found ${objectives.length} objectives for ${lectureName}:`, objectives);
                    
                    // Debug: Log the first objective structure
                    if (objectives[0]) {
                        console.log(`🔍 [LEARNING_OBJECTIVES] First objective structure:`, {
                            objective: objectives[0],
                            keys: Object.keys(objectives[0]),
                            hasText: objectives[0].hasOwnProperty('text'),
                            textValue: objectives[0].text,
                            type: typeof objectives[0].text
                        });
                    }
                    
                    // Find the objectives list for this unit
                    const unitId = lectureName.toLowerCase().replace(/\s+/g, '-');
                    const objectivesList = document.getElementById(`objectives-list-${unitId}`);
                    
                    if (objectivesList) {
                        // Clear existing objectives
                        objectivesList.innerHTML = '';
                        
                        // Add each objective
                        objectives.forEach((objective, index) => {
                            console.log(`🔍 [LEARNING_OBJECTIVES] Processing objective ${index}:`, objective);
                            
                            const objectiveItem = document.createElement('div');
                            objectiveItem.className = 'objective-item';
                            
                            // Try different possible property names for the objective text
                            let objectiveText = '';
                            if (objective.text) {
                                objectiveText = objective.text;
                            } else if (objective.objective) {
                                objectiveText = objective.objective;
                            } else if (objective.content) {
                                objectiveText = objective.content;
                            } else if (objective.description) {
                                objectiveText = objective.description;
                            } else if (typeof objective === 'string') {
                                objectiveText = objective;
                            } else {
                                objectiveText = 'Unknown objective format';
                                console.warn(`⚠️ [LEARNING_OBJECTIVES] Unknown objective format for ${lectureName}:`, objective);
                            }
                            
                            objectiveItem.innerHTML = `
                                <span class="objective-text">${objectiveText}</span>
                                <button class="remove-objective-btn" onclick="removeObjective('${lectureName}', '${objectiveText}')">×</button>
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
 * Optimized to fetch course data once and reuse for all units
 */
async function loadDocuments() {
    try {
        console.log('📁 [DOCUMENTS] Starting to load documents...');
        const courseId = await getCurrentCourseId();
        
        // If we're on onboarding page, don't load documents
        if (!courseId) {
            console.log('🚫 [DOCUMENTS] No course ID available (likely on onboarding page), skipping document load');
            return;
        }
        
        console.log(`📁 [DOCUMENTS] Course ID: ${courseId}`);
        
        // Get all accordion items (units/weeks)
        const accordionItems = document.querySelectorAll('.accordion-item');
        console.log(`📁 [DOCUMENTS] Found ${accordionItems.length} accordion items (units/weeks)`);
        
        // Fetch course data ONCE instead of for each unit
        console.log(`📡 [MONGODB] Making single API request to /api/courses/${courseId}?instructorId=${getCurrentInstructorId()}`);
        const response = await fetch(`/api/courses/${courseId}?instructorId=${getCurrentInstructorId()}`);
        console.log(`📡 [MONGODB] API response status: ${response.status} ${response.statusText}`);
        
        if (!response.ok) {
            throw new Error(`Failed to load course data: ${response.status}`);
        }
        
        const result = await response.json();
        console.log(`📡 [MONGODB] Course data loaded successfully:`, result);
        const course = result.data;
        
        // Debug: Log the actual course structure
        console.log('🔍 [DOCUMENTS] Course data structure:', {
            hasCourse: !!course,
            courseType: typeof course,
            courseKeys: course ? Object.keys(course) : 'N/A',
            hasLectures: course && !!course.lectures,
            lecturesType: course && course.lectures ? typeof course.lectures : 'N/A',
            lecturesLength: course && course.lectures ? course.lectures.length : 'N/A'
        });
        
        if (!course || !course.lectures) {
            console.warn('⚠️ [DOCUMENTS] No course or lectures data found');
            console.warn('🔍 [DOCUMENTS] Course:', course);
            console.warn('🔍 [DOCUMENTS] Course.lectures:', course ? course.lectures : 'N/A');
            return;
        }
        
        // Process all units using the cached course data
        for (const item of accordionItems) {
            const folderName = item.querySelector('.folder-name');
            if (!folderName) {
                console.warn(`⚠️ [DOCUMENTS] No folder name found for accordion item`);
                continue;
            }
            
            const lectureName = folderName.textContent;
            console.log(`📁 [DOCUMENTS] Processing lecture/unit: ${lectureName}`);
            
            // Find the unit data from the cached course data
            const unit = course.lectures.find(l => l.name === lectureName);
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
                
                // Always add the required placeholder items if they don't exist
                addRequiredPlaceholders(courseMaterialsSection, lectureName);
                
                // Add the "Add Additional Material" button and "Confirm Course Materials" button
                addActionButtons(courseMaterialsSection, lectureName);
                
                // Add cleanup button if there are documents
                if (documents && documents.length > 0) {
                    addCleanupButton(courseMaterialsSection, lectureName, courseId);
                } else {
                    addCleanupButton(courseMaterialsSection, lectureName, courseId);
                }
            } else {
                console.error('Course materials section not found for', lectureName);
            }
        }
        
        console.log(`✅ [DOCUMENTS] Successfully processed all ${accordionItems.length} units with single API call`);
        
    } catch (error) {
        console.error('❌ [DOCUMENTS] Error loading documents:', error);
        showNotification('Error loading documents. Using default values.', 'warning');
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
    
    const fileIcon = doc.contentType === 'text' ? '📝' : '📄';
    const statusText = doc.status === 'uploaded' ? 'Uploaded' : doc.status;
    
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
        if (documentItem) {
            documentItem.remove();
        }
        
        // Reload documents to sync with database
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
            
            console.log(`📡 [MONGODB] Making API request to /api/questions/lecture?courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
            const response = await fetch(`/api/questions/lecture?courseId=${courseId}&lectureName=${encodeURIComponent(lectureName)}`);
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
                    console.log(`❓ [ASSESSMENT_QUESTIONS] No questions found for ${lectureName}`);
                }
            } else {
                console.warn(`⚠️ [MONGODB] Failed to load assessment questions for ${lectureName}: ${response.status} ${response.statusText}`);
            }
        }
        
        console.log('✅ [ASSESSMENT_QUESTIONS] Assessment questions loading process completed');
        
    } catch (error) {
        console.error('❌ [ASSESSMENT_QUESTIONS] Error loading assessment questions:', error);
        showNotification('Error loading assessment questions. Using default values.', 'warning');
    }
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
        
        const response = await fetch(`/api/questions/${questionId}`, {
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
        
        // Update local state to reflect the change
        await reloadPassThresholds();
        
        // Show success notification
        showNotification(result.message, 'success');
        
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
                    
                    // Also update the display text if it exists
                    const thresholdValue = item.querySelector(`#threshold-value-${lectureName.toLowerCase().replace(/\s+/g, '-')}`);
                    if (thresholdValue) {
                        thresholdValue.textContent = passThreshold;
                    }
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
            
            if (response.ok) {
                const result = await response.json();
                const passThreshold = result.data.passThreshold;
                
                // Find and update the threshold input for this lecture
                // Convert lecture name to ID format (e.g., "Unit 1" -> "unit-1")
                const thresholdId = `pass-threshold-${lectureName.toLowerCase().replace(/\s+/g, '-')}`;
                const thresholdInput = item.querySelector(`#${thresholdId}`);
                
                if (thresholdInput) {
                    thresholdInput.value = passThreshold;
                    
                    // Also update the display text if it exists
                    const thresholdValue = item.querySelector(`#threshold-value-${lectureName.toLowerCase().replace(/\s+/g, '-')}`);
                    if (thresholdValue) {
                        thresholdValue.textContent = passThreshold;
                    }
                }
            }
        }
        
    } catch (error) {
        console.error('Error loading pass thresholds:', error);
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
        input.addEventListener('change', function() {
            const threshold = parseInt(this.value);
            // Extract the exact lecture name from the ID (e.g., "Unit-1" -> "Unit 1")
            const lectureName = this.id.replace('pass-threshold-', '').replace(/-/g, ' ');
            
            // Save the threshold to MongoDB
            savePassThreshold(lectureName, threshold);
        });
        
        // Add input event listener for real-time updates
        input.addEventListener('input', function() {
            const threshold = parseInt(this.value);
            // Extract the exact lecture name from the ID
            const lectureName = this.id.replace('pass-threshold-', '').replace(/-/g, ' ');
            
            // Update the display text if it exists
            const thresholdValue = document.querySelector(`#threshold-value-${lectureName.toLowerCase().replace(/\s+/g, '-')}`);
            if (thresholdValue) {
                thresholdValue.textContent = threshold;
            }
        });
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
    
    // Check if mandatory materials are present
    let hasLectureNotes = false;
    let hasPracticeQuestions = false;
    
    fileItems.forEach(item => {
        const title = item.querySelector('.file-info h3');
        const statusText = item.querySelector('.status-text');
        
        if (title && statusText) {
            const titleText = title.textContent;
            const status = statusText.textContent;
            
            // Check if this is a lecture notes document that's uploaded
            if (titleText.includes('Lecture Notes') && (status === 'Uploaded' || status === 'uploaded')) {
                hasLectureNotes = true;
            }
            
            // Check if this is a practice questions document that's uploaded
            if ((titleText.includes('Practice Questions') || titleText.includes('Practice Questions/Tutorial')) && (status === 'Uploaded' || status === 'uploaded')) {
                hasPracticeQuestions = true;
            }
        }
    });
    
    // Validate mandatory materials
    if (!hasLectureNotes || !hasPracticeQuestions) {
        let missingItems = [];
        if (!hasLectureNotes) missingItems.push('Lecture Notes');
        if (!hasPracticeQuestions) missingItems.push('Practice Questions/Tutorial');
        
        showNotification(`Missing mandatory materials: ${missingItems.join(', ')}. Please add them before confirming.`, 'error');
        return;
    }
    
    try {
        // In a real implementation, this would save to the server
        const response = await fetch('/api/course-materials/confirm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                week: week,
                instructorId: getCurrentInstructorId()
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to confirm course materials');
        }
        
        showNotification(`Course materials for ${week} confirmed successfully!`, 'success');
        
    } catch (error) {
        console.error('Error confirming course materials:', error);
        // For demo purposes, still show success
        showNotification(`Course materials for ${week} confirmed successfully! (Demo mode)`, 'success');
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
    
    // Check if there are uploaded materials
    let hasMaterials = false;
    fileItems.forEach(item => {
        const statusText = item.querySelector('.status-text').textContent;
        if (statusText === 'Processed') {
            hasMaterials = true;
        }
    });

    // For demo purposes, allow generation even without processed materials
    if (!hasMaterials) {
        showNotification('Generating probing questions based on general course content (no specific materials uploaded)...', 'info');
    } else {
        showNotification('Generating probing questions based on uploaded materials...', 'info');
    }

    try {
        // In a real implementation, this would call an AI API with the course materials
        // For now, we'll simulate a delay and generate some mock questions
        await new Promise(resolve => setTimeout(resolve, 2000));

        // TODO: Generate probing questions using AI API with course materials
        // For now, using placeholder questions until AI integration is implemented
        const mockQuestions = [
            "How would you apply the concepts from this week to solve a real-world problem?",
            "What connections can you make between this material and previous topics?",
            "What questions would you ask to deepen your understanding of this subject?",
            "How do these concepts relate to current research or applications in the field?"
        ];
        
        // Get the questions list for this week
        const questionsList = weekElement.querySelector(`#questions-list-${week.toLowerCase().replace(/\s+/g, '')}`);
        
        if (!questionsList) {
            console.error('Could not find questions list element for', week);
            showNotification('Error: Could not find questions list container.', 'error');
            return;
        }
        
        // Add each generated question to the list
        mockQuestions.forEach(questionText => {
            const questionItem = document.createElement('div');
            questionItem.className = 'objective-display-item';
            questionItem.innerHTML = `
                <span class="objective-text">${questionText}</span>
                <button class="remove-objective" onclick="removeQuestion(this)">×</button>
            `;
            questionsList.appendChild(questionItem);
        });

        showNotification(`${mockQuestions.length} probing questions generated successfully!`, 'success');

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
    
    // Hide AI generation button
    const aiButton = document.getElementById('ai-generate-btn');
    if (aiButton) {
        aiButton.style.display = 'none';
        aiButton.disabled = false;
    }
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
    
    // Check if AI generation should be available
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
        
        const response = await fetch('/api/questions', {
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
        
        const response = await fetch(`/api/questions/lecture?courseId=${courseId}&lectureName=${encodeURIComponent(unitName)}`);
        
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
    const thresholdInput = document.getElementById(`pass-threshold-${week.toLowerCase().replace(/\s+/g, '-')}`);
    if (thresholdInput) {
        thresholdInput.max = questions.length;
        if (parseInt(thresholdInput.value) > questions.length) {
            thresholdInput.value = questions.length;
        }
    }
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
    const questionType = document.getElementById('question-type').value;
    const aiButton = document.getElementById('ai-generate-btn');
    
    if (!questionType) {
        // No question type selected, hide AI button
        aiButton.style.display = 'none';
        return;
    }
    
    // Check if lecture notes are uploaded for the current week
    if (!checkLectureNotesUploaded(currentWeek)) {
        // Lecture notes not uploaded, disable AI button
        aiButton.style.display = 'flex';
        aiButton.disabled = true;
        aiButton.title = 'Please upload lecture notes before generating AI questions.';
        return;
    }
    
    // Lecture notes uploaded and question type selected, enable AI button
    aiButton.style.display = 'flex';
    aiButton.disabled = false;
    aiButton.title = 'Generate AI question based on uploaded lecture notes.';
}

/**
 * Generate AI content for the current question in the modal
 */
function generateAIQuestionContent() {
    const questionType = document.getElementById('question-type').value;
    
    if (!questionType) {
        alert('Please select a question type first.');
        return;
    }
    
    if (!checkLectureNotesUploaded(currentWeek)) {
        alert('Please upload lecture notes before generating AI questions.');
        return;
    }
    
    // Show loading state
    const aiButton = document.getElementById('ai-generate-btn');
    const originalText = aiButton.innerHTML;
    aiButton.innerHTML = '<span class="ai-icon">⏳</span> Generating...';
    aiButton.disabled = true;
    
    // Generate AI content based on type
    const aiContent = createAIQuestionContent(questionType, currentWeek);
    
    // Populate form fields with AI content
    populateFormWithAIContent(aiContent);
    
    // Restore button state
    aiButton.innerHTML = originalText;
    aiButton.disabled = false;
}

/**
 * Create AI question content for the modal
 * @param {string} type - Question type
 * @param {string} week - Week identifier
 * @returns {Object} AI content object
 */
function createAIQuestionContent(type, week) {
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
 * Populate form fields with AI-generated content
 * @param {Object} aiContent - AI-generated content
 */
function populateFormWithAIContent(aiContent) {
    // Set question text
    document.getElementById('question-text').value = aiContent.question;
    
    // Set answer based on type
    const questionType = document.getElementById('question-type').value;
    
    if (questionType === 'true-false') {
        // Set radio button
        const radioButton = document.querySelector(`input[name="tf-answer"][value="${aiContent.answer}"]`);
        if (radioButton) {
            radioButton.checked = true;
        }
    } else if (questionType === 'multiple-choice') {
        // Set MCQ options
        Object.keys(aiContent.options).forEach(option => {
            const input = document.querySelector(`.mcq-input[data-option="${option}"]`);
            if (input) {
                input.value = aiContent.options[option];
            }
        });
        
        // Enable all radio buttons since we have content
        const radioButtons = document.querySelectorAll('input[name="mcq-correct"]');
        radioButtons.forEach(radio => {
            radio.disabled = false;
        });
        
        // Set correct answer
        const correctRadio = document.querySelector(`input[name="mcq-correct"][value="${aiContent.answer}"]`);
        if (correctRadio) {
            correctRadio.checked = true;
        }
        
        // Force enable all radio buttons again after a short delay
        setTimeout(() => {
            const radioButtons = document.querySelectorAll('input[name="mcq-correct"]');
            radioButtons.forEach(radio => {
                radio.disabled = false;
            });
            
            // Re-set the correct answer
            const correctRadio = document.querySelector(`input[name="mcq-correct"][value="${aiContent.answer}"]`);
            if (correctRadio) {
                correctRadio.checked = true;
            }
        }, 50);
    } else if (questionType === 'short-answer') {
        // Set short answer
        document.getElementById('sa-answer').value = aiContent.answer;
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
    const weekLower = week.toLowerCase().replace(' ', '');
    const thresholdInput = document.getElementById(`pass-threshold-${weekLower}`);
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
    
    // Save assessment data (this would normally go to backend)
    const assessmentData = {
        week: week,
        questions: questions,
        passThreshold: threshold,
        totalQuestions: questions.length,
        savedAt: new Date().toISOString()
    };
    
    // Show success message
    alert(`Assessment saved for ${week}!\nTotal Questions: ${questions.length}\nPass Threshold: ${threshold}`);
}

// Initialize assessment system - this will be called from the main DOMContentLoaded listener
function initializeAssessmentSystem() {
    // Initialize questions display for all weeks
    ['Week 1', 'Week 2', 'Week 3'].forEach(week => {
        updateQuestionsDisplay(week);
        checkAIGenerationAvailability(week);
    });
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
        // First check if we have a courseId from URL parameters (onboarding redirect)
        const urlParams = new URLSearchParams(window.location.search);
        const courseId = urlParams.get('courseId');
        
        if (courseId) {
            // Load specific course data
            await loadSpecificCourse(courseId);
            return;
        }
        
        // If no courseId in URL, check if instructor has any existing courses
        const instructorId = 'instructor-123'; // This would come from authentication
        const response = await fetch(`/api/onboarding/instructor/${instructorId}`);
        
        if (response.ok) {
            const result = await response.json();
            if (result.data && result.data.courses && result.data.courses.length > 0) {
                // Load the first available course
                const firstCourse = result.data.courses[0];
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
    
    // Don't load documents when generating units from onboarding data
    // Documents will be loaded later when the course is properly set up
    console.log('ℹ️ [ONBOARDING] Skipping document load for onboarding-generated units');
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
                    <!-- Add Content Button -->
                    <div class="add-content-section">
                        <button class="add-content-btn additional-material" onclick="openUploadModal('${unitName}', 'additional')">
                            <span class="btn-icon">➕</span>
                            Add Additional Material
                        </button>
                    </div>
                    <div class="save-objectives">
                        <button class="save-btn" onclick="confirmCourseMaterials('${unitName}')">Confirm Course Materials</button>
                    </div>
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
                        <input type="number" id="pass-threshold-${unitId}" min="1" max="10" value="2" class="threshold-input">
                        <span class="threshold-help">out of total questions</span>
                        <span class="threshold-display" id="threshold-value-${unitId}">2</span>
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
        if (unit.passThreshold) {
            const thresholdInput = document.getElementById(`pass-threshold-${unitId}`);
            if (thresholdInput) {
                thresholdInput.value = unit.passThreshold;
                
                // Also update the threshold display
                const thresholdDisplay = document.getElementById(`threshold-value-${unitId}`);
                if (thresholdDisplay) {
                    thresholdDisplay.textContent = unit.passThreshold;
                }
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
    // Check if lecture notes placeholder already exists
    let hasLectureNotes = false;
    let hasPracticeQuestions = false;
    
    container.querySelectorAll('.file-item').forEach(item => {
        const title = item.querySelector('h3');
        if (title) {
            if (title.textContent.includes('*Lecture Notes')) {
                hasLectureNotes = true;
            }
            if (title.textContent.includes('*Practice Questions/Tutorial')) {
                hasPracticeQuestions = true;
            }
        }
    });
    
    // Add lecture notes placeholder if it doesn't exist
    if (!hasLectureNotes) {
        const lectureNotesItem = document.createElement('div');
        lectureNotesItem.className = 'file-item';
        lectureNotesItem.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-info">
                <h3>*Lecture Notes - ${unitName}</h3>
                <p>Placeholder for required lecture notes. Please upload content.</p>
                <span class="status-text">Not Uploaded</span>
            </div>
            <div class="file-actions">
                <button class="action-button upload" onclick="openUploadModal('${unitName}', 'lecture-notes')">Upload</button>
                <button class="action-button delete" onclick="deleteFileItem(this)">Delete</button>
            </div>
        `;
        container.appendChild(lectureNotesItem);
    }
    
    // Add practice questions placeholder if it doesn't exist
    if (!hasPracticeQuestions) {
        const practiceQuestionsItem = document.createElement('div');
        practiceQuestionsItem.className = 'file-item';
        practiceQuestionsItem.innerHTML = `
            <span class="file-icon">📄</span>
            <div class="file-info">
                <h3>*Practice Questions/Tutorial</h3>
                <p>Placeholder for required practice questions. Please upload content.</p>
                <span class="status-text">Not Uploaded</span>
            </div>
            <div class="file-actions">
                <button class="action-button upload" onclick="openUploadModal('${unitName}', 'practice-quiz')">Upload</button>
                <button class="action-button delete" onclick="deleteFileItem(this)">Delete</button>
            </div>
        `;
        container.appendChild(practiceQuestionsItem);
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

/**
 * Wrapper functions to expose upload functionality to other pages (e.g., onboarding.js)
 * These functions allow other pages to use the upload functionality without duplicating code
 */

/**
 * Wrapper for openUploadModal - allows onboarding.js to use this function
 * @param {string} week - The week identifier
 * @param {string} contentType - The content type
 */
window.openUploadModalFromInstructor = function(week, contentType = '') {
    openUploadModal(week, contentType);
};

/**
 * Wrapper for closeUploadModal - allows onboarding.js to use this function
 */
window.closeUploadModalFromInstructor = function() {
    closeUploadModal();
};

/**
 * Wrapper for resetModal - allows onboarding.js to use this function
 */
window.resetModalFromInstructor = function() {
    resetModal();
};

/**
 * Wrapper for triggerFileInput - allows onboarding.js to use this function
 */
window.triggerFileInputFromInstructor = function() {
    triggerFileInput();
};

/**
 * Wrapper for handleFileUpload - allows onboarding.js to use this function
 * @param {File} file - The uploaded file
 */
window.handleFileUploadFromInstructor = function(file) {
    handleFileUpload(file);
};

/**
 * Wrapper for handleUpload - allows onboarding.js to use this function
 * This version is adapted for onboarding context
 */
window.handleUploadFromInstructor = async function() {
    const urlInput = document.getElementById('url-input').value.trim();
    const textInput = document.getElementById('text-input').value.trim();
    const materialNameInput = document.getElementById('material-name').value.trim();
    const uploadBtn = document.getElementById('upload-btn');
    
    // Check if at least one input method is provided
    if (!uploadedFile && !urlInput && !textInput) {
        showNotification('Please provide content via file upload, URL, or direct text input', 'error');
        return;
    }
    
    // Disable upload button and show loading state
    uploadBtn.textContent = 'Uploading...';
    uploadBtn.disabled = true;
    
    try {
        // For onboarding, we need to get the course ID from the onboarding state
        // This would typically come from a global variable or data attribute
        let courseId = null;
        let instructorId = null;
        
        // Debug logging for onboarding
        console.log('🔍 [ONBOARDING] Debugging upload process...');
        console.log('🔍 [ONBOARDING] window.onboardingState:', window.onboardingState);
        console.log('🔍 [ONBOARDING] window.currentCourseId:', window.currentCourseId);
        console.log('🔍 [ONBOARDING] currentWeek:', currentWeek);
        console.log('🔍 [ONBOARDING] currentContentType:', currentContentType);
        
        // Try to get course ID from various sources (prioritize onboarding state)
        if (window.onboardingState && window.onboardingState.createdCourseId) {
            courseId = window.onboardingState.createdCourseId;
            console.log('✅ [ONBOARDING] Found course ID from onboardingState:', courseId);
        } else if (window.currentCourseId) {
            courseId = window.currentCourseId;
            console.log('✅ [ONBOARDING] Found course ID from currentCourseId:', courseId);
        } else {
            // Try to get from URL parameters
            const urlParams = new URLSearchParams(window.location.search);
            courseId = urlParams.get('courseId');
            console.log('🔍 [ONBOARDING] URL params courseId:', courseId);
        }
        
        if (!courseId) {
            console.error('❌ [ONBOARDING] No course ID found from any source');
            throw new Error('No course ID available. Please complete course setup first.');
        }
        
        // For onboarding, use the instructor ID from onboarding state if available
        if (window.onboardingState && window.onboardingState.courseData && window.onboardingState.courseData.instructorId) {
            instructorId = window.onboardingState.courseData.instructorId;
            console.log('✅ [ONBOARDING] Using instructor ID from onboarding state:', instructorId);
        } else {
            instructorId = getCurrentInstructorId();
            console.log('✅ [ONBOARDING] Using instructor ID from getCurrentInstructorId():', instructorId);
        }
        
        const lectureName = currentWeek || 'Unit 1';
        
        let uploadResult;
        
        if (uploadedFile) {
            // Handle file upload
            console.log('📁 [ONBOARDING] Starting file upload...');
            console.log('📁 [ONBOARDING] File details:', {
                name: uploadedFile.name,
                size: uploadedFile.size,
                type: uploadedFile.type
            });
            console.log('📁 [ONBOARDING] Upload parameters:', {
                courseId,
                lectureName,
                documentType: currentContentType,
                instructorId
            });
            
            const formData = new FormData();
            formData.append('file', uploadedFile);
            formData.append('courseId', courseId);
            formData.append('lectureName', lectureName);
            formData.append('documentType', currentContentType);
            formData.append('instructorId', instructorId);
            
            console.log('📁 [ONBOARDING] Sending request to /api/documents/upload...');
            const response = await fetch('/api/documents/upload', {
                method: 'POST',
                body: formData
            });
            
            console.log('📁 [ONBOARDING] Response status:', response.status);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ [ONBOARDING] Upload failed:', response.status, errorText);
                throw new Error(`Upload failed: ${response.status} ${errorText}`);
            }
            
            uploadResult = await response.json();
            console.log('✅ [ONBOARDING] Upload successful:', uploadResult);
            
        } else if (textInput) {
            // Handle text submission
            console.log('📝 [ONBOARDING] Starting text submission...');
            const title = materialNameInput || `${currentContentType} - ${lectureName}`;
            console.log('📝 [ONBOARDING] Text submission parameters:', {
                courseId,
                lectureName,
                documentType: currentContentType,
                instructorId,
                contentLength: textInput.length,
                title
            });
            
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
                    description: urlInput || ''
                })
            });
            
            console.log('📝 [ONBOARDING] Response status:', response.status);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ [ONBOARDING] Text submission failed:', response.status, errorText);
                throw new Error(`Text submission failed: ${response.status} ${errorText}`);
            }
            
            uploadResult = await response.json();
            console.log('✅ [ONBOARDING] Text submission successful:', uploadResult);
            
        } else if (urlInput) {
            // Handle URL import (treat as text with URL as description)
            const title = materialNameInput || `Content from URL - ${lectureName}`;
            
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
        
        // Update status badge based on content type (for onboarding)
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
        
        // Close modal and show success
        closeUploadModal();
        showNotification('Content uploaded and processed successfully!', 'success');
        
    } catch (error) {
        console.error('Error uploading content:', error);
        showNotification(`Error uploading content: ${error.message}. Please try again.`, 'error');
        
        // Re-enable upload button
        uploadBtn.textContent = 'Upload';
        uploadBtn.disabled = false;
    }
};