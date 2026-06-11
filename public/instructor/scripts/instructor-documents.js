/**
 * Instructor: document list, view/download/delete, material status.
 */

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
            ${buildDocumentActionButtons(doc.documentId)}
        </div>
    `;
    
    return documentItem;
}

/**
 * Download the original source file for a document
 * @param {string} documentId - Document identifier
 */
async function downloadDocument(documentId) {
    try {
        const response = await fetch(`/api/documents/${documentId}/download`);

        if (!response.ok) {
            const contentType = response.headers.get('Content-Type') || '';
            let message = 'Unable to download this document.';

            if (contentType.includes('application/json')) {
                const errorData = await response.json();
                message = errorData.message || message;
            } else {
                const errorText = await response.text();
                if (errorText && errorText.trim()) {
                    message = errorText.trim();
                }
            }

            throw new Error(message);
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const disposition = response.headers.get('Content-Disposition') || '';
        const fileName = extractFilenameFromDisposition(disposition) || `document-${documentId}`;
        const link = document.createElement('a');

        link.href = url;
        link.download = fileName;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (error) {
        console.error('Error downloading document:', error);
        showNotification(`Error downloading document: ${error.message}`, 'error');
    }
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
                    display: flex;
                    justify-content: flex-end;
                    gap: 10px;
                    border-top: 1px solid #eee;
                    padding-top: 10px;
                ">
                    ${(documentData.documentType === 'practice-quiz' || documentData.documentType === 'practice_q_tutorials') ? `
                    <button onclick="extractAssessmentQuestions('${documentData.documentId}', '${(documentData.lectureName || '').replace(/'/g, "\\'")}', '${documentData.courseId || ''}')" style="
                        background: #2563eb;
                        color: white;
                        border: none;
                        padding: 8px 16px;
                        border-radius: 4px;
                        cursor: pointer;
                        font-weight: 500;
                    ">Find Assessment Questions</button>
                    ` : ''}
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
