document.addEventListener('DOMContentLoaded', async () => {
    const uploadDropArea = document.getElementById('upload-drop-area');
    const fileUpload = document.getElementById('file-upload');
    const documentSearch = document.getElementById('document-search');
    const documentFilter = document.getElementById('document-filter');
    
    // Initialize authentication first
    await initAuth();
    
    // Wait for authentication to be ready before loading courses
    await waitForAuth();
    
    // If TA user, load TA courses for navigation BEFORE setting up sidebar
    if (typeof isTA === 'function' && isTA()) {
        await loadTACoursesForNavigation();
    }
    
    // Setup sidebar based on user role
    setupSidebarForUserRole();
    
    // Load available courses and initialize course selection
    loadAvailableCourses();
    
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
            console.log('Files selected:', files);
            // In a real implementation, you would upload these files to the server
            
            // Show a mock upload in progress for demonstration
            Array.from(files).forEach(file => {
                addDocumentRow({
                    name: file.name,
                    type: file.name.split('.').pop().toUpperCase(),
                    size: formatFileSize(file.size),
                    date: new Date().toISOString().split('T')[0],
                    status: 'processing'
                });
            });
        }
    }

    // Search functionality
    if (documentSearch) {
        documentSearch.addEventListener('input', filterDocuments);
    }

    // Filter functionality
    if (documentFilter) {
        documentFilter.addEventListener('change', filterDocuments);
    }

    function filterDocuments() {
        const searchTerm = documentSearch.value.toLowerCase();
        const filterType = documentFilter.value;
        
        const rows = document.querySelectorAll('.documents-table tbody tr');
        
        rows.forEach(row => {
            const name = row.querySelector('td:first-child').textContent.toLowerCase();
            const type = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
            
            const nameMatch = name.includes(searchTerm);
            const typeMatch = filterType === 'all' || type.toLowerCase() === filterType.toLowerCase();
            
            row.style.display = nameMatch && typeMatch ? '' : 'none';
        });
    }

    // Add document to table (for UI demo)
    function addDocumentRow(document) {
        const tbody = document.querySelector('.documents-table tbody');
        if (!tbody) return;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${document.name}</td>
            <td>${document.type}</td>
            <td>${document.size}</td>
            <td>${document.date}</td>
            <td><span class="status ${document.status}">${capitalizeFirstLetter(document.status)}</span></td>
            <td>
                <button class="action-button view">View</button>
                <button class="action-button delete">Delete</button>
            </td>
        `;
        
        // Add event listeners for the buttons
        const viewButton = tr.querySelector('.view');
        const deleteButton = tr.querySelector('.delete');
        
        viewButton.addEventListener('click', () => {
            console.log('View document:', document.name);
            // In a real implementation, this would open the document
        });
        
        deleteButton.addEventListener('click', () => {
            console.log('Delete document:', document.name);
            tr.remove();
            // In a real implementation, this would delete the document from the server
        });
        
        tbody.appendChild(tr);
    }

    // Helper functions
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
    
    function capitalizeFirstLetter(string) {
        return string.charAt(0).toUpperCase() + string.slice(1);
    }
});

/**
 * Load available courses for the instructor or TA
 */
async function loadAvailableCourses() {
    try {
        const courseSelect = document.getElementById('course-select');
        const courseTitle = document.getElementById('course-title');
        
        if (!courseSelect) return;
        
        let courses = [];
        let uniqueCourses = [];
        
        // Check if user is a TA
        if (typeof isTA === 'function' && isTA()) {
            console.log('Loading courses for TA user');
            courses = await loadTACourses();
        } else {
            console.log('Loading courses for instructor user');
            courses = await loadInstructorCourses();
        }
        
        // Filter out duplicate courses by courseId
        uniqueCourses = courses.filter((course, index, self) => 
            index === self.findIndex(c => c.courseId === course.courseId)
        );
        
        console.log('Unique courses after deduplication:', uniqueCourses);
        
        // Clear loading option
        courseSelect.innerHTML = '';
        
        // Add course options
        uniqueCourses.forEach(course => {
            const option = document.createElement('option');
            option.value = course.courseId;
            option.textContent = course.courseName;
            courseSelect.appendChild(option);
        });
        
        // Check for courseId parameter in URL or localStorage
        const urlParams = new URLSearchParams(window.location.search);
        const courseIdParam = urlParams.get('courseId');
        const courseIdFromStorage = localStorage.getItem('selectedCourseId');
        const selectedCourseId = courseIdParam || courseIdFromStorage;
        
        // Set default selection
        if (uniqueCourses.length > 0) {
            let selectedCourse = null;
            
            if (selectedCourseId) {
                // Use courseId from URL parameter or localStorage
                selectedCourse = uniqueCourses.find(course => course.courseId === selectedCourseId);
                console.log('Course ID from URL/localStorage:', selectedCourseId);
            }
            
            if (!selectedCourse) {
                // Sort by creation date to get the most recent course first
                const sortedCourses = uniqueCourses.sort((a, b) => {
                    const dateA = new Date(a.createdAt || 0);
                    const dateB = new Date(b.createdAt || 0);
                    return dateB - dateA; // Most recent first
                });
                selectedCourse = sortedCourses[0];
            }
            
            courseSelect.value = selectedCourse.courseId;
            
            // Update course title
            if (courseTitle) {
                courseTitle.textContent = selectedCourse.courseName;
            }
            
            console.log('Course selected:', selectedCourse.courseName, selectedCourse.courseId);
            
            // Update URL if course ID is from localStorage
            if (courseIdFromStorage && !courseIdParam) {
                urlParams.set('courseId', selectedCourse.courseId);
                window.history.replaceState({}, '', `${window.location.pathname}?${urlParams.toString()}`);
            }
        }
        
        // Add event listener for course selection changes
        courseSelect.addEventListener('change', function() {
            const selectedCourse = uniqueCourses.find(course => course.courseId === this.value);
            if (selectedCourse) {
                if (courseTitle) {
                    courseTitle.textContent = selectedCourse.courseName;
                }
                console.log('Course changed to:', selectedCourse.courseName);
                
                // Update localStorage and URL
                localStorage.setItem('selectedCourseId', selectedCourse.courseId);
                const urlParams = new URLSearchParams(window.location.search);
                urlParams.set('courseId', selectedCourse.courseId);
                window.history.replaceState({}, '', `${window.location.pathname}?${urlParams.toString()}`);
                
                // Reload course data
                if (typeof loadSpecificCourse === 'function') {
                    loadSpecificCourse(selectedCourse.courseId);
                } else if (typeof loadCourseData === 'function') {
                    loadCourseData();
                }
            }
        });
        
        console.log('Available courses loaded and deduplicated:', uniqueCourses);
        
    } catch (error) {
        console.error('Error loading available courses:', error);
        // Fallback to default course if API fails
        const courseSelect = document.getElementById('course-select');
        const courseTitle = document.getElementById('course-title');
        
        if (courseSelect) {
            courseSelect.innerHTML = '<option value="default">No courses available</option>';
        }
        if (courseTitle) {
            courseTitle.textContent = 'No Course Available';
        }
    }
}

/**
 * Load courses for TA users
 */
async function loadTACourses() {
    try {
        const taId = getCurrentInstructorId(); // Using same function for user ID
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return [];
        }
        
        console.log(`Loading courses for TA: ${taId}`);
        
        // Fetch courses for this TA
        const response = await authenticatedFetch(`/api/courses/ta/${taId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch TA courses');
        }
        
        const courses = result.data || [];
        console.log('TA courses loaded:', courses);
        return courses;
        
    } catch (error) {
        console.error('Error loading TA courses:', error);
        return [];
    }
}

/**
 * Load courses for instructor users
 */
async function loadInstructorCourses() {
    try {
        // Fetch courses from the API
        const response = await fetch('/api/courses/available/all');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch courses');
        }
        
        const courses = result.data;
        console.log('All available courses from API:', courses);
        return courses;
        
    } catch (error) {
        console.error('Error loading instructor courses:', error);
        return [];
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
 * Load TA courses for navigation (copied from ta-home.js)
 */
async function loadTACoursesForNavigation() {
    try {
        const taId = getCurrentInstructorId();
        if (!taId) {
            console.error('No TA ID found. User not authenticated.');
            return;
        }
        
        console.log(`Loading courses for TA navigation: ${taId}`);
        
        // Fetch courses for this TA
        const response = await authenticatedFetch(`/api/courses/ta/${taId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch TA courses');
        }
        
        const courses = result.data || [];
        console.log('🔍 [TA COURSES] TA courses loaded for navigation:', courses);
        console.log('🔍 [TA COURSES] Number of courses:', courses.length);
        
        // Store courses globally for navigation
        window.taCourses = courses;
        console.log('🔍 [TA COURSES] window.taCourses set to:', window.taCourses);
        
    } catch (error) {
        console.error('Error loading TA courses for navigation:', error);
    }
}

/**
 * Show notification to user
 * @param {string} message - The message to display
 * @param {string} type - The type of notification (info, success, warning, error)
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Add styles
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: 4px;
        color: white;
        font-weight: 500;
        z-index: 10000;
        max-width: 400px;
        word-wrap: break-word;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transform: translateX(100%);
        transition: transform 0.3s ease-in-out;
    `;
    
    // Set background color based on type
    const colors = {
        info: '#2196F3',
        success: '#4CAF50',
        warning: '#FF9800',
        error: '#F44336'
    };
    notification.style.backgroundColor = colors[type] || colors.info;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 5000);
}

/**
 * Setup sidebar navigation based on user role (instructor or TA)
 */
function setupSidebarForUserRole() {
    try {
        console.log('🔍 [SIDEBAR] Starting sidebar setup...');
        console.log('🔍 [SIDEBAR] isTA function available:', typeof isTA === 'function');
        
        // Check if user is a TA
        const isTAUser = typeof isTA === 'function' && isTA();
        console.log('🔍 [SIDEBAR] isTA() result:', isTAUser);
        console.log('🔍 [SIDEBAR] Current URL:', window.location.href);
        
        if (isTAUser) {
            console.log('🔍 [SIDEBAR] Detected TA user, setting up TA sidebar');
            setupTASidebar();
        } else {
            console.log('🔍 [SIDEBAR] Detected instructor user, setting up instructor sidebar');
            setupInstructorSidebar();
        }
    } catch (error) {
        console.error('❌ [SIDEBAR] Error setting up sidebar:', error);
        // Default to instructor sidebar on error
        setupInstructorSidebar();
    }
}

/**
 * Setup sidebar for instructor users
 */
function setupInstructorSidebar() {
    // Show instructor navigation items
    const instructorNavItems = [
        'instructor-home-nav',
        'instructor-documents-nav',
        'instructor-onboarding-nav',
        'instructor-flagged-nav',
        'instructor-downloads-nav',
        'instructor-ta-hub-nav',
        'instructor-settings-nav'
    ];
    
    instructorNavItems.forEach(itemId => {
        const element = document.getElementById(itemId);
        if (element) {
            element.style.display = 'block';
        }
    });
    
    // Hide TA navigation items
    const taNavItems = [
        'ta-dashboard-nav',
        'ta-courses-nav',
        'ta-support-nav',
        'ta-settings-nav'
    ];
    
    taNavItems.forEach(itemId => {
        const element = document.getElementById(itemId);
        if (element) {
            element.style.display = 'none';
        }
    });
    
    // Update user info
    updateUserInfo('Instructor', 'I');
    
    console.log('✅ [SIDEBAR] Instructor sidebar configured');
}

/**
 * Setup sidebar for TA users
 */
function setupTASidebar() {
    console.log('🔍 [TA SIDEBAR] Setting up TA sidebar...');
    console.log('🔍 [TA SIDEBAR] window.taCourses available:', !!window.taCourses);
    console.log('🔍 [TA SIDEBAR] window.taCourses length:', window.taCourses ? window.taCourses.length : 'N/A');
    
    // Show/hide navigation items based on role
    const instructorNavItems = [
        'instructor-home-nav',
        'instructor-documents-nav', 
        'instructor-onboarding-nav',
        'instructor-flagged-nav',
        'instructor-downloads-nav',
        'instructor-ta-hub-nav',
        'instructor-settings-nav'
    ];
    
    const taNavItems = [
        'ta-dashboard-nav',
        'ta-courses-nav',
        'ta-support-nav',
        'ta-settings-nav'
    ];
    
    // Show TA navigation, hide instructor navigation
    instructorNavItems.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.style.display = 'none';
    });
    
    taNavItems.forEach(id => {
        const element = document.getElementById(id);
        if (element) element.style.display = 'block';
    });
    
    // Update user info for TA
    const userAvatar = document.getElementById('user-avatar');
    const userRole = document.getElementById('user-role');
    
    if (userAvatar) userAvatar.textContent = 'T';
    if (userRole) userRole.textContent = 'Teaching Assistant';
    
    // Setup TA navigation handlers
    setupTANavigationHandlers();
    
    console.log('✅ [SIDEBAR] TA sidebar configured');
}

/**
 * Update user information display
 */
function updateUserInfo(role, avatar) {
    const userRoleElement = document.getElementById('user-role');
    const userAvatarElement = document.getElementById('user-avatar');
    const userNameElement = document.getElementById('user-display-name');
    
    if (userRoleElement) {
        userRoleElement.textContent = role;
    }
    
    if (userAvatarElement) {
        userAvatarElement.textContent = avatar;
    }
    
    if (userNameElement) {
        // Try to get user name from auth if available
        if (typeof getCurrentInstructorId === 'function') {
            const userId = getCurrentInstructorId();
            userNameElement.textContent = userId ? `User ${userId}` : 'User Name';
        } else {
            userNameElement.textContent = 'User Name';
        }
    }
}

/**
 * Setup TA navigation handlers
 */
function setupTANavigationHandlers() {
    // TA My Courses link
    const taMyCoursesLink = document.getElementById('ta-my-courses-link');
    if (taMyCoursesLink) {
        taMyCoursesLink.addEventListener('click', (e) => {
            e.preventDefault();
            
            // Check permissions first
            checkTAPermissionsAndNavigate('courses', '/instructor/documents');
        });
    }
    
    // TA Student Support link
    const taStudentSupportLink = document.getElementById('ta-student-support-link');
    console.log('🔍 [DEBUG] Looking for ta-student-support-link element:', taStudentSupportLink);
    if (taStudentSupportLink) {
        console.log('🔍 [DEBUG] Setting up TA Student Support link');
        console.log('🔍 [DEBUG] Element found, adding click listener');
        taStudentSupportLink.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('🔍 [DEBUG] TA Student Support clicked');
            
            // First try to get courseId from URL (most reliable)
            const urlParams = new URLSearchParams(window.location.search);
            const courseId = urlParams.get('courseId');
            console.log('🔍 [DEBUG] Current URL:', window.location.href);
            console.log('🔍 [DEBUG] CourseId from URL:', courseId);
            console.log('🔍 [DEBUG] TA Courses:', window.taCourses);
            
            if (courseId) {
                // Use courseId from URL (same as dashboard)
                console.log('🔍 [DEBUG] Using courseId from URL:', courseId);
                window.location.href = `/instructor/flagged?courseId=${courseId}`;
            } else if (window.taCourses && window.taCourses.length > 0) {
                // Fallback to first TA course
                const firstCourse = window.taCourses[0];
                console.log('🔍 [DEBUG] Using first TA course:', firstCourse);
                window.location.href = `/instructor/flagged?courseId=${firstCourse.courseId}`;
            } else {
                console.error('No courseId found in URL or TA courses');
                showNotification('No course selected. Please try again.', 'error');
            }
        });
    } else {
        console.warn('⚠️ [DEBUG] TA Student Support link not found');
    }
}

/**
 * Check TA permissions and navigate if allowed
 */
async function checkTAPermissionsAndNavigate(feature, targetPage) {
    try {
        const taId = getCurrentInstructorId();
        if (!taId) {
            showNotification('No TA ID found. User not authenticated.', 'error');
            return;
        }
        
        // Get TA courses first
        const response = await authenticatedFetch(`/api/courses/ta/${taId}`);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.message || 'Failed to fetch TA courses');
        }
        
        const courses = result.data || [];
        
        if (courses.length === 0) {
            showNotification('No courses assigned. Contact an instructor to be added to a course.', 'warning');
            return;
        }
        
        // Check permissions for each course
        let hasPermission = false;
        for (const course of courses) {
            const permResponse = await authenticatedFetch(`/api/courses/${course.courseId}/ta-permissions/${taId}`);
            
            if (permResponse.ok) {
                const permResult = await permResponse.json();
                if (permResult.success) {
                    const permissions = permResult.data.permissions;
                    if ((feature === 'courses' && permissions.canAccessCourses) || 
                        (feature === 'flags' && permissions.canAccessFlags)) {
                        hasPermission = true;
                        break;
                    }
                }
            } else {
                // Default permissions if not set
                hasPermission = true;
                break;
            }
        }
        
        if (!hasPermission) {
            const featureName = feature === 'courses' ? 'My Courses' : 'Student Support';
            showNotification(`You do not have permission to access ${featureName}. Contact your instructor.`, 'error');
            return;
        }
        
        // Navigate to the first assigned course
        const firstCourse = courses[0];
        window.location.href = `${targetPage}?courseId=${firstCourse.courseId}`;
        
    } catch (error) {
        console.error('Error checking TA permissions:', error);
        showNotification('Error checking permissions. Please try again.', 'error');
    }
} 