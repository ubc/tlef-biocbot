document.addEventListener('DOMContentLoaded', async () => {
    const saveSettingsBtn = document.getElementById('save-settings');
    const resetSettingsBtn = document.getElementById('reset-settings');
    const deleteCollectionBtn = document.getElementById('delete-collection');
    
    // Check if user can see the delete all button
    await waitForAuth();
    const canManageDB = await checkDeleteAllPermission();
    
    // Load initial settings including prompts
    await loadSettings(canManageDB);

    async function loadSettings(canManageDB) {
        try {
            // Load global config (prompts and additive retrieval)
            await loadGlobalConfig();

            // Load quiz practice settings
            await loadQuizSettings();

            // If user has permission, load global settings (login restriction)
            // and question generation prompts
            if (canManageDB) {
                await loadAdminSettings();
                await loadQuestionPrompts();
            }
        } catch (error) {
            console.error('Error loading settings:', error);
            showNotification('Failed to load settings', 'error');
        }
    }

    async function loadAdminSettings() {
        try {
            const response = await fetch('/api/settings/global');
            const result = await response.json();
            
            if (result.success && result.settings) {
                const allowLocalLoginToggle = document.getElementById('allow-local-login-toggle');
                if (allowLocalLoginToggle) {
                    allowLocalLoginToggle.checked =  result.settings.allowLocalLogin !== false; // Default true
                }
            }
        } catch (error) {
            console.error('Error loading admin settings:', error);
        }
    }

    async function loadGlobalConfig() {
        try {
            const courseId = await getCurrentCourseId();
            const response = await fetch(`/api/settings/prompts?courseId=${courseId}`);
            const result = await response.json();
            
            if (result.success && result.prompts) {
                const basePromptInput = document.getElementById('base-prompt');
                const protegePromptInput = document.getElementById('protege-prompt');
                const tutorPromptInput = document.getElementById('tutor-prompt');
                const explainPromptInput = document.getElementById('explain-prompt');
                const directivePromptInput = document.getElementById('directive-prompt');
                const quizHelpPromptInput = document.getElementById('quiz-help-prompt');
                const additiveToggle = document.getElementById('additive-retrieval-toggle');
                const idleTimeoutInput = document.getElementById('idle-timeout-input');

                if (basePromptInput) basePromptInput.value = result.prompts.base || '';
                if (protegePromptInput) protegePromptInput.value = result.prompts.protege || '';
                if (tutorPromptInput) tutorPromptInput.value = result.prompts.tutor || '';
                if (explainPromptInput) explainPromptInput.value = result.prompts.explain || '';
                if (directivePromptInput) directivePromptInput.value = result.prompts.directive || '';
                if (quizHelpPromptInput) quizHelpPromptInput.value = result.prompts.quizHelp || '';
                if (additiveToggle) additiveToggle.checked = !!result.prompts.additiveRetrieval;
                
                // Convert seconds to minutes for display
                if (idleTimeoutInput && result.prompts.studentIdleTimeout) {
                    idleTimeoutInput.value = result.prompts.studentIdleTimeout / 60;
                }
            }
        } catch (error) {
            console.error('Error fetching global config:', error);
        }
    }

    /**
     * Load question generation prompts for privileged users only
     * These are course-specific prompts used for AI question generation
     */
    async function loadQuestionPrompts() {
        try {
            const courseId = await getCurrentCourseId();
            const response = await fetch(`/api/settings/question-prompts?courseId=${courseId}`);
            const result = await response.json();
            
            if (result.success && result.prompts) {
                const systemPromptInput = document.getElementById('question-system-prompt');
                const trueFalseInput = document.getElementById('question-true-false-prompt');
                const multipleChoiceInput = document.getElementById('question-multiple-choice-prompt');
                const shortAnswerInput = document.getElementById('question-short-answer-prompt');
                
                if (systemPromptInput) systemPromptInput.value = result.prompts.systemPrompt || '';
                if (trueFalseInput) trueFalseInput.value = result.prompts.trueFalse || '';
                if (multipleChoiceInput) multipleChoiceInput.value = result.prompts.multipleChoice || '';
                if (shortAnswerInput) shortAnswerInput.value = result.prompts.shortAnswer || '';
            }
        } catch (error) {
            console.error('Error fetching question prompts:', error);
        }
    }
    
    /**
     * Load quiz practice settings and populate the testable units checkboxes
     */
    async function loadQuizSettings() {
        try {
            const courseId = await getCurrentCourseId();
            if (!courseId) return;

            // Fetch quiz settings and course lectures in parallel
            const [settingsRes, courseRes] = await Promise.all([
                fetch(`/api/settings/quiz?courseId=${courseId}`),
                fetch(`/api/courses/${courseId}`)
            ]);

            const settingsData = await settingsRes.json();
            const courseData = await courseRes.json();

            // Populate toggles
            const quizEnabledToggle = document.getElementById('quiz-enabled-toggle');
            const materialAccessToggle = document.getElementById('quiz-material-access-toggle');
            const sourceAttributionDownloadToggle = document.getElementById('source-attribution-download-toggle');

            if (settingsData.success && settingsData.settings) {
                if (quizEnabledToggle) quizEnabledToggle.checked = settingsData.settings.enabled === true;
                if (materialAccessToggle) materialAccessToggle.checked = settingsData.settings.allowLectureMaterialAccess !== false;
                if (sourceAttributionDownloadToggle) sourceAttributionDownloadToggle.checked = settingsData.settings.allowSourceAttributionDownloads === true;
            }

            // Populate testable units checkboxes
            const container = document.getElementById('testable-units-container');
            if (!container) return;
            container.innerHTML = '';

            let publishedLectures = [];
            if (courseData.success && courseData.data && courseData.data.lectures) {
                publishedLectures = courseData.data.lectures.filter(l => l.isPublished);
            }

            if (publishedLectures.length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary, #666); font-size: 0.9rem;">No published units yet. Publish units from Course Upload to make them available for quiz practice.</p>';
                return;
            }

            const testableUnits = settingsData.success && settingsData.settings
                ? settingsData.settings.testableUnits
                : 'all';

            for (const lecture of publishedLectures) {
                const label = document.createElement('label');

                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.className = 'testable-unit-checkbox';
                checkbox.value = lecture.name;
                checkbox.checked = testableUnits === 'all' || (Array.isArray(testableUnits) && testableUnits.includes(lecture.name));

                const text = document.createElement('span');
                text.textContent = lecture.displayName || lecture.name;

                label.appendChild(checkbox);
                label.appendChild(text);
                container.appendChild(label);
            }
        } catch (error) {
            console.error('Error loading quiz settings:', error);
        }
    }

    // Handle save button click
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', async () => {
            saveSettingsBtn.disabled = true;
            saveSettingsBtn.textContent = 'Saving...';
            
            try {
                // Save prompts and config
                const base = document.getElementById('base-prompt')?.value;
                const protege = document.getElementById('protege-prompt')?.value;
                const tutor = document.getElementById('tutor-prompt')?.value;
                const explain = document.getElementById('explain-prompt')?.value;
                const directive = document.getElementById('directive-prompt')?.value;
                const quizHelp = document.getElementById('quiz-help-prompt')?.value;
                const additiveRetrieval = document.getElementById('additive-retrieval-toggle')?.checked;
                const idleTimeoutInput = document.getElementById('idle-timeout-input');
                const courseId = await getCurrentCourseId();
                
                // Convert minutes back to seconds
                let studentIdleTimeout = 240;
                if (idleTimeoutInput) {
                    studentIdleTimeout = parseFloat(idleTimeoutInput.value) * 60;
                }
                
                // Save login restriction setting if visible
                const loginRestrictionSection = document.getElementById('login-restriction-section');
                if (loginRestrictionSection && loginRestrictionSection.style.display !== 'none') {
                    const allowLocalLogin = document.getElementById('allow-local-login-toggle')?.checked;
                    
                    await fetch('/api/settings/global', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ allowLocalLogin })
                    });
                }

                // Save quiz practice settings
                const quizEnabled = document.getElementById('quiz-enabled-toggle')?.checked;
                const materialAccess = document.getElementById('quiz-material-access-toggle')?.checked;
                const sourceAttributionDownloads = document.getElementById('source-attribution-download-toggle')?.checked;
                const unitCheckboxes = document.querySelectorAll('.testable-unit-checkbox');
                let testableUnits = 'all';
                if (unitCheckboxes.length > 0) {
                    const checkedUnits = Array.from(unitCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
                    // If all are checked, store 'all'; otherwise store the selected names
                    testableUnits = checkedUnits.length === unitCheckboxes.length ? 'all' : checkedUnits;
                }

                await fetch('/api/settings/quiz', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        courseId,
                        enabled: quizEnabled === true,
                        testableUnits,
                        allowLectureMaterialAccess: materialAccess === true,
                        allowSourceAttributionDownloads: sourceAttributionDownloads === true
                    })
                });

                // Save question generation prompts if section is visible (privileged users only)
                const questionGenSection = document.getElementById('question-generation-section');
                if (questionGenSection && questionGenSection.style.display !== 'none') {
                    const systemPrompt = document.getElementById('question-system-prompt')?.value;
                    const trueFalse = document.getElementById('question-true-false-prompt')?.value;
                    const multipleChoice = document.getElementById('question-multiple-choice-prompt')?.value;
                    const shortAnswer = document.getElementById('question-short-answer-prompt')?.value;
                    
                    if (systemPrompt && trueFalse && multipleChoice && shortAnswer) {
                        await fetch('/api/settings/question-prompts', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ systemPrompt, trueFalse, multipleChoice, shortAnswer, courseId })
                        });
                    }
                }
                
                if (base && protege && tutor) {
                    const response = await fetch('/api/settings/prompts', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ base, protege, tutor, explain, directive, quizHelp, additiveRetrieval, studentIdleTimeout, courseId })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        showNotification('Settings saved successfully', 'success');
                    } else {
                        showNotification('Failed to save settings: ' + result.message, 'error');
                    }
                } else {
                    // Fallback if inputs missing (shouldn't happen if HTML is correct)
                    showNotification('Settings saved (simulated)', 'info');
                }
                
            } catch (error) {
                console.error('Error saving settings:', error);
                showNotification('Error saving settings', 'error');
            } finally {
                saveSettingsBtn.disabled = false;
                saveSettingsBtn.textContent = 'Save Settings';
            }
        });
    }
    
    // Handle reset button click
    if (resetSettingsBtn) {
        resetSettingsBtn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to reset all settings to default values?')) {
                return;
            }
            
            resetSettingsBtn.disabled = true;
            resetSettingsBtn.textContent = 'Resetting...';
            
            try {
                const courseId = await getCurrentCourseId();

                // Reset prompts
                const response = await fetch('/api/settings/prompts/reset', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ courseId })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    // Reload values
                    if (result.prompts) {
                        const basePromptInput = document.getElementById('base-prompt');
                        const protegePromptInput = document.getElementById('protege-prompt');
                        const tutorPromptInput = document.getElementById('tutor-prompt');
                        const explainPromptInput = document.getElementById('explain-prompt');
                        const directivePromptInput = document.getElementById('directive-prompt');
                        const additiveToggle = document.getElementById('additive-retrieval-toggle');
                        
                        if (basePromptInput) basePromptInput.value = result.prompts.base || '';
                        if (protegePromptInput) protegePromptInput.value = result.prompts.protege || '';
                        if (tutorPromptInput) tutorPromptInput.value = result.prompts.tutor || '';
                        if (explainPromptInput) explainPromptInput.value = result.prompts.explain || '';
                        if (directivePromptInput) directivePromptInput.value = result.prompts.directive || '';
                        // Default for additive retrieval is true (on)
                        if (additiveToggle) additiveToggle.checked = true;
                        
                        const idleTimeoutInput = document.getElementById('idle-timeout-input');
                        if (idleTimeoutInput) idleTimeoutInput.value = 4; // Default 4 mins
                    }
                    
                    // Reset quiz settings to defaults
                    const quizEnabledToggle = document.getElementById('quiz-enabled-toggle');
                    const materialAccessToggle = document.getElementById('quiz-material-access-toggle');
                    const sourceAttributionDownloadToggle = document.getElementById('source-attribution-download-toggle');
                    if (quizEnabledToggle) quizEnabledToggle.checked = false;
                    if (materialAccessToggle) materialAccessToggle.checked = true;
                    if (sourceAttributionDownloadToggle) sourceAttributionDownloadToggle.checked = false;
                    // Check all unit checkboxes
                    document.querySelectorAll('.testable-unit-checkbox').forEach(cb => { cb.checked = true; });
                    // Save quiz defaults
                    await fetch('/api/settings/quiz', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            courseId,
                            enabled: false,
                            testableUnits: 'all',
                            allowLectureMaterialAccess: true,
                            allowSourceAttributionDownloads: false
                        })
                    });

                    showNotification('Settings reset to defaults', 'success');
                } else {
                    showNotification('Failed to reset settings: ' + result.message, 'error');
                }
                
            } catch (error) {
                console.error('Error resetting settings:', error);
                showNotification('Error resetting settings', 'error');
            } finally {
                resetSettingsBtn.disabled = false;
                resetSettingsBtn.textContent = 'Reset to Default';
            }
        });
    }

    // Handle delete collection button click
    if (deleteCollectionBtn) {
        deleteCollectionBtn.addEventListener('click', async () => {
            // Show confirmation dialog
            const confirmed = confirm(
                '⚠️ WARNING: This will permanently delete ALL BiocBot data!\n\n' +
                'This includes:\n' +
                '• Vector embeddings (Qdrant)\n' +
                '• Document metadata (MongoDB)\n' +
                '• Course information\n' +
                '• Questions and assessments\n' +
                '• Onboarding data\n\n' +
                'This action cannot be undone and will completely reset the system.\n\n' +
                'Are you absolutely sure you want to continue?'
            );

            if (!confirmed) {
                return;
            }

            try {
                // Disable button to prevent multiple clicks
                deleteCollectionBtn.disabled = true;
                deleteCollectionBtn.textContent = 'Deleting...';

                // Call API to delete all collections
                const response = await fetch('/api/qdrant/delete-all-collections', {
                    method: 'DELETE',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });

                const result = await response.json();

                if (result.success) {
                    showNotification(
                        `All data deleted successfully! Qdrant: ${result.data.qdrantDeletedCount}, MongoDB: ${result.data.mongoDeletedCount} documents removed.`, 
                        'success'
                    );
                } else {
                    showNotification(
                        `Failed to delete data: ${result.message || 'Unknown error'}`, 
                        'error'
                    );
                }

            } catch (error) {
                console.error('Error deleting data:', error);
                showNotification(
                    'Failed to delete data: Network or server error', 
                    'error'
                );
            } finally {
                // Re-enable button
                deleteCollectionBtn.disabled = false;
                deleteCollectionBtn.textContent = 'Delete All Data';
            }
        });
    }

    // Handle reset question prompts button click (privileged users only)
    const resetQuestionPromptsBtn = document.getElementById('reset-question-prompts');
    if (resetQuestionPromptsBtn) {
        resetQuestionPromptsBtn.addEventListener('click', async () => {
            if (!confirm('Are you sure you want to reset all question generation prompts to default values? This only affects the current course.')) {
                return;
            }
            
            resetQuestionPromptsBtn.disabled = true;
            resetQuestionPromptsBtn.textContent = 'Resetting...';
            
            try {
                const courseId = await getCurrentCourseId();
                
                const response = await fetch('/api/settings/question-prompts/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ courseId })
                });
                
                const result = await response.json();
                
                if (result.success && result.prompts) {
                    // Reload the textareas with default values
                    const systemPromptInput = document.getElementById('question-system-prompt');
                    const trueFalseInput = document.getElementById('question-true-false-prompt');
                    const multipleChoiceInput = document.getElementById('question-multiple-choice-prompt');
                    const shortAnswerInput = document.getElementById('question-short-answer-prompt');
                    
                    if (systemPromptInput) systemPromptInput.value = result.prompts.systemPrompt || '';
                    if (trueFalseInput) trueFalseInput.value = result.prompts.trueFalse || '';
                    if (multipleChoiceInput) multipleChoiceInput.value = result.prompts.multipleChoice || '';
                    if (shortAnswerInput) shortAnswerInput.value = result.prompts.shortAnswer || '';
                    
                    showNotification('Question prompts reset to defaults', 'success');
                } else {
                    showNotification('Failed to reset question prompts: ' + (result.message || 'Unknown error'), 'error');
                }
            } catch (error) {
                console.error('Error resetting question prompts:', error);
                showNotification('Error resetting question prompts', 'error');
            } finally {
                resetQuestionPromptsBtn.disabled = false;
                resetQuestionPromptsBtn.textContent = 'Reset Question Prompts to Default';
            }
        });
    }
    
    /**
     * Check if the current user has permission to see the delete all button
     * Hides the entire Database Management section if user doesn't have permission
     * Returns true if user has permission
     */
    async function checkDeleteAllPermission() {
        try {
            const response = await fetch('/api/settings/can-delete-all', {
                credentials: 'include'
            });
            
            const result = await response.json();
            
            // Get all privileged sections by ID
            const databaseSection = document.getElementById('database-management-section');
            const loginRestrictionSection = document.getElementById('login-restriction-section');
            const questionGenerationSection = document.getElementById('question-generation-section');
            
            if (result.success && result.canDeleteAll) {
                // User has permission, ensure the sections are visible
                if (databaseSection) databaseSection.style.display = '';
                if (loginRestrictionSection) loginRestrictionSection.style.display = '';
                if (questionGenerationSection) questionGenerationSection.style.display = '';
                return true;
            } else {
                // User doesn't have permission, hide the sections
                if (databaseSection) databaseSection.style.display = 'none';
                if (loginRestrictionSection) loginRestrictionSection.style.display = 'none';
                if (questionGenerationSection) questionGenerationSection.style.display = 'none';
                return false;
            }
        } catch (error) {
            console.error('Error checking delete all permission:', error);
            // On error, hide the sections for security
            const databaseSection = document.getElementById('database-management-section');
            const loginRestrictionSection = document.getElementById('login-restriction-section');
            const questionGenerationSection = document.getElementById('question-generation-section');
            if (databaseSection) databaseSection.style.display = 'none';
            if (loginRestrictionSection) loginRestrictionSection.style.display = 'none';
            if (questionGenerationSection) questionGenerationSection.style.display = 'none';
            return false;
        }
    }
    
    // Function to show notification
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
}); 
