document.addEventListener('DOMContentLoaded', async () => {
    const saveSettingsBtn = document.getElementById('save-settings');
    const resetSettingsBtn = document.getElementById('reset-settings');
    const deleteCollectionBtn = document.getElementById('delete-collection');
    const courseLifecycleSection = document.getElementById('course-lifecycle-section');
    const toggleCourseActiveBtn = document.getElementById('toggle-course-active-btn');
    const transferCourseBtn = document.getElementById('transfer-course-btn');
    const transferUnitGrid = document.getElementById('transfer-unit-grid');
    const transferCourseNameInput = document.getElementById('transfer-course-name');
    const transferAllDocsToggle = document.getElementById('transfer-all-docs');
    const transferAllObjectivesToggle = document.getElementById('transfer-all-objectives');
    const transferAllQuestionsToggle = document.getElementById('transfer-all-questions');
    const transferCourseModal = document.getElementById('transfer-course-modal');
    const transferModalTitle = document.getElementById('transfer-modal-title');
    const transferModalDescription = document.getElementById('transfer-modal-description');
    const transferModalSummary = document.getElementById('transfer-modal-summary');
    const transferModalConfirmation = document.getElementById('transfer-modal-confirmation');
    const transferModalLoading = document.getElementById('transfer-modal-loading');
    const transferModalLoadingText = document.getElementById('transfer-modal-loading-text');
    const transferModalCancelBtn = document.getElementById('transfer-modal-cancel');
    const transferModalConfirmBtn = document.getElementById('transfer-modal-confirm');
    const systemAdminList = document.getElementById('system-admin-list');
    const systemAdminEmailInput = document.getElementById('system-admin-email-input');
    const grantSystemAdminBtn = document.getElementById('grant-system-admin-btn');
    let lifecycleCourseData = null;
    let pendingTransferPayload = null;
    let isTransferInProgress = false;
    
    // Check if user has system admin access
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

            // Load privacy settings (anonymize students)
            await loadAnonymizeStudentsSetting();

            // Load mental health detection prompt
            await loadMentalHealthDetectionPrompt();

            // Load course lifecycle controls for instructors
            await initializeCourseLifecycle();

            // If user has permission, load global settings (login restriction)
            // and question generation prompts
            if (canManageDB) {
                await loadAdminSettings();
                await loadQuestionPrompts();
                await loadSystemAdmins();
            }

            consumeDeferredFlashMessage();
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

    async function loadSystemAdmins() {
        if (!systemAdminList) {
            return;
        }

        systemAdminList.innerHTML = '<div class="system-admin-empty">Loading system admins...</div>';

        try {
            const response = await fetch('/api/settings/system-admins', {
                credentials: 'include'
            });
            const result = await response.json();

            if (!result.success || !Array.isArray(result.admins)) {
                throw new Error(result.error || 'Failed to load system admins');
            }

            renderSystemAdmins(result.admins);
        } catch (error) {
            console.error('Error loading system admins:', error);
            systemAdminList.innerHTML = '<div class="system-admin-empty">Failed to load system admins.</div>';
        }
    }

    function formatSystemAdminTimestamp(value) {
        if (!value) {
            return 'Never';
        }

        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return 'Never';
        }

        return date.toLocaleString();
    }

    function renderSystemAdmins(admins) {
        if (!systemAdminList) {
            return;
        }

        if (!admins.length) {
            systemAdminList.innerHTML = '<div class="system-admin-empty">No system admins found.</div>';
            return;
        }

        const currentUser = typeof getCurrentUser === 'function' ? getCurrentUser() : null;
        const currentUserEmail = currentUser && currentUser.email ? String(currentUser.email).toLowerCase() : '';

        systemAdminList.innerHTML = admins.map(admin => {
            const adminEmail = admin.email || '';
            const isCurrentUser = adminEmail.toLowerCase() === currentUserEmail;
            const displayName = admin.displayName || adminEmail;
            const lastLogin = formatSystemAdminTimestamp(admin.lastLogin);

            return `
                <div class="system-admin-row${isCurrentUser ? ' is-self' : ''}">
                    <div class="system-admin-details">
                        <div class="system-admin-name-row">
                            <strong>${escapeHtml(displayName)}</strong>
                            ${isCurrentUser ? '<span class="system-admin-badge">You</span>' : ''}
                        </div>
                        <div class="system-admin-email">${escapeHtml(adminEmail)}</div>
                        <div class="system-admin-meta">Last login: ${escapeHtml(lastLogin)}</div>
                    </div>
                    <button
                        class="secondary-button system-admin-revoke-btn"
                        data-email="${escapeHtml(adminEmail)}"
                    >
                        Revoke
                    </button>
                </div>
            `;
        }).join('');
    }

    function escapeHtml(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
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
     * Load question generation prompts for system admins only
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

    async function loadAnonymizeStudentsSetting() {
        try {
            const courseId = await getCurrentCourseId();
            if (!courseId) return;
            const response = await fetch(`/api/settings/anonymize-students?courseId=${courseId}`);
            const result = await response.json();
            if (result.success) {
                const toggle = document.getElementById('anonymize-students-toggle');
                if (toggle) toggle.checked = !!result.enabled;
            }
        } catch (error) {
            console.error('Error loading anonymize students setting:', error);
        }
    }

    async function loadMentalHealthDetectionPrompt() {
        try {
            const courseId = await getCurrentCourseId();
            const response = await fetch(`/api/settings/mental-health-prompt?courseId=${courseId}`);
            const result = await response.json();
            if (result.success) {
                const textarea = document.getElementById('mental-health-detection-prompt');
                if (textarea) textarea.value = result.prompt || '';
            }
        } catch (error) {
            console.error('Error loading mental health detection prompt:', error);
        }
    }

    function consumeDeferredFlashMessage() {
        try {
            const rawMessage = sessionStorage.getItem('settingsFlashMessage');
            if (!rawMessage) return;

            sessionStorage.removeItem('settingsFlashMessage');
            const parsed = JSON.parse(rawMessage);
            if (parsed && parsed.message) {
                showNotification(parsed.message, parsed.type || 'info');
            }
        } catch (error) {
            console.warn('Unable to display deferred settings message:', error);
        }
    }

    function updateMasterTransferToggle(toggleId, selector) {
        const toggle = document.getElementById(toggleId);
        if (!toggle) return;

        const checkboxes = Array.from(document.querySelectorAll(selector));
        if (checkboxes.length === 0) {
            toggle.checked = false;
            toggle.indeterminate = false;
            return;
        }

        const checkedCount = checkboxes.filter(checkbox => checkbox.checked).length;
        toggle.checked = checkedCount === checkboxes.length;
        toggle.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
    }

    function syncTransferMasterToggles() {
        updateMasterTransferToggle('transfer-all-docs', '.transfer-docs-checkbox');
        updateMasterTransferToggle('transfer-all-objectives', '.transfer-objectives-checkbox');
        updateMasterTransferToggle('transfer-all-questions', '.transfer-questions-checkbox');
    }

    function setTransferModalVisibility(isVisible) {
        if (!transferCourseModal) return;
        transferCourseModal.classList.toggle('show', isVisible);
        transferCourseModal.setAttribute('aria-hidden', isVisible ? 'false' : 'true');
        document.body.style.overflow = isVisible ? 'hidden' : '';
    }

    function resetTransferModalState() {
        isTransferInProgress = false;
        pendingTransferPayload = null;

        if (transferModalTitle) {
            transferModalTitle.textContent = 'Review Course Copy';
        }

        if (transferModalDescription) {
            transferModalDescription.textContent = 'This will create a new course copy and may take a few minutes while materials and existing chunks are copied over.';
        }

        if (transferModalSummary) {
            transferModalSummary.innerHTML = '';
        }

        if (transferModalConfirmation) {
            transferModalConfirmation.hidden = false;
        }

        if (transferModalLoading) {
            transferModalLoading.hidden = true;
        }

        if (transferModalLoadingText) {
            transferModalLoadingText.textContent = 'We’re copying materials, stored chunks, and saved course data into the new course.';
        }

        if (transferModalCancelBtn) {
            transferModalCancelBtn.disabled = false;
            transferModalCancelBtn.hidden = false;
        }

        if (transferModalConfirmBtn) {
            transferModalConfirmBtn.disabled = false;
            transferModalConfirmBtn.textContent = 'Start Course Copy';
            transferModalConfirmBtn.hidden = false;
        }
    }

    function closeTransferModal({ force = false } = {}) {
        if (isTransferInProgress && !force) return;
        resetTransferModalState();
        setTransferModalVisibility(false);
    }

    function getTransferSelectionCounts(units = []) {
        return {
            totalUnits: units.length,
            docsCount: units.filter(unit => unit.transferDocuments).length,
            objectivesCount: units.filter(unit => unit.transferLearningObjectives).length,
            questionsCount: units.filter(unit => unit.transferAssessmentQuestions).length
        };
    }

    function openTransferModal(payload) {
        if (!transferCourseModal) return;

        resetTransferModalState();
        pendingTransferPayload = payload;

        const counts = getTransferSelectionCounts(payload.units || []);
        const summaryItems = [
            `New course name: ${payload.newCourseName}`,
            `${counts.docsCount} of ${counts.totalUnits} unit${counts.totalUnits === 1 ? '' : 's'} will copy docs and existing chunks.`,
            `${counts.objectivesCount} of ${counts.totalUnits} unit${counts.totalUnits === 1 ? '' : 's'} will copy learning objectives.`,
            `${counts.questionsCount} of ${counts.totalUnits} unit${counts.totalUnits === 1 ? '' : 's'} will copy assessment questions.`,
            'Approved course topics will be copied exactly as-is.',
            'All copied units will start unpublished in the new course.',
            payload.transferSettings ? 'Course settings will be copied.' : 'Course settings will not be copied.',
            payload.transferTAs ? 'TAs and their permissions will be copied.' : 'TAs will not be copied.',
            payload.deactivateSourceCourse ? 'The source course will be deactivated after the transfer finishes.' : 'The source course will stay active after the transfer.'
        ];

        if (transferModalDescription) {
            transferModalDescription.textContent = 'This can take a few minutes because selected materials and their stored chunks are copied into the new course.';
        }

        if (transferModalSummary) {
            transferModalSummary.innerHTML = '';
            summaryItems.forEach(item => {
                const listItem = document.createElement('li');
                listItem.textContent = item;
                transferModalSummary.appendChild(listItem);
            });
        }

        setTransferModalVisibility(true);
        window.setTimeout(() => transferModalConfirmBtn?.focus(), 0);
    }

    function setTransferModalLoading(payload) {
        isTransferInProgress = true;

        if (transferModalTitle) {
            transferModalTitle.textContent = 'Creating Course Copy...';
        }

        if (transferModalConfirmation) {
            transferModalConfirmation.hidden = true;
        }

        if (transferModalLoading) {
            transferModalLoading.hidden = false;
        }

        if (transferModalLoadingText) {
            transferModalLoadingText.textContent = `Creating "${payload.newCourseName}" now. Please keep this tab open while materials and stored chunks are copied.`;
        }

        if (transferModalCancelBtn) {
            transferModalCancelBtn.disabled = true;
            transferModalCancelBtn.hidden = true;
        }

        if (transferModalConfirmBtn) {
            transferModalConfirmBtn.disabled = true;
            transferModalConfirmBtn.textContent = 'Creating...';
        }
    }

    function renderTransferUnitGrid(lectures = []) {
        if (!transferUnitGrid) return;

        if (!Array.isArray(lectures) || lectures.length === 0) {
            transferUnitGrid.innerHTML = '<div class="transfer-unit-grid-empty">No units found for this course yet.</div>';
            syncTransferMasterToggles();
            return;
        }

        const header = `
            <div class="transfer-unit-grid-head">Unit</div>
            <div class="transfer-unit-grid-head">Docs + Chunks</div>
            <div class="transfer-unit-grid-head">Learning objectives</div>
            <div class="transfer-unit-grid-head">Questions</div>
        `;

        const rows = lectures.map(lecture => `
            <div class="transfer-unit-row" data-unit-name="${lecture.name}">
                <div class="transfer-unit-name">${lecture.displayName || lecture.name}</div>
                <label class="transfer-unit-checkbox">
                    <input type="checkbox" class="transfer-docs-checkbox" data-unit-name="${lecture.name}" checked>
                </label>
                <label class="transfer-unit-checkbox">
                    <input type="checkbox" class="transfer-objectives-checkbox" data-unit-name="${lecture.name}" checked>
                </label>
                <label class="transfer-unit-checkbox">
                    <input type="checkbox" class="transfer-questions-checkbox" data-unit-name="${lecture.name}" checked>
                </label>
            </div>
        `).join('');

        transferUnitGrid.innerHTML = `${header}${rows}`;
        syncTransferMasterToggles();
    }

    function renderCourseStatus() {
        const badge = document.getElementById('course-status-badge');
        const note = document.getElementById('course-status-note');
        if (!badge || !note || !toggleCourseActiveBtn || !lifecycleCourseData) return;

        const isInactive = lifecycleCourseData.status === 'inactive';
        badge.textContent = isInactive ? 'Inactive' : 'Active';
        badge.classList.toggle('inactive', isInactive);
        badge.classList.toggle('active', !isInactive);
        note.textContent = isInactive
            ? 'Students are currently blocked from this course. Instructors and TAs can still manage it.'
            : 'Students, instructors, and TAs can currently use this course.';
        toggleCourseActiveBtn.textContent = isInactive ? 'Reactivate Course' : 'Deactivate Course';
        toggleCourseActiveBtn.classList.toggle('danger-button', !isInactive);
        toggleCourseActiveBtn.classList.toggle('secondary-button', isInactive);
    }

    async function initializeCourseLifecycle() {
        const currentUser = typeof getCurrentUser === 'function' ? getCurrentUser() : null;
        if (!courseLifecycleSection) return;

        if (!currentUser || currentUser.role !== 'instructor') {
            courseLifecycleSection.style.display = 'none';
            return;
        }

        courseLifecycleSection.style.display = '';

        try {
            const courseId = await getCurrentCourseId();
            if (!courseId) {
                lifecycleCourseData = null;
                if (transferUnitGrid) {
                    transferUnitGrid.innerHTML = '<div class="transfer-unit-grid-empty">Select a course first to use transfer and deactivate tools.</div>';
                }
                if (toggleCourseActiveBtn) toggleCourseActiveBtn.disabled = true;
                if (transferCourseBtn) transferCourseBtn.disabled = true;
                return;
            }

            const response = await fetch(`/api/courses/${courseId}`);
            const result = await response.json();
            if (!response.ok || !result.success || !result.data) {
                throw new Error(result.message || 'Failed to load course lifecycle data');
            }

            lifecycleCourseData = result.data;
            renderCourseStatus();
            renderTransferUnitGrid(lifecycleCourseData.lectures || []);

            if (transferCourseNameInput && !transferCourseNameInput.value.trim()) {
                transferCourseNameInput.value = `${lifecycleCourseData.name} Copy`;
            }

            if (toggleCourseActiveBtn) toggleCourseActiveBtn.disabled = false;
            if (transferCourseBtn) transferCourseBtn.disabled = false;
        } catch (error) {
            console.error('Error initializing course lifecycle section:', error);
            if (transferUnitGrid) {
                transferUnitGrid.innerHTML = '<div class="transfer-unit-grid-empty">Unable to load course transfer options right now.</div>';
            }
            if (toggleCourseActiveBtn) toggleCourseActiveBtn.disabled = true;
            if (transferCourseBtn) transferCourseBtn.disabled = true;
        }
    }

    // Handle mental health prompt reset button
    const resetMHPromptBtn = document.getElementById('reset-mh-prompt');
    if (resetMHPromptBtn) {
        resetMHPromptBtn.addEventListener('click', async () => {
            if (!confirm('Reset the mental health detection prompt to the default?')) return;
            try {
                const courseId = await getCurrentCourseId();
                const response = await fetch('/api/settings/mental-health-prompt/reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ courseId })
                });
                const result = await response.json();
                if (result.success) {
                    const textarea = document.getElementById('mental-health-detection-prompt');
                    if (textarea) textarea.value = result.prompt || '';
                    showNotification('Detection prompt reset to default', 'success');
                }
            } catch (error) {
                console.error('Error resetting MH detection prompt:', error);
                showNotification('Failed to reset detection prompt', 'error');
            }
        });
    }

    if (transferAllDocsToggle) {
        transferAllDocsToggle.addEventListener('change', (event) => {
            document.querySelectorAll('.transfer-docs-checkbox').forEach(checkbox => {
                checkbox.checked = event.target.checked;
            });
            syncTransferMasterToggles();
        });
    }

    if (transferAllObjectivesToggle) {
        transferAllObjectivesToggle.addEventListener('change', (event) => {
            document.querySelectorAll('.transfer-objectives-checkbox').forEach(checkbox => {
                checkbox.checked = event.target.checked;
            });
            syncTransferMasterToggles();
        });
    }

    if (transferAllQuestionsToggle) {
        transferAllQuestionsToggle.addEventListener('change', (event) => {
            document.querySelectorAll('.transfer-questions-checkbox').forEach(checkbox => {
                checkbox.checked = event.target.checked;
            });
            syncTransferMasterToggles();
        });
    }

    if (transferUnitGrid) {
        transferUnitGrid.addEventListener('change', (event) => {
            if (!event.target.matches('input[type="checkbox"]')) return;
            syncTransferMasterToggles();
        });
    }

    if (transferCourseModal) {
        transferCourseModal.addEventListener('click', (event) => {
            if (event.target === transferCourseModal) {
                closeTransferModal();
            }
        });
    }

    if (transferModalCancelBtn) {
        transferModalCancelBtn.addEventListener('click', () => {
            closeTransferModal();
        });
    }

    if (transferModalConfirmBtn) {
        transferModalConfirmBtn.addEventListener('click', async () => {
            if (!pendingTransferPayload || isTransferInProgress) return;

            isTransferInProgress = true;
            setTransferModalLoading(pendingTransferPayload);

            transferCourseBtn.disabled = true;
            const previousLabel = transferCourseBtn.textContent;
            transferCourseBtn.textContent = 'Creating Copy...';

            try {
                const courseId = await getCurrentCourseId();
                const response = await fetch(`/api/courses/${courseId}/transfer`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        newCourseName: pendingTransferPayload.newCourseName,
                        transferSettings: pendingTransferPayload.transferSettings,
                        transferTAs: pendingTransferPayload.transferTAs,
                        deactivateSourceCourse: pendingTransferPayload.deactivateSourceCourse,
                        units: pendingTransferPayload.units
                    })
                });

                const result = await response.json();
                if (!response.ok || !result.success) {
                    throw new Error(result.message || 'Failed to transfer course');
                }

                const warnings = Array.isArray(result.data?.warnings) ? result.data.warnings : [];
                const summary = warnings.length > 0
                    ? `Course copy created with ${warnings.length} warning${warnings.length === 1 ? '' : 's'}.`
                    : 'Course copy created successfully.';

                sessionStorage.setItem('settingsFlashMessage', JSON.stringify({
                    message: warnings.length > 0
                        ? `${summary} Switched to ${result.data.courseName}.`
                        : `${summary} Switched to ${result.data.courseName}.`,
                    type: warnings.length > 0 ? 'info' : 'success'
                }));

                localStorage.setItem('selectedCourseId', result.data.courseId);
                if (typeof setCurrentCourseId === 'function') {
                    await setCurrentCourseId(result.data.courseId);
                }

                closeTransferModal({ force: true });

                if (warnings.length > 0) {
                    alert(`${summary}\n\n${warnings.slice(0, 8).join('\n')}`);
                }

                window.location.href = `/instructor/settings?courseId=${encodeURIComponent(result.data.courseId)}`;
            } catch (error) {
                console.error('Error transferring course:', error);
                closeTransferModal({ force: true });
                showNotification(error.message || 'Failed to transfer course', 'error');
            } finally {
                transferCourseBtn.disabled = false;
                transferCourseBtn.textContent = previousLabel;
            }
        });
    }

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && transferCourseModal?.classList.contains('show')) {
            closeTransferModal();
        }
    });

    if (toggleCourseActiveBtn) {
        toggleCourseActiveBtn.addEventListener('click', async () => {
            if (!lifecycleCourseData) return;

            const isInactive = lifecycleCourseData.status === 'inactive';
            const nextStatus = isInactive ? 'active' : 'inactive';
            const confirmMessage = isInactive
                ? 'Reactivate this course so students can use it again?'
                : 'Deactivate this course? Students will be blocked until you reactivate it, but instructors and TAs will still be able to manage it.';

            if (!confirm(confirmMessage)) {
                return;
            }

            toggleCourseActiveBtn.disabled = true;
            const previousLabel = toggleCourseActiveBtn.textContent;
            toggleCourseActiveBtn.textContent = isInactive ? 'Reactivating...' : 'Deactivating...';

            try {
                const courseId = await getCurrentCourseId();
                const instructorId = getCurrentInstructorId();
                const response = await fetch(`/api/courses/${courseId}?instructorId=${encodeURIComponent(instructorId)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        instructorId,
                        status: nextStatus
                    })
                });

                const result = await response.json();
                if (!response.ok || !result.success) {
                    throw new Error(result.message || 'Failed to update course status');
                }

                lifecycleCourseData.status = nextStatus;
                renderCourseStatus();
                showNotification(
                    nextStatus === 'inactive'
                        ? 'Course deactivated. Students are now blocked, but instructors and TAs still have access.'
                        : 'Course reactivated successfully.',
                    'success'
                );
            } catch (error) {
                console.error('Error updating course status:', error);
                showNotification(error.message || 'Failed to update course status', 'error');
            } finally {
                toggleCourseActiveBtn.disabled = false;
                if (toggleCourseActiveBtn.textContent === 'Reactivating...' || toggleCourseActiveBtn.textContent === 'Deactivating...') {
                    toggleCourseActiveBtn.textContent = previousLabel;
                }
                renderCourseStatus();
            }
        });
    }

    if (transferCourseBtn) {
        transferCourseBtn.addEventListener('click', async () => {
            if (!lifecycleCourseData) {
                showNotification('Course data is still loading. Please try again.', 'warning');
                return;
            }

            const newCourseName = transferCourseNameInput?.value?.trim() || '';
            if (!newCourseName) {
                showNotification('Please enter a name for the new course.', 'error');
                transferCourseNameInput?.focus();
                return;
            }

            const unitRows = Array.from(document.querySelectorAll('.transfer-unit-row'));
            const units = unitRows.map(row => {
                const unitName = row.getAttribute('data-unit-name');
                return {
                    unitName,
                    transferDocuments: row.querySelector('.transfer-docs-checkbox')?.checked !== false,
                    transferLearningObjectives: row.querySelector('.transfer-objectives-checkbox')?.checked !== false,
                    transferAssessmentQuestions: row.querySelector('.transfer-questions-checkbox')?.checked !== false
                };
            });

            const deactivateSourceCourse = document.getElementById('deactivate-source-after-transfer-toggle')?.checked === true;
            openTransferModal({
                newCourseName,
                transferSettings: document.getElementById('transfer-settings-toggle')?.checked === true,
                transferTAs: document.getElementById('transfer-tas-toggle')?.checked === true,
                deactivateSourceCourse,
                units
            });
        });
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

                // Save mental health detection prompt
                const mhDetectionPrompt = document.getElementById('mental-health-detection-prompt')?.value;
                if (mhDetectionPrompt) {
                    await fetch('/api/settings/mental-health-prompt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ prompt: mhDetectionPrompt, courseId })
                    });
                }

                // Save anonymize students setting
                const anonymizeStudents = document.getElementById('anonymize-students-toggle')?.checked;
                await fetch('/api/settings/anonymize-students', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ courseId, enabled: anonymizeStudents === true })
                });

                // Save question generation prompts if section is visible (system admins only)
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

    if (grantSystemAdminBtn) {
        grantSystemAdminBtn.addEventListener('click', async () => {
            const email = systemAdminEmailInput ? systemAdminEmailInput.value.trim() : '';
            if (!email) {
                showNotification('Enter an email address first.', 'error');
                return;
            }

            grantSystemAdminBtn.disabled = true;
            grantSystemAdminBtn.textContent = 'Granting...';

            try {
                const response = await fetch('/api/settings/system-admins', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ email })
                });

                const result = await response.json();

                if (!result.success) {
                    showNotification(result.error || 'Failed to grant system admin access.', 'error');
                    return;
                }

                if (systemAdminEmailInput) {
                    systemAdminEmailInput.value = '';
                }

                await loadSystemAdmins();
                showNotification(`System admin access granted to ${email}.`, 'success');
            } catch (error) {
                console.error('Error granting system admin access:', error);
                showNotification('Failed to grant system admin access.', 'error');
            } finally {
                grantSystemAdminBtn.disabled = false;
                grantSystemAdminBtn.textContent = 'Grant Admin Access';
            }
        });
    }

    if (systemAdminList) {
        systemAdminList.addEventListener('click', async event => {
            const revokeButton = event.target.closest('.system-admin-revoke-btn');
            if (!revokeButton) {
                return;
            }

            const email = revokeButton.dataset.email;
            if (!email) {
                return;
            }

            if (!confirm(`Revoke system admin access for ${email}?`)) {
                return;
            }

            revokeButton.disabled = true;
            revokeButton.textContent = 'Revoking...';

            try {
                const response = await fetch('/api/settings/system-admins/revoke', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ email })
                });

                const result = await response.json();

                if (!result.success) {
                    showNotification(result.error || 'Failed to revoke system admin access.', 'error');
                    await loadSystemAdmins();
                    return;
                }

                await loadSystemAdmins();
                showNotification(`System admin access revoked for ${email}.`, 'success');
            } catch (error) {
                console.error('Error revoking system admin access:', error);
                showNotification('Failed to revoke system admin access.', 'error');
                await loadSystemAdmins();
            }
        });
    }

    // Handle reset question prompts button click (system admins only)
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
     * Check if the current user has system admin access
     * Hides the entire privileged section set if the user does not
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
            const mhDetectionSection = document.getElementById('mental-health-detection-section');
            const adminSection = document.getElementById('system-admin-section');

            if (result.success && result.canDeleteAll) {
                // User has permission, ensure the sections are visible
                if (databaseSection) databaseSection.style.display = '';
                if (loginRestrictionSection) loginRestrictionSection.style.display = '';
                if (questionGenerationSection) questionGenerationSection.style.display = '';
                if (mhDetectionSection) mhDetectionSection.style.display = '';
                if (adminSection) adminSection.style.display = '';
                return true;
            } else {
                // User doesn't have permission, hide the sections
                if (databaseSection) databaseSection.style.display = 'none';
                if (loginRestrictionSection) loginRestrictionSection.style.display = 'none';
                if (questionGenerationSection) questionGenerationSection.style.display = 'none';
                if (mhDetectionSection) mhDetectionSection.style.display = 'none';
                if (adminSection) adminSection.style.display = 'none';
                return false;
            }
        } catch (error) {
            console.error('Error checking delete all permission:', error);
            // On error, hide the sections for security
            const databaseSection = document.getElementById('database-management-section');
            const loginRestrictionSection = document.getElementById('login-restriction-section');
            const questionGenerationSection = document.getElementById('question-generation-section');
            const mhDetectionSection = document.getElementById('mental-health-detection-section');
            const adminSection = document.getElementById('system-admin-section');
            if (databaseSection) databaseSection.style.display = 'none';
            if (loginRestrictionSection) loginRestrictionSection.style.display = 'none';
            if (questionGenerationSection) questionGenerationSection.style.display = 'none';
            if (mhDetectionSection) mhDetectionSection.style.display = 'none';
            if (adminSection) adminSection.style.display = 'none';
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
