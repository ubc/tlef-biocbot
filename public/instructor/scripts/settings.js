document.addEventListener('DOMContentLoaded', async () => {
    const SUPER_STUDENT_LEVELS = ['intro', 'undergraduate', 'graduate'];
    const SUPER_INSTRUCTOR_LEVELS = ['overview', 'standard', 'deepDive'];

    const settingsHub = document.getElementById('settings-hub');
    const settingsPanels = document.getElementById('settings-panels');
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
    // Currently-selected Super Course bucket in the bucket editor (null = none yet).
    let selectedSuperchatId = null;
    // Cached bucket summaries so the per-course checklist can re-render without a
    // page refresh whenever buckets are created/renamed/deleted.
    let availableSuperchats = [];
    // Buckets created in this session get a "New" badge until membership is saved.
    const newlyCreatedSuperchatIds = new Set();

    /* =============================================
       Hub / panel navigation (hash-routed)
       ============================================= */

    const BASE_PANEL_NAMES = ['course-basics', 'student-chat', 'prompts', 'quiz', 'privacy', 'super-course'];
    const ADMIN_PANEL_NAMES = ['admin-platform', 'admin-access', 'admin-safety', 'admin-database'];

    function getVisiblePanelNames() {
        const names = [...BASE_PANEL_NAMES];
        const lifecycleTile = document.getElementById('lifecycle-tile');
        if (lifecycleTile && !lifecycleTile.hidden) {
            names.push('lifecycle');
        }
        const adminTileGroup = document.getElementById('admin-tile-group');
        if (adminTileGroup && !adminTileGroup.hidden) {
            names.push(...ADMIN_PANEL_NAMES);
        }
        return names;
    }

    function currentPanelName() {
        const hash = decodeURIComponent((window.location.hash || '').replace(/^#/, ''));
        return getVisiblePanelNames().includes(hash) ? hash : null;
    }

    // Show either the hub (tile grid) or the panel view for the current hash.
    // Deep links (/instructor/settings#quiz), refresh, and the browser back
    // button all work because the hash is the source of truth.
    function renderSettingsView({ focusHeading = false } = {}) {
        if (!settingsHub || !settingsPanels) return;

        const active = currentPanelName();
        settingsHub.hidden = !!active;
        settingsPanels.hidden = !active;

        document.querySelectorAll('.settings-panel').forEach(panel => {
            panel.hidden = panel.dataset.panel !== active;
        });

        document.querySelectorAll('.settings-rail-link').forEach(link => {
            if (link.dataset.panel === active) {
                link.setAttribute('aria-current', 'true');
            } else {
                link.removeAttribute('aria-current');
            }
        });

        // Move focus to the panel heading so keyboard and screen-reader users
        // land on the section they navigated to.
        if (active && focusHeading) {
            const heading = document.querySelector(`.settings-panel[data-panel="${active}"] .settings-panel-title`);
            if (heading) heading.focus();
        }
    }

    window.addEventListener('hashchange', () => renderSettingsView({ focusHeading: true }));
    renderSettingsView();

    /* =============================================
       Per-section dirty tracking
       ============================================= */

    function initDirtyTracking() {
        document.querySelectorAll('.settings-section').forEach(section => {
            const note = section.querySelector('.settings-dirty-note');
            if (!note) return;
            const markDirty = (event) => {
                if (event.target.closest('.settings-section-actions')) return;
                note.hidden = false;
            };
            section.addEventListener('input', markDirty);
            section.addEventListener('change', markDirty);
        });
    }

    function clearDirty(elementInSection) {
        const section = elementInSection && elementInSection.closest
            ? elementInSection.closest('.settings-section')
            : null;
        const note = section ? section.querySelector('.settings-dirty-note') : null;
        if (note) note.hidden = true;
    }

    function markSectionDirty(sectionId) {
        const note = document.querySelector(`#${sectionId} .settings-dirty-note`);
        if (note) note.hidden = false;
    }

    // Shared wiring for section save/reset buttons: confirm (optional), busy
    // state, error notification, and clearing the section's dirty note.
    function wireSectionButton(buttonId, handler, { confirmMessage, busyLabel } = {}) {
        const btn = document.getElementById(buttonId);
        if (!btn) return;
        btn.addEventListener('click', async () => {
            if (confirmMessage && !confirm(confirmMessage)) return;
            const originalLabel = btn.textContent;
            btn.disabled = true;
            if (busyLabel) btn.textContent = busyLabel;
            try {
                await handler();
                clearDirty(btn);
            } catch (error) {
                console.error(`Error handling ${buttonId}:`, error);
                showNotification(error.message || 'Something went wrong', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = originalLabel;
            }
        });
    }

    initDirtyTracking();

    // Check if user has system admin access
    await waitForAuth();
    const canManageDB = await checkDeleteAllPermission();

    // Load initial settings including prompts
    await loadSettings(canManageDB);

    // Visibility of the lifecycle and admin groups may have changed during load;
    // re-resolve the current hash against what this user can actually see.
    renderSettingsView();

    async function loadSettings(canManageDB) {
        // Super Course settings (per-course bucket membership + bucket management)
        // are available to instructors, not just admins, so they can curate their
        // own Super Course groupings. Load these FIRST and independently, so a
        // failure in an unrelated section below can never hide them.
        try {
            await loadAiSettings();
            await loadSuperCourseChatSettings();
        } catch (error) {
            console.error('Error loading Super Course settings:', error);
        }

        try {
            // Load global config (prompts and additive retrieval)
            await loadGlobalConfig();

            // Load quiz practice settings
            await loadQuizSettings();

            // Load course year level
            await loadCourseLevel();

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
                await loadLLMSettings();
                await loadQuestionPrompts();
                await loadSystemAdmins();
            }

            consumeDeferredFlashMessage();
        } catch (error) {
            console.error('Error loading settings:', error);
            showNotification('Failed to load settings', 'error');
        }
    }

    function isGpt5Family(model) {
        return typeof model === 'string' && model.startsWith('gpt-5');
    }

    function updateReasoningVisibility() {
        const modelSelect = document.getElementById('llm-model-select');
        const reasoningItem = document.getElementById('llm-reasoning-item');
        const reasoningSelect = document.getElementById('llm-reasoning-select');
        if (!modelSelect || !reasoningItem) return;

        reasoningItem.style.display = isGpt5Family(modelSelect.value) ? '' : 'none';

        // gpt-5.4-nano does not support "minimal"; hide it and bump to "low".
        if (reasoningSelect) {
            const minimalOption = reasoningSelect.querySelector('option[value="minimal"]');
            if (minimalOption) {
                if (modelSelect.value === 'gpt-5.4-nano') {
                    minimalOption.hidden = true;
                    minimalOption.disabled = true;
                    if (reasoningSelect.value === 'minimal') reasoningSelect.value = 'low';
                } else {
                    minimalOption.hidden = false;
                    minimalOption.disabled = false;
                }
            }
        }
    }

    async function loadLLMSettings() {
        try {
            const response = await fetch('/api/settings/llm', { credentials: 'include' });
            const result = await response.json();
            if (!result.success || !result.settings) return;

            const modelSelect = document.getElementById('llm-model-select');
            const reasoningSelect = document.getElementById('llm-reasoning-select');
            if (modelSelect) {
                modelSelect.value = result.settings.model;
                modelSelect.removeEventListener('change', updateReasoningVisibility);
                modelSelect.addEventListener('change', updateReasoningVisibility);
            }
            if (reasoningSelect) {
                reasoningSelect.value = result.settings.reasoningEffort || 'minimal';
            }
            updateReasoningVisibility();
        } catch (error) {
            console.error('Error loading LLM settings:', error);
        }
    }

    async function loadAdminSettings() {
        try {
            const response = await fetch('/api/settings/global');
            const result = await response.json();

            if (result.success && result.settings) {
                const allowLocalLoginToggle = document.getElementById('allow-local-login-toggle');
                if (allowLocalLoginToggle) {
                    allowLocalLoginToggle.checked = result.settings.allowLocalLogin !== false; // Default true
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

    async function loadAiSettings() {
        try {
            const courseId = await getCurrentCourseId();
            if (!courseId) return;

            const response = await fetch(`/api/settings/ai-settings?courseId=${encodeURIComponent(courseId)}`, {
                credentials: 'include'
            });
            const result = await response.json();
            if (!result.success || !result.settings) return;

            const topKInput = document.getElementById('student-chat-topk-input');
            if (topKInput) topKInput.value = result.settings.ragSettings?.student?.topK || 3;

            availableSuperchats = result.availableSuperchats || [];
            renderCourseSuperchatChecklist(
                availableSuperchats,
                result.settings.superchatIds || []
            );
        } catch (error) {
            console.error('Error loading AI settings:', error);
        }
    }

    // Render the per-course bucket checklist. Each bucket is a checkbox; checked
    // state reflects the course's current superchatIds. Read on save.
    function renderCourseSuperchatChecklist(buckets, selectedIds) {
        const container = document.getElementById('course-superchat-checklist');
        if (!container) return;

        if (!buckets.length) {
            container.innerHTML = '<p class="superchat-checklist-empty">No Super Course buckets exist yet. Create one below.</p>';
            return;
        }

        const selected = new Set(selectedIds || []);
        container.innerHTML = buckets.map(b => {
            const id = `course-superchat-${b.superchatId}`;
            const checked = selected.has(b.superchatId) ? 'checked' : '';
            const isNew = newlyCreatedSuperchatIds.has(b.superchatId);
            return `
                <label class="superchat-checklist-item${isNew ? ' is-new' : ''}" for="${id}">
                    <input type="checkbox" id="${id}" class="course-superchat-checkbox" value="${escapeHtml(b.superchatId)}" ${checked}>
                    <span>${escapeHtml(b.name)}</span>
                    ${isNew ? '<span class="superchat-checklist-new-badge">New</span>' : ''}
                </label>`;
        }).join('');
    }

    // Re-render the checklist from the cached bucket list, preserving whatever
    // the user currently has checked (plus any ids passed in, e.g. a bucket that
    // was just created and should start checked for this course).
    function refreshCourseSuperchatChecklist(extraCheckedIds = []) {
        const checked = new Set(collectCourseSuperchatIds());
        extraCheckedIds.forEach(id => checked.add(id));
        renderCourseSuperchatChecklist(availableSuperchats, Array.from(checked));
    }

    // Collect the checked bucket ids from the per-course checklist.
    function collectCourseSuperchatIds() {
        return Array.from(document.querySelectorAll('.course-superchat-checkbox'))
            .filter(cb => cb.checked)
            .map(cb => cb.value);
    }

    function applyLevelModifiersToFields(prefix, levels, modifiers) {
        const map = modifiers && typeof modifiers === 'object' ? modifiers : {};
        levels.forEach(level => {
            const el = document.getElementById(`${prefix}-${level}`);
            if (el) el.value = typeof map[level] === 'string' ? map[level] : '';
        });
    }

    function collectLevelModifiersFromFields(prefix, levels) {
        const result = {};
        levels.forEach(level => {
            const el = document.getElementById(`${prefix}-${level}`);
            result[level] = el ? el.value : '';
        });
        return result;
    }

    // Fill the bucket editor form from a superchat object ({ name, yearLevel,
    // showToStudents, settings }).
    function fillSuperchatForm(superchat) {
        const s = (superchat && superchat.settings) || {};
        const nameInput = document.getElementById('superchat-name-input');
        const yearSelect = document.getElementById('superchat-year-select');
        const showStudentToggle = document.getElementById('show-student-super-course-toggle');

        if (nameInput) nameInput.value = (superchat && superchat.name) || '';
        if (yearSelect) yearSelect.value = (superchat && superchat.yearLevel) ? String(superchat.yearLevel) : '';
        if (showStudentToggle) showStudentToggle.checked = superchat && superchat.showToStudents === true;
        fillSuperchatChatSettingsFields(s);
    }

    // Fill only the chat-settings fields (the "Advanced" group) of the bucket
    // editor. Used by both fillSuperchatForm and the per-bucket reset, which
    // restores defaults without touching the bucket's name/year/visibility.
    function fillSuperchatChatSettingsFields(s) {
        const instructorTopKInput = document.getElementById('super-instructor-topk-input');
        const studentTopKInput = document.getElementById('super-student-topk-input');
        const includeInactiveToggle = document.getElementById('include-inactive-super-course-toggle');
        const includeNotesToggle = document.getElementById('include-notes-super-course-toggle');
        const noteRatioInput = document.getElementById('super-note-ratio-input');
        const noteMinScoreInput = document.getElementById('super-note-min-score-input');
        const instructorPrompt = document.getElementById('super-instructor-prompt');
        const studentPrompt = document.getElementById('super-student-prompt');

        if (instructorTopKInput) instructorTopKInput.value = s.instructorTopK || 8;
        if (studentTopKInput) studentTopKInput.value = s.studentTopK || 8;
        if (includeInactiveToggle) includeInactiveToggle.checked = s.includeInactiveCourses === true;
        if (includeNotesToggle) includeNotesToggle.checked = s.includeNotesInRetrieval !== false;
        if (noteRatioInput) noteRatioInput.value = s.noteRetrievalRatio ?? 0.25;
        if (noteMinScoreInput) noteMinScoreInput.value = s.noteMinScore ?? 0.25;
        if (instructorPrompt) instructorPrompt.value = s.instructorPrompt || '';
        if (studentPrompt) studentPrompt.value = s.studentPrompt || '';
        applyLevelModifiersToFields('super-student-level', SUPER_STUDENT_LEVELS, s.studentLevelModifiers);
        applyLevelModifiersToFields('super-instructor-level', SUPER_INSTRUCTOR_LEVELS, s.instructorLevelModifiers);
    }

    // Enable/disable the editor fields based on whether a bucket is selected.
    function setSuperchatEditorEnabled(enabled) {
        const ids = [
            'superchat-name-input', 'superchat-year-select', 'delete-superchat-btn',
            'super-instructor-topk-input', 'super-student-topk-input',
            'include-inactive-super-course-toggle', 'show-student-super-course-toggle',
            'include-notes-super-course-toggle', 'super-note-ratio-input', 'super-note-min-score-input',
            'super-instructor-prompt', 'super-student-prompt',
            'reset-superchat-bucket', 'save-superchat-bucket'
        ];
        for (const id of ids) {
            const el = document.getElementById(id);
            if (el) el.disabled = !enabled;
        }
    }

    // Load a single bucket into the editor by id.
    async function loadSuperchatIntoForm(superchatId) {
        if (!superchatId) {
            selectedSuperchatId = null;
            setSuperchatEditorEnabled(false);
            return;
        }
        try {
            const response = await fetch(`/api/superchats/${encodeURIComponent(superchatId)}`, { credentials: 'include' });
            const result = await response.json();
            if (!response.ok || !result.success) throw new Error(result.message || 'Failed to load bucket');
            selectedSuperchatId = superchatId;
            setSuperchatEditorEnabled(true);
            fillSuperchatForm(result.superchat);
            clearDirty(document.getElementById('superchat-select'));
        } catch (error) {
            console.error('Error loading superchat:', error);
        }
    }

    // Populate the bucket <select> from the list endpoint, refresh the cached
    // bucket summaries, and load the preferred (or first) bucket into the editor.
    async function loadSuperchatList(preferredId) {
        const select = document.getElementById('superchat-select');
        if (!select) return;
        try {
            const response = await fetch('/api/superchats', { credentials: 'include' });
            const result = await response.json();
            if (!response.ok || !result.success) throw new Error(result.message || 'Failed to list buckets');

            const buckets = result.superchats || [];
            availableSuperchats = buckets;
            select.innerHTML = buckets.length
                ? buckets.map(b => `<option value="${escapeHtml(b.superchatId)}">${escapeHtml(b.name)} (${b.courseCount} course${b.courseCount === 1 ? '' : 's'})</option>`).join('')
                : '<option value="">No buckets yet</option>';

            if (!buckets.length) {
                await loadSuperchatIntoForm(null);
                return;
            }

            const toSelect = (preferredId && buckets.some(b => b.superchatId === preferredId))
                ? preferredId
                : buckets[0].superchatId;
            select.value = toSelect;
            await loadSuperchatIntoForm(toSelect);
        } catch (error) {
            console.error('Error loading superchat list:', error);
        }
    }

    // Wire up bucket management controls (select / create / delete).
    function initSuperchatManagement() {
        const select = document.getElementById('superchat-select');
        const newBtn = document.getElementById('new-superchat-btn');
        const newNameInput = document.getElementById('new-superchat-name');
        const deleteBtn = document.getElementById('delete-superchat-btn');

        if (select) {
            select.addEventListener('change', () => loadSuperchatIntoForm(select.value || null));
        }

        async function createBucket() {
            const name = (newNameInput?.value || '').trim();
            if (!name) {
                showNotification('Enter a name for the new bucket first.', 'error');
                newNameInput?.focus();
                return;
            }
            newBtn.disabled = true;
            try {
                const response = await fetch('/api/superchats', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ name })
                });
                const result = await response.json();
                if (!response.ok || !result.success) throw new Error(result.message || 'Failed to create bucket');

                const newId = result.superchat.superchatId;
                newlyCreatedSuperchatIds.add(newId);
                if (newNameInput) newNameInput.value = '';

                // Refresh the bucket editor select AND the per-course checklist in
                // place (no page refresh needed). The new bucket starts checked for
                // this course; saving bucket membership confirms it.
                await loadSuperchatList(newId);
                refreshCourseSuperchatChecklist([newId]);
                markSectionDirty('course-superchats-section');
                showNotification('Bucket created and checked for this course. Save bucket membership to confirm.', 'success');
            } catch (error) {
                console.error('Error creating bucket:', error);
                showNotification(error.message || 'Failed to create bucket', 'error');
            } finally {
                newBtn.disabled = false;
            }
        }

        if (newBtn) {
            newBtn.addEventListener('click', createBucket);
        }
        if (newNameInput) {
            newNameInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    createBucket();
                }
            });
        }
        if (deleteBtn) {
            deleteBtn.addEventListener('click', async () => {
                if (!selectedSuperchatId) return;
                if (!confirm('Delete this Super Course bucket? It will be removed from every course and hidden from students.')) return;
                try {
                    const response = await fetch(`/api/superchats/${encodeURIComponent(selectedSuperchatId)}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    const result = await response.json();
                    if (!response.ok || !result.success) throw new Error(result.message || 'Failed to delete bucket');
                    newlyCreatedSuperchatIds.delete(selectedSuperchatId);
                    await loadSuperchatList();
                    // Drop the deleted bucket from the per-course checklist too.
                    refreshCourseSuperchatChecklist();
                    showNotification('Super Course bucket deleted', 'success');
                } catch (error) {
                    console.error('Error deleting bucket:', error);
                    showNotification(error.message || 'Failed to delete bucket', 'error');
                }
            });
        }
    }

    async function loadSuperCourseChatSettings() {
        initSuperchatManagement();
        await loadSuperchatList();
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
                applyPromptValues(result.prompts);

                const additiveToggle = document.getElementById('additive-retrieval-toggle');
                if (additiveToggle) additiveToggle.checked = !!result.prompts.additiveRetrieval;

                // Convert seconds to minutes for display
                const idleTimeoutInput = document.getElementById('idle-timeout-input');
                if (idleTimeoutInput && result.prompts.studentIdleTimeout) {
                    idleTimeoutInput.value = result.prompts.studentIdleTimeout / 60;
                }
            }
        } catch (error) {
            console.error('Error fetching global config:', error);
        }
    }

    // Fill the six persona prompt textareas from a prompts object.
    function applyPromptValues(promptValues) {
        const fields = {
            'base-prompt': promptValues.base,
            'protege-prompt': promptValues.protege,
            'tutor-prompt': promptValues.tutor,
            'explain-prompt': promptValues.explain,
            'directive-prompt': promptValues.directive,
            'quiz-help-prompt': promptValues.quizHelp
        };
        for (const [id, value] of Object.entries(fields)) {
            const el = document.getElementById(id);
            if (el) el.value = value || '';
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
                applyQuestionPromptValues(result.prompts);
            }
        } catch (error) {
            console.error('Error fetching question prompts:', error);
        }
    }

    function applyQuestionPromptValues(promptValues) {
        const systemPromptInput = document.getElementById('question-system-prompt');
        const trueFalseInput = document.getElementById('question-true-false-prompt');
        const multipleChoiceInput = document.getElementById('question-multiple-choice-prompt');
        const shortAnswerInput = document.getElementById('question-short-answer-prompt');

        if (systemPromptInput) systemPromptInput.value = promptValues.systemPrompt || '';
        if (trueFalseInput) trueFalseInput.value = promptValues.trueFalse || '';
        if (multipleChoiceInput) multipleChoiceInput.value = promptValues.multipleChoice || '';
        if (shortAnswerInput) shortAnswerInput.value = promptValues.shortAnswer || '';
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

    /**
     * Load the course's year level into the Course Level select.
     */
    async function loadCourseLevel() {
        const select = document.getElementById('course-year-level-select');
        if (!select) return;
        try {
            const courseId = await getCurrentCourseId();
            if (!courseId) return;

            const response = await fetch(`/api/courses/${courseId}`);
            const result = await response.json();
            if (result.success && result.data) {
                const level = result.data.yearLevel;
                select.value = (level === null || level === undefined) ? '' : String(level);
            }
        } catch (error) {
            console.error('Error loading course year level:', error);
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

    /* =============================================
       Shared save helpers (one per backend document)

       The /prompts, /quiz, and /ai-settings endpoints are full-document
       writes, so each helper collects every field the endpoint owns from the
       DOM (values are loaded fresh on page load, so untouched fields simply
       round-trip their current server values).
       ============================================= */

    async function saveAiSettingsToServer() {
        const courseId = await getCurrentCourseId();
        const superchatIds = collectCourseSuperchatIds();
        const studentTopK = Number(document.getElementById('student-chat-topk-input')?.value || 3);
        const response = await fetch('/api/settings/ai-settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ courseId, superchatIds, studentTopK })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save AI settings');
        }
        return result;
    }

    async function savePromptsConfigToServer() {
        const courseId = await getCurrentCourseId();
        const idleTimeoutInput = document.getElementById('idle-timeout-input');
        let studentIdleTimeout = 240;
        if (idleTimeoutInput && idleTimeoutInput.value !== '') {
            studentIdleTimeout = Math.round(parseFloat(idleTimeoutInput.value) * 60);
        }

        const response = await fetch('/api/settings/prompts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                base: document.getElementById('base-prompt')?.value ?? '',
                protege: document.getElementById('protege-prompt')?.value ?? '',
                tutor: document.getElementById('tutor-prompt')?.value ?? '',
                explain: document.getElementById('explain-prompt')?.value ?? '',
                directive: document.getElementById('directive-prompt')?.value ?? '',
                quizHelp: document.getElementById('quiz-help-prompt')?.value ?? '',
                additiveRetrieval: document.getElementById('additive-retrieval-toggle')?.checked === true,
                studentIdleTimeout,
                courseId
            })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save course settings');
        }
        return result;
    }

    async function saveQuizConfigToServer() {
        const courseId = await getCurrentCourseId();
        const unitCheckboxes = document.querySelectorAll('.testable-unit-checkbox');
        let testableUnits = 'all';
        if (unitCheckboxes.length > 0) {
            const checkedUnits = Array.from(unitCheckboxes).filter(cb => cb.checked).map(cb => cb.value);
            // If all are checked, store 'all'; otherwise store the selected names
            testableUnits = checkedUnits.length === unitCheckboxes.length ? 'all' : checkedUnits;
        }

        const response = await fetch('/api/settings/quiz', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                courseId,
                enabled: document.getElementById('quiz-enabled-toggle')?.checked === true,
                testableUnits,
                allowLectureMaterialAccess: document.getElementById('quiz-material-access-toggle')?.checked === true,
                allowSourceAttributionDownloads: document.getElementById('source-attribution-download-toggle')?.checked === true
            })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save quiz settings');
        }
        return result;
    }

    async function saveAnonymizeStudentsToServer() {
        const courseId = await getCurrentCourseId();
        const enabled = document.getElementById('anonymize-students-toggle')?.checked === true;
        const response = await fetch('/api/settings/anonymize-students', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ courseId, enabled })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save anonymize students setting');
        }
        return result;
    }

    async function saveSuperchatBucketToServer() {
        if (!selectedSuperchatId) {
            throw new Error('Select a bucket first');
        }
        const yearValue = document.getElementById('superchat-year-select')?.value || '';
        const response = await fetch(`/api/superchats/${encodeURIComponent(selectedSuperchatId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                name: document.getElementById('superchat-name-input')?.value || '',
                yearLevel: yearValue ? Number(yearValue) : null,
                showToStudents: document.getElementById('show-student-super-course-toggle')?.checked === true,
                instructorTopK: Number(document.getElementById('super-instructor-topk-input')?.value || 8),
                studentTopK: Number(document.getElementById('super-student-topk-input')?.value || 8),
                includeInactiveCourses: document.getElementById('include-inactive-super-course-toggle')?.checked === true,
                includeNotesInRetrieval: document.getElementById('include-notes-super-course-toggle')?.checked !== false,
                noteRetrievalRatio: Number(document.getElementById('super-note-ratio-input')?.value ?? 0.25),
                noteMinScore: Number(document.getElementById('super-note-min-score-input')?.value ?? 0.25),
                instructorPrompt: document.getElementById('super-instructor-prompt')?.value || '',
                studentPrompt: document.getElementById('super-student-prompt')?.value || '',
                studentLevelModifiers: collectLevelModifiersFromFields('super-student-level', SUPER_STUDENT_LEVELS),
                instructorLevelModifiers: collectLevelModifiersFromFields('super-instructor-level', SUPER_INSTRUCTOR_LEVELS)
            })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save Super Course settings');
        }
        return result;
    }

    /* =============================================
       Per-section save / reset wiring
       ============================================= */

    // Course basics
    wireSectionButton('save-course-basics', async () => {
        const courseId = await getCurrentCourseId();
        const yearLevelSelect = document.getElementById('course-year-level-select');
        if (!courseId || !yearLevelSelect) {
            throw new Error('Select a course first');
        }
        const rawLevel = yearLevelSelect.value;
        const yearLevel = rawLevel === '' ? null : Number(rawLevel);
        const instructorId = getCurrentInstructorId();
        const response = await fetch(`/api/courses/${courseId}?instructorId=${encodeURIComponent(instructorId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ instructorId, yearLevel })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save course level');
        }
        showNotification('Course basics saved', 'success');
    }, { busyLabel: 'Saving...' });

    // Student chat (top-K lives in ai-settings; additive retrieval in the
    // prompts config; source attribution downloads in the quiz config)
    wireSectionButton('save-student-chat', async () => {
        await saveAiSettingsToServer();
        await savePromptsConfigToServer();
        await saveQuizConfigToServer();
        showNotification('Student chat settings saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-student-chat', async () => {
        const topKInput = document.getElementById('student-chat-topk-input');
        const additiveToggle = document.getElementById('additive-retrieval-toggle');
        const sourceAttributionToggle = document.getElementById('source-attribution-download-toggle');
        if (topKInput) topKInput.value = 3;
        if (additiveToggle) additiveToggle.checked = true;
        if (sourceAttributionToggle) sourceAttributionToggle.checked = false;
        await saveAiSettingsToServer();
        await savePromptsConfigToServer();
        await saveQuizConfigToServer();
        showNotification('Student chat settings reset to defaults', 'success');
    }, {
        confirmMessage: 'Reset student chat settings (Top-K, additive retrieval, source downloads) to defaults?',
        busyLabel: 'Resetting...'
    });

    // AI persona prompts
    wireSectionButton('save-prompts', async () => {
        await savePromptsConfigToServer();
        showNotification('Prompts saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-prompts', async () => {
        // Fetch the platform defaults (GET without courseId), fill the fields,
        // then save. Only the six persona prompts reset - additive retrieval and
        // idle timeout belong to other sections and keep their current values.
        const response = await fetch('/api/settings/prompts');
        const result = await response.json();
        if (!result.success || !result.prompts) {
            throw new Error('Failed to load default prompts');
        }
        applyPromptValues(result.prompts);
        await savePromptsConfigToServer();
        showNotification('Prompts reset to defaults', 'success');
    }, {
        confirmMessage: 'Reset all AI persona prompts for this course to the default values?',
        busyLabel: 'Resetting...'
    });

    // Quiz practice
    wireSectionButton('save-quiz-settings', async () => {
        await saveQuizConfigToServer();
        showNotification('Quiz settings saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-quiz-settings', async () => {
        const quizEnabledToggle = document.getElementById('quiz-enabled-toggle');
        const materialAccessToggle = document.getElementById('quiz-material-access-toggle');
        if (quizEnabledToggle) quizEnabledToggle.checked = false;
        if (materialAccessToggle) materialAccessToggle.checked = true;
        document.querySelectorAll('.testable-unit-checkbox').forEach(cb => { cb.checked = true; });
        await saveQuizConfigToServer();
        showNotification('Quiz settings reset to defaults', 'success');
    }, {
        confirmMessage: 'Reset quiz practice settings to defaults? Quiz practice will be disabled and all published units marked testable.',
        busyLabel: 'Resetting...'
    });

    // Privacy & sessions
    wireSectionButton('save-privacy-settings', async () => {
        await saveAnonymizeStudentsToServer();
        await savePromptsConfigToServer();
        showNotification('Privacy settings saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-privacy-settings', async () => {
        const anonymizeToggle = document.getElementById('anonymize-students-toggle');
        const idleTimeoutInput = document.getElementById('idle-timeout-input');
        if (anonymizeToggle) anonymizeToggle.checked = false;
        if (idleTimeoutInput) idleTimeoutInput.value = 4;
        await saveAnonymizeStudentsToServer();
        await savePromptsConfigToServer();
        showNotification('Privacy settings reset to defaults', 'success');
    }, {
        confirmMessage: 'Reset privacy and session settings to defaults (anonymization off, 4 minute idle timeout)?',
        busyLabel: 'Resetting...'
    });

    // Super course: per-course bucket membership
    wireSectionButton('save-course-superchats', async () => {
        await saveAiSettingsToServer();
        newlyCreatedSuperchatIds.clear();
        refreshCourseSuperchatChecklist();
        showNotification('Bucket membership saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-course-superchats', async () => {
        document.querySelectorAll('.course-superchat-checkbox').forEach(cb => { cb.checked = false; });
        await saveAiSettingsToServer();
        newlyCreatedSuperchatIds.clear();
        refreshCourseSuperchatChecklist();
        showNotification('Course removed from all Super Course buckets', 'success');
    }, {
        confirmMessage: 'Remove this course from every Super Course bucket?',
        busyLabel: 'Removing...'
    });

    // Super course: shared bucket settings
    wireSectionButton('save-superchat-bucket', async () => {
        await saveSuperchatBucketToServer();
        // Refresh the select label and checklist (name/course count may have changed).
        await loadSuperchatList(selectedSuperchatId);
        refreshCourseSuperchatChecklist();
        showNotification('Bucket settings saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-superchat-bucket', async () => {
        if (!selectedSuperchatId) {
            throw new Error('Select a bucket first');
        }
        const response = await fetch('/api/superchats/defaults', { credentials: 'include' });
        const result = await response.json();
        if (!response.ok || !result.success || !result.settings) {
            throw new Error(result.message || 'Failed to load default bucket settings');
        }
        // Restore the chat-settings defaults but keep the bucket's identity
        // (name, year level, student visibility) untouched, then persist.
        fillSuperchatChatSettingsFields(result.settings);
        await saveSuperchatBucketToServer();
        showNotification('Bucket chat settings reset to defaults', 'success');
    }, {
        confirmMessage: 'Reset this bucket\'s chat settings (Top-K, notes, prompts, modifiers) to defaults? Its name, year level, and student visibility are kept.',
        busyLabel: 'Resetting...'
    });

    // Admin: platform & models
    wireSectionButton('save-llm-settings', async () => {
        const model = document.getElementById('llm-model-select')?.value;
        const reasoningEffort = document.getElementById('llm-reasoning-select')?.value || 'minimal';
        if (!model) {
            throw new Error('Select a model first');
        }
        const response = await fetch('/api/settings/llm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ model, reasoningEffort })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.error || 'Failed to save LLM settings');
        }
        showNotification('Model settings saved', 'success');
    }, { busyLabel: 'Saving...' });

    // Admin: login restrictions
    wireSectionButton('save-access-settings', async () => {
        const allowLocalLogin = document.getElementById('allow-local-login-toggle')?.checked;
        const response = await fetch('/api/settings/global', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ allowLocalLogin })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.error || 'Failed to save login settings');
        }
        showNotification('Login settings saved', 'success');
    }, { busyLabel: 'Saving...' });

    // Admin: question generation prompts
    wireSectionButton('save-question-prompts', async () => {
        const courseId = await getCurrentCourseId();
        const systemPrompt = document.getElementById('question-system-prompt')?.value;
        const trueFalse = document.getElementById('question-true-false-prompt')?.value;
        const multipleChoice = document.getElementById('question-multiple-choice-prompt')?.value;
        const shortAnswer = document.getElementById('question-short-answer-prompt')?.value;

        if (!systemPrompt || !trueFalse || !multipleChoice || !shortAnswer) {
            throw new Error('All four question prompts are required');
        }

        const response = await fetch('/api/settings/question-prompts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ systemPrompt, trueFalse, multipleChoice, shortAnswer, courseId })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save question prompts');
        }
        showNotification('Question prompts saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-question-prompts', async () => {
        const courseId = await getCurrentCourseId();
        const response = await fetch('/api/settings/question-prompts/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ courseId })
        });
        const result = await response.json();
        if (!response.ok || !result.success || !result.prompts) {
            throw new Error(result.message || 'Failed to reset question prompts');
        }
        applyQuestionPromptValues(result.prompts);
        showNotification('Question prompts reset to defaults', 'success');
    }, {
        confirmMessage: 'Are you sure you want to reset all question generation prompts to default values? This only affects the current course.',
        busyLabel: 'Resetting...'
    });

    // Admin: mental health detection prompt
    wireSectionButton('save-mh-prompt', async () => {
        const courseId = await getCurrentCourseId();
        const prompt = document.getElementById('mental-health-detection-prompt')?.value;
        if (!prompt) {
            throw new Error('Detection prompt cannot be empty');
        }
        const response = await fetch('/api/settings/mental-health-prompt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prompt, courseId })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to save detection prompt');
        }
        showNotification('Detection prompt saved', 'success');
    }, { busyLabel: 'Saving...' });

    wireSectionButton('reset-mh-prompt', async () => {
        const courseId = await getCurrentCourseId();
        const response = await fetch('/api/settings/mental-health-prompt/reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ courseId })
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Failed to reset detection prompt');
        }
        const textarea = document.getElementById('mental-health-detection-prompt');
        if (textarea) textarea.value = result.prompt || '';
        showNotification('Detection prompt reset to default', 'success');
    }, {
        confirmMessage: 'Reset the mental health detection prompt to the default?',
        busyLabel: 'Resetting...'
    });

    /* =============================================
       Course lifecycle + transfer (action buttons)
       ============================================= */

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
        const lifecycleTile = document.getElementById('lifecycle-tile');
        const lifecycleRailItem = document.getElementById('lifecycle-rail-item');
        if (!courseLifecycleSection) return;

        if (!currentUser || currentUser.role !== 'instructor') {
            courseLifecycleSection.style.display = 'none';
            if (lifecycleTile) lifecycleTile.hidden = true;
            if (lifecycleRailItem) lifecycleRailItem.hidden = true;
            renderSettingsView();
            return;
        }

        courseLifecycleSection.style.display = '';
        if (lifecycleTile) lifecycleTile.hidden = false;
        if (lifecycleRailItem) lifecycleRailItem.hidden = false;
        renderSettingsView();

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
                    message: `${summary} Switched to ${result.data.courseName}.`,
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

    /* =============================================
       Database management + system admin actions
       ============================================= */

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

    /**
     * Check if the current user has system admin access.
     * Toggles the admin-only sections, hub tiles, and rail links.
     * Returns true if user has permission.
     */
    async function checkDeleteAllPermission() {
        const adminSectionIds = [
            'database-management-section',
            'login-restriction-section',
            'question-generation-section',
            'mental-health-detection-section',
            'system-admin-section',
            'llm-model-section'
        ];

        function setAdminVisibility(isAdmin) {
            adminSectionIds.forEach(id => {
                const section = document.getElementById(id);
                if (section) section.style.display = isAdmin ? '' : 'none';
            });
            const adminTileGroup = document.getElementById('admin-tile-group');
            const adminRailGroup = document.getElementById('admin-rail-group');
            if (adminTileGroup) adminTileGroup.hidden = !isAdmin;
            if (adminRailGroup) adminRailGroup.hidden = !isAdmin;
            renderSettingsView();
        }

        try {
            const response = await fetch('/api/settings/can-delete-all', {
                credentials: 'include'
            });

            const result = await response.json();
            const isAdmin = !!(result.success && result.canDeleteAll);
            setAdminVisibility(isAdmin);
            return isAdmin;
        } catch (error) {
            console.error('Error checking delete all permission:', error);
            // On error, hide the sections for security
            setAdminVisibility(false);
            return false;
        }
    }
});
