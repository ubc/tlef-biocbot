/**
 * LLM platform selector
 *
 * Shared UI for every keyed surface: pick a platform (OpenAI Chat GPT or UBC
 * On-Premise LLM), see that platform's help text and key status, and watch the
 * migration that prepares course material when the platform changes.
 *
 * Instructors choose a platform label only — this module never displays chat or
 * embedding model names. Those are system-admin settings.
 */
(function attachLlmPlatform(global) {
    'use strict';

    const SUPPORT_EMAIL = 'LT.hub@ubc.ca';

    const PROVIDERS = [
        {
            provider: 'openai',
            label: 'OpenAI Chat GPT',
            helpText: 'Feel free to use your own OpenAI API key, or contact the support team for assistance.',
            keyPlaceholder: 'sk-...'
        },
        {
            provider: 'ubc-llm-sandbox',
            label: 'UBC On-Premise LLM',
            helpText: 'Contact the LTIC team to request a UBC LLM Sandbox API key.',
            keyPlaceholder: 'UBC LLM Sandbox API key'
        },
        {
            provider: 'ubc-llm-proxy',
            label: 'UBC LLM Proxy',
            helpText: 'Enter the UBC LLM Proxy key issued for this AI surface. Available models are loaded after the key is validated.',
            keyPlaceholder: 'UBC LLM Proxy API key'
        }
    ];

    const MIGRATION_POLL_MS = 4000;

    function providerMeta(provider) {
        return PROVIDERS.find(entry => entry.provider === provider) || PROVIDERS[0];
    }

    function providerLabel(provider) {
        return providerMeta(provider).label;
    }

    /**
     * Build the platform radio group + help text for one surface and insert it
     * before the key input's controls.
     *
     * @param {string} prefix - Element id prefix, e.g. 'course'
     * @param {HTMLElement} container - Element the selector is prepended to
     */
    function renderSelector(prefix, container) {
        if (!container || document.getElementById(`${prefix}-llm-platform`)) return null;

        const wrapper = document.createElement('div');
        wrapper.className = 'llm-platform-selector';
        wrapper.id = `${prefix}-llm-platform`;

        const fieldset = document.createElement('fieldset');
        fieldset.className = 'llm-platform-choice';

        const legend = document.createElement('legend');
        legend.textContent = 'AI platform';
        fieldset.appendChild(legend);

        for (const entry of PROVIDERS) {
            const label = document.createElement('label');
            label.className = 'llm-platform-option';

            const radio = document.createElement('input');
            radio.type = 'radio';
            radio.name = `${prefix}-llm-provider`;
            radio.value = entry.provider;
            radio.id = `${prefix}-llm-provider-${entry.provider}`;
            radio.dataset.platform = entry.provider;

            const text = document.createElement('span');
            text.textContent = entry.label;

            label.appendChild(radio);
            label.appendChild(text);
            fieldset.appendChild(label);
        }

        const help = document.createElement('p');
        help.className = 'llm-platform-help';
        help.id = `${prefix}-llm-platform-help`;

        const changeNote = document.createElement('p');
        changeNote.className = 'llm-platform-change-note';
        changeNote.id = `${prefix}-llm-platform-change-note`;
        changeNote.hidden = true;

        const actions = document.createElement('div');
        actions.className = 'llm-platform-actions';
        actions.innerHTML = [
            `<button type="button" class="primary-button" id="${prefix}-llm-prepare">Prepare material</button>`
        ].join('');

        wrapper.appendChild(fieldset);
        wrapper.appendChild(help);
        wrapper.appendChild(changeNote);
        wrapper.appendChild(actions);
        container.insertBefore(wrapper, container.firstChild);

        return wrapper;
    }

    /**
     * Migration progress panel: persistent totals, current item, failures and a
     * retry control.
     */
    function renderMigrationPanel(prefix, container) {
        if (!container || document.getElementById(`${prefix}-llm-migration`)) return null;

        const panel = document.createElement('div');
        panel.className = 'llm-migration';
        panel.id = `${prefix}-llm-migration`;
        panel.hidden = true;
        panel.setAttribute('role', 'status');
        panel.setAttribute('aria-live', 'polite');

        panel.innerHTML = [
            `<p class="llm-migration-status" id="${prefix}-llm-migration-status"></p>`,
            `<p class="llm-migration-detail" id="${prefix}-llm-migration-detail" hidden></p>`,
            `<progress class="llm-migration-progress" id="${prefix}-llm-migration-progress" max="100" value="0"></progress>`,
            `<p class="llm-migration-failures-label" id="${prefix}-llm-migration-failures-label" hidden></p>`,
            `<ul class="llm-migration-failures" id="${prefix}-llm-migration-failures"></ul>`,
            `<div class="llm-migration-actions">`,
            `<button type="button" class="secondary-button llm-migration-retry" id="${prefix}-llm-migration-retry" hidden>Retry failed items</button>`,
            `<button type="button" class="danger-button llm-migration-cancel" id="${prefix}-llm-migration-cancel" hidden>Cancel preparation and delete partial data</button>`,
            `</div>`
        ].join('');

        container.appendChild(panel);
        return panel;
    }

    function selectedProvider(prefix) {
        const checked = document.querySelector(`input[name="${prefix}-llm-provider"]:checked`);
        return checked ? checked.value : 'openai';
    }

    function setProvider(prefix, provider) {
        const radio = document.getElementById(`${prefix}-llm-provider-${provider}`);
        if (radio) radio.checked = true;
    }

    /**
     * Refresh the help text, key placeholder and "material must be prepared"
     * warning for the currently selected platform.
     *
     * @param {string} prefix
     * @param {Object} state - Surface state from the API
     */
    function refreshSelector(prefix, state = {}) {
        const provider = selectedProvider(prefix);
        const meta = providerMeta(provider);

        const help = document.getElementById(`${prefix}-llm-platform-help`);
        if (help) {
            help.textContent = meta.helpText;
            if (provider === 'openai') {
                help.innerHTML = `${meta.helpText.replace(
                    'the support team',
                    `<a href="mailto:${SUPPORT_EMAIL}">the support team</a>`
                )}`;
            }
        }

        const activeProvider = state.llmProvider || 'openai';
        const storedKey = (state.llmKeysByProvider || {})[provider];
        const hasStoredKey = storedKey && storedKey.status && storedKey.status !== 'missing';
        const hasValidKey = !!(storedKey && storedKey.status === 'valid');
        const migrationActive = !!(state.migration
            && (state.migration.status === 'queued' || state.migration.status === 'running'));

        const input = document.getElementById(`${prefix}-llm-key-input`);
        const hasEnteredKey = !!(input && input.value && input.value.trim());
        if (input) {
            input.placeholder = hasStoredKey
                ? `Optional: enter a replacement ${meta.label} key`
                : meta.keyPlaceholder;
        }

        const actionButton = document.getElementById(`save-${prefix}-llm-key`);
        if (actionButton) {
            actionButton.textContent = hasStoredKey
                ? `Replace ${meta.label} key`
                : `Save ${meta.label} key`;
            actionButton.disabled = hasStoredKey && !hasEnteredKey;
        }

        const prepareButton = document.getElementById(`${prefix}-llm-prepare`);
        if (prepareButton) {
            const action = provider === activeProvider ? 'prepare' : 'switch';
            prepareButton.dataset.action = action;
            prepareButton.textContent = action === 'prepare'
                ? `Refresh ${meta.label} material`
                : `Switch to ${meta.label}`;
            prepareButton.disabled = !hasValidKey || migrationActive;
            prepareButton.title = !hasValidKey
                ? `Save and validate a ${meta.label} key first`
                : action === 'switch'
                    ? `Reuse existing ${meta.label} material if it is current; prepare only missing or changed items`
                    : `Create or update ${meta.label} embeddings`;
        }

        const note = document.getElementById(`${prefix}-llm-platform-change-note`);
        if (note) {
            if (provider !== activeProvider) {
                note.hidden = false;
                note.textContent = hasStoredKey
                    ? `Your saved ${meta.label} key and embeddings are kept separately. Switching reuses current material; `
                        + `only missing or changed items need preparation. ${providerLabel(activeProvider)} keeps answering until then.`
                    : `Save a ${meta.label} key, then switch platforms. Only missing or changed material will be prepared; `
                        + `${providerLabel(activeProvider)} keeps answering until then.`;
            } else {
                note.hidden = true;
                note.textContent = '';
            }
        }

        return provider;
    }

    /**
     * Key status line for the platform currently selected in the UI.
     */
    function renderKeyStatus(prefix, state = {}) {
        const statusElement = document.getElementById(`${prefix}-llm-key-status`);
        if (!statusElement) return;

        const provider = selectedProvider(prefix);
        const byProvider = state.llmKeysByProvider || {};
        const key = byProvider[provider] || (provider === (state.llmProvider || 'openai') ? state.llmKey : null);
        const status = (key && key.status) || 'missing';
        const label = providerLabel(provider);
        const last4 = key && key.last4 ? ` ending ${key.last4}` : '';
        const checkedAt = key && key.validatedAt ? new Date(key.validatedAt).toLocaleString() : '';

        statusElement.className = `llm-key-status ${status}`;

        if (status === 'valid') {
            statusElement.textContent = checkedAt
                ? `Valid ${label} key${last4}. Last checked ${checkedAt}.`
                : `Valid ${label} key${last4}.`;
        } else if (status === 'quota_exhausted') {
            statusElement.textContent = `AI disabled. The saved ${label} key is out of quota. Contact ${SUPPORT_EMAIL}.`;
        } else if (status === 'invalid') {
            statusElement.textContent = `AI disabled. The saved ${label} key failed validation. Contact ${SUPPORT_EMAIL}.`;
        } else {
            statusElement.textContent = `No ${label} key saved. Enter one to use ${label}.`;
        }
    }

    function describeMigration(migration) {
        const total = migration.total || 0;
        const done = migration.completed || 0;
        const failed = migration.failed || 0;
        const target = providerLabel(migration.toProvider || (migration.targetProfile || {}).provider);

        if (migration.status === 'completed') {
            return `${target} is ready and active. ${done} of ${total} item(s) prepared.`;
        }
        if (migration.status === 'failed') {
            // The server names the cause in a person's words; the raw provider
            // error is logged to the console instead of shown here.
            return (migration.failureSummary && migration.failureSummary.headline)
                || `${target} could not prepare ${failed} item(s).`;
        }
        if (migration.status === 'cancelled') {
            return `Preparation for ${target} was cancelled. The previous platform is still active.`;
        }

        const current = migration.currentItem && migration.currentItem.title
            ? ` Currently: ${migration.currentItem.title}.`
            : '';
        return `Preparing course material for ${target}: ${done} of ${total} done`
            + (failed ? `, ${failed} failed` : '') + `.${current}`;
    }

    /**
     * Paint the migration panel. Returns true while the job is still running so
     * callers know to keep polling.
     */
    function renderMigration(prefix, migration) {
        const panel = document.getElementById(`${prefix}-llm-migration`);
        if (!panel) return false;

        if (!migration) {
            panel.hidden = true;
            return false;
        }

        panel.hidden = false;
        panel.dataset.status = migration.status;
        panel.dataset.migrationId = migration.migrationId;

        const statusLine = document.getElementById(`${prefix}-llm-migration-status`);
        if (statusLine) statusLine.textContent = describeMigration(migration);

        const progress = document.getElementById(`${prefix}-llm-migration-progress`);
        if (progress) {
            const total = migration.total || 0;
            progress.max = 100;
            progress.value = total === 0 ? 100 : Math.round(((migration.completed || 0) / total) * 100);
        }

        const summary = migration.failureSummary || null;

        const detail = document.getElementById(`${prefix}-llm-migration-detail`);
        if (detail) {
            detail.hidden = !summary;
            detail.textContent = summary ? summary.detail : '';
        }

        const failureList = migration.failures || [];
        const label = document.getElementById(`${prefix}-llm-migration-failures-label`);
        if (label) {
            label.hidden = failureList.length === 0;
            label.textContent = failureList.length === 1
                ? 'This item was affected:'
                : `These ${failureList.length} items were affected:`;
        }

        const failures = document.getElementById(`${prefix}-llm-migration-failures`);
        if (failures) {
            failures.innerHTML = '';
            const affected = (summary && summary.affected) || [];
            failureList.forEach((failure, index) => {
                const item = document.createElement('li');
                const title = failure.title || failure.itemId;
                // A cause per file only when the job failed more than one way;
                // otherwise the shared cause is already stated above the list.
                const cause = affected[index] && affected[index].cause;
                item.textContent = cause ? `${title} — ${cause}` : title;
                failures.appendChild(item);
            });
        }

        // Everything a developer needs, kept out of the panel: the console. The
        // panel repaints on every poll tick and page load, so log once per job.
        const logKey = `${migration.migrationId}:${migration.status}:${failureList.length}`;
        if (failureList.length > 0 && panel.dataset.loggedFailures !== logKey) {
            panel.dataset.loggedFailures = logKey;
            console.warn(
                `Migration ${migration.migrationId} failed (${summary ? summary.reason : 'unclassified'}):`,
                failureList.map(failure => ({
                    item: failure.title || failure.itemId,
                    type: failure.itemType,
                    reason: failure.failureReason,
                    attempts: failure.attempts,
                    error: failure.error
                }))
            );
        }

        const retry = document.getElementById(`${prefix}-llm-migration-retry`);
        if (retry) {
            retry.hidden = !(migration.failures && migration.failures.length > 0);
        }

        const cancel = document.getElementById(`${prefix}-llm-migration-cancel`);
        if (cancel) {
            cancel.hidden = !(migration.status === 'queued' || migration.status === 'running');
        }

        return migration.status === 'queued' || migration.status === 'running';
    }

    /**
     * Poll a migration until it finishes, repainting the panel each tick.
     */
    function watchMigration(prefix, migrationId, onUpdate) {
        if (!migrationId) return null;

        const timer = setInterval(async () => {
            try {
                const response = await fetch(`/api/provider-migrations/${encodeURIComponent(migrationId)}`, {
                    credentials: 'include'
                });
                const result = await response.json();
                if (!result.success) {
                    clearInterval(timer);
                    return;
                }
                const stillRunning = renderMigration(prefix, result.migration);
                if (typeof onUpdate === 'function') onUpdate(result.migration);
                if (!stillRunning) clearInterval(timer);
            } catch (error) {
                clearInterval(timer);
            }
        }, MIGRATION_POLL_MS);

        return timer;
    }

    async function retryMigration(migrationId) {
        const response = await fetch(`/api/provider-migrations/${encodeURIComponent(migrationId)}/retry`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
        });
        return response.json();
    }

    async function cancelMigration(migrationId) {
        const response = await fetch(`/api/provider-migrations/${encodeURIComponent(migrationId)}/cancel`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
        });
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || 'Could not cancel preparation');
        }
        return result;
    }

    global.LlmPlatform = {
        MIGRATION_POLL_MS,
        PROVIDERS,
        SUPPORT_EMAIL,
        cancelMigration,
        describeMigration,
        providerLabel,
        providerMeta,
        renderKeyStatus,
        renderMigration,
        renderMigrationPanel,
        renderSelector,
        refreshSelector,
        retryMigration,
        selectedProvider,
        setProvider,
        watchMigration
    };
}(typeof window !== 'undefined' ? window : globalThis));
