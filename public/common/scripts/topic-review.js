/**
 * Shared topic-review helpers and modal used by the instructor documents page
 * (instructor.js) and instructor onboarding (onboarding.js).
 *
 * Load order: after ui-utils.js (escapeHTML), before the page script.
 * Page scripts keep their page-specific entry points (openTopicReviewModal,
 * showInlineTopicReview, handleSaveTopicsFromModal) and page state such as
 * currentWeek; this file only holds the behavior that was duplicated.
 */

// Shared topic-review modal state (was declared in both page scripts)
let topicReviewResolve = null;
let pendingTopicReviewData = null;

// Set when the server skipped topic extraction because the uploaded document
// is an additional material and the course de-prioritizes additional
// materials ("Additional material secondary search" is turned on).
let topicExtractionSkippedAdditionalMaterial = false;

const TOPIC_EXTRACTION_SKIP_NOTICE = 'Additional material secondary search is turned on for this course, so struggle topics were not picked from this additional material. You can still add topics manually.';

/**
 * Ensure a notice paragraph exists right after the given anchor element and
 * show it only when the last extraction was skipped for additional material.
 */
function syncTopicExtractionSkipNotice(anchorEl, noticeId) {
    if (!anchorEl) return;

    let notice = document.getElementById(noticeId);
    if (!notice) {
        notice = document.createElement('p');
        notice.id = noticeId;
        notice.className = 'topic-review-skip-notice';
        anchorEl.insertAdjacentElement('afterend', notice);
    }

    notice.textContent = TOPIC_EXTRACTION_SKIP_NOTICE;
    notice.style.display = topicExtractionSkippedAdditionalMaterial ? '' : 'none';
}

function normalizeTopicLabel(topic) {
    if (typeof topic === 'string') {
        return topic.replace(/\s+/g, ' ').trim();
    }

    if (topic && typeof topic === 'object') {
        return normalizeTopicLabel(topic.topic);
    }

    return '';
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

function normalizeTopicSource(source, fallback = 'manual') {
    return source === 'scraped' || source === 'manual' ? source : fallback;
}

function normalizeTopicUnitId(unitId, fallback = null) {
    if (typeof unitId === 'string' && unitId.trim()) {
        return unitId.trim();
    }

    return fallback || null;
}

function normalizeTopicEntry(topicEntry, defaults = {}) {
    const topic = normalizeTopicLabel(topicEntry);
    if (!topic) return null;

    const rawObject = topicEntry && typeof topicEntry === 'object' ? topicEntry : {};
    return {
        topic,
        unitId: normalizeTopicUnitId(rawObject.unitId, normalizeTopicUnitId(defaults.unitId)),
        source: normalizeTopicSource(rawObject.source, defaults.source || 'manual'),
        createdAt: rawObject.createdAt || defaults.createdAt || new Date().toISOString()
    };
}

function dedupeTopicEntries(topics = [], defaults = {}) {
    const seen = new Set();
    const output = [];

    (Array.isArray(topics) ? topics : []).forEach((topicEntry) => {
        const normalized = normalizeTopicEntry(topicEntry, defaults);
        if (!normalized) return;

        const key = normalized.topic.toLowerCase();
        if (seen.has(key)) return;

        seen.add(key);
        output.push(normalized);
    });

    return output;
}

function getTopicUnitOptions(selectedUnitId = currentWeek) {
    const units = Array.isArray(window.currentCourseData?.lectures)
        ? window.currentCourseData.lectures
        : [];
    const selected = normalizeTopicUnitId(selectedUnitId, currentWeek) || '';
    const unitNames = units.map(unit => unit?.name).filter(Boolean);

    if (selected && !unitNames.includes(selected)) {
        unitNames.unshift(selected);
    }

    return unitNames.map(unitName => (
        `<option value="${escapeHTML(unitName)}"${unitName === selected ? ' selected' : ''}>${escapeHTML(unitName)}</option>`
    )).join('');
}

function setCourseTopicsGlobal(courseId, topics) {
    if (!courseId) return;
    const cleanTopicDetails = dedupeTopicEntries(topics);
    const cleanTopics = cleanTopicDetails.map((topic) => topic.topic);
    window.courseApprovedTopicDetailsByCourse = window.courseApprovedTopicDetailsByCourse || {};
    window.courseApprovedTopicDetailsByCourse[courseId] = cleanTopicDetails;
    window.courseApprovedTopicDetails = cleanTopicDetails;
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
    const topics = result?.data?.topics || result?.data?.topicLabels || [];
    setCourseTopicsGlobal(courseId, topics);
    return window.courseApprovedTopicDetails || [];
}

async function extractTopicsForUploadedDocument(courseId, documentId) {
    topicExtractionSkippedAdditionalMaterial = false;
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
    topicExtractionSkippedAdditionalMaterial = result?.data?.skippedAdditionalMaterial === true;
    return dedupeTopics(result?.data?.topicLabels || result?.data?.topics || []);
}

async function saveCourseApprovedTopics(courseId, topics) {
    const response = await fetch(`/api/courses/${courseId}/approved-topics`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topics: dedupeTopicEntries(topics) })
    });

    if (!response.ok) {
        throw new Error(`Failed to save approved topics: ${response.status}`);
    }

    const result = await response.json();
    const savedTopics = result?.data?.topics || result?.data?.topicLabels || [];
    setCourseTopicsGlobal(courseId, savedTopics);
    return window.courseApprovedTopicDetails || [];
}

function ensureTopicReviewModal(hintText = 'Edit, add, or remove topics before saving this course-level list.') {
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
            .topic-review-skip-notice {
                margin: 0 0 12px;
                padding: 8px 10px;
                background: #fff8e6;
                border: 1px solid #f0d48a;
                border-radius: 6px;
                color: #7a5b00;
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
                grid-template-columns: 1fr auto auto;
                gap: 8px;
                margin-top: 6px;
            }
            .topic-review-unit-select {
                padding: 10px;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                font-size: 14px;
                background: #fff;
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
                <button class="modal-close" id="topic-review-close-btn" aria-label="Close"><span aria-hidden="true">×</span></button>
            </div>
            <div class="modal-body">
                <p class="topic-review-context" id="topic-review-context"></p>
                <p class="topic-review-hint">${hintText}</p>
                <div class="topic-review-list" id="topic-review-list"></div>
                <div class="topic-review-add-row">
                    <input id="topic-review-new-input" class="topic-review-input" type="text" placeholder="Add a topic (e.g., Enzyme Kinetics)" />
                    <select id="topic-review-new-unit-select" class="topic-review-unit-select" title="Topic unit">${getTopicUnitOptions(currentWeek)}</select>
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
        addTopicReviewRow(value, {
            unitId: modal.querySelector('#topic-review-new-unit-select')?.value || currentWeek,
            source: 'manual',
            createdAt: new Date().toISOString()
        });
        input.value = '';
        input.focus();
    });

    modal.querySelector('#topic-review-save-btn').addEventListener('click', () => {
        closeWithResult(collectTopicReviewRows());
    });

    return modal;
}

function addTopicReviewRow(topic, metadata = {}) {
    const modal = ensureTopicReviewModal();
    const list = modal.querySelector('#topic-review-list');

    // Remove empty placeholder when first real topic is added.
    const emptyState = list.querySelector('.topic-review-empty');
    if (emptyState) emptyState.remove();

    const row = document.createElement('div');
    row.className = 'topic-review-item';
    row.dataset.unitId = normalizeTopicUnitId(metadata.unitId, currentWeek) || '';
    row.dataset.source = normalizeTopicSource(metadata.source, 'manual');
    row.dataset.createdAt = metadata.createdAt || new Date().toISOString();
    const input = document.createElement('input');
    input.className = 'topic-review-input';
    input.type = 'text';
    input.value = normalizeTopicLabel(topic);

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
    const rows = Array.from(modal.querySelectorAll('.topic-review-item'));
    return dedupeTopicEntries(rows.map((row) => ({
        topic: row.querySelector('.topic-review-input')?.value || '',
        unitId: row.dataset.unitId || currentWeek || null,
        source: row.dataset.source || 'manual',
        createdAt: row.dataset.createdAt || new Date().toISOString()
    })));
}

function ensureTopicReviewStyles() {
    if (document.getElementById('topic-review-style')) return;
    const style = document.createElement('style');
    style.id = 'topic-review-style';
    style.textContent = `
        .topic-review-context { margin: 0 0 10px; color: #333; font-size: 14px; }
        .topic-review-hint { margin: 0 0 12px; color: #666; font-size: 13px; }
        .topic-review-skip-notice { margin: 0 0 12px; padding: 8px 10px; background: #fff8e6; border: 1px solid #f0d48a; border-radius: 6px; color: #7a5b00; font-size: 13px; }
        .topic-review-list { display: flex; flex-direction: column; gap: 8px; max-height: 280px; overflow-y: auto; margin-bottom: 10px; }
        .topic-review-item { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center; }
        .topic-review-input { width: 100%; padding: 10px; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; }
        .topic-review-remove { border: 1px solid #d0d7de; background: #fff; color: #a61b1b; border-radius: 6px; padding: 8px 10px; cursor: pointer; font-size: 12px; }
        .topic-review-add-row { display: grid; grid-template-columns: 1fr auto auto; gap: 8px; margin-top: 6px; }
        .topic-review-unit-select { padding: 10px; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; background: #fff; }
        .topic-review-empty { padding: 10px; border: 1px dashed #c7ced6; border-radius: 6px; color: #666; font-size: 13px; text-align: center; }
    `;
    document.head.appendChild(style);
}

function addInlineTopicRow(topic, metadata = {}) {
    const list = document.getElementById('upload-topic-review-list');
    if (!list) return;

    const emptyState = list.querySelector('.topic-review-empty');
    if (emptyState) emptyState.remove();

    const row = document.createElement('div');
    row.className = 'topic-review-item';
    row.dataset.unitId = normalizeTopicUnitId(metadata.unitId, currentWeek) || '';
    row.dataset.source = normalizeTopicSource(metadata.source, 'manual');
    row.dataset.createdAt = metadata.createdAt || new Date().toISOString();
    const input = document.createElement('input');
    input.className = 'topic-review-input';
    input.type = 'text';
    input.value = normalizeTopicLabel(topic);

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
    const rows = Array.from(document.querySelectorAll('#upload-topic-review-list .topic-review-item'));
    return dedupeTopicEntries(rows.map((row) => ({
        topic: row.querySelector('.topic-review-input')?.value || '',
        unitId: row.dataset.unitId || currentWeek || null,
        source: row.dataset.source || 'manual',
        createdAt: row.dataset.createdAt || new Date().toISOString()
    })));
}
