// @ts-check
/**
 * Companion browser coverage for public/styles/documents.css branch states.
 *
 * Keep this separate from documents-css-coverage.spec.js: the original spec
 * covers the current instructor document workflow. This harness enters
 * branch-only and legacy states that still have live CSS rules.
 */

const { test, expect } = require('./fixtures/monocart');

const HARNESS_PATH = '/documents-css-coverage-branches-harness';

function branchHarness() {
    return `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Documents CSS Branch Coverage Harness</title>
    <link rel="stylesheet" href="/styles/style.css">
    <link rel="stylesheet" href="/styles/documents.css">
</head>
<body>
    <main class="main-content">
        <section class="upload-section">
            <div class="upload-container">
                <div class="upload-box" id="legacy-upload-box">
                    <span class="upload-icon">Upload</span>
                    <label class="upload-button" for="legacy-file-input">Choose File</label>
                    <input id="legacy-file-input" type="file">
                    <p class="upload-info">PDF, DOCX, TXT accepted.</p>
                </div>
            </div>
        </section>

        <section class="documents-list">
            <div class="document-filters">
                <input id="document-search" type="search" value="enzyme">
                <select id="document-filter">
                    <option>All</option>
                </select>
            </div>
            <table class="documents-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr id="document-row">
                        <td>Lecture notes</td>
                        <td>
                            <span class="status processed">Processed</span>
                            <span class="status processing">Processing</span>
                            <span class="status failed">Failed</span>
                            <span class="status-text processing">Queued</span>
                            <span class="status-text not-uploaded">Not Uploaded</span>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div class="empty-state">
                <div class="empty-state-icon">Empty</div>
                <p>No documents yet.</p>
            </div>
        </section>

        <section class="document-cards">
            <article class="document-card" id="document-card">
                <div class="card-content">
                    <h3>Card document</h3>
                    <p>Displayed in card layout.</p>
                    <div class="card-icons">
                        <span class="info-icon">i</span>
                        Ready
                    </div>
                </div>
            </article>
        </section>

        <section class="folder-structure">
            <div class="folder-item" id="folder-item">
                <span class="folder-icon">Folder</span>
                <span class="folder-name">Unit folder</span>
            </div>
        </section>

        <section class="file-type-section">
            <h3>File Type</h3>
            <div class="file-type-options">
                <label class="file-type-option"><input type="radio" name="type" checked> Lecture</label>
                <label class="file-type-option"><input type="radio" name="type"> Additional</label>
            </div>
        </section>

        <section class="week-selection">
            <div class="form-group">
                <label for="week-select">Week</label>
                <select id="week-select">
                    <option>Week 1</option>
                </select>
            </div>
        </section>

        <section class="accordion-container">
            <article class="accordion-item">
                <header class="accordion-header" id="unpublished-header">
                    <span class="folder-name">Unpublished unit</span>
                    <div class="header-actions">
                        <div class="publish-toggle">
                            <label class="toggle-switch">
                                <input id="publish-off" type="checkbox">
                                <span class="toggle-slider"></span>
                            </label>
                            <span class="toggle-label">Draft</span>
                        </div>
                        <button class="delete-unit-btn" id="delete-unit" type="button">
                            <span class="btn-icon">x</span>
                        </button>
                    </div>
                    <span class="accordion-toggle">&gt;</span>
                </header>
                <div class="accordion-content">
                    <section class="unit-section">
                        <div class="section-header" id="section-header">
                            <h3>Branch Section</h3>
                            <button class="toggle-section" type="button">v</button>
                        </div>
                        <div class="section-content collapsed">
                            <p>Collapsed section content.</p>
                        </div>
                    </section>
                </div>
            </article>
        </section>

        <section class="add-week-section" id="add-week-section">
            <button class="add-week-btn" id="add-week-btn" type="button">
                <span class="btn-icon">+</span>
                Add Week
            </button>
        </section>

        <div id="branch-modal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h2>Branch Modal</h2>
                    <button class="modal-close" id="modal-close" type="button">x</button>
                </div>
                <div class="modal-body">
                    <div class="modal-step active">
                        <div class="step-indicators">
                            <span class="step-dot active"></span>
                            <span class="step-dot"></span>
                        </div>
                    </div>

                    <div class="auto-link-confirmation-copy">
                        <p>Confirm these links.</p>
                        <ul class="auto-link-confirmation-list">
                            <li>Question 1 to objective 1.</li>
                            <li>Question 2 to objective 2.</li>
                        </ul>
                        <p class="auto-link-confirmation-note">Review before saving.</p>
                    </div>

                    <div class="file-upload-area">
                        <div class="upload-zone dragover" id="upload-zone">
                            <span class="upload-icon">Drop</span>
                            <p>Drop files here.</p>
                        </div>
                    </div>

                    <div class="objectives-options">
                        <label class="objectives-checkbox">
                            <input id="objectives-check" type="checkbox" checked>
                            <span class="checkmark"></span>
                            Include objectives
                        </label>
                    </div>
                    <div class="objectives-input">
                        <textarea id="objectives-textarea">Objective details.</textarea>
                    </div>
                    <div class="objectives-input hidden" id="hidden-objectives">
                        <textarea>Hidden objective details.</textarea>
                    </div>

                    <div class="content-preview">
                        <section class="preview-section">
                            <h4>Preview</h4>
                            <ul>
                                <li>Parsed concept</li>
                            </ul>
                            <p>Preview copy.</p>
                        </section>
                    </div>

                    <div class="mode-info">
                        <h3>Calibration mode</h3>
                        <p>Question rules.</p>
                        <ul>
                            <li>Use unit material.</li>
                        </ul>
                    </div>

                    <section class="questions-section">
                        <h3>Mode Questions</h3>
                        <p>Branch editor controls.</p>
                        <div class="questions-list">
                            <article class="question-item">
                                <header class="question-header">
                                    <span class="question-number">Question 2</span>
                                    <button class="delete-question" id="delete-question" type="button">x</button>
                                </header>
                                <div class="question-content">
                                    <label class="question-text-container" for="question-textarea">
                                        <span class="question-label">Prompt</span>
                                        <textarea id="question-textarea" class="question-text">What is ATP?</textarea>
                                    </label>
                                    <div class="options-container">
                                        <span class="options-label">Options</span>
                                        <div class="options-list">
                                            <div class="option-item" id="option-item">
                                                <div class="option-input-group">
                                                    <input class="correct-radio" type="radio" checked>
                                                    <input id="option-text" class="option-text" value="Energy carrier">
                                                </div>
                                                <span class="correct-label">Correct</span>
                                                <span class="score-box correct-answer"></span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </article>
                        </div>
                    </section>

                    <section class="threshold-section">
                        <label class="threshold-input" for="mode-threshold">
                            Passing threshold
                            <input id="mode-threshold" type="range" value="2">
                            <span id="threshold-value">2</span>
                        </label>
                    </section>

                    <div class="generate-questions-container">
                        <button class="generate-btn" id="generate-btn" type="button">
                            <span class="btn-icon">*</span>
                            Generate Questions
                        </button>
                        <p class="generate-help-text">Uses uploaded unit material.</p>
                    </div>

                    <div class="content-type-options">
                        <button class="content-type-btn selected" id="selected-content-type" type="button">
                            <span class="type-icon">T</span>
                            <span class="type-info">
                                <h4>Text</h4>
                                <p>Paste text.</p>
                            </span>
                        </button>
                        <button class="content-type-btn" id="content-type-hover" type="button">
                            <span class="type-icon">L</span>
                            <span class="type-info">
                                <h4>Link</h4>
                                <p>Paste URL.</p>
                            </span>
                        </button>
                    </div>

                    <div class="input-section">
                        <label for="branch-url">Source URL</label>
                        <input id="branch-url" type="url" value="https://example.test">
                    </div>
                    <div class="input-section">
                        <label for="branch-text">Content</label>
                        <textarea id="branch-text">Paste text.</textarea>
                    </div>

                    <div class="assessment-actions">
                        <button class="add-question-btn" id="add-question-btn" type="button">
                            <span class="btn-icon">+</span>
                            Add Question
                        </button>
                        <button class="auto-link-btn" id="auto-link-btn" type="button">Auto-link</button>
                        <button class="generate-ai-btn" id="generate-ai-btn" type="button">Generate with AI</button>
                    </div>

                    <div class="question-header">
                        <span class="question-type-badge multiple-choice">Multiple Choice</span>
                        <span class="question-type-badge short-answer">Short Answer</span>
                        <button class="edit-question-btn" id="edit-question-btn" type="button">e</button>
                        <button class="delete-question-btn" id="delete-question-btn" type="button">x</button>
                    </div>

                    <div class="struggle-topic-actions">
                        <button class="struggle-topic-scope-btn" id="scope-hover" type="button">Assigned only</button>
                        <button class="btn-ai compact" type="button">Generate from Topic</button>
                    </div>

                    <label class="radio-option" id="radio-option">
                        <input type="radio" name="branch-radio">
                        False
                    </label>

                    <label class="ai-type-option">
                        <input type="radio" checked>
                        <span>Short answer</span>
                    </label>
                </div>
                <div class="modal-footer">
                    <div class="validation-actions">
                        <button class="btn-secondary" id="secondary-btn" type="button">Back</button>
                        <button class="btn-primary" id="primary-btn" type="button">Continue</button>
                    </div>
                </div>
            </div>
        </div>

        <section class="empty-course-state">
            <div class="empty-message">
                <h3>No documents yet</h3>
                <p>Add documents before publishing this course.</p>
                <a class="btn-primary" id="empty-primary" href="/instructor/documents">Add Documents</a>
            </div>
        </section>
    </main>
</body>
</html>`;
}

/**
 * @param {import('@playwright/test').Page} page
 */
async function gotoHarness(page) {
    await page.route(`**${HARNESS_PATH}`, async (route) => {
        await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: branchHarness(),
        });
    });
    await page.goto(HARNESS_PATH);
    await page.waitForLoadState('networkidle');
    await page.waitForFunction(() => {
        const testWindow = /** @type {any} */ (window);
        const uploadZone = testWindow.document.querySelector('.upload-zone.dragover');
        const table = testWindow.document.querySelector('.documents-table');
        if (!uploadZone || !table) return false;
        return testWindow.getComputedStyle(uploadZone).borderTopStyle === 'dashed'
            && testWindow.getComputedStyle(table).width !== '';
    });
}

/**
 * @param {import('@playwright/test').Locator} locator
 * @param {string} pseudo
 * @param {string} property
 */
async function pseudoStyle(locator, pseudo, property) {
    return locator.evaluate(
        (element, args) => window.getComputedStyle(element, args.pseudo).getPropertyValue(args.property),
        { pseudo, property }
    );
}

test.describe('documents.css branch harness coverage', () => {
    test('styles branch-only upload, document, accordion, and empty states', async ({ page }) => {
        await page.setViewportSize({ width: 1120, height: 1200 });
        await gotoHarness(page);

        await expect(page.locator('.upload-box')).toHaveCSS('border-top-style', 'dashed');
        await page.locator('#legacy-upload-box').hover();
        await expect(page.locator('.upload-box')).toHaveCSS('border-top-color', 'rgb(74, 111, 165)');
        await page.locator('.upload-button').hover();
        await expect(page.locator('.upload-button')).toHaveCSS('background-color', 'rgb(61, 90, 128)');
        await expect(page.locator('.upload-info')).toHaveCSS('font-size', '14px');

        await expect(page.locator('.documents-list')).toHaveCSS('padding-top', '20px');
        await expect(page.locator('.document-filters')).toHaveCSS('display', 'flex');
        await expect(page.locator('#document-search')).toHaveCSS('flex-grow', '1');
        await expect(page.locator('#document-filter')).toHaveCSS('width', '150px');
        await expect(page.locator('.documents-table')).toHaveCSS('border-collapse', 'collapse');
        await page.locator('#document-row').hover();
        await expect(page.locator('#document-row')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0.02)');
        await expect(page.locator('.status.processed')).toHaveCSS('color', 'rgb(40, 167, 69)');
        await expect(page.locator('.status.processing')).toHaveCSS('color', 'rgb(255, 193, 7)');
        await expect(page.locator('.status.failed')).toHaveCSS('color', 'rgb(220, 53, 69)');
        await expect(page.locator('.status-text.processing')).toHaveCSS('color', 'rgb(255, 193, 7)');
        await expect(page.locator('.status-text.not-uploaded')).toHaveCSS('color', 'rgb(220, 53, 69)');
        await expect(page.locator('.empty-state')).toHaveCSS('text-align', 'center');
        await expect(page.locator('.empty-state-icon')).toHaveCSS('font-size', '48px');

        await expect(page.locator('.document-cards')).toHaveCSS('display', 'grid');
        await page.locator('#document-card').hover();
        expect(await page.locator('#document-card').evaluate((element) => window.getComputedStyle(element).transform)).not.toBe('none');
        await expect(page.locator('.card-icons')).toHaveCSS('justify-content', 'flex-end');

        await expect(page.locator('.folder-structure')).toHaveCSS('margin-top', '20px');
        await page.locator('#folder-item').hover();
        await expect(page.locator('#folder-item')).toHaveCSS('background-color', 'rgb(245, 247, 250)');
        await expect(page.locator('.file-type-section')).toHaveCSS('padding-top', '20px');
        await expect(page.locator('.file-type-options')).toHaveCSS('display', 'flex');
        await expect(page.locator('.week-selection')).toHaveCSS('display', 'grid');
        await expect(page.locator('.form-group label')).toHaveCSS('display', 'block');

        await page.locator('#publish-off').focus();
        await expect(page.locator('#publish-off + .toggle-slider')).toHaveCSS('background-color', 'rgb(204, 204, 204)');
        await expect(page.locator('#publish-off + .toggle-slider')).toHaveCSS('box-shadow', 'rgba(74, 111, 165, 0.2) 0px 0px 0px 3px');
        await page.locator('#unpublished-header').hover();
        await expect(page.locator('#unpublished-header')).toHaveCSS('background-color', 'rgba(0, 0, 0, 0.03)');
        await page.locator('#section-header').hover();
        await expect(page.locator('#section-header')).toHaveCSS('background-color', 'rgb(232, 232, 232)');
        await expect(page.locator('.section-content.collapsed')).toHaveCSS('display', 'none');
        await page.locator('#delete-unit').hover();
        await expect(page.locator('#delete-unit')).toHaveCSS('background-color', 'rgb(200, 35, 51)');

        await page.locator('#add-week-section').hover();
        await expect(page.locator('#add-week-section')).toHaveCSS('border-top-color', 'rgb(74, 111, 165)');
        await page.locator('#add-week-btn').hover();
        await expect(page.locator('#add-week-btn')).toHaveCSS('color', 'rgb(255, 255, 255)');
        await page.locator('#empty-primary').hover();
        // #1b5e20 — the WCAG-AA accessible hover green for .empty-course-state .btn-primary
        // (7.87:1 on white). The old #45a049 (rgb 69,160,73) failed AA and was darkened.
        await expect(page.locator('#empty-primary')).toHaveCSS('background-color', 'rgb(27, 94, 32)');
    });

    test('styles branch-only modal and question editor states', async ({ page }) => {
        await page.setViewportSize({ width: 1120, height: 1200 });
        await gotoHarness(page);
        await page.locator('#branch-modal').evaluate((element) => element.classList.add('show'));

        await expect(page.locator('.modal-step.active')).toHaveCSS('display', 'block');
        await expect(page.locator('.step-indicators')).toHaveCSS('display', 'flex');
        await expect(page.locator('.step-dot.active')).toHaveCSS('background-color', 'rgb(74, 111, 165)');
        await page.locator('#modal-close').hover();
        await expect(page.locator('#modal-close')).toHaveCSS('background-color', 'rgb(240, 240, 240)');
        await expect(page.locator('.auto-link-confirmation-list')).toHaveCSS('line-height', '25.6px');
        await expect(page.locator('.auto-link-confirmation-note')).toHaveCSS('font-size', '15.2px');

        await expect(page.locator('.upload-zone.dragover')).toHaveCSS('background-color', 'rgb(240, 244, 248)');
        await page.locator('#upload-zone').hover();
        await expect(page.locator('.upload-zone')).toHaveCSS('border-top-color', 'rgb(74, 111, 165)');

        await expect(page.locator('.objectives-checkbox')).toHaveCSS('display', 'flex');
        await expect(page.locator('#objectives-check + .checkmark')).toHaveCSS('background-color', 'rgb(74, 111, 165)');
        expect(await pseudoStyle(page.locator('#objectives-check + .checkmark'), '::after', 'content')).not.toBe('none');
        await expect(page.locator('#hidden-objectives')).toHaveCSS('opacity', '0');
        await page.locator('#objectives-textarea').focus();
        await expect(page.locator('#objectives-textarea')).toHaveCSS('border-color', 'rgb(74, 111, 165)');
        await expect(page.locator('.content-preview')).toHaveCSS('margin-top', '20px');
        await expect(page.locator('.preview-section h4')).toHaveCSS('font-size', '16px');

        await expect(page.locator('.mode-info')).toHaveCSS('background-color', 'rgb(248, 249, 250)');
        await expect(page.locator('.questions-section h3')).toHaveCSS('font-size', '16px');
        await page.locator('#delete-question').hover();
        await expect(page.locator('#delete-question')).toHaveCSS('background-color', 'rgb(248, 215, 218)');
        await page.locator('#question-textarea').focus();
        await expect(page.locator('#question-textarea')).toHaveCSS('background-color', 'rgb(255, 255, 255)');
        await page.locator('#option-item').hover();
        await expect(page.locator('#option-item')).toHaveCSS('background-color', 'rgb(233, 236, 239)');
        await expect(page.locator('.option-input-group')).toHaveCSS('display', 'flex');
        await expect(page.locator('.correct-radio')).toHaveCSS('accent-color', 'rgb(74, 111, 165)');
        await page.locator('#option-text').focus();
        await expect(page.locator('#option-text')).toHaveCSS('border-color', 'rgb(74, 111, 165)');
        await expect(page.locator('.correct-label')).toHaveCSS('white-space', 'nowrap');
        await expect(page.locator('.score-box.correct-answer')).toHaveCSS('background-color', 'rgb(212, 237, 218)');
        await expect(page.locator('.threshold-section')).toHaveCSS('background-color', 'rgb(248, 249, 250)');
        await expect(page.locator('#threshold-value')).toHaveCSS('color', 'rgb(74, 111, 165)');

        await expect(page.locator('.generate-questions-container')).toHaveCSS('text-align', 'center');
        await page.locator('#generate-btn').hover();
        expect(await page.locator('#generate-btn').evaluate((element) => window.getComputedStyle(element).boxShadow)).not.toBe('none');
        await page.mouse.down();
        expect(await page.locator('#generate-btn').evaluate((element) => window.getComputedStyle(element).transform)).not.toBe('none');
        await page.mouse.up();
        await expect(page.locator('.generate-help-text')).toHaveCSS('font-style', 'italic');

        await expect(page.locator('#selected-content-type')).toHaveCSS('background-color', 'rgb(240, 244, 248)');
        await page.locator('#content-type-hover').hover();
        await expect(page.locator('#content-type-hover')).toHaveCSS('border-top-color', 'rgb(74, 111, 165)');
        await page.locator('#branch-url').focus();
        await expect(page.locator('#branch-url')).toHaveCSS('border-color', 'rgb(74, 111, 165)');
        await page.locator('#branch-text').focus();
        await expect(page.locator('#branch-text')).toHaveCSS('border-color', 'rgb(74, 111, 165)');

        await page.locator('#add-question-btn').hover();
        await expect(page.locator('#add-question-btn')).toHaveCSS('color', 'rgb(51, 51, 51)');
        await page.locator('#auto-link-btn').hover();
        await expect(page.locator('#auto-link-btn')).toHaveCSS('background-color', 'rgb(219, 234, 254)');
        await page.locator('#generate-ai-btn').hover();
        await expect(page.locator('#generate-ai-btn')).toHaveCSS('background-color', 'rgb(90, 45, 145)');
        await expect(page.locator('.question-type-badge.multiple-choice')).toHaveCSS('color', 'rgb(0, 64, 133)');
        await expect(page.locator('.question-type-badge.short-answer')).toHaveCSS('color', 'rgb(133, 100, 4)');
        await page.locator('#edit-question-btn').hover();
        await expect(page.locator('#edit-question-btn')).toHaveCSS('background-color', 'rgb(11, 94, 215)');
        await page.locator('#delete-question-btn').hover();
        await expect(page.locator('#delete-question-btn')).toHaveCSS('background-color', 'rgb(200, 35, 51)');
        await page.locator('#scope-hover').hover();
        await expect(page.locator('#scope-hover')).toHaveCSS('color', 'rgb(40, 77, 122)');
        await page.locator('#radio-option').hover();
        await expect(page.locator('#radio-option')).toHaveCSS('background-color', 'rgb(248, 249, 250)');

        await page.locator('#secondary-btn').hover();
        await expect(page.locator('#secondary-btn')).toHaveCSS('background-color', 'rgb(225, 229, 235)');
        await page.locator('#primary-btn').hover();
        await expect(page.locator('#primary-btn')).toHaveCSS('background-color', 'rgb(61, 90, 128)');
    });

    test('applies remaining mobile branch layout rules', async ({ page }) => {
        await page.setViewportSize({ width: 520, height: 900 });
        await gotoHarness(page);

        await expect(page.locator('.document-filters')).toHaveCSS('flex-direction', 'column');
        await expect(page.locator('.document-filters')).toHaveCSS('gap', '10px');
        await expect(page.locator('.documents-table')).toHaveCSS('display', 'block');
        await expect(page.locator('.document-cards')).toHaveCSS('grid-template-columns', '480px');
        await expect(page.locator('.week-selection')).toHaveCSS('grid-template-columns', '440px');
        await expect(page.locator('.file-type-options')).toHaveCSS('flex-direction', 'column');
        await expect(page.locator('.content-type-btn').first()).toHaveCSS('padding-top', '20px');
        await expect(page.locator('.upload-zone')).toHaveCSS('padding-top', '30px');
        await expect(page.locator('.validation-actions')).toHaveCSS('flex-direction', 'column');
        await expect(page.locator('.modal-header')).toHaveCSS('padding-top', '20px');
        await expect(page.locator('.modal-body')).toHaveCSS('padding-top', '20px');
        await expect(page.locator('.modal-footer')).toHaveCSS('padding-top', '20px');
    });
});
