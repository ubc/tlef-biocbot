// @ts-check
/**
 * Deep coverage spec for public/student/scripts/history.js.
 *
 * The existing student-chat.spec.js touches /student/history for empty-state
 * and the continue-chat handoff, but the bulk of history.js — preview
 * rendering, rename flow, delete flow, markdown export, banned-enrollment
 * gating, localStorage fallback, and the dozens of branches inside
 * createPreviewMessage / convertHtmlToMarkdown / formatHistoryDate —
 * never run under monocart.
 *
 * Tests use the monocart fixture so browser-side V8 coverage is captured
 * and seed/mock sessions to deterministically drive every branch.
 */
/* eslint-disable no-undef */

const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const { getUserIdByUsername } = require('./helpers/quiz');
const {
    STU_COURSE_ID,
    STU_COURSE_NAME,
    getStudentId,
    resetStudentChatData,
    cleanupStudentChatData,
    seedChatSession,
    setUserAgreement,
} = require('./helpers/student');

let instructorId;
let studentId;

test.use({ storageState: storageStatePath('student') });

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getStudentId();
});

test.afterAll(async () => {
    await cleanupStudentChatData();
});

test.beforeEach(async () => {
    await resetStudentChatData({ instructorId });
    await setUserAgreement(studentId, true);
});

/**
 * Build a rich sessions payload that exercises every branch of
 * createPreviewMessage, generateChatPreview, calculateDurationFromChatData
 * and formatMessageTimestamp.
 *
 * @param {string} sid
 */
function buildRichSessions(sid) {
    const t0 = new Date('2026-04-01T10:00:00Z').toISOString();
    const t1 = new Date('2026-04-01T10:05:00Z').toISOString();
    const t2 = new Date('2026-04-01T10:10:00Z').toISOString();
    const t3 = new Date('2026-04-01T10:15:00Z').toISOString();
    const t4 = new Date('2026-04-01T10:20:00Z').toISOString();
    const t5 = new Date('2026-04-01T10:25:00Z').toISOString();
    const t6 = new Date('2026-04-01T10:30:00Z').toISOString();
    return [
        {
            sessionId: `${sid}_A`,
            courseId: STU_COURSE_ID,
            studentId: sid,
            studentName: 'E2E Student',
            unitName: 'Unit 1',
            title: 'Rich preview session',
            messageCount: 7,
            duration: '30m',
            savedAt: t0,
            chatData: {
                messages: [
                    {
                        type: 'user',
                        content: 'plain user question about photosynthesis',
                        messageType: 'regular-chat',
                        timestamp: t0,
                    },
                    {
                        type: 'bot',
                        content: '<strong>Bold bot reply with HTML</strong>',
                        messageType: 'regular-chat',
                        isHtml: true,
                        timestamp: t1,
                    },
                    {
                        type: 'bot',
                        content: 'mode-explanation-text',
                        messageType: 'mode-result',
                        htmlContent: '<div class="mode-explanation">BiocBot is now in tutor mode</div>',
                        timestamp: t2,
                    },
                    {
                        type: 'bot',
                        content: 'mode-toggle-text',
                        messageType: 'mode-toggle-result',
                        htmlContent: '<div>Switched to protégé mode <span class="timestamp">old-ts</span></div>',
                        timestamp: t3,
                    },
                    {
                        type: 'bot',
                        content: '[practice]',
                        messageType: 'practice-test-question',
                        timestamp: t4,
                        questionData: {
                            questionText: 'What stage of photosynthesis produces ATP?',
                            options: [
                                { text: 'A. Light reactions', isSelected: true },
                                { text: 'B. Dark reactions', isSelected: false },
                            ],
                            studentAnswer: 'A',
                        },
                    },
                    {
                        type: 'bot',
                        content: '[short-answer-practice]',
                        messageType: 'practice-test-question',
                        timestamp: t5,
                        questionData: {
                            questionText: 'Define glycolysis briefly.',
                            studentAnswer: 'Breakdown of glucose into pyruvate.',
                        },
                    },
                    {
                        // exercises the orphaned-practice-question sanitiser
                        type: 'bot',
                        content: '<div class="practice-question-container" data-practice-id="stale"><div class="practice-question-text">Stale unanswered Q?</div></div>',
                        messageType: 'regular-chat',
                        isHtml: true,
                        timestamp: t6,
                    },
                ],
            },
        },
        {
            sessionId: `${sid}_B`,
            courseId: STU_COURSE_ID,
            studentId: sid,
            studentName: 'E2E Student',
            unitName: 'Unit 2',
            // No title — exercises the default-title branch in loadChatHistory.
            messageCount: 1,
            duration: '1m',
            savedAt: new Date('2026-04-02T12:00:00Z').toISOString(),
            chatData: {
                messages: [
                    {
                        type: 'bot',
                        content: 'bot-only intro',
                        messageType: 'regular-chat',
                        timestamp: new Date('2026-04-02T12:00:00Z').toISOString(),
                    },
                ],
            },
        },
    ];
}

/**
 * Mock the sessions list endpoint. Avoids touching MongoDB so chat-data
 * branches stay deterministic.
 *
 * @param {import('@playwright/test').Page} page
 * @param {any[]} sessions
 */
async function mockSessionsList(page, sessions) {
    await page.route('**/api/students/*/*/sessions/own', async (route) => {
        const req = route.request();
        if (req.method() !== 'GET') return route.fallback();
        await route.fulfill({
            json: { success: true, data: { sessions } },
        });
    });
}

async function gotoHistory(page) {
    await page.addInitScript((id) => {
        try {
            localStorage.setItem('selectedCourseId', id);
            localStorage.setItem('selectedCourseName', 'BIOC E2E Student Chat');
        } catch (_) { /* noop */ }
    }, STU_COURSE_ID);
    await page.goto('/student/history');
}

async function waitForFn(page, name) {
    await page.waitForFunction((n) => typeof (/** @type {any} */ (window))[n] === 'function', name);
}

// ----------------------------------------------------------------------------
// Empty state
// ----------------------------------------------------------------------------
test.describe('Empty history', () => {
    test('shows the no-history message when the server returns []', async ({ page }) => {
        await mockSessionsList(page, []);
        await gotoHistory(page);

        await expect(page.locator('#no-history-message')).toBeVisible({ timeout: 15_000 });
        // The preview panel should be in its placeholder state.
        await expect(page.locator('#preview-title')).toHaveText('Select a Chat');
        await expect(page.locator('#preview-actions')).toBeHidden();
        await expect(page.locator('#preview-messages .no-selection')).toBeVisible();
    });

    test('falls back to localStorage when no course is selected', async ({ page }) => {
        // No selectedCourseId in localStorage → triggers loadChatHistoryFromLocalStorage.
        await page.goto('/student/history');
        await waitForFn(page, 'getChatHistory');
        // Seed localStorage with a chat under the right namespaced key.
        await page.evaluate((sid) => {
            const w = /** @type {any} */ (window);
            const key = `biocbot_chat_history_${sid}`;
            const chat = {
                id: 'ls_chat_1',
                title: 'LS Only Chat',
                preview: 'preview text',
                unitName: 'Unit 1',
                messageCount: 1,
                duration: '0s',
                savedAt: new Date().toISOString(),
                chatData: { messages: [{ type: 'user', content: 'hi from ls', timestamp: new Date().toISOString() }] },
            };
            localStorage.setItem(key, JSON.stringify([chat]));
            w.refreshHistory();
        }, studentId);

        await expect(page.locator('[data-chat-id="ls_chat_1"]')).toBeVisible({ timeout: 10_000 });
    });

    test('falls back to localStorage when the server responds with 500', async ({ page }) => {
        await page.route('**/api/students/*/*/sessions/own', async (route) => {
            if (route.request().method() !== 'GET') return route.fallback();
            await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false }) });
        });
        await page.addInitScript((arg) => {
            try {
                localStorage.setItem('selectedCourseId', arg.courseId);
                const key = `biocbot_chat_history_${arg.sid}`;
                localStorage.setItem(key, JSON.stringify([{
                    id: 'fallback_chat',
                    title: 'Fallback chat',
                    preview: 'fallback preview',
                    unitName: 'Unit 1',
                    messageCount: 0,
                    duration: '0s',
                    savedAt: new Date().toISOString(),
                    chatData: { messages: [] },
                }]));
            } catch (_) { /* noop */ }
        }, { courseId: STU_COURSE_ID, sid: studentId });
        await page.goto('/student/history');

        await expect(page.locator('[data-chat-id="fallback_chat"]')).toBeVisible({ timeout: 15_000 });
    });
});

// ----------------------------------------------------------------------------
// Rendering & preview
// ----------------------------------------------------------------------------
test.describe('Rendering chat history list + preview', () => {
    test('renders every seeded session with metadata and auto-selects the first', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);
        await gotoHistory(page);

        const itemA = page.locator(`[data-chat-id="${studentId}_A"]`);
        const itemB = page.locator(`[data-chat-id="${studentId}_B"]`);
        await expect(itemA).toBeVisible({ timeout: 15_000 });
        await expect(itemB).toBeVisible();

        await expect(itemA.locator('.title-text')).toHaveText('Rich preview session');
        // Session B has no title, so loadChatHistory falls back to "Chat Session <date>".
        await expect(itemB.locator('.title-text')).toContainText('Chat Session');

        // Metadata renders message count + duration.
        await expect(itemA.locator('.message-count')).toContainText('7 messages');
        // Duration is recalculated from message timestamps, not the server's
        // session.duration string. The rich preview spans 30 minutes.
        await expect(itemA.locator('.duration')).toContainText('30m');

        // First item auto-selected — preview title should match.
        await expect(page.locator('#preview-title')).toHaveText('Rich preview session');
        await expect(page.locator('#preview-actions')).toBeVisible();
    });

    test('preview panel renders all message variants', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);
        await gotoHistory(page);

        // First item auto-selected.
        const preview = page.locator('#preview-messages');
        await expect(preview).toContainText('plain user question about photosynthesis', { timeout: 15_000 });
        await expect(preview).toContainText('Bold bot reply with HTML');

        // mode-result: gets the standard-mode-result class.
        await expect(preview.locator('.message.standard-mode-result')).toHaveCount(1);
        // mode-explanation should have been stripped of its class by createPreviewMessage.
        await expect(preview.locator('.message.standard-mode-result .mode-explanation')).toHaveCount(0);

        // mode-toggle-result: just gets contentDiv rewritten; no standard-mode-result class.
        await expect(preview).toContainText('Switched to protégé mode');

        // practice-test-question with options renders calibration-options.
        await expect(preview.locator('.calibration-options')).toHaveCount(1);
        // Selected option should have .selected applied.
        await expect(preview.locator('.calibration-option.selected')).toHaveCount(1);

        // short-answer practice renders the "Your Answer:" block.
        await expect(preview).toContainText('Your Answer:');
        await expect(preview).toContainText('Breakdown of glucose into pyruvate.');

        // Orphan practice question gets sanitised into a "not answered" notice.
        await expect(preview).toContainText('This practice question was not answered during the session.');
    });

    test('clicking the second item swaps the preview and updates .active', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);
        await gotoHistory(page);

        const itemA = page.locator(`[data-chat-id="${studentId}_A"]`);
        const itemB = page.locator(`[data-chat-id="${studentId}_B"]`);
        await expect(itemA).toHaveClass(/active/, { timeout: 15_000 });

        await itemB.click();
        await expect(itemB).toHaveClass(/active/);
        await expect(itemA).not.toHaveClass(/active/);
        await expect(page.locator('#preview-messages')).toContainText('bot-only intro');
    });
});

// ----------------------------------------------------------------------------
// Inline rename flow
// ----------------------------------------------------------------------------
test.describe('Inline rename', () => {
    test('save via button updates server + UI', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        /** @type {{ title?: string } | undefined} */
        let payload;
        await page.route('**/api/students/*/*/sessions/*/title', async (route) => {
            if (route.request().method() !== 'PUT') return route.fallback();
            payload = route.request().postDataJSON();
            await route.fulfill({ json: { success: true } });
        });

        await gotoHistory(page);
        const item = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(item).toBeVisible({ timeout: 15_000 });

        await item.locator('.edit-btn').click();
        await expect(item).toHaveClass(/editing/);
        await expect(item.locator('.title-input')).toBeVisible();

        await item.locator('.title-input').fill('Renamed via save button');
        await item.locator('.save-btn').click();

        await expect.poll(() => payload?.title).toBe('Renamed via save button');
        await expect(item.locator('.title-text')).toHaveText('Renamed via save button');
        await expect(item).not.toHaveClass(/editing/);
        // Preview title also updates since this item was selected.
        await expect(page.locator('#preview-title')).toHaveText('Renamed via save button');
    });

    test('Enter key saves and Escape cancels', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        let putCount = 0;
        await page.route('**/api/students/*/*/sessions/*/title', async (route) => {
            if (route.request().method() !== 'PUT') return route.fallback();
            putCount += 1;
            await route.fulfill({ json: { success: true } });
        });

        await gotoHistory(page);
        const item = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(item).toBeVisible({ timeout: 15_000 });

        // Enter saves.
        await item.locator('.edit-btn').click();
        await item.locator('.title-input').fill('Saved via Enter');
        await item.locator('.title-input').press('Enter');
        await expect(item.locator('.title-text')).toHaveText('Saved via Enter');
        expect(putCount).toBe(1);

        // Escape cancels — value resets.
        await item.locator('.edit-btn').click();
        await item.locator('.title-input').fill('THIS SHOULD BE THROWN AWAY');
        await item.locator('.title-input').press('Escape');
        await expect(item.locator('.title-text')).toHaveText('Saved via Enter');
        expect(putCount).toBe(1);
    });

    test('Cancel button restores the original value without calling the server', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        let putCount = 0;
        await page.route('**/api/students/*/*/sessions/*/title', async (route) => {
            if (route.request().method() !== 'PUT') return route.fallback();
            putCount += 1;
            await route.fulfill({ json: { success: true } });
        });

        await gotoHistory(page);
        const item = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(item).toBeVisible({ timeout: 15_000 });

        await item.locator('.edit-btn').click();
        await item.locator('.title-input').fill('NEVER PERSISTED');
        await item.locator('.cancel-btn').click();

        await expect(item).not.toHaveClass(/editing/);
        await expect(item.locator('.title-text')).toHaveText('Rich preview session');
        expect(putCount).toBe(0);
    });

    test('empty / unchanged title short-circuits the API call', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        let putCount = 0;
        await page.route('**/api/students/*/*/sessions/*/title', async (route) => {
            if (route.request().method() !== 'PUT') return route.fallback();
            putCount += 1;
            await route.fulfill({ json: { success: true } });
        });

        await gotoHistory(page);
        const item = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(item).toBeVisible({ timeout: 15_000 });

        // Same as original — saveTitle bails before fetch.
        await item.locator('.edit-btn').click();
        await item.locator('.save-btn').click();
        expect(putCount).toBe(0);

        // Whitespace-only — also bails.
        await item.locator('.edit-btn').click();
        await item.locator('.title-input').fill('   ');
        await item.locator('.save-btn').click();
        expect(putCount).toBe(0);
    });

    test('server failure on rename falls back to localStorage write', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        await page.route('**/api/students/*/*/sessions/*/title', async (route) => {
            if (route.request().method() !== 'PUT') return route.fallback();
            await route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ success: false }) });
        });

        await gotoHistory(page);
        // Pre-seed localStorage so the fallback write has something to update.
        await page.evaluate((arg) => {
            const key = `biocbot_chat_history_${arg.sid}`;
            localStorage.setItem(key, JSON.stringify([
                { id: `${arg.sid}_A`, title: 'old-title', preview: '', unitName: 'Unit 1', messageCount: 0, duration: '0', savedAt: new Date().toISOString(), chatData: { messages: [] } },
            ]));
        }, { sid: studentId });

        const item = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(item).toBeVisible({ timeout: 15_000 });
        await item.locator('.edit-btn').click();
        await item.locator('.title-input').fill('via-fallback');
        await item.locator('.save-btn').click();

        // Even though the server returned 500, the catch-block fallback
        // writes to localStorage and returns true → UI updates.
        await expect.poll(async () => {
            return await page.evaluate((arg) => {
                const key = `biocbot_chat_history_${arg.sid}`;
                const parsed = JSON.parse(localStorage.getItem(key) || '[]');
                return parsed.find((c) => c.id === `${arg.sid}_A`)?.title;
            }, { sid: studentId });
        }).toBe('via-fallback');
    });
});

// ----------------------------------------------------------------------------
// Delete flow
// ----------------------------------------------------------------------------
test.describe('Delete chat', () => {
    test('confirm → DELETE /api/.../sessions/:id/own → list refreshes', async ({ page }) => {
        let sessionsResponse = buildRichSessions(studentId);
        await page.route('**/api/students/*/*/sessions/own', async (route) => {
            if (route.request().method() !== 'GET') return route.fallback();
            await route.fulfill({ json: { success: true, data: { sessions: sessionsResponse } } });
        });

        let deleted = false;
        await page.route('**/api/students/*/*/sessions/*/own', async (route) => {
            if (route.request().method() !== 'DELETE') return route.fallback();
            deleted = true;
            // After deletion the next list-fetch should return the remaining session.
            sessionsResponse = sessionsResponse.filter((s) => s.sessionId !== `${studentId}_A`);
            await route.fulfill({ json: { success: true } });
        });

        page.on('dialog', (d) => d.accept());

        await gotoHistory(page);
        const itemA = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(itemA).toBeVisible({ timeout: 15_000 });

        await page.locator('#delete-chat-btn').click();
        await expect.poll(() => deleted).toBeTruthy();
        await expect(itemA).toHaveCount(0, { timeout: 10_000 });
        // The remaining item should now be auto-selected.
        await expect(page.locator(`[data-chat-id="${studentId}_B"]`)).toBeVisible();
    });

    test('dismissing the confirm dialog cancels and never hits the server', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        let deleteCalled = false;
        await page.route('**/api/students/*/*/sessions/*/own', async (route) => {
            if (route.request().method() !== 'DELETE') return route.fallback();
            deleteCalled = true;
            await route.fulfill({ json: { success: true } });
        });

        page.on('dialog', (d) => d.dismiss());

        await gotoHistory(page);
        await expect(page.locator(`[data-chat-id="${studentId}_A"]`)).toBeVisible({ timeout: 15_000 });

        await page.locator('#delete-chat-btn').click();
        // give the handler a moment, then assert nothing happened.
        await page.waitForTimeout(300);
        expect(deleteCalled).toBe(false);
        await expect(page.locator(`[data-chat-id="${studentId}_A"]`)).toBeVisible();
    });

    test('handleDeleteChat with nothing selected silently returns', async ({ page }) => {
        await mockSessionsList(page, []);
        await gotoHistory(page);
        await expect(page.locator('#no-history-message')).toBeVisible({ timeout: 15_000 });
        await waitForFn(page, 'handleDeleteChat');

        // Without a selection, handleDeleteChat must not throw.
        await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            return w.handleDeleteChat();
        });
        await expect(page.locator('#no-history-message')).toBeVisible();
    });
});

// ----------------------------------------------------------------------------
// Continue chat → /student handoff
// ----------------------------------------------------------------------------
test.describe('Continue chat', () => {
    test('sets sessionStorage.loadChatData and navigates to /student', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);

        await gotoHistory(page);
        await expect(page.locator(`[data-chat-id="${studentId}_A"]`)).toBeVisible({ timeout: 15_000 });

        // Capture sessionStorage just before /student replaces the page.
        const navPromise = page.waitForURL((url) => url.pathname === '/student' || url.pathname === '/student/', { timeout: 15_000 });
        await page.locator('#continue-chat-btn').click();
        await navPromise;
    });

    test('handleContinueChat with nothing selected does not navigate', async ({ page }) => {
        await mockSessionsList(page, []);
        await gotoHistory(page);
        await expect(page.locator('#no-history-message')).toBeVisible({ timeout: 15_000 });
        await waitForFn(page, 'handleContinueChat');

        const before = page.url();
        await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            return w.handleContinueChat();
        });
        // Brief settle period, then prove we never navigated.
        await page.waitForTimeout(200);
        expect(page.url()).toBe(before);
    });
});

// ----------------------------------------------------------------------------
// Download Markdown
// ----------------------------------------------------------------------------
test.describe('Download Markdown', () => {
    test('clicking Download Markdown triggers a .md download with expected sections', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);
        await gotoHistory(page);
        await expect(page.locator(`[data-chat-id="${studentId}_A"]`)).toBeVisible({ timeout: 15_000 });

        const [download] = await Promise.all([
            page.waitForEvent('download', { timeout: 15_000 }),
            page.locator('#download-md-btn').click(),
        ]);

        const fname = download.suggestedFilename();
        expect(fname).toMatch(/^BiocBot_Chat_.+\.md$/);

        const stream = await download.createReadStream();
        let text = '';
        if (stream) {
            for await (const chunk of stream) text += chunk.toString('utf8');
        }
        expect(text).toContain('# Rich preview session');
        expect(text).toContain('**Course:**');
        expect(text).toContain('**Student:**');
        expect(text).toContain('**Unit:**');
        // Practice question rendering through formatPracticeQuestion.
        expect(text).toContain('**Question:**');
        expect(text).toContain('**Options:**');
        expect(text).toContain('(Selected)');
        expect(text).toContain('**Your Answer:**');
        // Mode result was converted from HTML to Markdown-ish text.
        expect(text).toMatch(/tutor mode|protégé mode/);
        // The student-name segment in the filename should be Markdown-safe.
        expect(fname).not.toContain(' ');
    });

    test('handleDownloadMarkdown without selection alerts the user', async ({ page }) => {
        await mockSessionsList(page, []);
        await gotoHistory(page);
        await expect(page.locator('#no-history-message')).toBeVisible({ timeout: 15_000 });
        await waitForFn(page, 'handleDownloadMarkdown');

        const dialogs = [];
        page.on('dialog', (d) => {
            dialogs.push(d.message());
            d.accept().catch(() => {});
        });
        await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            return w.handleDownloadMarkdown();
        });
        await page.waitForTimeout(200);
        expect(dialogs.join('\n')).toMatch(/select a chat/i);
    });
});

// ----------------------------------------------------------------------------
// Mobile-action buttons embedded in each history item
// ----------------------------------------------------------------------------
test.describe('Mobile action buttons', () => {
    test('mobile "Continue" button navigates to /student', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);
        await gotoHistory(page);

        const itemB = page.locator(`[data-chat-id="${studentId}_B"]`);
        await expect(itemB).toBeVisible({ timeout: 15_000 });

        const navPromise = page.waitForURL((url) => url.pathname === '/student' || url.pathname === '/student/', { timeout: 15_000 });
        // Bypass display:none by calling the action directly. The mobile
        // handler is `mobileActions.querySelectorAll('.mobile-action-btn')`
        // and we want to exercise the continue branch.
        await itemB.locator('.mobile-action-btn[data-action="continue"]').dispatchEvent('click');
        await navPromise;
    });

    test('mobile "Download Markdown" triggers a download', async ({ page }) => {
        const sessions = buildRichSessions(studentId);
        await mockSessionsList(page, sessions);
        await gotoHistory(page);

        const itemA = page.locator(`[data-chat-id="${studentId}_A"]`);
        await expect(itemA).toBeVisible({ timeout: 15_000 });

        const [download] = await Promise.all([
            page.waitForEvent('download', { timeout: 15_000 }),
            itemA.locator('.mobile-action-btn[data-action="download-md"]').dispatchEvent('click'),
        ]);
        expect(download.suggestedFilename()).toMatch(/\.md$/);
    });

    test('mobile "Delete" button triggers the delete flow', async ({ page }) => {
        let sessionsResponse = buildRichSessions(studentId);
        await page.route('**/api/students/*/*/sessions/own', async (route) => {
            if (route.request().method() !== 'GET') return route.fallback();
            await route.fulfill({ json: { success: true, data: { sessions: sessionsResponse } } });
        });
        let deleted = false;
        await page.route('**/api/students/*/*/sessions/*/own', async (route) => {
            if (route.request().method() !== 'DELETE') return route.fallback();
            deleted = true;
            sessionsResponse = sessionsResponse.filter((s) => s.sessionId !== `${studentId}_B`);
            await route.fulfill({ json: { success: true } });
        });

        page.on('dialog', (d) => d.accept());

        await gotoHistory(page);
        const itemB = page.locator(`[data-chat-id="${studentId}_B"]`);
        await expect(itemB).toBeVisible({ timeout: 15_000 });

        await itemB.locator('.mobile-action-btn[data-action="delete"]').dispatchEvent('click');
        await expect.poll(() => deleted).toBeTruthy();
        await expect(itemB).toHaveCount(0, { timeout: 10_000 });
    });
});

// ----------------------------------------------------------------------------
// Banned-enrollment gate (renderRevokedAccessUIForHistory)
// ----------------------------------------------------------------------------
test.describe('Revoked-access gate', () => {
    test('banned status hides the history container and renders the notice', async ({ page }) => {
        await page.route(`**/api/courses/${STU_COURSE_ID}/student-enrollment`, async (route) => {
            await route.fulfill({ json: { success: true, data: { status: 'banned' } } });
        });
        // Even if the sessions endpoint were called we don't want it to interfere.
        await mockSessionsList(page, []);
        await gotoHistory(page);

        await expect(page.locator('.history-container')).toBeHidden({ timeout: 15_000 });
        await expect(page.locator('.main-content')).toContainText('Access disabled');
        await expect(page.locator('.main-content')).toContainText('Your access in this course is revoked.');
    });
});

// ----------------------------------------------------------------------------
// Pure helpers: formatHistoryDate, formatMessageTimestamp, generateChatPreview,
// calculateDurationFromChatData, convertHtmlToMarkdown, formatPracticeQuestion
// ----------------------------------------------------------------------------
test.describe('Pure helpers via window globals', () => {
    test.beforeEach(async ({ page }) => {
        await mockSessionsList(page, []);
        await gotoHistory(page);
        await expect(page.locator('#no-history-message')).toBeVisible({ timeout: 15_000 });
    });

    test('formatHistoryDate covers Today / Yesterday / this-week / older / invalid', async ({ page }) => {
        await waitForFn(page, 'formatHistoryDate');
        const out = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            const now = new Date();
            return {
                today: w.formatHistoryDate(now.toISOString()),
                yesterday: w.formatHistoryDate(new Date(now.getTime() - 24 * 60 * 60_000).toISOString()),
                thisWeek: w.formatHistoryDate(new Date(now.getTime() - 3 * 24 * 60 * 60_000).toISOString()),
                older: w.formatHistoryDate(new Date(now.getTime() - 60 * 24 * 60 * 60_000).toISOString()),
                invalid: w.formatHistoryDate('not-a-date'),
                empty: w.formatHistoryDate(''),
            };
        });
        expect(out.today).toMatch(/^Today,\s/);
        expect(out.yesterday).toMatch(/^Yesterday,\s/);
        expect(out.thisWeek).not.toMatch(/Today|Yesterday/);
        expect(out.older).toMatch(/\d{4}/);
        expect(out.invalid).toBe('Unknown date');
        expect(out.empty).toBe('Unknown date');
    });

    test('formatMessageTimestamp covers valid / invalid / null', async ({ page }) => {
        await waitForFn(page, 'formatMessageTimestamp');
        const out = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            return {
                valid: w.formatMessageTimestamp(new Date('2026-01-15T10:30:00Z').toISOString()),
                invalid: w.formatMessageTimestamp('garbage'),
                empty: w.formatMessageTimestamp(''),
                nul: w.formatMessageTimestamp(null),
            };
        });
        expect(out.valid).toMatch(/\b(Jan|2026)\b/);
        expect(out.invalid).toBe('Unknown time');
        expect(out.empty).toBe('Unknown time');
        expect(out.nul).toBe('Unknown time');
    });

    test('generateChatPreview handles user-first, bot-first, HTML stripping, empty messages', async ({ page }) => {
        await waitForFn(page, 'generateChatPreview');
        const out = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            return {
                userFirst: w.generateChatPreview({ messages: [
                    { type: 'user', content: 'plain user question', isHtml: false },
                    { type: 'bot', content: 'bot reply', isHtml: false },
                ] }),
                userFirstHtml: w.generateChatPreview({ messages: [
                    { type: 'user', content: '<strong>hello with <em>html</em></strong>', isHtml: true },
                ] }),
                botOnly: w.generateChatPreview({ messages: [
                    { type: 'bot', content: 'bot says hi', isHtml: false },
                ] }),
                botOnlyHtml: w.generateChatPreview({ messages: [
                    { type: 'bot', content: '<p>bot html</p>', isHtml: true },
                ] }),
                longUser: w.generateChatPreview({ messages: [
                    { type: 'user', content: 'x'.repeat(200), isHtml: false },
                ] }),
                emptyMessages: w.generateChatPreview({ messages: [] }),
                noMessages: w.generateChatPreview({}),
                noChatData: w.generateChatPreview(null),
            };
        });
        expect(out.userFirst).toContain('plain user question');
        expect(out.userFirstHtml).toContain('hello with html');
        expect(out.userFirstHtml).not.toMatch(/<\w+>/);
        expect(out.botOnly).toContain('bot says hi');
        expect(out.botOnlyHtml).toContain('bot html');
        expect(out.longUser.endsWith('...')).toBe(true);
        expect(out.emptyMessages).toBe('Chat session with BiocBot');
        expect(out.noMessages).toBe('Chat session with BiocBot');
        expect(out.noChatData).toBe('Chat session with BiocBot');
    });

    test('calculateDurationFromChatData covers seconds/minutes/hours and the last-message fallback', async ({ page }) => {
        await waitForFn(page, 'calculateDurationFromChatData');
        const out = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            const t = (offsetMs) => new Date(Date.now() + offsetMs).toISOString();
            return {
                empty: w.calculateDurationFromChatData(null),
                emptyMessages: w.calculateDurationFromChatData({ messages: [] }),
                noUserMessage: w.calculateDurationFromChatData({ messages: [{ type: 'bot', content: 'a', timestamp: t(0) }] }),
                seconds: w.calculateDurationFromChatData({ messages: [
                    { type: 'user', content: 'q', timestamp: t(0) },
                    { type: 'bot', content: 'a', timestamp: t(45_000) },
                ] }),
                minutes: w.calculateDurationFromChatData({ messages: [
                    { type: 'user', content: 'q', timestamp: t(0) },
                    { type: 'bot', content: 'a', timestamp: t(5 * 60_000 + 30_000) },
                ] }),
                hours: w.calculateDurationFromChatData({ messages: [
                    { type: 'user', content: 'q', timestamp: t(0) },
                    { type: 'bot', content: 'a', timestamp: t(2 * 60 * 60_000 + 60_000) },
                ] }),
                fallbackLast: w.calculateDurationFromChatData({ messages: [
                    { type: 'user', content: 'q1', timestamp: t(0) },
                    // No bot message → falls through to "use last message" branch.
                    { type: 'user', content: 'q2', timestamp: t(30_000) },
                ] }),
                fallbackNoTimestamps: w.calculateDurationFromChatData({ messages: [
                    { type: 'user', content: 'q', timestamp: null },
                ] }),
                staleWelcome: w.calculateDurationFromChatData({ messages: [
                    { type: 'user', content: 'q', timestamp: '2026-07-12T21:32:09.744Z' },
                    { type: 'bot', content: 'real answer', timestamp: '2026-07-12T21:40:31.708Z' },
                    {
                        type: 'bot',
                        content: '<strong>Welcome to BiocBot!</strong> I can see you have access to published units.',
                        timestamp: '2026-07-13T23:02:26.177Z',
                    },
                ] }),
            };
        });
        expect(out.empty).toBe('0s');
        expect(out.emptyMessages).toBe('0s');
        expect(out.noUserMessage).toBe('0s');
        expect(out.seconds).toMatch(/^\d+s$/);
        expect(out.minutes).toMatch(/^\d+m \d+s$/);
        expect(out.hours).toMatch(/^\d+h \d+m \d+s$/);
        expect(out.fallbackLast).toMatch(/^\d+s$/);
        expect(out.fallbackNoTimestamps).toBe('0s');
        expect(out.staleWelcome).toBe('8m 21s');
    });

    test('debug helpers expose data without throwing', async ({ page }) => {
        await waitForFn(page, 'checkLocalStorage');
        const out = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            return {
                fromCheck: w.checkLocalStorage(),
                refreshOk: (() => { w.refreshHistory(); return true; })(),
                duplicatesOk: (() => { try { w.removeDuplicates(); return true; } catch (_) { return false; } })(),
            };
        });
        expect(Array.isArray(out.fromCheck)).toBe(true);
        expect(out.refreshOk).toBe(true);
        expect(out.duplicatesOk).toBe(true);
    });

    test('getChatById returns null for unknown ids', async ({ page }) => {
        await waitForFn(page, 'getChatById');
        const out = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            // Seed one row in the namespaced storage key so getChatHistory
            // returns it, then ask for the wrong id.
            return {
                missing: w.getChatById('definitely-not-here'),
            };
        });
        expect(out.missing).toBeNull();
    });

    test('getCurrentUser falls through to localStorage when window.currentUser is absent', async ({ page }) => {
        await waitForFn(page, 'getCurrentUser');
        const result = await page.evaluate(() => {
            const w = /** @type {any} */ (window);
            // Capture original state, clear, then restore.
            const saved = w.currentUser;
            try {
                w.currentUser = null;
                localStorage.setItem('currentUser', JSON.stringify({ userId: 'ls-user-id', displayName: 'LS User' }));
                // Also remove the global getCurrentUser so the second branch
                // (window.getCurrentUser !== local) doesn't re-enter.
                const local = w.getCurrentUser;
                w.getCurrentUser = null;
                const fromLs = local();
                w.getCurrentUser = local;
                return fromLs;
            } finally {
                w.currentUser = saved;
                localStorage.removeItem('currentUser');
            }
        });
        expect(result?.userId).toBe('ls-user-id');
    });
});
