// @ts-check
const { test, expect } = require('./fixtures/monocart');
const { storageStatePath } = require('./helpers/users');

const STORAGE_KEY = 'biocbot_last_known_flags';
const STUDENT_ID = 'user_e2e_student';
const COURSE_ID = 'BIOC-E2E-FLAG-NOTIFICATIONS';
const OTHER_COURSE_ID = 'BIOC-E2E-FLAG-NOTIFICATIONS-OTHER';

/**
 * @typedef {{
 *   flagId: string,
 *   flagStatus: string,
 *   instructorResponse: string | null,
 *   createdAt: string,
 *   updatedAt: string,
 *   [key: string]: any,
 * }} FlagFixture
 *
 * @typedef {{
 *   status: number,
 *   body: {
 *     success: boolean,
 *     data?: { flags: FlagFixture[], count: number },
 *     message?: string,
 *   },
 * }} MockFlagResponse
 *
 * @typedef {{
 *   responses?: MockFlagResponse[],
 *   initialFlags?: FlagFixture[],
 *   selectedCourseId?: string,
 *   shortAutoDismiss?: boolean,
 *   responseDelayMs?: number,
 * }} HarnessOptions
 */

function recentIso(offsetMs = 0) {
    return new Date(Date.now() + offsetMs).toISOString();
}

/**
 * @param {Partial<FlagFixture>} [overrides]
 * @returns {FlagFixture}
 */
function flag(overrides = {}) {
    return {
        flagId: 'flag_e2e_notification',
        questionId: 'question_e2e_notification',
        courseId: COURSE_ID,
        unitName: 'Unit 1',
        studentId: STUDENT_ID,
        studentName: 'E2E Student',
        flagReason: 'unclear',
        flagDescription: 'This answer needs instructor review.',
        flagStatus: 'pending',
        instructorResponse: null,
        instructorId: null,
        instructorName: null,
        questionContent: {
            question: 'Which bond joins two amino acids?',
            questionType: 'short-answer',
        },
        createdAt: recentIso(-60_000),
        updatedAt: recentIso(-60_000),
        ...overrides,
    };
}

/**
 * @param {FlagFixture[]} flags
 * @param {number} [status]
 * @returns {MockFlagResponse}
 */
function apiResponse(flags, status = 200) {
    return {
        status,
        body: {
            success: status >= 200 && status < 300,
            data: { flags, count: flags.length },
        },
    };
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {HarnessOptions} [options]
 */
async function loadHarness(page, options = {}) {
    const {
        responses = [],
        initialFlags = [],
        selectedCourseId = COURSE_ID,
        shortAutoDismiss = false,
        responseDelayMs = 0,
    } = options;
    const apiRequests = [];
    const queuedResponses = /** @type {MockFlagResponse[]} */ ([...responses]);

    await page.route('**/student/flagged', (route) => route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><html><body><main id="flagged-page">Flagged questions</main></body></html>',
    }));

    await page.route('**/api/settings/llm-tag', (route) => route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, llmIndex: null, reasoningIndex: null }),
    }));

    await page.route('**/api/user-agreement/status', (route) => route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, hasAgreed: true }),
    }));

    await page.route('**/api/courses/*/student-enrollment', (route) => route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
            success: true,
            data: {
                enrolled: true,
                isBanned: false,
                role: 'student',
            },
        }),
    }));

    await page.route('**/api/students/*/*/sessions/own', (route) => route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, data: { sessions: [] } }),
    }));

    await page.route('**/api/flags/my**', async (route) => {
        apiRequests.push({
            url: route.request().url(),
            headers: route.request().headers(),
        });
        if (responseDelayMs > 0) {
            await new Promise((resolve) => setTimeout(resolve, responseDelayMs));
        }
        const next = queuedResponses.shift() || apiResponse([]);
        return route.fulfill({
            status: next.status || 200,
            contentType: 'application/json',
            body: JSON.stringify(next.body),
        });
    });

    await page.addInitScript(({ storageKey, initialFlagsValue, selectedCourseIdValue, studentId, accelerateTimeouts }) => {
        localStorage.clear();
        localStorage.setItem(storageKey, JSON.stringify(initialFlagsValue));
        localStorage.setItem('selectedCourseId', selectedCourseIdValue);
        localStorage.setItem('currentUser', JSON.stringify({
            userId: studentId,
            username: 'e2e_student',
            displayName: 'E2E Student',
            role: 'student',
        }));

        if (accelerateTimeouts) {
            const nativeSetTimeout = window.setTimeout.bind(window);
            /** @type {any} */ (window).setTimeout = (callback, delay, ...args) => {
                const acceleratedDelay = delay === 8000 ? 800 : delay === 300 ? 10 : delay;
                return nativeSetTimeout(callback, acceleratedDelay, ...args);
            };
        }
    }, {
        storageKey: STORAGE_KEY,
        initialFlagsValue: initialFlags,
        selectedCourseIdValue: selectedCourseId,
        studentId: STUDENT_ID,
        accelerateTimeouts: shortAutoDismiss,
    });

    await page.goto('/student/history');

    await page.evaluate(() => {
        /** @type {any} */ (window).initializeFlagNotifications = async () => {};
    });
    await page.waitForFunction(() => typeof /** @type {any} */ (window).checkForFlagUpdates === 'function');

    return { apiRequests };
}

async function checkForUpdates(page) {
    await page.evaluate(async () => {
        const win = /** @type {any} */ (window);
        win.loadLastKnownFlags();
        await win.checkForFlagUpdates();
    });
}

async function storedFlags(page) {
    return page.evaluate((storageKey) => JSON.parse(localStorage.getItem(storageKey) || '[]'), STORAGE_KEY);
}

test.describe('public/student/scripts/flag-notifications.js', () => {
    test.use({ storageState: storageStatePath('student') });

    test('first successful response seeds local notification state without showing a stale notification', async ({ page }) => {
        const pendingFlag = flag({ flagId: 'flag_e2e_first_seen' });
        const { apiRequests } = await loadHarness(page, {
            responses: [apiResponse([pendingFlag])],
        });

        await checkForUpdates(page);

        await expect(page.locator('.flag-notification')).toHaveCount(0);
        expect(apiRequests).toHaveLength(1);
        expect(apiRequests[0].url).toContain('/api/flags/my');

        await expect.poll(() => storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_first_seen',
                flagStatus: 'pending',
                instructorResponse: null,
            }),
        ]);
    });

    test('shows and persists instructor-reviewed state when a pending flag receives a response', async ({ page }) => {
        const pendingFlag = flag({
            flagId: 'flag_e2e_reviewed',
            flagStatus: 'pending',
            instructorResponse: null,
            updatedAt: recentIso(-120_000),
        });
        const reviewedFlag = flag({
            ...pendingFlag,
            flagStatus: 'resolved',
            instructorResponse: 'Good catch. The answer key has been corrected.',
            instructorId: 'user_e2e_instructor',
            instructorName: 'E2E Instructor',
            updatedAt: recentIso(),
        });

        await loadHarness(page, {
            initialFlags: [pendingFlag],
            responses: [apiResponse([reviewedFlag])],
        });

        await checkForUpdates(page);

        const notification = page.locator('.flag-notification');
        await expect(notification).toHaveCount(1);
        await expect(notification).toContainText('E2E Instructor responded to your flag');

        expect(await storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_reviewed',
                flagStatus: 'resolved',
                instructorResponse: 'Good catch. The answer key has been corrected.',
            }),
        ]);

        await notification.click();
        await expect(page).toHaveURL(/\/student\/flagged$/);
    });

    test('keeps the visible notification count in sync with multiple reviewed flags', async ({ page }) => {
        const responseFlag = flag({
            flagId: 'flag_e2e_response_count',
            updatedAt: recentIso(-120_000),
        });
        const dismissedFlag = flag({
            flagId: 'flag_e2e_dismissed_count',
            updatedAt: recentIso(-120_000),
        });

        await loadHarness(page, {
            initialFlags: [responseFlag, dismissedFlag],
            responses: [apiResponse([
                flag({
                    ...responseFlag,
                    flagStatus: 'resolved',
                    instructorResponse: 'This question was updated.',
                    instructorName: 'E2E Instructor',
                    updatedAt: recentIso(),
                }),
                flag({
                    ...dismissedFlag,
                    flagStatus: 'dismissed',
                    instructorName: 'E2E Instructor',
                    updatedAt: recentIso(),
                }),
            ])],
        });

        await checkForUpdates(page);

        const notifications = page.locator('.flag-notification');
        await expect(notifications).toHaveCount(2);
        await expect(notifications.nth(0)).toContainText('responded to your flag');
        await expect(notifications.nth(1)).toContainText('dismissed by E2E Instructor');
        await expect(notifications.nth(0)).toHaveCSS('top', '20px');
        await expect(notifications.nth(1)).toHaveCSS('top', '100px');
    });

    test('auto-dismisses transient notifications without losing the stored reviewed state', async ({ page }) => {
        const pendingFlag = flag({ flagId: 'flag_e2e_auto_dismiss' });
        const dismissedFlag = flag({
            ...pendingFlag,
            flagStatus: 'dismissed',
            instructorName: 'E2E Instructor',
            updatedAt: recentIso(),
        });

        await loadHarness(page, {
            initialFlags: [pendingFlag],
            responses: [apiResponse([dismissedFlag])],
            shortAutoDismiss: true,
        });

        await checkForUpdates(page);

        await expect(page.locator('.flag-notification')).toHaveCount(1);
        await expect(page.locator('.flag-notification')).toHaveCount(0, { timeout: 2_000 });
        expect(await storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_auto_dismiss',
                flagStatus: 'dismissed',
            }),
        ]);
    });

    test('handles empty and failed API responses without creating notifications or corrupting last-known state', async ({ page }) => {
        const pendingFlag = flag({ flagId: 'flag_e2e_error_guard' });

        await loadHarness(page, {
            initialFlags: [pendingFlag],
            responses: [
                apiResponse([]),
                {
                    status: 401,
                    body: { success: false, message: 'Authentication required' },
                },
            ],
        });

        await checkForUpdates(page);

        await expect(page.locator('.flag-notification')).toHaveCount(0);
        expect(await storedFlags(page)).toEqual([]);

        await checkForUpdates(page);

        await expect(page.locator('.flag-notification')).toHaveCount(0);
        expect(await storedFlags(page)).toEqual([]);
    });

    test('recovers from corrupt localStorage and seeds a fresh flag snapshot', async ({ page }) => {
        const pendingFlag = flag({ flagId: 'flag_e2e_corrupt_storage' });

        await loadHarness(page, {
            responses: [apiResponse([pendingFlag])],
        });
        await page.evaluate((storageKey) => {
            localStorage.setItem(storageKey, '{not-valid-json');
        }, STORAGE_KEY);

        await checkForUpdates(page);

        await expect(page.locator('.flag-notification')).toHaveCount(0);
        expect(await storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_corrupt_storage',
                flagStatus: 'pending',
            }),
        ]);
    });

    test('preserves the last-known snapshot when a 200 API response reports success false', async ({ page }) => {
        const pendingFlag = flag({ flagId: 'flag_e2e_success_false_guard' });

        await loadHarness(page, {
            initialFlags: [pendingFlag],
            responses: [{
                status: 200,
                body: { success: false, message: 'Flag service unavailable' },
            }],
        });

        await checkForUpdates(page);

        await expect(page.locator('.flag-notification')).toHaveCount(0);
        expect(await storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_success_false_guard',
                flagStatus: 'pending',
            }),
        ]);
    });

    test('notifies when an instructor updates an existing response with a newer timestamp', async ({ page }) => {
        const previouslyResolvedFlag = flag({
            flagId: 'flag_e2e_response_updated',
            flagStatus: 'resolved',
            instructorResponse: 'Original instructor response.',
            instructorName: 'E2E Instructor',
            updatedAt: recentIso(-120_000),
        });
        const updatedResolvedFlag = flag({
            ...previouslyResolvedFlag,
            instructorResponse: 'Updated instructor response with more detail.',
            updatedAt: recentIso(),
        });

        await loadHarness(page, {
            initialFlags: [previouslyResolvedFlag],
            responses: [apiResponse([updatedResolvedFlag])],
        });

        await checkForUpdates(page);

        const notification = page.locator('.flag-notification');
        await expect(notification).toHaveCount(1);
        await expect(notification).toContainText('E2E Instructor updated their response to your flag');
        expect(await storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_response_updated',
                instructorResponse: 'Updated instructor response with more detail.',
            }),
        ]);
    });

    test('notifies for a newly seen recent resolved flag but ignores stale resolved history', async ({ page }) => {
        const knownPendingFlag = flag({
            flagId: 'flag_e2e_known_pending',
            updatedAt: recentIso(-120_000),
        });
        const recentResolvedFlag = flag({
            flagId: 'flag_e2e_recent_resolved',
            flagStatus: 'resolved',
            instructorName: 'E2E Instructor',
            createdAt: recentIso(-15_000),
            updatedAt: recentIso(-15_000),
        });
        const staleResolvedFlag = flag({
            flagId: 'flag_e2e_stale_resolved',
            flagStatus: 'resolved',
            instructorName: 'E2E Instructor',
            createdAt: recentIso(-3 * 60 * 60 * 1000),
            updatedAt: recentIso(-3 * 60 * 60 * 1000),
        });

        await loadHarness(page, {
            initialFlags: [knownPendingFlag],
            responses: [apiResponse([knownPendingFlag, recentResolvedFlag, staleResolvedFlag])],
        });

        await checkForUpdates(page);

        const notifications = page.locator('.flag-notification');
        await expect(notifications).toHaveCount(1);
        await expect(notifications).toContainText('Your flag has been approved by E2E Instructor');
        await expect(notifications).not.toContainText('flag_e2e_stale_resolved');
        expect(await storedFlags(page)).toHaveLength(3);
    });

    test('skips overlapping update checks while a fetch is already in flight', async ({ page }) => {
        const pendingFlag = flag({ flagId: 'flag_e2e_concurrent_guard' });
        const { apiRequests } = await loadHarness(page, {
            responses: [apiResponse([pendingFlag]), apiResponse([])],
            responseDelayMs: 150,
        });

        await page.evaluate(async () => {
            const win = /** @type {any} */ (window);
            win.loadLastKnownFlags();
            await Promise.all([
                win.checkForFlagUpdates(),
                win.checkForFlagUpdates(),
            ]);
        });

        expect(apiRequests).toHaveLength(1);
        expect(await storedFlags(page)).toEqual([
            expect.objectContaining({
                flagId: 'flag_e2e_concurrent_guard',
            }),
        ]);
    });

    test('does not start duplicate polling intervals and clears the active interval on stop', async ({ page }) => {
        await loadHarness(page);

        const result = await page.evaluate(() => {
            const win = /** @type {any} */ (window);
            const intervalDelays = /** @type {number[]} */ ([]);
            const clearedIds = /** @type {number[]} */ ([]);
            const nativeSetInterval = win.setInterval;
            const nativeClearInterval = win.clearInterval;

            win.setInterval = (_callback, delay) => {
                intervalDelays.push(delay);
                return intervalDelays.length;
            };
            win.clearInterval = (id) => {
                clearedIds.push(id);
            };

            win.startFlagPolling();
            win.startFlagPolling();
            win.stopFlagPolling();

            win.setInterval = nativeSetInterval;
            win.clearInterval = nativeClearInterval;

            return { intervalDelays, clearedIds };
        });

        expect(result.intervalDelays).toEqual([30_000]);
        expect(result.clearedIds).toEqual([1]);
    });

    test('DESIRED: ignores cross-student or non-selected-course flags if the API response contains them', async ({ page }) => {
        const leakedPendingFlag = flag({
            flagId: 'flag_e2e_leaked_notification',
            courseId: OTHER_COURSE_ID,
            studentId: 'user_e2e_other_student',
            studentName: 'Other Student',
        });
        const leakedResolvedFlag = flag({
            ...leakedPendingFlag,
            flagStatus: 'resolved',
            instructorResponse: 'This belongs to another student and course.',
            instructorName: 'E2E Instructor',
            updatedAt: recentIso(),
        });

        await loadHarness(page, {
            selectedCourseId: COURSE_ID,
            initialFlags: [leakedPendingFlag],
            responses: [apiResponse([leakedResolvedFlag])],
        });

        await checkForUpdates(page);

        // Current behaviour: the script trusts every item in /api/flags/my and
        // shows this notification. The notification layer should not surface
        // foreign student/course data if the backend response is ever wrong.
        await expect(page.locator('.flag-notification')).toHaveCount(0);
        expect(await storedFlags(page)).toEqual([]);
    });
});
