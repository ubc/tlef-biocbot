// @ts-check
const { test, expect } = require('./fixtures/monocart');

const loginHarnessPath = '/__coverage-login';
const idleHarnessPath = '/__coverage-idle';

/**
 * @typedef {import('@playwright/test').Page} Page
 */

/**
 * @param {Page} page
 */
async function installDashboardRoutes(page) {
    await page.route('**/student', (route) => route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>Student</title><main>student dashboard</main>',
    }));
    await page.route('**/ta', (route) => route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>TA</title><main>ta dashboard</main>',
    }));
    await page.route('**/instructor/home', (route) => route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>Instructor</title><main>instructor dashboard</main>',
    }));
    await page.route('**/Shibboleth.sso/Login', (route) => route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>CWL</title><main>cwl login</main>',
    }));
    await page.route('**/logout', (route) => route.fulfill({
        contentType: 'text/html',
        body: '<!doctype html><title>Logout</title><main>logout fallback</main>',
    }));
}

/**
 * @param {Page} page
 */
async function installLoginHarness(page) {
    await installDashboardRoutes(page);
    await page.route(`**${loginHarnessPath}**`, (route) => route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html>
            <html lang="en">
            <head><title>Login Harness</title></head>
            <body>
                <div id="login-form" class="login-form">
                    <h2>Sign In</h2>
                    <form id="auth-form">
                        <input id="username" name="username">
                        <input id="password" name="password" type="password">
                        <button id="login-btn" type="submit">Sign In</button>
                    </form>
                    <div id="login-divider" style="display: none;"><span>or</span></div>
                    <button id="cwl-login-btn" type="button" style="display: none;">Sign in with CWL</button>
                    <div class="form-footer"><a href="#" id="show-register">Create one</a></div>
                </div>
                <div id="register-form" class="login-form" style="display: none;">
                    <form id="register-form-element">
                        <input id="reg-username" name="username">
                        <input id="reg-email" name="email">
                        <input id="reg-password" name="password" type="password">
                        <select id="reg-role" name="role">
                            <option value="">Select your role...</option>
                            <option value="instructor">Instructor</option>
                            <option value="student">Student</option>
                            <option value="ta">Teaching Assistant</option>
                        </select>
                        <input id="reg-display-name" name="displayName">
                        <button id="register-btn" type="submit">Create Account</button>
                    </form>
                    <div class="form-footer"><a href="#" id="show-login">Sign in</a></div>
                </div>
                <div id="message-container" style="display: none;"><div id="message"></div></div>
                <script src="/common/scripts/login.js"></script>
            </body>
            </html>`,
    }));
}

/**
 * @param {Page} page
 * @param {Record<string, Array<any>>} queues
 */
async function routeAuthQueues(page, queues) {
    await page.route('**/api/auth/**', async (route) => {
        const url = new URL(route.request().url());
        const key = `${route.request().method()} ${url.pathname}`;
        const queue = queues[key] || queues[url.pathname] || [];
        const next = queue.length ? queue.shift() : { success: false };

        if (next === 'abort') {
            await route.abort('failed');
            return;
        }

        await route.fulfill({
            contentType: 'application/json',
            body: JSON.stringify(next),
        });
    });
}

/**
 * @param {Page} page
 * @param {string} path
 */
async function gotoLoginHarness(page, path = loginHarnessPath) {
    await page.goto(path);
    await page.waitForLoadState('domcontentloaded');
}

/**
 * @param {Page} page
 * @param {string} selector
 */
async function dispatchSubmit(page, selector) {
    await page.locator(selector).evaluate((form) => {
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    });
}

test.describe('login.js focused browser coverage', () => {
    test('shows SAML auth errors, hides local login when disabled, and starts CWL login', async ({ page }) => {
        await installLoginHarness(page);
        await routeAuthQueues(page, {
            'GET /api/auth/methods': [
                { success: true, methods: { ubcshib: true, allowLocalLogin: false } },
                { success: true, methods: { ubcshib: true, allowLocalLogin: false } },
            ],
            'GET /api/auth/me': [{ success: false }],
        });

        await gotoLoginHarness(page, `${loginHarnessPath}?error=saml_failed`);

        await expect(page.locator('#message')).toHaveText('CWL authentication failed. Please try again or use your username and password.');
        await expect.poll(() => new URL(page.url()).search).toBe('');
        await expect(page.locator('#auth-form')).toBeHidden();
        await expect(page.locator('#login-form h2')).toBeHidden();
        await expect(page.locator('#login-divider')).toBeHidden();
        await expect(page.locator('#login-form .form-footer')).toBeHidden();
        await expect(page.locator('#cwl-login-btn')).toBeVisible();

        await page.locator('#auth-form').evaluate((node) => node.remove());
        await page.evaluate(() => /** @type {any} */ (window).checkAvailableAuthMethods());

        await page.locator('#cwl-login-btn').click();
        await page.waitForURL('**/Shibboleth.sso/Login');
    });

    test('toggles forms, validates required fields, and auto-hides success messages', async ({ page }) => {
        await page.clock.install();
        await installLoginHarness(page);
        await routeAuthQueues(page, {
            'GET /api/auth/methods': [{ success: true, methods: { ubcshib: false } }],
            'GET /api/auth/me': [{ success: false }],
        });

        await gotoLoginHarness(page);

        await page.locator('#show-register').click();
        await expect(page.locator('#login-form')).toBeHidden();
        await expect(page.locator('#register-form')).toBeVisible();

        await page.locator('#show-login').click();
        await expect(page.locator('#register-form')).toBeHidden();
        await expect(page.locator('#login-form')).toBeVisible();

        await dispatchSubmit(page, '#auth-form');
        await expect(page.locator('#message')).toHaveText('Please fill in all required fields');

        await page.locator('#show-register').click();
        await dispatchSubmit(page, '#register-form-element');
        await expect(page.locator('#message')).toHaveText('Please fill in all required fields');

        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            testWindow.showMessage('Saved', 'success');
        });
        await expect(page.locator('#message-container')).toBeVisible();
        await page.clock.fastForward(3000);
        await expect(page.locator('#message-container')).toBeHidden();
    });

    test('handles login failures, network errors, and successful redirect', async ({ page }) => {
        await page.clock.install();
        await installLoginHarness(page);
        await routeAuthQueues(page, {
            'GET /api/auth/methods': [{ success: true, methods: { ubcshib: true } }],
            'GET /api/auth/me': [{ success: false }],
            'POST /api/auth/login': [
                { success: false, error: 'Bad credentials' },
                { success: false },
                'abort',
                { success: true, redirect: '/student' },
            ],
        });

        await gotoLoginHarness(page);
        await expect(page.locator('#cwl-login-btn')).toBeVisible();
        await expect(page.locator('#login-divider')).toBeVisible();

        await page.locator('#username').fill('student');
        await page.locator('#password').fill('wrong');
        await dispatchSubmit(page, '#auth-form');
        await expect(page.locator('#message')).toHaveText('Bad credentials');
        await expect(page.locator('#login-btn')).toBeEnabled();

        await dispatchSubmit(page, '#auth-form');
        await expect(page.locator('#message')).toHaveText('Login failed');

        await dispatchSubmit(page, '#auth-form');
        await expect(page.locator('#message')).toHaveText('Login failed. Please try again.');

        await dispatchSubmit(page, '#auth-form');
        await expect(page.locator('#message')).toHaveText('Login successful! Redirecting...');
        await page.clock.fastForward(1000);
        await page.waitForURL('**/student');
    });

    test('handles registration failures, network errors, and successful form reset', async ({ page }) => {
        await page.clock.install();
        await installLoginHarness(page);
        await routeAuthQueues(page, {
            'GET /api/auth/methods': [{ success: true, methods: { allowLocalLogin: true } }],
            'GET /api/auth/me': [{ success: false }],
            'POST /api/auth/register': [
                { success: false, error: 'Username taken' },
                { success: false },
                'abort',
                { success: true },
            ],
        });

        await gotoLoginHarness(page);
        await page.locator('#show-register').click();
        await page.locator('#reg-username').fill('new-student');
        await page.locator('#reg-email').fill('new@example.test');
        await page.locator('#reg-password').fill('secret');
        await page.locator('#reg-role').selectOption('student');
        await page.locator('#reg-display-name').fill('New Student');

        await dispatchSubmit(page, '#register-form-element');
        await expect(page.locator('#message')).toHaveText('Username taken');
        await expect(page.locator('#register-btn')).toBeEnabled();

        await dispatchSubmit(page, '#register-form-element');
        await expect(page.locator('#message')).toHaveText('Registration failed');

        await dispatchSubmit(page, '#register-form-element');
        await expect(page.locator('#message')).toHaveText('Registration failed. Please try again.');

        await dispatchSubmit(page, '#register-form-element');
        await expect(page.locator('#message')).toHaveText('Account created successfully! Please sign in.');
        await page.clock.fastForward(2000);
        await expect(page.locator('#register-form')).toBeHidden();
        await expect(page.locator('#login-form')).toBeVisible();
        await expect(page.locator('#message-container')).toBeHidden();
    });

    for (const { role, expectedPath } of [
        { role: 'instructor', expectedPath: '/instructor/home' },
        { role: 'ta', expectedPath: '/ta' },
        { role: 'student', expectedPath: '/student' },
    ]) {
        test(`redirects an already-authenticated ${role}`, async ({ page }) => {
            await installLoginHarness(page);
            await routeAuthQueues(page, {
                'GET /api/auth/methods': [{ success: false }],
                'GET /api/auth/me': [{ success: true, user: { role } }],
            });

            await gotoLoginHarness(page);
            await page.waitForURL(`**${expectedPath}`);
        });
    }

    test('fails closed on the login page when auth method lookup fails', async ({ page }) => {
        await installLoginHarness(page);
        await routeAuthQueues(page, {
            'GET /api/auth/methods': ['abort'],
            'GET /api/auth/me': ['abort'],
        });

        await gotoLoginHarness(page, `${loginHarnessPath}?error=unknown`);

        await expect(page.locator('#message')).toHaveText('Sign-in is temporarily unavailable. Please try again later.');
        await expect(page.locator('#auth-form')).toBeHidden();
        await expect(page.locator('#cwl-login-btn')).toBeHidden();
        await expect.poll(() => new URL(page.url()).pathname).toBe(loginHarnessPath);
    });

    test('does not require the optional CWL button to wire local forms', async ({ page }) => {
        await page.route(`**${loginHarnessPath}**`, (route) => route.fulfill({
            contentType: 'text/html',
            body: `<!doctype html>
                <form id="auth-form"><input name="username"><input name="password"><button id="login-btn">Sign In</button></form>
                <div id="login-form"><a href="#" id="show-register">Create one</a></div>
                <div id="register-form" style="display:none"><form id="register-form-element"></form><a href="#" id="show-login">Sign in</a></div>
                <div id="message-container" style="display:none"><div id="message"></div></div>
                <script src="/common/scripts/login.js"></script>`,
        }));
        await routeAuthQueues(page, {
            'GET /api/auth/methods': [{ success: true, methods: { ubcshib: true, allowLocalLogin: false } }],
            'GET /api/auth/me': [{ success: false }],
        });

        await gotoLoginHarness(page);
        await dispatchSubmit(page, '#auth-form');
        await expect(page.locator('#message')).toHaveText('Please fill in all required fields');
    });
});

/**
 * @param {Page} page
 * @param {{ existingModal?: boolean, includeLogoutButton?: boolean }} [options]
 */
async function installIdleHarness(page, options = {}) {
    await installDashboardRoutes(page);
    const { existingModal = false, includeLogoutButton = false } = options;
    await page.route(`**${idleHarnessPath}**`, (route) => route.fulfill({
        contentType: 'text/html',
        body: `<!doctype html>
            <html lang="en">
            <head><title>Idle Harness</title></head>
            <body>
                ${includeLogoutButton ? '<button id="logout-btn" onclick="window.logoutClicks=(window.logoutClicks||0)+1">Logout</button>' : ''}
                ${existingModal ? `
                    <div id="idle-timeout-modal" style="display: none;">
                        <span id="idle-countdown-display">--:--</span>
                        <button id="idle-signout-btn">Sign Out</button>
                        <button id="idle-stay-btn">Stay</button>
                    </div>` : ''}
                <script src="/common/scripts/idle-timer.js"></script>
            </body>
            </html>`,
    }));
}

/**
 * @param {Page} page
 * @param {any} result
 */
async function setCourseFetchResult(page, result) {
    await page.evaluate((fetchResult) => {
        const testWindow = /** @type {any} */ (window);
        localStorage.setItem('selectedCourseId', 'COURSE-1');
        testWindow.authenticatedFetch = async () => ({
            json: async () => fetchResult,
        });
    }, result);
}

test.describe('idle-timer.js focused browser coverage', () => {
    test('injects the modal and exits when no course is selected', async ({ page }) => {
        await installIdleHarness(page);
        await page.goto(idleHarnessPath);

        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            localStorage.removeItem('selectedCourseId');
            return testWindow.initializeIdleTimer();
        });

        await expect(page.locator('#idle-timeout-modal')).toBeAttached();
        await expect(page.locator('#idle-timeout-modal')).toBeHidden();
    });

    test('exits when authenticatedFetch is unavailable or course data is invalid', async ({ page }) => {
        await installIdleHarness(page);
        await page.goto(idleHarnessPath);

        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            localStorage.setItem('selectedCourseId', 'COURSE-1');
            delete testWindow.authenticatedFetch;
            return testWindow.initializeIdleTimer();
        });

        await setCourseFetchResult(page, { success: false });
        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());

        await setCourseFetchResult(page, { success: true, data: null });
        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());

        await expect(page.locator('#idle-timeout-modal')).toBeAttached();
        await expect(page.locator('#idle-timeout-modal')).toBeHidden();
    });

    test('logs initialization errors without changing the page', async ({ page }) => {
        await installIdleHarness(page);
        await page.goto(idleHarnessPath);

        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            localStorage.setItem('selectedCourseId', 'COURSE-1');
            testWindow.authenticatedFetch = async () => {
                throw new Error('course endpoint failed');
            };
            return testWindow.initializeIdleTimer();
        });

        await expect(page.locator('#idle-timeout-modal')).toBeAttached();
        await expect(page.locator('#idle-timeout-modal')).toBeHidden();
    });

    test('uses the default timeout when course settings omit studentIdleTimeout', async ({ page }) => {
        await page.clock.install();
        await installIdleHarness(page, { existingModal: true });
        await page.goto(idleHarnessPath);
        await setCourseFetchResult(page, { success: true, data: {} });

        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());
        await page.clock.fastForward(1000);

        await expect(page.locator('#idle-timeout-modal')).toBeHidden();
    });

    test('shows countdown, ignores background activity while open, and handles stay and signout buttons', async ({ page }) => {
        await page.clock.install();
        await installIdleHarness(page, { existingModal: true, includeLogoutButton: true });
        await page.goto(idleHarnessPath);
        await setCourseFetchResult(page, { success: true, data: { studentIdleTimeout: 4 } });

        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());
        await page.clock.fastForward(2000);

        await expect(page.locator('#idle-timeout-modal')).toBeVisible();
        await expect(page.locator('#idle-countdown-display')).toHaveText('0:02');

        await page.mouse.move(10, 10);
        await page.clock.fastForward(500);
        await expect(page.locator('#idle-timeout-modal')).toBeVisible();
        await page.clock.fastForward(500);
        await expect(page.locator('#idle-countdown-display')).toHaveText('0:01');

        await page.locator('#idle-stay-btn').click();
        await expect(page.locator('#idle-timeout-modal')).toBeHidden();

        await page.clock.fastForward(2000);
        await expect(page.locator('#idle-timeout-modal')).toBeVisible();
        await page.locator('#idle-signout-btn').click();

        await expect.poll(() => page.evaluate(() => /** @type {any} */ (window).logoutClicks || 0)).toBe(1);
    });

    test('auto-logout falls back to /logout when no logout button exists', async ({ page }) => {
        await page.clock.install();
        await installIdleHarness(page);
        await page.goto(idleHarnessPath);
        await setCourseFetchResult(page, { success: true, data: { studentIdleTimeout: 2 } });

        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());
        await page.clock.fastForward(1000);
        await expect(page.locator('#idle-timeout-modal')).toBeVisible();

        await page.locator('#idle-countdown-display').evaluate((node) => node.remove());
        await page.clock.fastForward(1000);

        await page.waitForURL('**/logout');
    });

    test('activity before the warning resets the idle timer', async ({ page }) => {
        await page.clock.install();
        await installIdleHarness(page, { existingModal: true });
        await page.goto(idleHarnessPath);
        await setCourseFetchResult(page, { success: true, data: { studentIdleTimeout: 2 } });

        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());
        await page.clock.fastForward(500);
        await page.mouse.down();
        await page.clock.fastForward(600);
        await expect(page.locator('#idle-timeout-modal')).toBeHidden();

        await page.clock.fastForward(400);
        await expect(page.locator('#idle-timeout-modal')).toBeVisible();
    });

    test('timer callbacks tolerate the modal being removed before warning time', async ({ page }) => {
        await page.clock.install();
        await installIdleHarness(page);
        await page.goto(idleHarnessPath);
        await setCourseFetchResult(page, { success: true, data: { studentIdleTimeout: 2 } });

        await page.evaluate(() => /** @type {any} */ (window).initializeIdleTimer());
        await page.locator('#idle-timeout-modal').evaluate((node) => node.remove());
        await page.clock.fastForward(2000);

        await expect(page.locator('#idle-timeout-modal')).toHaveCount(0);
    });
});
