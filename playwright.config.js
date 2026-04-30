// @ts-check
const { defineConfig, devices } = require('@playwright/test');

const PORT = process.env.TLEF_BIOCBOT_PORT || 8085;
const BASE_URL = `http://localhost:${PORT}`;

module.exports = defineConfig({
    testDir: './tests/e2e',
    globalSetup: require.resolve('./tests/e2e/global-setup'),
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: 1,
    reporter: [['html', { open: 'never' }], ['list']],

    use: {
        baseURL: BASE_URL,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
    },

    projects: [
        {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
        },
    ],

    webServer: {
        command: 'cross-env NODE_ENV=development node src/server.js',
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
        stdout: 'pipe',
        stderr: 'pipe',
    },
});
