// @ts-check
const { defineConfig, devices } = require('@playwright/test');

const PORT = process.env.TLEF_BIOCBOT_PORT || 8050;
const BASE_URL = `http://localhost:${PORT}`;
const NODE_V8_COVERAGE_DIR = 'coverage-reports/.v8-server';
const COVERAGE_RUN_ID = process.env.BIOCBOT_COVERAGE_RUN_ID || String(Date.now());
process.env.BIOCBOT_COVERAGE_RUN_ID = COVERAGE_RUN_ID;

function isAppCoveragePath(value) {
    const normalized = String(value || '').replace(/\\/g, '/');
    return (
        /\.(js|css)($|\?)/.test(normalized) &&
        /\/(src|public)\//.test(normalized) &&
        !normalized.includes('/node_modules/')
    );
}

module.exports = defineConfig({
    testDir: './tests/e2e',
    globalSetup: require.resolve('./tests/e2e/global-setup'),
    globalTeardown: require.resolve('./tests/e2e/global-teardown'),
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    workers: 1,
    reporter: [
        ['html', { open: 'never' }],
        ['list'],
        ['monocart-reporter', {
            name: 'BiocBot Playwright E2E Report',
            outputFile: './monocart-report/index.html',
            json: true,
            coverage: {
                name: 'BiocBot E2E Coverage',
                outputDir: './coverage-reports/e2e',
                reports: ['v8', 'v8-json', 'json-summary', 'lcovonly', 'console-summary'],
                inline: true,
                lcov: true,
                entryFilter: (entry) => {
                    const url = entry && entry.url;
                    if (!url) return false;
                    if (url.startsWith(BASE_URL)) return /\.(js|css)($|\?)/.test(url);
                    if (url.startsWith('file:')) return isAppCoveragePath(url);
                    return false;
                },
                sourceFilter: isAppCoveragePath,
                all: {
                    dir: ['./src', './public'],
                    filter: {
                        '**/node_modules/**': false,
                        '**/tests/**': false,
                        '**/*.js': true,
                        '**/*.css': true,
                        '**/*': false,
                    },
                },
            },
        }],
    ],

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
        command: `cross-env NODE_ENV=development BIOCBOT_TEST_LLM_STUB=1 NODE_V8_COVERAGE=${NODE_V8_COVERAGE_DIR} BIOCBOT_COVERAGE_RUN_ID=${COVERAGE_RUN_ID} node --require ./tests/e2e/helpers/v8-coverage-hook.js src/server.js`,
        url: BASE_URL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
        stdout: 'pipe',
        stderr: 'pipe',
    },
});
