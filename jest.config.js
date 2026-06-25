// Jest configuration — unit tests for the Node/CommonJS backend (src/).
//
// Scope is deliberately limited to tests/unit/** so this runner NEVER overlaps
// the Playwright e2e suite, which lives in tests/e2e/** (see playwright.config.js
// `testDir`). The two test systems are fully independent:
//   - `npm run test:unit`  -> jest   (fast, no server/DB, this config)
//   - `npm run test:e2e`   -> playwright (browser-driven, tests/e2e)
//
// CommonJS + Node 20/24 means no Babel/transform is required.

/** @type {import('jest').Config} */
module.exports = {
    testEnvironment: 'node',
    // Only files under tests/unit are unit tests. Playwright owns tests/e2e.
    testMatch: ['<rootDir>/tests/unit/**/*.test.js'],
    // Coverage reflects the backend logic these unit tests exercise.
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/server.js',
    ],
    coverageDirectory: 'coverage-reports/unit',
    coverageReporters: ['text-summary', 'lcovonly'],
    // Reset mock state between tests so suites stay isolated.
    clearMocks: true,
};
