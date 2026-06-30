const baseConfig = require('./jest.config');

/** @type {import('jest').Config} */
module.exports = {
    ...baseConfig,
    // Keep the regular Jest/Istanbul report untouched. This dedicated command
    // collects native V8 data for Monocart's interactive visualization.
    collectCoverage: true,
    coverageProvider: 'v8',
    coverageReporters: ['none'],
    reporters: [
        'default',
        ['jest-monocart-coverage', {
            name: 'BiocBot Unit Test Coverage',
            outputDir: './coverage-reports/unit-monocart',
            reports: [
                ['v8'],
                ['console-summary'],
                ['lcovonly'],
                ['json-summary'],
                ['markdown-summary']
            ]
        }]
    ]
};
