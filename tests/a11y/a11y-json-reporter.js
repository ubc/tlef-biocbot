// @ts-check
/// <reference types="node" />
const fs = require('fs');
const path = require('path');

const REPORT_PATH = path.resolve(process.cwd(), 'a11y-results/a11y-results.json');

/** @param {object} report */
function writeReport(report) {
    fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });
    const temporaryPath = `${REPORT_PATH}.tmp`;
    fs.writeFileSync(temporaryPath, `${JSON.stringify(report, null, 2)}\n`);
    fs.renameSync(temporaryPath, REPORT_PATH);
}

/** @param {import('@playwright/test/reporter').TestResult} result */
function readScans(result) {
    return result.attachments
        .filter((attachment) => attachment.name === 'a11y-scan')
        .map((attachment) => {
            const body = attachment.body || (attachment.path ? fs.readFileSync(attachment.path) : null);
            if (!body) {
                return { status: 'failed', error: 'Accessibility scan attachment had no body.', violations: [] };
            }
            try {
                return JSON.parse(body.toString());
            } catch (error) {
                return {
                    status: 'failed',
                    error: `Could not parse accessibility scan attachment: ${error instanceof Error ? error.message : String(error)}`,
                    violations: [],
                };
            }
        });
}

class AccessibilityJsonReporter {
    constructor() {
        /** @type {Map<string, { test: import('@playwright/test/reporter').TestCase, results: import('@playwright/test/reporter').TestResult[] }>} */
        this.tests = new Map();
    }

    /**
     * Write a non-green running marker before tests start. If Playwright is killed
     * or interrupted before onEnd, the artifact cannot be mistaken for a pass.
     *
     * @param {import('@playwright/test/reporter').FullConfig} _config
     * @param {import('@playwright/test/reporter').Suite} suite
     */
    onBegin(_config, suite) {
        for (const test of suite.allTests()) {
            this.tests.set(test.id, { test, results: [] });
        }
        writeReport({
            schemaVersion: 1,
            generatedAt: new Date().toISOString(),
            runStatus: 'running',
            ok: false,
            discoveredTests: this.tests.size,
            summary: null,
            tests: [],
            scans: [],
            violations: [],
        });
    }

    /**
     * @param {import('@playwright/test/reporter').TestCase} test
     * @param {import('@playwright/test/reporter').TestResult} result
     */
    onTestEnd(test, result) {
        const entry = this.tests.get(test.id) || { test, results: [] };
        entry.results.push(result);
        this.tests.set(test.id, entry);
    }

    /** @param {import('@playwright/test/reporter').FullResult} result */
    onEnd(result) {
        /** @type {any[]} */
        const tests = [];
        const scans = [];
        for (const { test, results } of this.tests.values()) {
            const finalResult = results[results.length - 1];
            const priorFailure = results.slice(0, -1).some((attempt) => attempt.status !== 'passed');
            let outcome = 'failed';
            if (!finalResult) outcome = 'interrupted';
            else if (finalResult.status === 'skipped') outcome = 'skipped';
            else if (finalResult.status === 'passed') outcome = priorFailure ? 'flaky' : 'passed';

            const testScans = finalResult ? readScans(finalResult) : [];
            scans.push(...testScans.map((scan) => ({ testId: test.id, title: test.title, ...scan })));
            tests.push({
                id: test.id,
                title: test.title,
                titlePath: test.titlePath(),
                file: test.location.file,
                line: test.location.line,
                outcome,
                attempts: results.map((attempt) => ({
                    retry: attempt.retry,
                    status: attempt.status,
                    durationMs: attempt.duration,
                    error: attempt.error ? attempt.error.message : null,
                })),
                scanCount: testScans.length,
            });
        }

        const violations = scans.flatMap((scan) => Array.isArray(scan.violations) ? scan.violations : []);
        const scanErrors = scans.filter((scan) => scan.status !== 'completed');
        const count = (/** @type {string} */ outcome) => tests.filter((test) => test.outcome === outcome).length;
        /** @type {Record<string, number>} */
        const impacts = { critical: 0, serious: 0, moderate: 0, minor: 0, unknown: 0 };
        for (const violation of violations) {
            const impact = Object.prototype.hasOwnProperty.call(impacts, violation.impact)
                ? violation.impact
                : 'unknown';
            impacts[impact] += 1;
        }

        const summary = {
            passed: count('passed'),
            failed: count('failed') + count('interrupted'),
            flaky: count('flaky'),
            skipped: count('skipped'),
            scansCompleted: scans.length - scanErrors.length,
            scansFailed: scanErrors.length,
            violationTargets: violations.length,
            violationsByImpact: impacts,
        };
        writeReport({
            schemaVersion: 1,
            generatedAt: new Date().toISOString(),
            runStatus: result.status,
            ok: result.status === 'passed' && summary.failed === 0 && summary.flaky === 0 && scanErrors.length === 0,
            discoveredTests: this.tests.size,
            summary,
            tests,
            scans,
            violations,
        });
    }
}

module.exports = AccessibilityJsonReporter;
