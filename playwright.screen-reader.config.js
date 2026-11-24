// @ts-check
/// <reference types="node" />
// Screen reader checks: Playwright opens the browser, Guidepup starts a real
// screen reader and records what it says, and the tests assert on that speech.
// They take over the Mac (keyboard, focus and sound) while they run, so they
// are kept out of the e2e and a11y suites. See tests/screen-reader/README.md.
//
// Port 8052 by default: the long-running dev server on 8050 is nodemon, and the
// speech logs these tests write inside the repo would restart it mid-run.
// AGENT_CHAT_MODES is blanked to match CI, where the agents framework is absent.
process.env.TLEF_BIOCBOT_PORT = process.env.TLEF_BIOCBOT_PORT || '8052';
if (process.env.AGENT_CHAT_MODES === undefined) process.env.AGENT_CHAT_MODES = '';

const { devices } = require('@playwright/test');
const { withGuidepup } = require('@guidepup/playwright');
const base = require('./playwright.config');

const viewport = { width: 1280, height: 900 };

/** @type {import('@playwright/test').PlaywrightTestConfig} */
module.exports = withGuidepup({
    ...base,
    testDir: './tests/screen-reader',
    testMatch: '**/*.sr.spec.js',
    // Starting VoiceOver and finding the web content takes tens of seconds.
    timeout: 5 * 60 * 1000,
    retries: 0,
    reporter: [
        ['list'],
        ['html', { open: 'never', outputFolder: 'playwright-report-screen-reader' }],
        // Full errors, including the causes Guidepup wraps under "VoiceOver
        // cannot be started", in a file that can be read without the HTML report.
        ['json', { outputFile: 'a11y-results/screen-reader/results.json' }],
    ],
    use: { ...base.use, trace: 'off', video: 'off' },
    projects: [
        // VoiceOver users mostly use Safari. Playwright cannot drive Safari
        // itself; its WebKit build is the same engine, and the pairing
        // Guidepup's own VoiceOver examples use.
        { name: 'voiceover-webkit', use: { ...devices['Desktop Safari'], viewport } },
        // Fallback only: VoiceOver with Chrome is the least used pairing.
        { name: 'voiceover-chromium', use: { ...devices['Desktop Chrome'], viewport } },
    ],
});
