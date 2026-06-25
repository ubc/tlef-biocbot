// Smoke test: proves the Jest unit runner is wired up and runs independently of
// the Playwright e2e suite. Real module tests live alongside this file under
// tests/unit/<area>/*.test.js (e.g. tests/unit/services, tests/unit/models).

describe('jest wiring', () => {
    test('runs unit tests outside Playwright', () => {
        expect(1 + 1).toBe(2);
    });
});
