# Bug-fix Mode — Handoff Instructions

This file describes how to continue bug-fix work on this codebase across
sessions. When picking this up in a fresh session, the user will say
something like "read tests/e2e/AGENTS_HANDOFF.md and follow it."

## Source of truth

- **`tests/e2e/FINDINGS.md`** — catalog of individual bugs surfaced by the
  e2e suite. Some are marked ✅ fixed; the rest are open. Each entry names
  the failing test that exposed it.
- **`tests/e2e/Redundancies.md`** — companion tracker grouping bugs by
  "same mistake in N places, real fix is one shared thing." Status emoji:
  🟥 open · 🟡 partial · ✅ fixed · ⏸ deferred. Update as fixes land.

## Working rules

### 1. Bug fixes only — no refactors of working code

If something looks ugly but the tests pass and there's no bug behind it,
leave it alone. Don't rename, don't extract helpers, don't tidy. Touch
only what's needed to make a specific failing test pass or to close a
specific FINDINGS entry.

### 2. Verify the failure is real before fixing anything

Full-suite failure lists contain false positives. Cross-spec state
pollution can fail tests that have no actual product bug behind them
(documented example: `routes-courses-api-error-branches.spec.js:465,479`
maxTopics clamping — fails in the 1500-test suite, passes alone and in
its own spec file. The product code at `src/routes/courses.js:1115` is
already correct.)

**Before fixing, always:**

1. Read the production code at the location the test asserts about.
   Confirm the bug is actually there.
2. Run the failing test alone:
   `npx playwright test tests/e2e/<spec>.spec.js -g "<test substring>" --reporter=line`
3. If alone-mode passes, run the **entire spec file** alone:
   `npx playwright test tests/e2e/<spec>.spec.js --reporter=line`
4. **Only treat a test as a real product failure if it also fails in
   isolation.** If it passes alone but fails in the suite, it's a
   test-isolation bug, not a product bug — note it and move on.

### 3. Don't blindly trust the tests

They were largely AI-generated. Before "fixing" code to match a failing
assertion:

- Read the test and confirm the assertion describes correct product
  behavior, not what the test author guessed.
- Cross-check against FINDINGS.md — most failing tests have a written
  explanation there. If FINDINGS describes the bug and the test asserts
  the opposite of the bug, the test is trustworthy.
- Watch for tests that "document the bug" — those exist too. They assert
  the broken behavior is present, not that it's been fixed. Don't satisfy
  those by hardening the bug; flag them and fix the underlying code,
  accepting that those tests will then fail.
- If the test seems wrong (asserts behavior that contradicts how a real
  user would expect the system to work, or contradicts adjacent passing
  tests), flag it before editing product code. Sometimes the right fix
  is to correct the test, not the code.

### 4. One small fix at a time

Smallest blast radius. After each fix:

- Confirm the named test goes from red to green.
- Re-run the **targeted subset** of related specs (not the full suite).
- Full-suite sweep only at the end of a batch of fixes.

### 5. Update `Redundancies.md` when a fix advances an R-numbered entry

Flip status emoji, add a one-line "Progress" note. The file is a living
document — keep it honest.

### 6. Don't trust prior summaries — verify from the code

Memory from earlier sessions may be stale; re-grep, re-read, then act.
The current state of the files is authoritative; prior chat is not.

## What's been done so far (verify from code, don't trust this list)

11 fixes landed across FINDINGS #6, #11a, #21, #28, #29, #30, #31, #32,
#33, #35, #38. The handoff doesn't enumerate them in detail because they
may have evolved since this file was written — read the current state of
the source files and `Redundancies.md` to know what's real now.

## Today's target

[ Fill this in when starting the session. A concrete starting target
keeps the agent focused; vague "keep going" prompts cause it to wander
into refactor territory. ]
