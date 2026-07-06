# removal.md

Codebase cleanup and maintainability review. Analysis only — no source, tests, or
config were modified in producing this report.

Scope inspected: `src/` (routes, models, services, middleware, config), `public/`
(all four frontends), `scripts/`, `tests/` (unit + e2e + a11y), package scripts,
jest/playwright configs, GitHub workflows, and the kept documentation files.

Method: every JS module in `src/`, `public/`, and `tests/e2e/helpers/` was
reference-counted across the repo (grep by filename); every `public/` JS/CSS asset
was checked against every HTML page; every route file was checked against the
mounts in `src/server.js`; every npm dependency was grepped for actual usage.

> Note: a large deletion pass was already staged in this working tree (old
> scaffolding docs in `documents/` and `documents-2/`, shipped-feature specs,
> `diagnose.js`, `scripts/verify_tracker.js`, `scripts/migrate-question-schema.js`,
> `tests/unit/sample.test.js`, and stale e2e handoff docs). This report covers what
> remains **after** that pass.

---

## 1. Executive Summary

The repo is **mostly clean**. The application code is tightly wired: all 27 route
files are mounted in `src/server.js`, every frontend script and stylesheet is
referenced by at least one HTML page, every npm dependency (including the four
`ubc-genai-toolkit-*` packages and the odd-looking `delegates` devDependency) is
genuinely used, and every e2e helper/harness is required by at least one spec.
The unit-test layer (76 suites, ~1,370 tests, ~85% statement coverage per
`unit_tests.md`) maps 1:1 onto `src/` modules.

The remaining cleanup opportunity is small and specific: **one fully dead service
(`mongoService.js`), one broken route serving a file that no longer exists
(`/qdrant-test`), three dead imports, and a handful of stale documentation
references** left behind by this session's deletions. The larger opportunity is
not removal but refactoring — a few very large files (3,000+ lines) and the
inconsistency patterns already cataloged in `tests/e2e/Redundancies.md`.

---

## 2. Likely Unreachable or Unused Code

### 2.1 `MongoService` class — superseded, never used by the app

- **Confidence:** High
- **File path:** `src/services/mongoService.js`
- **Precise location:** entire file (class `MongoService`, ~its own connection
  pool via `MongoClient`, collection bootstrap for `documents`, `courses`,
  `onboarding`, `questions`, `flaggedQuestions`)
- **Why it appears unused:** The app establishes a single shared Mongo connection
  in `src/server.js` (line 8, `MongoClient`) and distributes it via
  `app.locals.db`; models and routes consume `req.app.locals.db` or a passed-in
  `db` handle (e.g. `src/routes/courses.js:320`). `MongoService` implements a
  parallel, older connection-management approach that nothing in the runtime path
  ever instantiates.
- **Evidence checked:**
  - imports/references: `grep -rn "mongoService" src scripts tests` — the **only**
    reference in the entire repo is `tests/unit/services/mongoService.test.js:10`.
  - route usage: not required by `src/server.js` or any route/service.
  - tests: covered by its own unit test (i.e., the test protects dead code).
  - package scripts: none reference it.
  - documentation: not mentioned in README or kept docs.
- **Risk of removal:** Low (nothing at runtime can reach it). The only knock-on
  effect is that `tests/unit/services/mongoService.test.js` must be deleted with
  it, and unit-coverage numbers will shift slightly (it currently inflates
  covered-line counts for code that never runs).
- **Recommended next step:** Confirm with maintainer, then remove file + its test
  together in one commit.

### 2.2 `/qdrant-test` route — serves a file that does not exist

- **Confidence:** High
- **File path:** `src/server.js`
- **Precise location:** lines 323–324:
  `app.get('/qdrant-test', …)` → `res.sendFile(path.join(__dirname, '../public/qdrant-test.html'))`
- **Why it appears unreachable/broken:** `public/qdrant-test.html` is **not in the
  repo** (`ls public/qdrant-test.html` → no such file; not in `git ls-files`).
  Any authenticated request to `/qdrant-test` will hit an `ENOENT` in `sendFile`.
- **Evidence checked:**
  - imports/references: no HTML page links to `/qdrant-test`; no test requests it.
  - route usage: mounted, but the target asset is missing.
  - tests: no e2e or unit spec touches this path.
  - documentation: README **still advertises it** — line 139 ("Visit
    `/qdrant-test` to test the Qdrant functionality interactively.") and line 159
    (project-structure entry `qdrant-test.html`). Both are stale.
- **Risk of removal:** Low. The `/api/qdrant` API routes (`src/routes/qdrant.js`)
  are separate, fully mounted, and fully tested — only the HTML test-page route is
  dead.
- **Recommended next step:** Remove the route (server.js:323–324) and the two
  README references (lines 139 and 159) together.

### 2.3 Dead `MongoClient` imports in three models

- **Confidence:** High
- **File paths / locations:**
  - `src/models/Course.js:6`
  - `src/models/User.js:7`
  - `src/models/FlaggedQuestion.js:8`
- **Why unused:** Each file does `const { MongoClient } = require('mongodb');`
  but never uses the symbol — `grep -rn "MongoClient" src/models/ | grep -v require`
  returns nothing. These models operate on a `db` handle passed in from the shared
  connection, consistent with the rest of `src/models/`.
- **Evidence checked:** full-repo grep for `MongoClient` usage in models; only the
  three require lines exist.
- **Risk of removal:** Low (deleting an unused import is behavior-neutral).
- **Recommended next step:** Remove the three import lines (trivial, safe).

### 2.4 `apiResponse` middleware — only partially wired up

- **Confidence:** Medium (it *is* used — the issue is partial adoption, not death)
- **File path:** `src/middleware/apiResponse.js`
- **Precise location:** whole module; consumed only by `src/routes/auth.js` and
  `src/routes/settings.js` (`grep -rln "apiResponse" src` → 2 route files out of
  ~25).
- **Why it looks incomplete:** It appears to be the intended standard response
  envelope, but ~23 route files build responses ad hoc. This is the same problem
  tracked as **R12 ("Error-response shape: `error` vs `message`") 🟥 open** in
  `tests/e2e/Redundancies.md:289`.
- **Evidence checked:** imports across `src/`; Redundancies.md R12/R12b.
- **Risk of removal:** High — do **not** remove; it's the keeper, the ad-hoc code
  is the debt.
- **Recommended next step:** Leave as-is for removal purposes; treat as the target
  of refactor 6.2 below.

---

## 3. Possibly Obsolete Files or Scripts

### 3.1 Stale references to the just-deleted migration script

Not files to delete, but dangling pointers created by this cleanup pass:

| Location | Reference | Recommended action |
|---|---|---|
| `tests/e2e/FINDINGS.md:46–48` | Describes `scripts/migrate-question-schema.js` and the two `npm run migrate:question-schema*` commands as "SCRIPT READY" | Update the Phase 3a entry to note the script was removed (recoverable via `git show fe0923c:scripts/migrate-question-schema.js`) |
| `unit_tests.md:544` | Cites the same script | Same annotation |
| `tests/e2e/instructor-onboarding.spec.js:1069` | Code comment: "(see scripts/migrate-question-schema.js)" | Harmless; optionally reword the comment next time the spec is touched (rule: no test changes now) |
| `unit_tests.md:6` | Points to `testing-overhaul-plan.md` "in project memory" — that file is not in the repo | Fine if intentional (it lives in the maintainer's Claude memory dir); confirm |

### 3.2 `.DS_Store` tracked in git

- **File path:** `.DS_Store` (repo root, tracked per `git ls-files`)
- **Current apparent purpose:** none — macOS Finder metadata.
- **Why obsolete:** should never be versioned; churns on every Finder visit.
- **References:** none.
- **Recommended action:** `git rm --cached .DS_Store` and add `.DS_Store` to
  `.gitignore`.

### 3.3 Local, gitignored report directories (not repo clutter, just disk)

`coverage-reports/`, `monocart-report/`, `playwright-report/`,
`playwright-report-a11y/`, `test-results/`, `playwright/.auth` — all already in
`.gitignore`, all regenerable. Safe to `rm -rf` locally at any time; nothing to do
in the repo itself.

### 3.4 Scripts directory — nothing obsolete remains

`scripts/` now contains only `grant-system-admin.js`, which is wired to the
`grant:system-admin` package script and explicitly designated keep-by-maintainer.

---

## 4. Test Coverage Clues

**Well covered (behavior actively expected to work):**
- Every file in `src/routes/`, `src/services/`, `src/models/`, `src/middleware/`,
  and `src/config/` has at least one matching unit suite under `tests/unit/`
  (verified by directory listing; e.g. `settings.js` has six suites, `chat.js`
  five). `unit_tests.md` reports ~85% statements / ~77% branches overall, with
  `src/routes/settings.js` and `src/routes/chat.js` near-complete.
- The frontend (`public/**`) is exercised through the large Playwright e2e suite
  (~120 spec files) plus a dedicated a11y suite; jest deliberately excludes it.
- `src/server.js` is excluded from jest coverage by config
  (`jest.config.js:22–26`, `'!src/server.js'`) — intentional, since e2e boots the
  real server.

**Tests protecting disconnected code:**
- `tests/unit/services/mongoService.test.js` — the only consumer of
  `src/services/mongoService.js` (see §2.1). This is the textbook case of "has
  tests but is disconnected from the current app." Coverage percentages modestly
  overstate live-code coverage because of it.

**Tests that may encode old behavior:**
- `tests/e2e/instructor-onboarding.spec.js:1069` asserts the *new* boolean
  true/false answer format while citing the now-deleted migration script — the
  assertion itself is current; only the comment is stale.
- `tests/e2e/FINDINGS.md` documents intentionally-failing specs (its stated
  policy: leave a failing test in place until the product bug is fixed). Any
  currently-failing e2e specs should be interpreted through that file before being
  "fixed" or deleted.

**No apparent gaps worth flagging:** nothing in `src/` is both untested *and*
unreferenced, other than the items already listed in §2.

---

## 5. Import and Reference Analysis

Summary of the systematic pass (commands run from repo root):

- **Route mounting:** all 27 files in `src/routes/` are required and mounted in
  `src/server.js` (lines 13–37 requires; lines 563–593 + 617 mounts).
  `src/routes/testLlmStub.js` is mounted **conditionally** behind a test-env guard
  (server.js:592) — intentional test infrastructure, not dead code.
- **Frontend assets:** a scripted check of every file in
  `public/{common,instructor,student,ta}/scripts/*.js` and all three `styles/`
  trees against every `*.html` found **zero unreferenced JS or CSS files**.
- **npm dependencies:** each runtime dependency grepped individually — all used
  (`bad-words` → quiz/chat profanity filter; `js-tiktoken` → documents route;
  `node-fetch` → `llmKeyStore`; `passport-saml`/`passport-ubcshib` → passport
  config; the four `ubc-genai-toolkit-*` packages → llm/qdrant/documents;
  `delegates` (devDependency) → required by three unit suites as a module-shape
  shim). **No removable dependencies found.**
- **e2e helpers:** every file in `tests/e2e/helpers/` (including all eleven
  `*-harness.js` files) is required by at least one spec.
- **Stubs:** `src/services/llmStub.js`, `src/services/embeddingsStub.js`, and
  `src/routes/testLlmStub.js` are referenced 3–4× each by the config/service layer
  and their tests; they are the test-mode seams for the LLM/embeddings stack.
  Not dead.
- **Suspicious-but-fine:** `public/student/scripts/student-chat-survey.js` showed
  only one inbound reference — but it is a `<script>` include in
  `public/student/index.html`, which is exactly the wiring a page script needs.

The only modules that failed the reference check outright are the three items in
§2.1–2.3.

---

## 6. Larger Refactor Opportunities

### 6.1 Monolithic route and page files

- **Area:** backend routes + instructor/student frontend controllers
- **Files involved:** `src/routes/courses.js` (3,760 lines),
  `public/instructor/scripts/home.js` (3,040), `public/instructor/scripts/settings.js`
  (2,290), `src/routes/chat.js` (1,964), `public/instructor/scripts/flagged.js`
  (1,919), `src/routes/settings.js` (1,792), plus five more files over 1,300 lines.
- **Problem:** single files carry many unrelated endpoints/behaviors; hard to
  review, easy to duplicate logic within (Redundancies.md R3/R4 document duplicate
  function declarations inside `instructor.js` and `onboarding.js` — later
  declaration silently wins).
- **Why refactoring helps:** smaller modules make the existing per-file unit
  suites sharper and stop the duplicate-declaration class of bug.
- **Suggested direction:** split `courses.js` by resource concern (roster/join,
  publish, units, super-course) mirroring how the instructor frontend was already
  decomposed into `instructor-*.js` modules.
- **Risk / complexity:** Medium (high test coverage is a safety net).
- **Before or after removal cleanup?** After — removals are tiny and independent.

### 6.2 Response-envelope standardization (finish wiring `apiResponse`)

- **Area:** all API routes
- **Files involved:** `src/middleware/apiResponse.js` (the standard, used by 2
  routes) vs. the other ~23 route files.
- **Problem:** error shape inconsistency (`error` vs `message`), "not found"
  returned as 400 — both tracked open in `tests/e2e/Redundancies.md` (R12:289,
  R12b:299). Frontends compensate with defensive parsing.
- **Suggested direction:** adopt `apiResponse` route-by-route; update the paired
  unit suite in the same commit each time.
- **Risk / complexity:** Medium (many callers assert on response shape).
- **Order:** after removal cleanup.

### 6.3 Assessment-question schema convergence

- **Area:** questions data model
- **Files involved:** `src/routes/questions.js`, `src/routes/onboarding.js`,
  `src/models/Question.js`, instructor question UIs.
- **Problem:** Redundancies.md **R8 (:185, 🟥 open)**: three competing question
  schemas depending on which UI created the record; FINDINGS.md calls it the
  "headline issue." The runtime migration for existing rows was written but the
  script has now been deleted **without having been run in staging/prod** (per
  commit `fe0923c`'s own message).
- **Suggested direction:** restore the migration from git history
  (`git show fe0923c:scripts/migrate-question-schema.js`), run it in staging/prod,
  then converge writers on the single boolean/index-based shape the tests already
  assert.
- **Risk / complexity:** High (data migration + multiple writers).
- **Order:** this is the one refactor with a live operational dependency — the
  staging/prod migration should be scheduled regardless of any cleanup.

### 6.4 Startup legacy-migration hooks in models

- **Area:** boot-time data migrations
- **Files involved:** `src/models/Course.js` (`ensureCourseCodes`, line 628),
  `src/models/Superchat.js` (`ensureSuperchatsFromLegacy`, line 220), both invoked
  from `src/server.js:9–10` on every boot.
- **Problem:** legacy-compat code that re-scans collections on every startup;
  `ensureSuperchatsFromLegacy` self-skips once migrated, but the code and its
  branch surface remain forever.
- **Suggested direction:** once all environments are confirmed migrated, demote
  these to one-off scripts (or delete) and drop the server.js calls.
- **Risk / complexity:** Medium — **requires environment confirmation first** (see
  §7).
- **Order:** after confirmation; not blocked by other cleanup.

### 6.5 Misplaced / confusingly-named modules (small, cosmetic)

- `src/routes/llmKeyMiddleware.js` is middleware living in `routes/` — move to
  `src/middleware/` for discoverability. Risk: Low (pure move + path updates in
  ~23 referencing files/tests).
- Two different stylesheets both named `style.css`
  (`public/styles/style.css`, 598 lines vs `public/instructor/styles/style.css`,
  307 lines, different content) — rename the instructor one (e.g.
  `instructor.css`) to stop grep/import confusion. Risk: Low.
- `src/server.js` re-requires modules inline mid-file (`qdrantService` at 267 and
  512, `config` at 496) instead of top-of-file — harmless in CommonJS but
  inconsistent. Risk: Low.

---

## 7. Do Not Remove Yet / Needs Confirmation

### 7.1 `documentation/instructors/screenshots/` (16 PNGs)

- **Suspicious because:** zero references anywhere in the repo (no markdown file
  embeds them; the README doesn't link them).
- **May still be needed because:** they look like an instructor user-guide asset
  set, plausibly consumed by an external wiki/LMS page or a doc that lives outside
  the repo.
- **Ask the maintainer:** "Is anything outside this repo (Confluence/Canvas/wiki)
  hotlinking or sourcing these screenshots, or were they for a doc that was never
  written?"

### 7.2 Startup migrations `ensureCourseCodes` / `ensureSuperchatsFromLegacy`

- **Suspicious because:** classic done-its-job migration code (see §6.4).
- **Still needed because:** any environment with an un-migrated database (staging,
  prod, a colleague's local DB) depends on them running at boot.
- **Ask:** "Have staging and prod both booted a build containing these hooks — can
  we consider all databases migrated?"

### 7.3 Test-mode stubs: `llmStub.js`, `embeddingsStub.js`, `testLlmStub.js`

- **Suspicious because:** stub/fake naming pattern often indicates leftovers.
- **Still needed because:** verified wiring — `testLlmStub` is env-gated in
  `server.js:592` and the stubs back the entire e2e suite's LLM/embedding calls;
  `tests/unit/services/stubs.test.js` and `tests/unit/routes/testLlmStub.test.js`
  cover them.
- **No question needed** — keep; listed here only so nobody flags them later.

### 7.4 Working docs: `unit_tests.md`, `tests/e2e/FINDINGS.md`, `tests/e2e/AGENTS.md`, `tests/e2e/Redundancies.md`

- **Suspicious because:** session-handoff-style docs, some sections dated.
- **Still needed because:** all four were reviewed this cycle and deliberately
  kept: FINDINGS/Redundancies carry open 🟥 items that are effectively the
  project's bug backlog; AGENTS.md is the standing rules file for test-writing
  agents; unit_tests.md was updated the same day as this review.
- **Ask:** "When the testing push wraps, should these be archived into a `docs/`
  folder rather than deleted, given FINDINGS/Redundancies double as a backlog?"

### 7.5 `delegates` in devDependencies

- **Suspicious because:** an unusual, tiny package to see in a 2026 project.
- **Still needed because:** required by three unit suites
  (`tests/unit/routes/qdrant.test.js`, `auth.test.js`, `auth.passport.test.js`) as
  a module-shape shim.
- **No action** unless those suites are rewritten.

---

*Report generated 2026-07-03 on branch `fixes_new`. All line numbers refer to the
working tree as of this date (including the staged deletions described in the
header note).*
