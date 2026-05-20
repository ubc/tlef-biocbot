# Redundancies

Living tracker for duplicate code, parallel implementations, dead code, and
repeated bug patterns. Companion to [FINDINGS.md](FINDINGS.md) — FINDINGS
catalogs individual bugs; this file groups them by "the same mistake is in
N places, and the real fix is one shared thing."

Update as fixes land: flip status, note the commit/PR.

Status legend: 🟥 open · 🟡 partial · ✅ fixed · ⏸ deferred

---

## Bug-pattern duplications (same mistake, multiple places)

### R0. `req.path` vs `req.originalUrl` for "is this an API request?" ✅ fixed

- **Where:** `src/middleware/auth.js` — 16 occurrences across `requireAuth`,
  `requireRole`, `requireInstructor`, `requireSystemAdmin`,
  `requireCourseContext`, `requireTAPermission`, etc.
- **Why it duplicates:** Every gate copy-pasted
  `req.path.startsWith('/api/')` to decide JSON-401 vs redirect-to-login.
  But inside a mounted router (`app.use('/api/foo', router)`), Express
  strips the prefix and `req.path` is `/bar`, not `/api/foo/bar`. The
  check was always false for mounted API routes, so every auth failure
  on an API endpoint redirected to `/login` (HTML 200) instead of
  returning JSON 401.
- **Resolution:** `replace_all` changed all 16 occurrences from
  `req.path` to `req.originalUrl`. Tests for unauthenticated 401 across
  user-agreement / mental-health-flags / struggle-activity now pass.
- **Source:** FINDINGS candidates H + I + J.
- **Impact:** Silently fixed JSON 401 behavior for *every* auth-protected
  API route, not just the three the tests called out.

### R1b. `req.body` destructure without `|| {}` (Express 5 leaves it undefined) 🟡 partial

- **Where:** Pattern of `const { foo } = req.body;` at the top of POST/DELETE
  handlers. In Express 5, a request with no body / no Content-Type leaves
  `req.body` as `undefined`, so the destructure throws and the route 500s.
- **Progress:**
  - `DELETE /api/courses/:courseId/units/:unitName` (FINDING #31) — fixed.
  - `POST /api/user-agreement/agree` (FINDING #31b) — fixed.
- **Audit follow-up:** grep for `} = req.body;` (no `|| {}`) in `src/routes/`
  and verify each handler's tolerance to bodyless calls. Likely a few more
  live instances.

### R1. Route ordering: static GET paths registered after `/:param` siblings ✅ fixed

- **Where:** `src/routes/questions.js`, `src/routes/onboarding.js`
- **Why it duplicates:** Express matches in registration order. `/:questionId`
  / `/:courseId` swallow any later static GET like `/stats` or
  `/course-material`. The same mistake was independently made in two routers.
- **Resolution:** Moved `/stats` and `/course-material` above `/:questionId`
  in `questions.js`; moved `/stats` above `/:courseId` in `onboarding.js`.
  Both files now carry a one-line comment explaining the ordering rule.
- **Source:** [FINDINGS #32, #33](FINDINGS.md).
- **Audit follow-up:** any other router with a `/:param` GET should be
  spot-checked — `courses.js` already has a comment about it, but the others
  haven't been audited.

---

## Duplicate function declarations (same name, same file, later wins)

### R1c. Global script collision: top-level `function foo()` aliases `window.foo` 🟡 partial

- **Where the pattern shows up:**
  - `public/common/scripts/auth.js:266` declares `function getCurrentUser()`.
  - `public/student/scripts/history.js:176` declares its own
    `function getCurrentUser()` AFTER auth.js loads — silently overwrites
    `window.getCurrentUser`.
  - Same pattern likely exists for any helper name re-declared across
    `public/common/` and a page-specific script.
- **Why it bites:** In a non-strict global script, a top-level
  `function foo()` binds the lexical name `foo` to the same slot as
  `window.foo`. Reassigning `window.foo = bar` later means a subsequent
  in-function check like `if (window.foo !== foo)` is comparing `bar` to
  `bar` — always false. Any "delegate to an external helper if window.foo
  has been replaced" fallback is dead.
- **Symptoms it produces:**
  - The `history.js` `getCurrentUser` fallback branch (FINDINGS history-page
    note) was unreachable until fixed.
  - Test pollution / staleness: tests that replace a global helper see the
    old behavior because the page-local copy still shadows.
  - Hard-to-debug "this branch never fires in production" coverage gaps.
- **Resolution shape (used in history.js):** capture the function reference
  into a separately-named `const` *after* the declaration. The const is a
  block-scoped binding that does NOT alias `window.foo`, so the `!==` check
  becomes meaningful.
- **Better long-term:** wrap page scripts in IIFEs (`(function () { ... })()`)
  so they don't pollute the global object at all, and explicitly publish
  what they want on `window.someNamespace = { ... }`. Until then, audit any
  page script that declares a function whose name also exists in
  `public/common/scripts/` — those are all latent shadow conflicts.
- **Source:** FINDINGS history.js note (now fixed) + FINDING #26 family
  (`showNotification`, `waitForAuth`, `removeObjective` duplicates within
  the same file).

### R1d. Library auto-attaches click handlers that fight page-level controllers ✅ partial (auth.js logout fixed)

- **Pattern:** A common library (`public/common/scripts/auth.js`) attaches a
  click handler to a well-known DOM id (`#logout-btn`, `#mobile-logout-btn`)
  on every page. Some pages (`dashboard.js`) ALSO attach their own handler
  to delegate through a page-level controller (`window.Auth.logout()`).
  Both fire on the same click — and the library's handler navigates the
  page before the page-level handler's side effects can be observed.
- **Resolution shape (used in auth.js `setupLogoutHandler`):** the library
  now defers when a page-level controller (`window.Auth.logout`) is already
  defined. Production behavior unchanged (no page assigns `window.Auth`
  outside tests/dashboard's read-only use of it), but the test shim and
  any future page-level Auth controller can now own logout cleanly.
- **Broader pattern to audit:** any library that auto-binds to a global
  selector (notification roots, modal anchors, mobile-nav toggles) should
  either expose an opt-out or check for a page-level controller before
  binding. Otherwise pages can't reliably override behavior.
- **Source:** student-dashboard-branches.spec.js
  `uses the page Auth shim for auth checks and logout handling` (now green).

### R2. `instructor.js` declares `showNotification` twice 🟥 open

- **Where:** `public/instructor/scripts/instructor.js` lines 344 and 6753.
- **Effect:** JS hoisting makes the later declaration win; the earlier one is
  dead code that still shows up in coverage as uncovered.
- **Source:** [FINDINGS #13, #26](FINDINGS.md).
- **Fix direction:** Delete one. Better — extract to
  `public/common/scripts/notifications.js` so `onboarding.js`, `student.js`
  etc. share one implementation.

### R3. `instructor.js` declares `waitForAuth` twice 🟥 open

- **Where:** lines 13 and 6952 of `instructor.js`.
- **Source:** [FINDINGS #26](FINDINGS.md).

### R4. `onboarding.js` declares `removeObjective` twice 🟥 open

- **Where:** lines 1590 and 1868 of `onboarding.js`.
- **Source:** [FINDINGS #26](FINDINGS.md).

---

## Parallel implementations of the same operation

### R5. Answer-checking endpoint exists twice 🟡 partial

- **Where:** `POST /api/quiz/check-answer` (`src/routes/quiz.js`) and
  `POST /api/chat/check-practice-answer` (`src/routes/chat.js:1281`).
- **Why it duplicates:** Different request shapes, different question lookup
  paths, different response payloads — but the core comparison logic is the
  same. The Phase 1 `String(...)` coercion had to be applied in both places.
- **Fix direction:** Extract `evaluateObjectiveAnswer(question, studentAnswer)`
  used by both endpoints. Endpoints stay (different UIs hit them), shared
  logic lives in one place.
- **Progress:** `src/routes/quiz.js` now has one local objective-answer
  evaluator and gates `/check-answer`/`/attempt` through quiz visibility before
  exposing or persisting results; the chat endpoint still needs the shared
  utility extraction.
- **Source:** [FINDINGS #9](FINDINGS.md).

### R6. Document ingest split across two endpoints 🟥 open

- **Where:** `POST /api/documents/upload` (multipart) and
  `POST /api/documents/text` (raw text), both in `src/routes/documents.js`.
- **Why it duplicates:** Both call `DocumentModel.uploadDocument` →
  `CourseModel.addDocumentToUnit` → Qdrant indexing. Only the extraction step
  differs.
- **Fix direction:** Internal `ingestDocument({ mode, payload, ... })` helper
  called by both endpoints.
- **Source:** [FINDINGS #17](FINDINGS.md).

### R7. Instructor course-code join flow exists on two pages 🟥 open

- **Where:** `public/instructor/scripts/home.js` (1938-2038) and
  `public/instructor/scripts/onboarding.js` (1071-1142). Same API contract,
  same error handling, different DOM ids.
- **Fix direction:** Extract `joinInstructorCourse({ courseId, code })`; keep
  small page-specific UI adapters.
- **Source:** [FINDINGS #27](FINDINGS.md).

---

## Schema / shape divergence between code paths

### R8. Assessment-question shape: three competing schemas 🟥 open (Phase 2/3 plan exists)

- **Where:** `onboarding.js` modal state (structured) → `onboarding.js`
  POST helper (string-y) → `instructor.js` POST (string-y) → `student.js` /
  `quiz.js` / `chat.js` reader-side (both shapes via defensive branches).
- **Why it matters:** TF `correctAnswer` is boolean here, `"true"` there;
  MCQ options array vs object; MCQ correctAnswer numeric index vs letter.
- **Source:** [FINDINGS headline + #8, #8a, #22](FINDINGS.md).
- **Status:** Phase 1 (defensive coercion) landed; Phase 2/3 (unify to
  structured shape and migrate stored data) is the real fix.

### R9. In-memory question object differs between modals 🟥 open

- **Where:** `onboarding.js:2243` builds `{ id, type, ... }`;
  `instructor.js:4194` builds `{ questionType, ... }`. Third (wire/DB) shape
  is different again.
- **Fix direction:** Shared `buildQuestionPayload(formInputs)` helper.
- **Source:** [FINDINGS #8](FINDINGS.md).

---

## Cross-cutting pattern duplications

### R10. Course-access checks: three different patterns 🟡 partial

- **Where:**
  - `src/routes/courses.js` uses local `hasInstructorOrTAAccess()` /
    `hasInstructorAccess()` helpers (lines 17-26).
  - `src/routes/documents.js`, `src/routes/lectures.js` call
    `CourseModel.userHasCourseAccess()` directly.
  - Other routes skip the check entirely (see [FINDINGS #11, #23, #24, #34,
    #36, #37](FINDINGS.md)).
- **Fix direction:** One canonical helper, exported from a single module,
  used by every route that takes a `courseId`.
- **Progress:**
  - FINDING #34b fixed for `PUT /api/courses/:courseId` and
    `POST /api/courses/:courseId/units`: legacy `instructorId` input must now
    match `req.user.userId`, and authorization/mutation use the session user.
  - FINDINGS #23/#24/#34 fixed for `src/routes/questions.js`: question-route
    reads and writes now authorize from `req.user` course access instead of
    body-supplied `instructorId`, including student, cross-instructor, and
    TA course-permission guardrails.
  - FINDINGS #40/#41 fixed for `src/routes/documents.js` and
    `src/routes/qdrant.js`: direct document/vector APIs now reject students,
    check requested-course access for instructors/TAs, and do not trust
    body-supplied `instructorId` for document mutations.
  - FINDING #44 fixed a flags/course-content slice: flag reads and mutations
    now enforce requested-course access and TA `canAccessFlags`, student flag
    reads are filtered by current enrollment, course content mutations check
    session-user course management access, and TA dashboard selection no
    longer prefers stale profile course context over assigned course data.
  - FINDING #45 fixed TA settings and course-settings writes: TA settings UI
    now evaluates the URL-selected course permissions, direct settings writes
    require instructor ownership, and status-only flag moderation records the
    acting user id.
  - FINDING #48 fixed student flag notifications: the client now requests
    flags for the selected course and ignores any returned rows whose
    `courseId` or `studentId` do not match the active student context.
- **Source:** [FINDINGS #18, #23, #24, #34, #34b, #40, #41, #44, #45, #48](FINDINGS.md).

### R19. Student/user identity accepted from body or path ✅ fixed for chat/history cluster

- **Pattern:** Routes accepted `studentId` / `userId` from request bodies or
  URL params and used it directly as the acting identity.
- **Fixed:**
  - `POST /api/chat/save` rejects student attempts to save under another
    `studentId`.
  - `DELETE /api/students/:courseId/:studentId/sessions/:sessionId` is now
    instructor-only; students must use the `/own` route, which already checks
    same-user ownership.
  - `GET /api/struggle-activity/student/:userId` rejects student attempts to
    read another student's activity history.
- **Source:** [FINDING #42](FINDINGS.md).

### R20. Shared TA/instructor page guard reused for instructor-only pages 🟡 partial

- **Pattern:** `requireInstructorOrTA` is correct for shared operational pages
  but too broad for instructor-only pages. When reused there, direct URL
  navigation bypasses the frontend sidebar hiding.
- **Progress:** `src/server.js` now redirects TA requests away from
  `/instructor/home`, `/instructor/settings`, and `/instructor/downloads`
  before serving instructor HTML.
- **Still open:** audit any `.html` static aliases and future instructor page
  routes so they choose either a shared TA permission gate or instructor-only
  role gate explicitly.
- **Source:** [FINDING #43](FINDINGS.md).

### R11. Soft-delete / inactive filtering: enforced inconsistently 🟡 partial

- **Where:** `getCourseById()` doesn't filter; several sister listings do.
  Each caller has to remember.
- **Progress:**
  - `GET /api/courses` (Finding #6) now filters `status: { $ne: 'deleted' }`.
  - `joinCourseAsInstructor()` (Finding #29) now rejects `deleted` and
    `inactive` courses — the direct-join path no longer side-doors the
    `/available/joinable` filter.
  - TA branch of `/available/all` (Finding #28) now filters from the
    already-narrowed list instead of resetting to the raw collection — same
    visible behavior today, defensive against future role-based narrowing.
- The underlying "every caller has to remember" pattern is still open.
- **Fix direction:** Either make the helper enforce the invariant by default,
  or split into `getActiveCourseById` / `getCourseByIdIncludingDeleted`.
- **Source:** [FINDINGS #6 (fixed), #7, #10, #28 (fixed), #29 (fixed)](FINDINGS.md).

### R12. Error-response shape: `error` vs `message` 🟥 open

- **Where:** `auth.js` uses `error:`; most other routes use `message:`;
  `settings.js` uses both.
- **Effect:** Frontend error-display code silently falls through to generic
  text whenever a route uses the "wrong" key.
- **Fix direction:** Standardize on one key + small `sendError(res, status,
  msg)` helper.
- **Source:** [FINDINGS #12](FINDINGS.md).

### R12b. "Not found" mapped to 400 instead of 404 across routes 🟥 open (tech debt)

- **Pattern:** Several routes (and their tests) rely on a "model returns
  `{success: false, error: 'not found'}` → route returns 400" mapping
  instead of the REST-correct 404. Encountered while landing FINDING #36/#37:
  `loadFlagAndAssertCourseAccess` in `src/routes/flags.js` would prefer to
  404 on an unknown `:flagId`, but three coverage tests (in
  `flags-api-coverage.spec.js` lines ~437, 513, 570) explicitly assert
  `expect(res.status()).toBe(400)`. Kept at 400 to preserve the legacy
  contract; an inline comment in `flags.js` points back here.
- **Why it matters:** Clients (and humans reading the API) can't
  distinguish "you gave me a bad ID" (404) from "your input was malformed"
  (400). Hampers retry logic, idempotency reasoning, and log triage.
- **Other suspects to audit** (likely same shape, not yet verified):
  - `src/routes/questions.js` — `updateAssessmentQuestions` "not found"
    branch surfaces as 400 today (see FINDING #35).
  - `src/routes/courses.js` — many "course not found" branches return 400.
  - `src/routes/lectures.js`, `src/routes/onboarding.js` — same idiom.
- **Fix direction (when undertaken):** add a small `sendNotFound(res, msg)`
  helper that returns 404 + `{ success: false, message }`, migrate routes
  one at a time, and flip the matching tests. Combine with R12
  (`error`-vs-`message`) so a single audit fixes both shape drifts.
- **Source:** FINDING #36/#37 fix (Aug 2026 wave).

### R13. ID generation: ad-hoc scheme per route 🟥 open

- **Where:** `${slug}-${Date.now()}` for courseId; `doc_${ts}_${rand}` for
  documentId; `pq_${ts}_${rand}` for practiceId; `user_${ts}_${rand}` for
  userId.
- **Effect:** Ms-granularity collisions, inconsistent prefixing, hard to
  redact in logs.
- **Fix direction:** Single `idFor(entity)` helper backed by
  `crypto.randomUUID()`.
- **Source:** [FINDINGS #15](FINDINGS.md).

### R14. Status modeling: boolean `is*` vs string enum drift 🟥 open

- **Where:** `lectures[].isPublished` (bool), `isOnboardingComplete` (bool),
  `course.status` (string enum), `user.isActive` (bool).
- **Fix direction:** Pick one per concept type (state machine → enum; truly
  binary → bool) and document the convention.
- **Source:** [FINDINGS #20](FINDINGS.md).

### R15. `/api/auth/me` fetched multiple times per page load 🟥 open

- **Where:** `student.js` (multiple call sites for `displayName`,
  `preferences.courseId`, …); likely same in `instructor.js`.
- **Fix direction:** Cached `getCurrentUser()` in
  `public/common/scripts/auth.js`.
- **Source:** [FINDINGS #16](FINDINGS.md).

---

## Dead / unreachable code

### R16. Commented Shibboleth routes in auth.js 🟥 open

- **Where:** `src/routes/auth.js` lines 835-907 (≈70 lines, marked DEPRECATED).
- **Source:** [FINDINGS #19](FINDINGS.md).
- **Fix direction:** Delete; leave a one-line breadcrumb pointing at the PR
  that removed the flow.

### R17. Dead CSS selectors in `documents.css` 🟥 open

- **Where:** Long list in [FINDINGS.md](FINDINGS.md) "Dead CSS candidates"
  section: legacy upload UI, prototype browsing UI, superseded modal flow,
  prototype question editor.
- **Fix direction:** Delete or move to page-specific stylesheet.

### R18. `instructor.js` runs document-page side effects on Settings 🟥 open

- **Where:** `public/instructor/settings.html` loads `instructor.js` which
  unconditionally polls publish status and looks up course ids.
- **Fix direction:** Split shared helpers out of `instructor.js`; load the
  document/upload controller only on document pages.
- **Source:** [FINDINGS #25](FINDINGS.md).
