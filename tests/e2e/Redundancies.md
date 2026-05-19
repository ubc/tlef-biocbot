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

### R5. Answer-checking endpoint exists twice 🟥 open

- **Where:** `POST /api/quiz/check-answer` (`src/routes/quiz.js:186`) and
  `POST /api/chat/check-practice-answer` (`src/routes/chat.js:1281`).
- **Why it duplicates:** Different request shapes, different question lookup
  paths, different response payloads — but the core comparison logic is the
  same. The Phase 1 `String(...)` coercion had to be applied in both places.
- **Fix direction:** Extract `evaluateObjectiveAnswer(question, studentAnswer)`
  used by both endpoints. Endpoints stay (different UIs hit them), shared
  logic lives in one place.
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

### R10. Course-access checks: three different patterns 🟥 open

- **Where:**
  - `src/routes/courses.js` uses local `hasInstructorOrTAAccess()` /
    `hasInstructorAccess()` helpers (lines 17-26).
  - `src/routes/documents.js`, `src/routes/lectures.js` call
    `CourseModel.userHasCourseAccess()` directly.
  - Other routes skip the check entirely (see [FINDINGS #11, #23, #24, #34,
    #36, #37](FINDINGS.md)).
- **Fix direction:** One canonical helper, exported from a single module,
  used by every route that takes a `courseId`.
- **Source:** [FINDINGS #18](FINDINGS.md).

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
