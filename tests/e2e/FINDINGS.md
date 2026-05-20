# E2E Test Findings

Bugs / inconsistencies surfaced by the Playwright suite. Each entry assumes a
test asserts the *expected* behavior; if the test fails, the discrepancy is
recorded here so it can be triaged into a real issue and fixed in code.

> Policy: when a new test fails, **don't relax the assertion**. Document it
> here, leave the test failing, and let the failure prompt a real fix.

---

## ⚠️ Headline issue: assessment-question schema is inconsistent

The same conceptual data — an assessment question — is persisted in **two
different shapes** depending on which UI flow created it. One extra wrinkle:
`onboarding.js` first builds a structured in-memory object, then its final save
helper converts that object back into the string-y/object shape before calling
`POST /api/questions`.

| Field                 | `onboarding.js` modal state       | `onboarding.js` final POST         | `instructor.js` POST               |
| --------------------- | ----------------------------------- | ------------------------------------ | ------------------------------------ |
| TF `correctAnswer`  | boolean `true` / `false`        | string `"true"` / `"false"`      | string `"true"` / `"false"`      |
| MCQ `options`       | array `["A text", "B text", ...]` | object `{A: "...", B: "...", ...}` | object `{A: "...", B: "...", ...}` |
| MCQ `correctAnswer` | numeric index `2`                 | letter `"C"`                       | letter `"C"`                       |
| SA `correctAnswer`  | string                              | string                               | string                               |

### Decided direction: standardize on the structured shape

Booleans should be booleans, ordered lists should be arrays, positions should
be numbers. The string-y shape has been pushing those concepts through string
radio values, which is exactly why `student.js` accumulated dual-shape branches
and `quiz.js`/`chat.js` were one bad input away from crashing.

### Phase plan

- **✅ Phase 1 — DONE.** Defensive `String(...)` coercion in `quiz.js:211` and
  `chat.js:1319` so the comparison works regardless of which shape is in the DB.
  Stops the runtime crash. Both shapes compare correctly today.
- **Phase 2a — fix `POST /api/questions` validation** so structured falsy
  answers are accepted. Today `src/routes/questions.js:178` rejects boolean
  `false` and numeric `0` because it checks `!correctAnswer`.
- **Phase 2b — fix the save paths** to write the structured shape:
  `instructor.js` `saveQuestion()` and onboarding's
  `saveUnit1AssessmentQuestion()` should both send TF→boolean,
  MCQ options→array, MCQ correctAnswer→numeric index.
  Existing failing tests in `tests/e2e/instructor.spec.js` turn green.
- **Phase 3a — Mongo migration script** in `scripts/` to convert
  instructor-created questions already in the DB to the structured shape.
- **Phase 3b — clean up `student.js`** dual-shape branches at lines 2200, 2213,
  2216–2221, and update its wire protocol so MCQ submits numeric index instead
  of letter.
- **Phase 4 — student-side spec** that exercises `/api/quiz/check-answer`
  end-to-end and would have caught Finding #4 originally.

---

## Individual findings

### 1. ✅ FIXED — `instructor.js` saves true/false `correctAnswer` as a string

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4207)
- **Was:** Persisted `correctAnswer: "true"` (string).
- **Now:** Converts the modal state at the wire boundary — TF answers ship as
  booleans, MCQ options as an ordered array, MCQ `correctAnswer` as a numeric
  index. Internal display state still uses the legacy in-memory shape, so the
  existing render helpers continue to work.
- **Failing test (now green):** `tests/e2e/instructor.spec.js` › "instructor can add an assessment question to a unit"

### 2. ✅ FIXED — `instructor.js` saves MCQ `options` as an object (not an array)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4217)
- **Was:** Persisted `options: { A: "...", B: "...", C: "...", D: "..." }`.
- **Now:** Saves an ordered array of option strings; #1's wire-boundary
  conversion translates the internal object shape to an array before POSTing.
- **Failing test (now green):** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"

### 3. ✅ FIXED — `instructor.js` saves MCQ `correctAnswer` as a letter (not a numeric index)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4240)
- **Was:** Persisted `correctAnswer: "C"` instead of `2`.
- **Now:** Converts the selected letter to its array index at the wire
  boundary alongside the options-shape conversion in #2.
- **Failing test (now green):** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"

### 4. ✅ FIXED (Phase 1) — `quiz.js` / `chat.js` could throw on non-string `correctAnswer`

- **Where:** `src/routes/quiz.js` line 211, `src/routes/chat.js` line 1319
- **Was:** `studentAnswer.toLowerCase() === question.correctAnswer.toLowerCase()` threw `TypeError` when `correctAnswer` was a boolean (TF) or number (MCQ index).
- **Now:** Both sides coerced via `String(...)`, comparison works for any shape.
- **Status:** Defensive coercion landed; can stay even after Phase 3 lands as belt-and-suspenders.

### 5. `student.js` has accumulated dual-shape handling

- **Where:** `public/student/scripts/student.js` lines 2200, 2213, 2216–2221
- **Symptom:** Branches that exist only because two ingest paths persist different shapes.
- **Coverage verdicts:**
  - `2200` (`practiceTests.passThreshold: null` while initializing missing `practiceTests`) is reachable today when autosave runs with calibration questions but no existing `practiceTests` object. Include in coverage prompts; it is not a Phase 3b-only branch.
  - `2213` (true/false answer index rendered as `True` / `False`) is reachable today from the true/false assessment flow created by either ingest path. Include in coverage prompts.
  - `2216-2218` (multiple-choice answer index resolves through `Object.keys(q.options)`) is reachable today for current legacy object options and future array options. Include in coverage prompts.
  - `2218-2220` (fallback to `Option ${studentAnswerIndex}` when the selected index has no option key) is not reachable through the current UI with valid ingested questions; treat as **skip — Phase 3b cleanup** rather than writing a direct coverage test against it.
  - `2221-2223` (non-true/false, non-multiple-choice answer text falls back to the raw submitted answer) is reachable today through short-answer assessment questions. Include in coverage prompts.
- **Fix:** Phase 3b — once shapes are unified, delete these branches and the wire-protocol fallback they support.

### 6. `GET /api/courses` returns soft-deleted courses

- **Where:** `src/routes/courses.js` line 537
- **Symptom:** Query is `collection.find({ instructorId })` with **no status filter**, so soft-deleted courses (set to `status: 'deleted'` by `DELETE /api/courses/:courseId` at line 1708) are returned to the instructor's "My Courses" list. This is why my onboarding test had to hard-delete via Mongo in `beforeEach` instead of using the API — soft-deletes piled up.
- **Compare to:** Sister routes that DO filter:
  - `GET /api/courses/available/all` (~line 1921): `status: { $ne: 'deleted' }`
  - `GET /api/courses/available/joinable` (~line 2011): `status: { $ne: 'deleted' }`
  - `GET /api/onboarding/instructor/:instructorId` (~line 242): `status: { $ne: 'deleted' }`
- **Fix:** Add `status: { $ne: 'deleted' }` to the `find()` query at line 537.

### 7. `getCourseById()` doesn't filter soft-deleted, leaving filtering to each caller

- **Where:** `src/models/Course.js` line 1309 — `findOne({ courseId })`, no status check.
- **Symptom:** Helper that "looks up a course by id" can return a deleted course. Callers either remember to check `course.status !== 'deleted'` (e.g., `quiz.js` does its own filtering) or silently operate on deleted data.
- **Why it matters:** Footgun. Every new caller has to know to filter; some will forget. Better to make the helper enforce the invariant.
- **Fix:** Either (a) make `getCourseById` filter soft-deleted by default with an explicit `{ includeDeleted: true }` opt-in, or (b) introduce `getActiveCourseById` and a separate `getCourseByIdIncludingDeleted` so the choice is explicit at the call site.

### 8. In-memory question shape differs between `onboarding.js` and `instructor.js`

- **Where:**
  - `onboarding.js` line 2243: builds `{ id: Date.now(), type: questionType, question, learningObjective, ... }`
  - `instructor.js` line 4194: builds `{ questionType, question, learningObjective, ... }` (no `id`, uses `questionType` directly)
- **Symptom:** Two different in-memory schemas for the same conceptual object. The wire protocol (POST `/api/questions`) and storage (`questionType`, `questionId`) use a third schema, so both client paths have to translate. Drift-prone — if one path's translation breaks, the other might mask it.
- **Fix:** Pick one in-memory shape (probably matching what the API expects: `questionType`, no separate `id` since the server assigns `questionId`). Consider extracting a shared `buildQuestionPayload(formInputs)` helper used by both pages.

### 8a. Onboarding's final assessment save undoes its structured modal shape

- **Where:** `public/instructor/scripts/onboarding.js` line 3676,
  especially lines 3711-3723 and 3741-3744.
- **Symptom:** The modal creates structured questions (`true`/`false`, arrays,
  numeric indexes), but `saveUnit1AssessmentQuestion()` explicitly converts MCQ
  arrays to `{A,B,C...}`, numeric indexes to letters, and TF booleans to strings
  immediately before calling `/api/questions`.
- **Why it matters:** It is easy to write an e2e assertion against the modal
  state and think onboarding has been fixed, while the database still receives
  the legacy shape.
- **Fix:** Delete this conversion once the API accepts the structured contract.

### 9. Quiz `/check-answer` and chat `/check-practice-answer` are parallel implementations with divergent contracts

- **Where:**
  - `src/routes/quiz.js` `POST /check-answer` — requires `{ courseId, questionId, lectureName, studentAnswer }`. Looks up the question via `CourseModel.getAssessmentQuestions`.
  - `src/routes/chat.js` line 1281 — requires `{ practiceId, studentAnswer }`. Looks up the question from an in-memory store keyed by `practiceId`.
- **Symptom:** Same conceptual operation ("check this student's answer to this question") implemented two ways with different request shapes, different lookup mechanisms, different response payloads, and different error handling. They both have the (now-fixed) string-comparison logic; future bugs fixed in one won't propagate to the other.
- **Fix:** Extract a shared `evaluateObjectiveAnswer(question, studentAnswer)` utility that both routes call. Keep the two endpoints (they serve different UIs / lookup paths) but the core logic should live in one place.

### 9b. ✅ FIXED — 🔒 `/api/quiz/check-answer` bypassed quiz visibility gates

- **Where:** `src/routes/quiz.js` `POST /check-answer`.
- **Was:** The endpoint looked up `{ courseId, lectureName, questionId }`
  directly and returned the answer verdict even when quiz practice was disabled,
  the unit was unpublished, or the unit was outside `testableUnits`.
- **Now:** `check-answer` uses the same quiz-enabled, published-unit, testable-unit,
  and active-question checks as the student question list before evaluating.
- **Failing tests (now green):** `tests/e2e/quiz-api.spec.js` ›
  "PRODUCT BUG: /check-answer reveals answers even when the quiz is disabled"
  and "PRODUCT BUG: /check-answer reveals answers for questions in unpublished
  units".

### 9c. ✅ FIXED — 🔒 `/api/quiz/attempt` trusted a student-supplied `correct` flag

- **Where:** `src/routes/quiz.js` `POST /attempt`.
- **Was:** The route persisted `Boolean(req.body.correct)` without checking the
  submitted answer against the stored objective-question answer.
- **Now:** Objective attempts are rejected when the submitted `correct` flag
  contradicts the canonical answer, so fabricated correct attempts are not
  stored or counted in history.
- **Failing test (now green):** `tests/e2e/quiz-api.spec.js` ›
  "PRODUCT BUG: /attempt trusts a student-supplied `correct` flag without
  cross-checking".

### 10. Soft-delete invariant is enforced inconsistently across `getCourse*` helpers

- **Where:** Various places in `src/models/Course.js` and route handlers.
- **Pattern:** Some routes filter `status !== 'deleted'` directly in the route (defensive), some helpers do, some don't. Closely related to #6 and #7.
- **Fix:** Audit every read path that resolves a `courseId` → course doc; standardize on either always filtering or having one canonical "active courses only" helper.

### 11. ✅ FIXED — 🔒 `/api/lectures/publish-status` trusts an `instructorId` query param with no auth check

- **Where:** `src/routes/lectures.js` lines 81–121.
- **Symptom:** Route accepts `instructorId` and `courseId` from query string and calls `CourseModel.getLecturePublishStatus(db, courseId)` directly. **There is no check that `req.user.userId === instructorId` or that the requester has any access to the course.** A logged-in student (or any authenticated user) hitting `GET /api/lectures/publish-status?instructorId=anybody&courseId=anycourse` gets back the publish state of every unit.
- **Compare to:** Other `lectures.js` routes (e.g. `/publish` at line 14) check `userHasCourseAccess()` before mutating.
- **Why it matters:** Information leak — students could enumerate course publish states, including units the instructor hasn't released.
- **Fix landed:** Added the same `req.user` + `CourseModel.userHasCourseAccess`
  gate that sister route `POST /publish` already uses. The `instructorId`
  query param is still accepted (kept for the existing 400-when-missing
  contract) but is now informational only — authorization is from the
  session. Students hitting the route get 403; the legitimate instructor
  dashboard still works (only caller is `instructor.js:2137`).
- **Failing test (now green):** `tests/e2e/routes-lectures-api.spec.js` ›
  "PRODUCT BUG (FINDINGS #11): a student can read the publish state of any
  course".

### 11a. TA Hub renders a missing TA display name as `undefined`

- **Where:** `public/instructor/scripts/ta-hub.js` around line 283.
- **Symptom:** The TA card heading interpolates `${ta.displayName}` directly. If the TA user document lacks `displayName`, the UI renders `undefined` instead of a useful fallback such as the TA username.
- **Failing test:** `tests/e2e/instructor-ta-hub-branches.spec.js` › "falls back to the TA username when displayName is missing"
- **Fix:** Render `ta.displayName || ta.username || ta.userId` anywhere the TA name is shown, including the remove-confirmation modal label.

### 12. Error-response shape drift: `error` vs `message`

- **Where:** Spread across `src/routes/`. Audit:
  - `src/routes/auth.js` — uses `error: '...'` everywhere (e.g. lines 35, 46, 56, 64, 74)
  - `src/routes/quiz.js`, `src/routes/courses.js`, `src/routes/lectures.js`, `src/routes/documents.js`, `src/routes/chat.js` — use `message: '...'`
  - `src/routes/settings.js` — uses **both** in the same file (lines 18, 23 use `error`; line 66 uses `message`)
- **Symptom:** Client code displaying server errors must guess: do I read `result.error` or `result.message`? Look at `public/common/scripts/login.js` line 83 — `result.error || 'Login failed'` works because auth.js uses `error`. But the same pattern would silently fall through to the fallback for any route that uses `message`.
- **Why it matters:** Real bugs — frontend will silently swallow real error messages from any route using the "wrong" key, showing generic fallback text instead of the actual reason.
- **Fix:** Pick one. Most routes already use `message`, so probably standardize on that and migrate `auth.js` + the affected `settings.js` lines. Add a small response helper (`sendError(res, status, message)`) to discourage future drift.

### 13. `showNotification()` is defined twice in `instructor.js`

- **Where:** `public/instructor/scripts/instructor.js` line 344 AND line 6736 — both `function showNotification(message, type = 'info')`.
- **Symptom:** Two function declarations with the same name. JS hoisting means whichever is parsed second silently wins. If a fix is applied to one but not the other, the wrong copy may execute.
- **Why it matters:** Whichever is "live" depends on script-load order, easy to mis-debug. Also an obvious code smell.
- **Fix:** Delete one. Better: extract `showNotification` to `public/common/scripts/notifications.js` so `onboarding.js`, `instructor.js`, `student.js`, etc. all share one helper. Currently each script has its own slightly-different copy.

### 14. Status field is a string enum with no canonical definition

- **Where:** Used at minimum at:
  - `src/routes/courses.js` line 1712 — sets `status: 'deleted'`
  - `src/routes/courses.js` line ~400 — sets `status: 'active'`
  - `src/routes/courses.js` line ~1573 — sets `status: 'inactive'`
  - `src/models/Course.js` line 244 — `(course.status || 'active') === 'inactive'` defaulting check
- **Symptom:** Three string values floating as literals across files. No `const STATUS = {...}` or shared enum. Adding a new state ("archived"? "draft"?) requires grep-replace across multiple files; typos like `'Deleted'` vs `'deleted'` silently fail comparisons.
- **Fix:** Define `const COURSE_STATUS = { ACTIVE: 'active', INACTIVE: 'inactive', DELETED: 'deleted' }` in `src/models/Course.js` and reference it everywhere instead of literals.

### 15. ID generation conventions are ad-hoc per route

- **Where:**
  - `src/routes/courses.js` line ~355: `${slug}-${Date.now()}` for `courseId`
  - `src/routes/documents.js` line ~87: `doc_${Date.now()}_${Math.random().toString(36)...}` for `documentId`
  - `src/routes/chat.js` line ~1253: `pq_${Date.now()}_${Math.random().toString(36)...}` for `practiceId`
  - `src/services/authService.js` (presumably): `user_${Date.now()}_...` for `userId` (seen in webserver logs as `user_1777579195685_t5domhg6j`)
- **Symptom:** Each route invents its own ID scheme. Date.now() granularity is millisecond, so two creates in the same ms collide silently. Some IDs are prefix+ts, some prefix+ts+random; no consistency.
- **Why it matters:** Hard to reason about uniqueness invariants. Hard to write a generic "redact IDs in logs" function. Hard to migrate later.
- **Fix:** A single `idFor(entity)` helper that uses `crypto.randomUUID()` (already in Node 14+) with optional prefix. Migrate gradually; keep accepting old-shape IDs.

### 16. Frontend re-fetches `/api/auth/me` multiple times per page load

- **Where:** `public/student/scripts/student.js` calls `fetch('/api/auth/me')` in multiple places (e.g., to get `displayName`, then again inside `getCurrentCourseId()` to read `preferences.courseId`). Same pattern likely in `instructor.js`.
- **Symptom:** Two or more identical requests for the same user object on every page load. No caching, no deduplication, no shared state.
- **Why it matters:** Wasted round-trips. Worse: a race window where one fetch sees pre-update session and another sees post-update, leading to inconsistent UI state.
- **Fix:** A single `getCurrentUser()` helper in `public/common/scripts/auth.js` that caches the result on first call (you already use the global `currentUser` pattern; the issue is helpers that bypass it).

### 17. Document upload is split across two endpoints with overlapping logic

- **Where:**
  - `POST /api/documents/upload` (multipart file) — `src/routes/documents.js`
  - `POST /api/documents/text` (raw text) — same file
- **Symptom:** Both ultimately call `DocumentModel.uploadDocument`, then `CourseModel.addDocumentToUnit`, then trigger Qdrant indexing. The "what file extraction does we need" is the only meaningful divergence (file path → toolkit parser; text → use as-is).
- **Why it matters:** Two endpoints to keep in sync. If Qdrant config changes, both need updating; if one is missed, the two paths produce subtly different chunks/indexes.
- **Fix:** Internal helper `ingestDocument({ courseId, lectureName, instructorId, mode, payload })` called by both endpoints. Endpoints stay; logic is one place.

### 18. Permission-check call-site patterns disagree

- **Where:**
  - `src/routes/courses.js` defines and uses local helpers `hasInstructorOrTAAccess()`, `hasInstructorAccess()` (lines 17–26) — used inline throughout.
  - `src/routes/documents.js`, `src/routes/lectures.js` call `CourseModel.userHasCourseAccess()` directly.
  - Some routes (#11) skip the check entirely.
- **Symptom:** Three patterns for "is this user allowed to touch this course?" Easy to miss. Easy to drift.
- **Fix:** One canonical helper exported from `src/models/Course.js` (or a dedicated `src/services/access.js`), used by everyone. Audit: every route that takes `courseId` should call it.

### 19. Dead Shibboleth code in `auth.js`

- **Where:** `src/routes/auth.js` lines 835–907 (the `/ubcshib` and `/ubcshib/callback` routes are fully commented out, marked DEPRECATED).
- **Symptom:** ~70 lines of commented code masquerading as documentation.
- **Why it matters:** Confuses readers, fails grep ("is /ubcshib still live?"), accumulates rot. Either the routes are needed (uncomment + fix) or they're not (delete + leave a one-line comment if you want a breadcrumb).
- **Fix:** Delete. Add a single-line `// /ubcshib was removed 2024-XX in favor of /saml — see PR #NNN` if breadcrumbs are wanted.

### 20. Boolean-state vs enum-state drift across collections

- **Where:**
  - `course.lectures[].isPublished` — boolean
  - `course.isOnboardingComplete` — boolean
  - `course.status` — string enum (`'active'`/`'inactive'`/`'deleted'`)
  - `user.isActive` — boolean
- **Symptom:** Two patterns to model "is this thing currently live?": a boolean prefix `is*` and a string enum `status`. The choice seems arbitrary per concept.
- **Why it matters:** Future engineer adding "what's the publish status?" has to remember whether this concept uses a boolean or a string. Easy to query incorrectly.
- **Fix:** Pick one per concept type and document. State machines (multiple values) → string enum. Binary states (truly two values forever) → boolean. Audit current fields and migrate any that don't fit.

### 21. `POST /api/questions` rejects valid structured answers that are falsy

- **Where:** `src/routes/questions.js` line 178.
- **Symptom:** The required-field check uses `!correctAnswer`. That means a
  structured TF answer of `false` and a structured MCQ correct index of `0` are
  treated as missing. This is currently hidden because both instructor and
  onboarding POST string-y values such as `"false"` and `"A"`.
- **Failing test to add:** API-level or e2e test that creates a TF question with
  `correctAnswer: false`, and an MCQ with `correctAnswer: 0`.
- **Fix:** Check presence instead:
  `correctAnswer === undefined || correctAnswer === null || correctAnswer === ''`.

### 22. `instructor.js` display helpers assume the legacy string-y shape

- **Where:** `public/instructor/scripts/instructor.js` lines 4504-4513.
- **Symptom:** TF display checks `question.answer === 'true'`, so a boolean
  `true` would render as `False`. MCQ display uses `Object.entries(options)` and
  compares keys to `question.answer`, so array options plus numeric answer would
  render index labels and no correct highlight.
- **Why it matters:** After storage is standardized, tests may pass at the DB
  level but fail visually unless display normalization is updated too.
- **Fix:** Normalize question objects at the page boundary, then render from one
  shape.

### 23. ✅ FIXED — Question routes trust body `instructorId` and do not check course access

- **Where:** `src/routes/questions.js` lines 159-220, 519-551, 585-613, and
  734-803.
- **Symptom:** Routes are authenticated globally, but the handler trusts
  `courseId`, `lectureName`, and `instructorId` from the request body. There is
  no local check that `req.user.userId` matches `instructorId` or that the user
  has instructor/TA access to the course before creating, updating, deleting, or
  bulk-adding questions.
- **Why it matters:** An authenticated user who knows another course ID can
  mutate that course's assessment questions. This also makes tests weaker,
  because seeding only "a logged-in instructor" may accidentally pass without
  proving authorization.
- **Fix:** Use `req.user.userId`, ignore body `instructorId` except where a
  migration absolutely needs it, and call the canonical course-access helper.
- **Now:** `POST /api/questions`, `PUT /api/questions/:questionId`,
  `DELETE /api/questions/:questionId`, `POST /api/questions/bulk`, and
  `POST /api/questions/auto-link-learning-objectives` authorize from
  `req.user`, require real course access, and use the session user as the
  mutation actor. Legacy `instructorId` input is still accepted for caller
  compatibility, but a mismatched instructor body no longer authorizes a write.
- **Failing tests (now green):** `tests/e2e/routes-questions-api.spec.js` ›
  the FINDINGS #23 POST tests, and
  `tests/e2e/questions-api-ownership-branches.spec.js` › cross-instructor
  mutation tests.

### 24. ✅ FIXED — `GET /api/questions/:questionId` searches globally with no access check

- **Where:** `src/routes/questions.js` lines 452-503.
- **Symptom:** The endpoint finds a question by ID across all courses and returns
  it to any authenticated requester. It does not verify course membership or
  instructor/TA access after finding the containing course.
- **Why it matters:** Question IDs are not secrets, and this can leak assessment
  content across courses.
- **Fix:** Include course context in the request, or derive the containing course
  and check `userHasCourseAccess()` before responding.
- **Now:** After locating the containing course, the route requires the
  authenticated user to have access to that course before returning the
  question record. Inaccessible questions return a denial instead of raw
  assessment content.
- **Failing tests (now green):** `tests/e2e/routes-questions-api.spec.js` ›
  FINDINGS #24 direct question fetch, plus
  `tests/e2e/questions-api-ownership-branches.spec.js` read-leak coverage.

### 25. `instructor.js` runs document-page side effects on pages that only wanted settings

- **Where:** `public/instructor/settings.html` lines 509-511 loads
  `auth.js`, `instructor.js`, then `settings.js`; `instructor.js` unconditionally
  calls `loadPublishStatus()` and `startPublishStatusPolling()` at lines 279-283.
- **Symptom:** Opening Settings can trigger lecture publish-status requests,
  course-id lookup, polling intervals, and possible onboarding redirects from
  code that belongs to the Course Upload page.
- **Why it matters:** Settings e2e tests may need to wait around unrelated
  network activity or get surprised by course-context side effects.
- **Fix:** Split shared helpers out of `instructor.js`, and only load the
  document/upload controller on document pages.

### 26. `instructor.js` and `onboarding.js` contain duplicate global functions

- **Where:** Examples:
  - `instructor.js`: `showNotification()` at lines 344 and 6736; `waitForAuth()`
    at lines 13 and 6935.
  - `onboarding.js`: `removeObjective()` at lines 1590 and 1868.
- **Symptom:** Later function declarations silently win. A change to the earlier
  copy can be dead code without looking dead.
- **Why it matters:** Tests can appear flaky when the developer patched the
  "obvious" function but the browser is executing a later duplicate.
- **Fix:** Keep one definition per page, then extract common helpers to
  `public/common/scripts/`.

### 27. `home.js` and `onboarding.js` duplicate instructor course-code join flows

- **Where:** `public/instructor/scripts/home.js` lines 1938-2038 and
  `public/instructor/scripts/onboarding.js` lines 1071-1142.
- **Symptom:** Both collect `instructor-course-code`, call
  `POST /api/courses/:courseId/instructors`, mark onboarding complete, and show
  code-specific validation messages. The IDs and UI containers differ, but the
  contract and error handling are the same.
- **Why it matters:** A code validation fix can land in onboarding but not Home,
  or vice versa. E2E should cover both until the flow is shared.
- **Fix:** Extract a shared `joinInstructorCourse({ courseId, code })` helper
  plus small page-specific UI adapters.

### 28. TA available-course filtering can re-include inactive courses

- **Where:** `src/routes/courses.js` lines 1929-1943.
- **Symptom:** The route first filters students/TAs down to active courses, but
  the TA-specific block then resets `availableCourses = courses.filter(...)`
  using the original non-deleted list. An invited or assigned TA can therefore
  see inactive courses in `/api/courses/available/all`.
- **Fix:** Filter from the already-narrowed `availableCourses`, or include the
  active-status condition inside the TA filter.

### 29. Instructor join-by-code can target inactive or deleted courses directly

- **Where:** `src/routes/courses.js` lines 2155-2224 and
  `src/models/Course.js` lines 1572-1608.
- **Symptom:** `/api/courses/available/joinable` hides deleted courses, but the
  direct join endpoint and `joinCourseAsInstructor()` do not reject
  `status: 'inactive'` or `status: 'deleted'`.
- **Why it matters:** A user who knows a course ID and instructor code can join a
  course that the UI would not list.
- **Fix:** Decide the intended lifecycle rule. If deleted means inaccessible,
  enforce it in `joinCourseAsInstructor()` and in the route before updating.

### 30. `GET /api/auth/users/:userId` always throws (mongo driver v6 API misuse)

- **Where:** `src/routes/auth.js` lines 610-620.
- **Symptom:** The route calls
  `usersCollection.findOne({ userId }).project({ ... })` — chaining `.project()`
  on a `findOne` result. In the mongodb v6 driver `findOne` returns a Document
  (or null) rather than a Cursor, so `.project` is undefined and every call
  throws a `TypeError`. The catch block converts it to a 500 response.
- **Why it matters:** The endpoint is completely unreachable. Any caller —
  including the instructor dashboard's "view user details" flow — gets a 500.
- **Failing tests:** `tests/e2e/routes-auth-api.spec.js` ›
  "PRODUCT BUG: GET /users/:userId throws because findOne(...).project() is
  not a function" and the matching 404 variant.
- **Fix:** Pass `projection` as the second argument to `findOne`:
  `usersCollection.findOne({ userId }, { projection: { userId: 1, ... } })`.

### 31b. ✅ FIXED — `POST /api/user-agreement/agree` 500s when no body sent

- **Where:** `src/routes/user-agreement.js:59`.
- **Was:** `const { agreementVersion = '1.0' } = req.body;` threw a TypeError
  when Playwright (or any client) sent a POST with no body, because Express 5
  leaves `req.body` undefined in that case. Same pattern as FINDING #31.
- **Now:** `req.body || {}` — the default value path is reachable.
- **Failing test (now green):** `tests/e2e/routes-user-agreement-api.spec.js` ›
  "POST /agree › an empty request body (no data field) still records the default".

### 31. `DELETE /api/courses/:courseId/units/:unitName` 500s when no body sent

- **Where:** `src/routes/courses.js` line 3140.
- **Symptom:** The handler runs `const { instructorId } = req.body;` before
  falling back to the querystring at line 3144. Express 5 leaves `req.body`
  undefined when the request has no Content-Type / no body, so the
  destructure throws and the route returns 500 — even when the caller
  supplied `?instructorId=...` in the URL.
- **Why it matters:** Clients that send DELETE with the id in the
  querystring (the documented fallback) crash instead of succeeding.
- **Failing test:** `tests/e2e/routes-courses-api.spec.js` ›
  "PRODUCT BUG: DELETE /units/:unitName 500 when no body sent
  (destructures req.body)".
- **Fix:** Default to an empty object — `const { instructorId } = req.body || {};` —
  or read the querystring first.

### 32. `/stats` and `/course-material` handlers in `routes/questions.js` are shadowed by `/:questionId`

- **Where:** `src/routes/questions.js` — `/:questionId` is registered at line
  452, well before `/stats` (line 646) and `/course-material` (line 839).
- **Symptom:** Express matches the dynamic `/:questionId` first for any
  single-segment GET, so `GET /api/questions/stats` and
  `GET /api/questions/course-material` are treated as questionId lookups,
  return 404, and the actual handlers never run.
- **Why it matters:** Two documented endpoints are completely unreachable.
  The course-material content fetch is required for AI question generation
  diagnostics; the stats endpoint is wired into the instructor dashboard.
- **Failing tests:** `tests/e2e/routes-questions-api.spec.js` ›
  "PRODUCT BUG: /stats is shadowed by /:questionId" and
  "PRODUCT BUG: /course-material is shadowed by /:questionId".
- **Fix:** Reorder the `router.get` calls so the static paths are registered
  before the parameterised one — mirroring the comment already in
  `routes/courses.js` ("must come before /:courseId to avoid route matching
  issues").

### 33. `/stats` in `routes/onboarding.js` is shadowed by `/:courseId`

- **Where:** `src/routes/onboarding.js` — `/:courseId` is registered at
  line 155, before `/stats` at line 549.
- **Symptom:** Same root cause as #32. `GET /api/onboarding/stats` is
  matched as a courseId lookup and falls through to a 404.
- **Failing test:** `tests/e2e/routes-onboarding-api.spec.js` ›
  "PRODUCT BUG: /stats is shadowed by /:courseId".
- **Fix:** Move `router.get('/stats', ...)` above `router.get('/:courseId', ...)`.

### 34. ✅ FIXED — 🔒 `src/routes/questions.js` has no role gate or per-course access check on most verbs

- **Where:** Every endpoint in `src/routes/questions.js` *except*
  `POST /generate-ai` (lines 1121-1139). The router is mounted at
  `src/server.js:497` with only `requireAuth` +
  `requireActiveCourseForNonInstructors` in front of it — there is no
  `requireInstructor` / `requireInstructorOrTA` middleware, and the handlers
  themselves do not call any of the `userHasCourseAccess` /
  `hasSystemAdminAccess` helpers used elsewhere.
- **Symptom (extends FINDINGS #23 / #24 to every verb):**
  - A logged-in **student** can `POST`, `PUT`, `DELETE`, `POST /bulk`, and
    `POST /auto-link-learning-objectives` against any **active** course, even
    courses they are not enrolled in.
  - A logged-in instructor can mutate **another instructor's course** via
    PUT / DELETE / bulk / auto-link (FINDINGS #23 covered only POST).
  - `GET /api/questions/lecture` is a cross-course read leak: any
    authenticated caller (including students not enrolled in the target
    course) can list its full assessmentQuestions for any lecture.
- **Failing tests:** `tests/e2e/questions-api-ownership-branches.spec.js` —
  the `Student-role caller cannot mutate questions`,
  `Cross-instructor mutations on another instructor's course`, and
  `GET /api/questions/lecture cross-course information leak` describe blocks.
- **Why it matters:** Course content integrity (vandalism, fabricated
  questions, mass deletion) plus a quiz-content leak. The
  `instructorId`-in-body pattern is decoration; the route never checks it.
- **Fix:** Centralize on a single permission helper for question mutations
  (e.g. `requireCourseInstructorOrTA(courseId)` driven off `req.user`), drop
  body `instructorId`, and add the same access check to `GET /lecture` and
  `GET /:questionId` (already noted in FINDINGS #24).
- **Now:** `src/routes/questions.js` uses one local helper for question-route
  read/write course checks. Students cannot mutate questions, instructors
  cannot mutate or list another instructor's course questions, and TAs must
  have the course permission before direct assessment-question mutations.
  Missing-course write requests from legitimate staff still fall through to
  the existing model-level 400/404 behavior.
- **Failing tests (now green):** `tests/e2e/questions-api-ownership-branches.spec.js`
  all 15 tests; `tests/e2e/ta.spec.js` › "TA with canAccessCourses=false
  cannot create, update, or delete assessment questions by direct API".

### 34b. ✅ FIXED — 🔒 `courses.js` PUT and POST units accepted spoofed `instructorId` from body

- **Where:** `src/routes/courses.js` — `PUT /api/courses/:courseId` (course
  settings) and `POST /api/courses/:courseId/units` (add a unit). Both routes
  accepted `instructorId` from the request and used it for authorization
  instead of comparing to `req.user.userId`.
- **Was:** A TA with `canAccessCourses: false` (or any authenticated
  user who knows a courseId and the real instructor's id) can:
  - rename the course (e.g. to "TA Spoofed Course Name"),
  - change the course's `status` (e.g. flip 'active' → 'inactive'),
  - add new units / lectures.
  All return **200**, all mutations land in the database.
- **Now:** The routes still accept legacy `instructorId` input for existing
  caller compatibility, but it must match the authenticated session user. The
  actual course-access check and mutation query use `req.user.userId`, so a TA
  or mismatched instructorId gets 403 before any write.
- **Failing test (now green):** `tests/e2e/ta.spec.js:1468` ›
  "TA cannot spoof an instructorId to mutate instructor-only course
  settings or units".
- **Why it matters:** Course settings and unit structure are
  instructor-only operations. Bypassing them lets a TA (or any session
  with a guessed instructorId) silently sabotage a course.
- **Pattern:** Same shape as FINDING #34 — request-body identity must not be
  trusted for course mutations. See Redundancies R10.

### 35b. ✅ FIXED — `deleteAssessmentQuestion` returns `deletedCount: 1` even when `$pull` matched nothing

- **Where:** `src/models/Course.js` `deleteAssessmentQuestion` (~line 622).
- **Was:** The update used `$pull` to remove the question and `$set` to bump
  `updatedAt`. Because `$set` always changes the doc, `result.modifiedCount`
  was `1` regardless of whether `$pull` actually matched. The route reported
  `deletedCount: 1` for a no-op DELETE on an unknown questionId, and also
  spuriously bumped the course's `updatedAt`.
- **Now:** Existence-check the questionId in the lecture's
  `assessmentQuestions` first. If absent, return `{ success: true,
  deletedCount: 0 }` without touching the doc.
- **Failing test (now green):** `tests/e2e/questions-api-ownership-branches.spec.js` ›
  "DELETE on existing course/lecture but unknown questionId → success with
  deletedCount=0".

### 35. `PUT /api/questions/:questionId` silently creates when the question does not exist

- **Where:** `src/routes/questions.js` PUT handler (line 519-579) →
  `src/models/Course.js` `updateAssessmentQuestions` (line 499-587).
- **Symptom:** When the supplied `:questionId` does not match any existing
  question on the target lecture, the model's `existingQuestionIndex < 0`
  branch (line 561-582) **inserts** a new question with the caller-supplied
  id and `$push`-es it onto `assessmentQuestions`. The PUT response shape is
  identical to a real update (`success: true, updatedCount: 1`).
- **Why it matters:** A REST `PUT` to an unknown resource should 404 — silent
  upsert is surprising, hides bugs in callers that race
  delete + update, and lets a stale client recreate a question that was just
  removed. It also means the same id-confusion / cross-instructor abuse path
  in FINDING #34 can be used to *create* questions on another instructor's
  course just by `PUT`-ing to any unused id.
- **Failing test:** `tests/e2e/questions-api-ownership-branches.spec.js` ›
  "PRODUCT BUG (FINDING #35): PUT on an unknown questionId silently creates
  a new question".
- **Fix:** In the PUT handler, look up the question first (or have the model
  surface `created` truthy and reject it on the PUT path) and return 404 when
  the question does not exist. Bulk insertion / create stays the POST path.

### 36. ✅ FIXED — 🔒 `DELETE /api/flags/:flagId` has no role gate or ownership check

- **Where:** `src/routes/flags.js` lines 490-538. The router is mounted at
  `src/server.js:492` with `requireAuth` + `requireActiveCourseForNonInstructors`
  + `requireStudentEnrolled`. The latter two only fire when a `courseId` is
  in `req.body`, `req.query`, or `req.params` — none of which exist for
  `DELETE /api/flags/:flagId` — so they pass through. The route handler
  itself looks up the flag by `flagId` only and deletes it.
- **Symptom:** Any authenticated user (student, TA, instructor) can delete
  any flagged-question document in the database — including flags belonging
  to other students in other courses they have no relationship with.
- **Why it matters:** Students can silently erase their own flags after the
  fact, or grief other students by removing legitimate flags. Instructors
  can erase flags raised against questions on courses they don't own.
- **Failing test:** `tests/e2e/flags-api-error-branches.spec.js` ›
  "PRODUCT BUG: a student can delete any flag (no role gate)".
- **Fix landed:** Extracted `loadFlagAndAssertCourseAccess(req, res, flagId)`
  in `src/routes/flags.js` (top of file). It (1) requires authentication,
  (2) requires `role === 'instructor' || 'ta'`, (3) loads the flag and 400s
  if missing (preserving the legacy "from model" contract), (4) calls
  `CourseModel.userHasCourseAccess(db, flag.courseId, user.userId, user.role)`
  and 403s if not on the course. The DELETE route (and the two PUT routes
  in FINDING #37) now call this helper.
- **Failing test (now green):** `tests/e2e/flags-api-error-branches.spec.js` ›
  "PRODUCT BUG: a student can delete any flag (no role gate)".

### 37. ✅ FIXED — 🔒 Flag instructor/TA response endpoints don't verify course membership

- **Where:** `src/routes/flags.js` PUT `/:flagId/response` (lines 288-364)
  and PUT `/:flagId/status` (lines 370-438). Both endpoints only check
  `user.role !== 'instructor' && user.role !== 'ta'` — they never confirm
  that the caller is on the specific course the flag belongs to.
- **Symptom:** Any instructor in the system can write an "instructor
  response" to a flag raised on another instructor's course, or flip a
  flag's status across course boundaries. A TA who is a TA on *any* course
  has the same cross-course write access.
- **Why it matters:** Flagged questions surface course-specific feedback /
  appeals. Allowing arbitrary instructors and TAs to author the canonical
  reply or close the case undermines the workflow's integrity and leaks the
  flag content to unrelated faculty.
- **Failing tests:** `tests/e2e/flags-api-error-branches.spec.js` ›
  "PRODUCT BUG: an instructor not on the flag's course can still update the
  response" and "PRODUCT BUG: a TA not on the flag's course can still
  update the status".
- **Fix landed:** Both PUT routes now call the same
  `loadFlagAndAssertCourseAccess` helper introduced in FINDING #36's fix.
  Cross-instructor / cross-course writes return 403.
- **Failing tests (now green):**
  - `tests/e2e/flags-api-error-branches.spec.js` ›
    "PRODUCT BUG: an instructor not on the flag's course can still update
    the response"
  - same file › "PRODUCT BUG: a TA not on the flag's course can still
    update the status".
- **Test-side cleanup:** Two seeds in `flags-api-error-branches.spec.js`
  and `flags-api-coverage.spec.js` were storing `tas` as
  `[{ userId, email }]` objects, which `userHasCourseAccess` doesn't match
  (it queries `tas: userId` against bare strings, per `Course.js:1219`
  and the schema comment at L18). Seeds updated to `tas: [taId]`.

### 38. `updateInstructorResponse` defaults `flagStatus` to "resolved" but does not stamp `resolvedAt`

- **Where:** `src/models/FlaggedQuestion.js` lines 165-180.
- **Symptom:** When the caller omits `flagStatus`, the model stores
  `flagStatus: 'resolved'` (via the `responseData.flagStatus || 'resolved'`
  default on line 169) but the subsequent `if (responseData.flagStatus
  === 'resolved')` check (line 173) tests the *input* value, which is
  `undefined`, so `resolvedAt` is never set.
- **Why it matters:** The implicit invariant "every flag in `'resolved'`
  state has a `resolvedAt` timestamp" is broken silently. Audit / dashboard
  queries that compute resolution latency or filter for "resolved without
  timestamp" miss these records.
- **Failing test:** `tests/e2e/flags-api-error-branches.spec.js` ›
  "PRODUCT BUG: stored.flagStatus='resolved' without a matching
  resolvedAt".
- **Fix:** Check the resolved status against the *final* value, e.g.
  `const finalStatus = responseData.flagStatus || 'resolved'; if
  (finalStatus === 'resolved') updateData.resolvedAt = now;`.

### 39. ✅ FIXED — auth middleware always redirected API requests instead of returning 401 JSON

- **Where:** `src/middleware/auth.js` — `requireAuth` and ~15 other role/
  permission gates all used `if (req.path.startsWith('/api/'))` to decide
  between JSON 401 and HTML redirect.
- **Symptom:** When a request comes in through a mounted router
  (`app.use('/api/foo', router)`), Express strips the mount prefix from
  `req.path` inside the middleware — so `req.path` is `/agree`, not
  `/api/user-agreement/agree`. The startsWith check is always false for
  any mounted API route, so every unauthenticated API call returned a
  302 to `/login` instead of a 401 JSON. Playwright (and any fetch())
  auto-follows the redirect and ends up with a 200 + HTML body, masking
  the real auth failure.
- **Impact pre-fix:** Frontend `fetch()` that tried `await response.json()`
  on an expired-session API call would silently throw on the HTML body;
  users saw generic error toasts instead of a clear "session expired"
  signal. Hid every auth-required failure behind a fake 200.
- **Failing tests that surfaced it:**
  - `tests/e2e/routes-user-agreement-api.spec.js` › "unauthenticated GET /status returns 401"
  - `tests/e2e/routes-user-agreement-api.spec.js` › "unauthenticated POST /agree returns 401"
  - `tests/e2e/routes-mental-health-flags-api.spec.js` › "unauthenticated GET /course/:courseId returns 401"
  - `tests/e2e/routes-mental-health-flags-api.spec.js` › "unauthenticated PUT /escalate returns 401"
  - `tests/e2e/routes-struggle-activity-api.spec.js` › "unauthenticated request returns 401 with JSON body"
- **Fix landed:** Replaced `req.path.startsWith('/api/')` with
  `req.originalUrl.startsWith('/api/')` in all 16 occurrences across
  the middleware file. `req.originalUrl` keeps the full client URL
  regardless of router mount depth. Page-route behavior (redirect to
  `/login` for unauthenticated `/student/dashboard` etc.) is unchanged.
- **Follow-up — not done:** The frontend has only one explicit 401 handler
  (`public/instructor/scripts/instructor.js:4324`). Now that the server
  emits clean JSON 401s on session expiry, a global handler in
  `public/common/scripts/auth.js` could intercept any API 401 and
  redirect the user to `/login`, instead of leaving them stuck on the
  current page with a generic error. See Redundancies.md → R0.

### 40. ✅ FIXED — 🔒 Document APIs trusted direct student access and body `instructorId`

- **Where:** `src/routes/documents.js` — direct document creation, listing,
  stats, fetch, delete, and cleanup routes.
- **Was:** A student could call document APIs directly and either read course
  material metadata or mutate course document state. Some mutation routes also
  accepted body-supplied `instructorId`, so the request body could be used as
  the authorization identity instead of the authenticated session.
- **Now:** Document routes authorize from `req.user`, restrict direct document
  management/read APIs to course staff, require real course access, and reject
  instructor-body identity mismatches before writes. TA access is still
  supported when the TA has the course permission.
- **Failing tests (now green):** `tests/e2e/chat-rag-documents.spec.js` ›
  "Document API permission boundaries for students", and `tests/e2e/ta.spec.js`
  › "TA with canAccessCourses=false cannot create, upload, or delete course
  documents by direct API".
- **Pattern:** Same root cause as FINDINGS #23/#34/#34b: route handlers must
  authorize from `req.user` and course membership, not request-body identity.
  See Redundancies R10.

### 41. ✅ FIXED — 🔒 Direct Qdrant APIs were reachable by students

- **Where:** `src/routes/qdrant.js` — `POST /process-document`, `POST /search`,
  `POST /cleanup-vectors`, `GET /collection-stats`, and
  `DELETE /document/:documentId`.
- **Was:** Direct vector-processing/search/cleanup routes had validation and
  service-level logic but no role gate. A student session could reach them
  through direct API calls, and course-scoped routes did not consistently
  verify that staff access matched the requested course.
- **Now:** Direct Qdrant routes require an authenticated instructor, TA with the
  course permission, or system admin. Course-scoped requests check access to the
  requested course before processing/searching/cleanup; students receive 403
  before validation/service work.
- **Failing tests (now green):** `tests/e2e/chat-rag-documents.spec.js` ›
  "Qdrant API permission boundaries for students".
- **Pattern:** Same route-level course-access gap as FINDING #40. See
  Redundancies R10.

### 42. ✅ FIXED — 🔒 Student chat/history routes trusted body or path `studentId`

- **Where:** `src/routes/chat.js` `POST /api/chat/save`,
  `src/routes/students.js` `DELETE /api/students/:courseId/:studentId/sessions/:sessionId`,
  and `src/routes/struggle-activity.js` `GET /api/struggle-activity/student/:userId`.
- **Was:** A logged-in student could supply another student's id in the body or
  URL and save a chat row under that account, delete another student's session
  through the instructor delete path, or read another student's struggle
  activity history.
- **Now:** Student sessions can only save/read/delete under their own user id;
  the non-`/own` session delete route is instructor-only.
- **Failing tests (now green):** `tests/e2e/student-chat.spec.js` ›
  "Security — student-controlled inputs that bypass auth".
- **Pattern:** Request body/path identity must be treated as the target record,
  not as authorization. See Redundancies R19.

### 43. ✅ FIXED — 🔒 TA sessions could load instructor-only pages directly

- **Where:** `src/server.js` protected page routes for `/instructor/home`,
  `/instructor/settings`, and `/instructor/downloads`.
- **Was:** The home/settings routes used `requireInstructorOrTA`, so direct
  TA navigation loaded instructor-only pages. The downloads route failed the
  system-admin check but redirected the TA to `/instructor/home`, which was
  also reachable.
- **Now:** TA direct navigation to instructor-only pages redirects to TA pages
  before instructor HTML is served. Shared TA-enabled instructor pages, such as
  course documents and flagged content, still use the existing TA permission
  gates.
- **Failing test (now green):** `tests/e2e/ta.spec.js` ›
  "TA cannot access instructor home, settings, downloads, or student hub pages".
- **Pattern:** Page route role guards must distinguish "shared instructor/TA
  shell" routes from truly instructor-only pages. See Redundancies R20.

### 44. ✅ FIXED — 🔒 Flag and TA course APIs did not consistently enforce course-scoped permissions

- **Where:** `src/routes/flags.js`, `src/routes/courses.js`, and
  `public/ta/scripts/ta-home.js`.
- **Was:** Several direct APIs either trusted broad role checks or stale course
  context. `/api/flags/my` could return a student's flags for courses they no
  longer had access to; `/api/flags/status/:status` could leak flags from
  courses outside the caller's review scope; TA flag read/write endpoints did
  not consistently enforce `canAccessFlags`; and course content mutation
  endpoints allowed TA/course access to be inferred too broadly or from
  body-supplied instructor identity. The TA dashboard could also let a stale
  persisted preference override the currently assigned course list.
- **Now:** Flag reads are filtered to courses the caller may actually review,
  student flag reads are filtered by current enrollment, flag mutations require
  course-scoped `canAccessFlags` for TAs, and the affected course-content
  mutation APIs require course-scoped management access tied to the session
  user. TA dashboard initial course selection now prefers assigned course data
  over stale profile preference data.
- **Failing tests (now green):**
  - `tests/e2e/flagging.spec.js` › "DESIRED: direct /my access does not return
    flags from courses where the student is not enrolled"
  - `tests/e2e/flagging.spec.js` › "DESIRED: scopes results to courses the
    caller teaches — should NOT leak flags from an unrelated instructor's
    course"
  - `tests/e2e/ta.spec.js` › "TA with canAccessFlags=false is hidden from and
    denied flagged-content access"
  - `tests/e2e/ta.spec.js` › "TA with canAccessCourses=false cannot mutate
    topics or unit structure by direct API"
  - `tests/e2e/ta.spec.js` › "TA with canAccessFlags=false cannot respond,
    status-update, or delete flags by direct API"
  - `tests/e2e/ta.spec.js` › "TA permissions are scoped to the requested
    course, not any course with that permission"
  - `tests/e2e/ta.spec.js` › "TA with canAccessFlags=false cannot use
    non-course-scoped flag APIs"
- **Pattern:** Course-scoped permissions must be checked against the requested
  resource and the session user, not inferred from any matching role or
  client-supplied course/instructor context. See Redundancies R10.

### 45. ✅ FIXED — 🔒 TA settings and flag-status flows used the wrong course/actor context

- **Where:** `public/ta/scripts/ta-settings.js`,
  `src/routes/settings.js`, and `src/models/FlaggedQuestion.js`.
- **Was:** TA settings UI checked permissions across all assigned courses, so
  `?courseId=...` could show and navigate with permissions from another
  selected or stale course. Direct course settings mutation APIs accepted TA
  sessions with course upload access and wrote instructor-only settings.
  Status-only flag moderation changed the flag status but did not persist the
  acting TA/instructor id for audit.
- **Now:** TA settings permission display/navigation is evaluated against the
  URL-selected course context, settings writes require an instructor who owns
  the requested course, and status-only flag moderation records
  `instructorId`.
- **Failing tests (now green):**
  - `tests/e2e/ta.spec.js` › "TA with flag permission can review and dismiss
    a seeded flag"
  - `tests/e2e/ta.spec.js` › "TA settings displays account details and
    permission status"
  - `tests/e2e/ta.spec.js` › "TA settings navigation respects the selected
    course permission context"
  - `tests/e2e/ta.spec.js` › "TA cannot mutate instructor settings APIs even
    when course upload permission is allowed"
- **Pattern:** UI and API permission checks must use the requested course
  context, and instructor-only settings writes must not be inferred from TA
  course feature permissions. See Redundancies R10.

### 46. ✅ FIXED — 🧪 TA spec setup left stale assignments from other tests

- **Where:** `tests/e2e/ta.spec.js` `resetTAUserState()`.
- **Was:** Several TA dashboard tests claimed to seed zero or one assigned
  course, but the helper only deleted that file's known course ids. If another
  spec had previously assigned the same TA to a different course, `/api/courses/ta/:taId`
  correctly returned that stale assignment and the tests failed against valid
  product behavior.
- **Now:** The TA spec setup removes the test TA from all existing course
  assignments, unsets per-course TA permissions, and clears stale selected
  course preference before seeding the scenario under test.
- **Failing tests (now green):**
  - `tests/e2e/ta.spec.js` › "TA dashboard marks an assigned inactive course
    while preserving permitted actions"
  - `tests/e2e/ta.spec.js` › "TA with no assigned courses sees an empty
    dashboard state and no course actions"
  - `tests/e2e/ta.spec.js` › "TA assignment revocation blocks stale
    selected-course access"
- **Pattern:** This was a test fixture isolation issue, not a production
  behavior bug.

### 47. ✅ FIXED — 🚩 Flagged-content page duplicate no-course redirect and browser-only TA coverage drift

- **Where:** `public/instructor/scripts/flagged.js` and
  `tests/e2e/flagged-coverage.spec.js`.
- **Was:** When no course could be resolved, `getCurrentCourseId()` scheduled
  an onboarding redirect and `loadFlaggedContent()` showed the same error
  notification and redirect again. The browser-only flagged coverage spec also
  tried to exercise TA sidebar branches while navigating through the real
  server page guard, so the mocked API state never loaded the HTML for TA
  scenarios. Two assertions also contradicted the page helpers by expecting
  lowercase `tutor mode` / platform-specific invalid-date output.
- **Now:** The no-course redirect path is guarded by one shared in-flight flag,
  invalid timestamps return the intended fallback text, and the TA browser
  harness serves the page HTML directly while mocking the API surface it is
  designed to cover.
- **Failing tests (now green):**
  - `tests/e2e/flagged-coverage.spec.js` › "renders multiple flag cards
    (reasons, priorities, resolved response, status text) and updates stats"
  - `tests/e2e/flagged-coverage.spec.js` › "redirect-on-missing-course path:
    API returns no courses, page shows notification and navigates to onboarding"
  - `tests/e2e/flagged-coverage.spec.js` › "TA sees TA nav rows, instructor
    rows are hidden, and \"My Courses\" link navigates when permitted"
  - `tests/e2e/flagged-coverage.spec.js` › "TA cannot navigate when the
    selected course denies that feature — shows a notification and stays put"
  - `tests/e2e/flagged-coverage.spec.js` › "TA with zero assigned courses gets
    a warning notification on navigation attempts"
  - `tests/e2e/flagged-coverage.spec.js` › "display helpers cover every reason
    / bot mode / status mapping"
- **Pattern:** Mixed product and test-harness cleanup; no shared redundancy
  entry applies.

### 48. ✅ FIXED — 🔒 Student flag notifications trusted foreign flag rows from `/api/flags/my`

- **Where:** `public/student/scripts/flag-notifications.js`.
- **Was:** The notification poller fetched `/api/flags/my` without the
  selected course context and then compared/stored every returned flag. If the
  API ever returned a flag for another course or another student, the client
  could show a notification for data outside the active student/course.
- **Now:** The poller includes `courseId` when a selected course exists,
  persists `courseId`/`studentId` in its local snapshot, and filters current
  plus stored flags against the active student and selected course before
  detecting changes or saving state.
- **Failing test (now green):** `tests/e2e/flag-notifications.spec.js` ›
  "DESIRED: ignores cross-student or non-selected-course flags if the API
  response contains them".
- **Pattern:** Client-side context checks mirror the server-side course/user
  scoping work tracked in Redundancies R10.

### 49. ✅ FIXED — 📝 Agreement modal reused student copy for instructor and TA contexts

- **Where:** `public/common/scripts/agreement-modal.js`.
- **Was:** The shared agreement modal always rendered student-oriented copy
  (`Your AI-Powered Study Assistant`) even when opened from instructor or TA
  paths. The modal is shared and can be displayed in all three contexts.
- **Now:** The modal chooses static copy from the current path: student copy is
  unchanged, instructor paths render instructor-tool copy, and TA paths render
  TA-tool copy.
- **Failing test (now green):** `tests/e2e/agreement-modal-branches.spec.js`
  › "student, instructor, and TA contexts render distinct copy".

## Duplicate top-level declarations in `public/instructor/scripts/instructor.js`

- `waitForAuth`: the declaration at lines 13-33 is shadowed by the later declaration at lines 6952-6969. Coverage marks the shadowed copy as uncovered.
- `showNotification`: the declaration at lines 344-373 is shadowed by the later declaration at lines 6753-6782. Coverage marks the shadowed copy as uncovered.

## Duplicate top-level declarations in `public/instructor/scripts/onboarding.js`

- `removeObjective`: the declaration at lines 1590-1605 is shadowed by the later declaration at lines 1868-1872. Coverage marks the shadowed copy as uncovered.

## History page auth-helper fallback in `public/student/scripts/history.js` ✅ FIXED

- **Was:** The branch at lines 183-185 intended to call the `auth.js` helper
  when `window.getCurrentUser` had been replaced by an external helper.
  But `history.js` declares its own top-level `function getCurrentUser()`,
  and in a non-strict global script that lexical name *aliases*
  `window.getCurrentUser` — so the check
  `window.getCurrentUser !== getCurrentUser` was always false once
  `window.getCurrentUser` got reassigned. A page-driven test that installed
  an external helper after load returned `null`.
- **Now:** the function captures itself into a separately-named
  module-private const (`_historyGetCurrentUserSelf`) immediately after the
  declaration. The check is against that const, which doesn't share
  storage with the window property, so the fallback branch is reachable.
- **Failing test (now green):**
  `tests/e2e/student-history-storage-branches.spec.js` ›
  "current user resolves through an external auth helper".
- **Pattern:** see Redundancies R1c — this is a class of footgun that will
  recur until page scripts are wrapped in IIFEs or migrated to modules.

## Mobile layout initial collapsed icon ✅ FIXED

- **Was:** `public/common/scripts/mobile-layout.js` always initialized the
  toggle button icon to `▲`, even if another script or server-rendered markup
  had already put `mobile-collapsed` on `body`.
- **Now:** the icon is initialized from the actual `body.mobile-collapsed`
  state before click handlers run, so the first render matches the visible
  layout.
- **Failing test (now green):** `tests/e2e/mobile-layout-coverage.spec.js` ›
  "PRODUCT BUG: initial icon ignores body already in mobile-collapsed state".

## Qdrant service coverage notes

- `src/services/qdrantService.js` has no score-threshold search option today. `searchDocuments()` builds `vector`, `limit`, `with_payload`, `with_vector`, and optional `courseId` / `lectureName` / `lectureNames` filters only, so there is no product branch to cover for threshold inclusion/exclusion.
- The service also has no retry or back-off implementation around client construction, collection validation, search, upsert, scroll, or delete. The added harness coverage exercises construction/config/provider failures and direct operation failures, but retry/back-off remains absent rather than skipped.

## Dead CSS candidates in `public/styles/documents.css`

While adding `tests/e2e/documents-css-coverage.spec.js`, `rg` found several
selectors that are only present in `documents.css` and not in current
instructor HTML or dynamic DOM construction. These were intentionally not
covered by fake harness markup:

- Legacy document-list/table upload UI: `.upload-box`, `.upload-button`,
  `.documents-list`, `.document-filters`, `#document-search`,
  `#document-filter`, `.documents-table`, `.status`, `.empty-state-icon`.
- Prototype browsing/selection UI: `.document-cards`, `.document-card`,
  `.folder-structure`, `.folder-item`, `.file-type-section`,
  `.file-type-options`, `.week-selection`, `.form-group`.
- Superseded upload/modal flow selectors: `.modal-step`, `.step-indicators`,
  `.step-dot`, `.file-upload-area`, `.upload-zone`, `.objectives-checkbox`,
  `.objectives-input`, `.content-preview`, `.preview-section`,
  `.validation-actions`.
- Calibration/prototype question editor selectors not present in current
  `index.html`/`onboarding.html` DOM: `.delete-question`, `.option-item`,
  `.score-box`, `.generate-questions-container`, `.generate-btn`,
  `.generate-help-text`.

These should be deleted or moved to a page-specific stylesheet if the product
no longer renders the corresponding UI.

### ✅ FIXED — `home.js` setSelectedCourse cascade read localStorage on every step

- **Where:** `public/instructor/scripts/home.js` `setSelectedCourse()` and the
  subroutines it awaits (`loadStatistics`, `loadFlaggedContent`,
  `checkMissingContent`, `loadStruggleTopics`, `loadApprovedGlobalTopics`,
  `loadPersistenceTopics`, `loadInitialStruggleActivity`,
  `loadWeeklyStruggleChart`).
- **Was:** Each subroutine called `getSelectedCourseId()` which re-reads
  `localStorage`. The cascade is interruptible — between the DOM update and
  the tail of background loaders, anything else (a Playwright `page.evaluate`,
  another tab, a stale event handler) could flip `localStorage.selectedCourseId`
  to a different value, and the loaders would suddenly fire `/api/*` requests
  against that other course.
- **Now:** `setSelectedCourse(courseId)` pins the active courseId in a
  module-level `_pinnedCourseId` for the duration of the cascade.
  `getSelectedCourseId()` returns the pin first, so dependent loaders always
  see the same value. The pin is cleared once the cascade ends, and also when
  `clearSelectedCourse()` runs.
- **Failing test (now green):** `tests/e2e/instructor-home.spec.js` › "does
  not use a stale unauthorized selected course from localStorage".

### ✅ FIXED — instructor home didn't validate localStorage course against owned courses

- **Where:** `public/instructor/scripts/home.js`.
- **Was:** A stale `selectedCourseId` left over from a different role/session
  drove `setSelectedCourse(staleCourse)` and triggered per-course fetches
  against a course the instructor doesn't own.
- **Now:** New `sanitizeStaleSelectedCourseStorage()` runs at the top of
  `initializeHomePage()` and strips any `selectedCourseId` that isn't in the
  instructor's owned courses list (URL `?courseId=` always wins). The
  pre-validation is also mirrored inside `loadCurrentCourse()` for direct
  callers.
- **Failing test (now green):** same as above.

### ✅ FIXED — onboarding `saveAssessment` double-saved already-persisted questions

- **Where:** `public/instructor/scripts/onboarding.js` `saveAssessment()`.
- **Was:** `saveAssessment()` iterated all questions and unconditionally POSTed
  each one to `/api/questions`, even ones that the earlier "persist on add"
  fast path had already saved (`question.saved === true`). E2E coverage that
  counted POSTs saw two saves per question.
- **Now:** `saveAssessment()` skips entries with `question.saved === true`, the
  same guard `saveAllUnit1Data()` already uses.
- **Failing tests (now green):**
  `tests/e2e/instructor-onboarding-save-upload-modal-branches.spec.js` ›
  "skips already saved questions when saving all Unit 1 data" and
  `tests/e2e/instructor-onboarding-focused.spec.js` ›
  "covers final onboarding serialization, save-assessment paths, and AI
  fallback content".

### ✅ FIXED — student-chat mode toggle was overwritten on every "no questions" branch

- **Where:** `public/student/scripts/student.js` `showNoQuestionsMessage()`
  and `showNoQuestionsForUnitMessage()`.
- **Was:** Both helpers unconditionally wrote `localStorage.studentMode =
  'tutor'`, which clobbered an explicit student toggle on every render. After
  the mode toggle's change handler set `'protege'`, the next paint of those
  messages reset it back to `'tutor'`.
- **Now:** Both helpers only seed `'tutor'` when the student has not toggled
  yet — they check the `lastModeChange` timestamp the toggle handler writes,
  and otherwise call `updateModeToggleUI(localStorage.studentMode || 'tutor')`.
- **Failing test (now green):** `tests/e2e/student-chat.spec.js` › "mode
  toggle defaults to Tutor and persists changes to localStorage".

### ✅ FIXED — qdrant harness branches reached 401 before exercising the failure under test

- **Where:** `tests/e2e/helpers/src-route-model-harness.js`.
- **Was:** The harness modes for `qdrant-process-fails`, `qdrant-search-throws`,
  `qdrant-delete-fails`, `qdrant-collection-fails`, `qdrant-cleanup-no-db`,
  etc. did not set `state.user`. `requireDirectQdrantAccess` then short-circuits
  on `!req.user` with a 401, so the qdrant route's actual failure branch was
  unreachable from the harness.
- **Now:** Each of those modes installs an instructor user (and stubs
  `CourseModel.userHasCourseAccess` where needed) so the request reaches the
  service-layer failure the spec is targeting.

### ✅ FIXED — promote-to-ta happy-path test relied on no course check

- **Where:** `tests/e2e/routes-auth-api.spec.js` › "happy path promotes a
  student to TA and assigns invitedCourses".
- **Was:** Test POSTed `courseId: 'BIOC-E2E-API-AUTH-X'` without seeding it.
  After the FINDINGS course-ownership check landed on `POST
  /api/auth/promote-to-ta`, the route correctly 404'd and the test failed.
- **Now:** Test seeds the course owned by the test instructor before promoting,
  asserts the happy path, then cleans up the course.
