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

| Field | `onboarding.js` modal state | `onboarding.js` final POST | `instructor.js` POST |
|---|---|---|---|
| TF `correctAnswer` | boolean `true` / `false` | string `"true"` / `"false"` | string `"true"` / `"false"` |
| MCQ `options` | array `["A text", "B text", ...]` | object `{A: "...", B: "...", ...}` | object `{A: "...", B: "...", ...}` |
| MCQ `correctAnswer` | numeric index `2` | letter `"C"` | letter `"C"` |
| SA `correctAnswer` | string | string | string |

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

### 1. `instructor.js` saves true/false `correctAnswer` as a string

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4207)
- **Symptom:** Persists `correctAnswer: "true"` (string) instead of boolean `true`.
- **Compare to:** `onboarding.js` `saveQuestion()` (~line 2228), which correctly
  coerces the modal state to boolean before a later helper turns it back into a
  string for the API.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add an assessment question to a unit"
- **Fix:** Phase 2a/2b.

### 2. `instructor.js` saves MCQ `options` as an object (not an array)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4217)
- **Symptom:** Persists `options: { A: "...", B: "...", C: "...", D: "..." }`.
- **Compare to:** `onboarding.js` `saveQuestion()` (~line 2258) uses an array
  in memory, but `saveUnit1AssessmentQuestion()` (~line 3711) converts that
  array back to an object before POSTing.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Fix:** Phase 2b.

### 3. `instructor.js` saves MCQ `correctAnswer` as a letter (not a numeric index)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4240)
- **Symptom:** `correctAnswer: "C"` instead of `2`.
- **Compare to:** `onboarding.js` `saveQuestion()` (~line 2269) stores the array
  index in memory, but `saveUnit1AssessmentQuestion()` (~line 3721) converts the
  index back to a letter before POSTing.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Fix:** Phase 2b (depends on #2 — options must be an array first).

### 4. ✅ FIXED (Phase 1) — `quiz.js` / `chat.js` could throw on non-string `correctAnswer`

- **Where:** `src/routes/quiz.js` line 211, `src/routes/chat.js` line 1319
- **Was:** `studentAnswer.toLowerCase() === question.correctAnswer.toLowerCase()` threw `TypeError` when `correctAnswer` was a boolean (TF) or number (MCQ index).
- **Now:** Both sides coerced via `String(...)`, comparison works for any shape.
- **Status:** Defensive coercion landed; can stay even after Phase 3 lands as belt-and-suspenders.

### 5. `student.js` has accumulated dual-shape handling

- **Where:** `public/student/scripts/student.js` lines 2200, 2213, 2216–2221
- **Symptom:** Branches that exist only because two ingest paths persist different shapes.
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
  - `src/routes/quiz.js` line 186 — requires `{ courseId, questionId, lectureName, studentAnswer }`. Looks up the question via `CourseModel.getAssessmentQuestions`.
  - `src/routes/chat.js` line 1281 — requires `{ practiceId, studentAnswer }`. Looks up the question from an in-memory store keyed by `practiceId`.
- **Symptom:** Same conceptual operation ("check this student's answer to this question") implemented two ways with different request shapes, different lookup mechanisms, different response payloads, and different error handling. They both have the (now-fixed) string-comparison logic; future bugs fixed in one won't propagate to the other.
- **Fix:** Extract a shared `evaluateObjectiveAnswer(question, studentAnswer)` utility that both routes call. Keep the two endpoints (they serve different UIs / lookup paths) but the core logic should live in one place.

### 10. Soft-delete invariant is enforced inconsistently across `getCourse*` helpers

- **Where:** Various places in `src/models/Course.js` and route handlers.
- **Pattern:** Some routes filter `status !== 'deleted'` directly in the route (defensive), some helpers do, some don't. Closely related to #6 and #7.
- **Fix:** Audit every read path that resolves a `courseId` → course doc; standardize on either always filtering or having one canonical "active courses only" helper.

### 11. 🔒 `/api/lectures/publish-status` trusts an `instructorId` query param with no auth check

- **Where:** `src/routes/lectures.js` lines 81–121.
- **Symptom:** Route accepts `instructorId` and `courseId` from query string and calls `CourseModel.getLecturePublishStatus(db, courseId)` directly. **There is no check that `req.user.userId === instructorId` or that the requester has any access to the course.** A logged-in student (or any authenticated user) hitting `GET /api/lectures/publish-status?instructorId=anybody&courseId=anycourse` gets back the publish state of every unit.
- **Compare to:** Other `lectures.js` routes (e.g. `/publish` at line 14) check `userHasCourseAccess()` before mutating.
- **Why it matters:** Information leak — students could enumerate course publish states, including units the instructor hasn't released.
- **Fix:** Drop the `instructorId` query param (use `req.user.userId` only). Add `userHasCourseAccess(db, courseId, req.user.userId)` check before responding.

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

### 23. Question routes trust body `instructorId` and do not check course access

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

### 24. `GET /api/questions/:questionId` searches globally with no access check

- **Where:** `src/routes/questions.js` lines 452-503.
- **Symptom:** The endpoint finds a question by ID across all courses and returns
  it to any authenticated requester. It does not verify course membership or
  instructor/TA access after finding the containing course.
- **Why it matters:** Question IDs are not secrets, and this can leak assessment
  content across courses.
- **Fix:** Include course context in the request, or derive the containing course
  and check `userHasCourseAccess()` before responding.

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

