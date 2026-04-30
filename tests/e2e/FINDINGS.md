# E2E Test Findings

Bugs / inconsistencies surfaced by the Playwright suite. Each entry assumes a
test asserts the *expected* behavior; if the test fails, the discrepancy is
recorded here so it can be triaged into a real issue and fixed in code.

> Policy: when a new test fails, **don't relax the assertion**. Document it
> here, leave the test failing, and let the failure prompt a real fix.

---

## ⚠️ Headline issue: assessment-question schema is inconsistent

The same conceptual data — an assessment question — is persisted in **two
different shapes** depending on which UI flow created it.

| Field | `onboarding.js` (structured) | `instructor.js` (string-y) |
|---|---|---|
| TF `correctAnswer` | boolean `true` / `false` | string `"true"` / `"false"` |
| MCQ `options` | array `["A text", "B text", ...]` | object `{A: "...", B: "...", ...}` |
| MCQ `correctAnswer` | numeric index `2` | letter `"C"` |
| SA `correctAnswer` | string | string ✓ |

### Decided direction: standardize on the structured shape

Booleans should be booleans, ordered lists should be arrays, positions should
be numbers. The string-y shape has been pushing those concepts through string
radio values, which is exactly why `student.js` accumulated dual-shape branches
and `quiz.js`/`chat.js` were one bad input away from crashing.

### Phase plan

- **✅ Phase 1 — DONE.** Defensive `String(...)` coercion in `quiz.js:211` and
  `chat.js:1319` so the comparison works regardless of which shape is in the DB.
  Stops the runtime crash. Both shapes compare correctly today.
- **Phase 2 — fix `instructor.js` `saveQuestion()`** to write the structured
  shape: TF→boolean, MCQ options→array, MCQ correctAnswer→numeric index.
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
- **Compare to:** `onboarding.js` (~line 2228), correctly coerces to boolean.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add an assessment question to a unit"
- **Fix:** Phase 2.

### 2. `instructor.js` saves MCQ `options` as an object (not an array)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4217)
- **Symptom:** Persists `options: { A: "...", B: "...", C: "...", D: "..." }`.
- **Compare to:** `onboarding.js` (~line 2238) which uses an array.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Fix:** Phase 2.

### 3. `instructor.js` saves MCQ `correctAnswer` as a letter (not a numeric index)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4240)
- **Symptom:** `correctAnswer: "C"` instead of `2`.
- **Compare to:** `onboarding.js` (~line 2241), which stores the array index.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Fix:** Phase 2 (depends on #2 — options must be an array first).

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
