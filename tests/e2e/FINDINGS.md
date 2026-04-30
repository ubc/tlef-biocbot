# E2E Test Findings

Bugs / inconsistencies surfaced by the Playwright suite. Each entry assumes a
test asserts the *expected* behavior; if the test fails, the discrepancy is
recorded here so it can be triaged into a real issue and fixed in code.

> Policy: when a new test fails, **don't relax the assertion**. Document it
> here, leave the test failing, and let the failure prompt a real fix.

---

## 1. `instructor.js` saves true/false `correctAnswer` as a string, not a boolean

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4207)
- **Symptom:** Saving a TF question via the instructor course-management page persists `correctAnswer: "true"` (string) instead of `correctAnswer: true` (boolean).
- **Compare to:** `public/instructor/scripts/onboarding.js` `saveQuestion()` (~line 2228), which correctly does `selectedAnswer.value === 'true'` to coerce.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add an assessment question to a unit"
- **Fix:** apply the same boolean coercion in `instructor.js`:
  ```js
  question.correctAnswer = tfAnswer.value === 'true';
  ```

## 2. `instructor.js` saves MCQ `options` as an object, not an array

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4217, 4239)
- **Symptom:** MCQ questions persist `options: { A: "...", B: "...", C: "...", D: "..." }` instead of an ordered array `["...", "...", "...", "..."]`. This makes ordering implicit (relies on object-key order) and fragile.
- **Compare to:** `onboarding.js` `saveQuestion()` (~line 2238) which pushes to `options = []` (array).
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Fix:** collect into an array and store as such (see onboarding.js for the pattern).

## 3. `instructor.js` saves MCQ `correctAnswer` as a letter, not an index

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4240)
- **Symptom:** MCQ `correctAnswer` is stored as `"C"` (the radio's letter) instead of `2` (the numeric index into the options array).
- **Compare to:** `onboarding.js` `saveQuestion()` (~line 2241) which stores `options.length - 1` as the numeric index.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Fix:** track the index of the correct option as it's pushed into the array.
- **Note:** depends on fix #2 (options must be an array first).
