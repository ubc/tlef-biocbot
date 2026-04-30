# E2E Test Findings

Bugs / inconsistencies surfaced by the Playwright suite. Each entry assumes a
test asserts the *expected* behavior; if the test fails, the discrepancy is
recorded here so it can be triaged into a real issue and fixed in code.

> Policy: when a new test fails, **don't relax the assertion**. Document it
> here, leave the test failing, and let the failure prompt a real fix.

---

## ⚠️ Headline issue: assessment-question schema is inconsistent

The same conceptual data — an assessment question — is persisted in **two
different shapes** depending on which UI flow created it. Downstream consumers
(the quiz route, the chat practice-answer route, `student.js`) have already
accumulated workarounds to defend against this, and one of them (`quiz.js`)
will throw at runtime if it ever encounters the "structured" shape.

| Field | `onboarding.js` (structured) | `instructor.js` (string-y) |
|---|---|---|
| TF `correctAnswer` | boolean `true` / `false` | string `"true"` / `"false"` |
| MCQ `options` | array `["A text", "B text", ...]` | object `{A: "...", B: "...", ...}` |
| MCQ `correctAnswer` | numeric index `2` | letter `"C"` |
| SA `correctAnswer` | string | string ✓ |

### What the consumers actually require

- **`src/routes/quiz.js` line 211** —
  `studentAnswer.toLowerCase() === question.correctAnswer.toLowerCase()`.
  Assumes `correctAnswer` is a string. Throws `TypeError: ... is not a function`
  if it's a boolean (TF onboarding) or number (MCQ onboarding).
- **`src/routes/chat.js` line 1319** — same pattern, same assumption.
- **`public/student/scripts/student.js` line 2213** — already handles both
  shapes defensively for TF: `q.correctAnswer === true || q.correctAnswer === 'true'`.
- **`public/student/scripts/student.js` lines 2216–2221** — already handles
  both shapes for MCQ: if `correctAnswer` is a string letter, look it up in
  `Object.keys(q.options)` to derive the index.
- **`public/student/scripts/student.js` line 2200** — reads MCQ options via
  `Object.keys(q.options)`. Only works for the **object** shape; won't handle
  array-shape options from onboarding-saved questions.

### What students submit
Both quiz and chat practice flows submit the radio button's `.value`:
- TF: literal string `"true"` / `"false"`
- MCQ: the letter `"A"`, `"B"`, `"C"`, or `"D"` (because `student.js` builds the
  radios from `Object.keys(options)` — see line 2200)

So the wire-protocol the server already expects is the **string-y** shape.
Picking that for storage too is the path of least disruption.

### Recommended fix
Standardize on the **string-y** shape (matching `instructor.js` and what
`quiz.js`/`chat.js` already require). Concretely:
1. Update `onboarding.js` `saveQuestion()` to persist TF `correctAnswer` as a
   string and MCQ `correctAnswer` as a letter / `options` as an object —
   matching `instructor.js`.
2. Once persisted shapes are consistent, simplify `student.js` (drop the
   dual-shape branches at lines 2213, 2216–2221).
3. Migrate any existing onboarding-created questions in Mongo to the new
   shape (one-off script).

The alternative — standardizing on the structured shape — is also defensible,
but requires changes in **more** places (`quiz.js`, `chat.js`, `instructor.js`,
plus client-side rebuild) and a wire-protocol change for student submissions.

---

## Individual findings

### 1. `instructor.js` saves true/false `correctAnswer` as a string

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4207)
- **Symptom:** Saving a TF question via the instructor course-management page persists `correctAnswer: "true"` (string).
- **Compare to:** `onboarding.js` `saveQuestion()` (~line 2228), which coerces to boolean.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add an assessment question to a unit"
- **Status:** Not necessarily a bug — `quiz.js`/`chat.js` actually require the string form. The fix likely belongs in `onboarding.js`, not here. Update the test assertion once the headline issue above is resolved.

### 2. `instructor.js` saves MCQ `options` as an object (vs array in onboarding)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4217)
- **Symptom:** MCQ questions persist `options: { A: "...", B: "...", C: "...", D: "..." }`.
- **Compare to:** `onboarding.js` (~line 2238) which uses an array.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Status:** Same as #1 — `student.js` line 2200 reads options via `Object.keys(q.options)`, so the object form is what the client UI actually expects. The fix likely belongs in `onboarding.js`.

### 3. `instructor.js` saves MCQ `correctAnswer` as a letter (vs numeric index in onboarding)

- **Where:** `public/instructor/scripts/instructor.js` `saveQuestion()` (~line 4240)
- **Symptom:** MCQ `correctAnswer` is `"C"` instead of `2`.
- **Compare to:** `onboarding.js` (~line 2241), which stores the array index.
- **Failing test:** `tests/e2e/instructor.spec.js` › "instructor can add a multiple-choice question to a unit"
- **Status:** Same as #1 / #2 — letter form is what the wire protocol expects.

### 4. `quiz.js` will throw if it encounters a non-string `correctAnswer`

- **Where:** `src/routes/quiz.js` line 211 (`POST /api/quiz/check-answer`)
- **Symptom:** Calling `.toLowerCase()` on a boolean or number throws `TypeError`. Reproducible right now: if a TF question is created via onboarding and a student takes it via the quiz page, the request 500s.
- **Same pattern in:** `src/routes/chat.js` line 1319 (`POST /api/chat/check-practice-answer`).
- **Failing test:** none yet — would need a student-side test that takes a quiz on an onboarding-created question. Worth adding once the headline issue is resolved.
- **Status:** Latent runtime bug. Even after standardizing the persisted shape, this code should be defensive (`String(question.correctAnswer)`).

### 5. `student.js` has accumulated dual-shape handling

- **Where:** `public/student/scripts/student.js` lines 2200, 2213, 2216–2221.
- **Symptom:** Branches that exist only because two ingest paths persist different shapes. Once shapes are unified, these can be deleted.
- **Status:** Cleanup follow-up to the headline fix.
