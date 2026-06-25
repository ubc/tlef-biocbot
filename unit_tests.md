# Unit Testing — Continuation Handoff

Working doc for building out the **Jest unit-test layer** for the BiocBot backend
(`src/**`, Node/CommonJS/Express). Hand this file to a fresh session to continue
where the last one stopped. Background lives in project memory
(`testing-overhaul-plan.md`).

---

## 0. Current status (2026-06-25)

- **142 unit tests passing** across 8 suites via `npm run test:unit` (131 new + 11 baseline).
- Branch: `api_key_flow`. All work so far is **ADD-ONLY** (only new files under `tests/unit/`).
- Shared in-memory Mongo double already built: `tests/unit/helpers/memory-db.js`.

**Modules with unit tests so far:**

| Module | Test file | Notes |
|---|---|---|
| `src/services/authorization.js` | `tests/unit/services/authorization.test.js` | pre-existing (copy its style) |
| `src/services/llmKeyStore.js` | `tests/unit/services/llmKeyStore.test.js` | network `fetch` paths intentionally NOT covered |
| `src/services/prompts.js` | `tests/unit/services/prompts.test.js` | 100% |
| `src/services/superCourseService.js` | `tests/unit/services/superCourseService.test.js` | pure + enrollment + pool helpers; **Qdrant `searchSuperCourse` retrieval NOT covered** |
| `src/services/tracker.js` | `tests/unit/services/tracker.test.js` | 100% |
| `src/services/llmRegistry.js` | `tests/unit/services/llmRegistry.test.js` | 94% (only `onProviderKeyFailure` callback uncovered) |
| `src/models/Superchat.js` | `tests/unit/models/Superchat.test.js` | 100% stmts |

---

## 1. COPY-PASTE KICKOFF PROMPT (for a new session)

> I'm continuing a Jest unit-test build-out for the BiocBot backend (Node/CommonJS,
> Express) on branch `api_key_flow`. The infrastructure is ALREADY set up — do NOT
> re-scaffold. **Read `unit_tests.md` at the repo root first** — it has the tracker,
> conventions, the reusable in-memory DB helper, mocking recipes, and the ground rules.
>
> Work is **ADD-ONLY**:
> - Do NOT modify or delete anything under `tests/e2e/`.
> - Do NOT change the `"test"` script (stays `"playwright test"`).
> - Do NOT commit the `file:../` lines in `package.json` (local dev override).
>
> **Two hard rules (read §2 of unit_tests.md):**
> 1. **Do NOT fix bugs/oddities you find in `src/`.** Characterize the *actual*
>    behavior in the test and log it under "Findings (DO NOT fix)" in `unit_tests.md`.
>    Tests are an independent check; editing source in the same pass biases the result.
> 2. **Test real behavior, not trivial/wrong things.** Read each source module FIRST,
>    assert its real outputs (exact objects, real branches, real error messages). No
>    tautologies, no asserting that a mock returns what you fed it.
>
> Pick the next unchecked item(s) from the tracker in `unit_tests.md` (top of the
> "Remaining" list = highest priority). For each: read the source, write the test in
> `tests/unit/<area>/<module>.test.js`, run `npm run test:unit`, keep it green, then
> tick the tracker box and append any findings. Reuse `tests/unit/helpers/memory-db.js`
> for DB-backed code. Start with: **`src/models/Course.js`** (pure normalizers first).

---

## 2. GROUND RULES (the important ones)

### 2a. Do NOT fix source code you're testing
When a test surfaces surprising, buggy, or "wrong-looking" behavior:
- **Write the test to the behavior that exists**, not the behavior you wish existed.
- Add a short comment in the test explaining the quirk.
- Add an entry to **§6 Findings (DO NOT fix here)** below.
- Leave the fix for a separate, deliberate pass (so the test suite stays an
  *independent* oracle and we don't confirmation-bias the code into passing).

Example already in the suite: `encryptApiKey('')` produces an empty payload segment
that `decryptApiKey` then rejects as malformed — so an empty/non-string key built via
`buildKeySubdocument` is **not round-trippable**. We characterized that (test asserts
it throws) instead of "fixing" encrypt. That is the pattern to follow.

### 2b. Test actual behavior — don't validate the wrong thing
- **Read the source module before writing the test.** Test its *real* exports and
  signatures — never assume.
- Assert concrete results: exact returned objects (`toEqual`/`toMatchObject`), the
  real branch taken, the actual error message/`.status`/`.code`.
- Cover **happy path + edge + error/branch** cases, not just the happy path.
- **Avoid tautologies / mock-echo tests.** Don't assert that an injected fake returned
  the value you told it to; assert what *the unit under test* did with it (e.g. how
  `tracker` parses/maps the LLM response, not that the fake LLM returned your JSON).
- When mocking a collaborator, still assert the unit's observable effect (return value,
  which collection/query it hit, cache hit/miss), not the mock internals for their own
  sake.
- Prefer pure-logic functions; for DB code use the in-memory double (§4), not real Mongo.

---

## 3. Conventions & how to run

- **Location:** `tests/unit/<area>/<module>.test.js` (areas: `services`, `models`,
  `middleware`). Helpers go in `tests/unit/helpers/` (NOT `*.test.js`, so Jest ignores them).
- **Imports:** relative paths, e.g. `require('../../../src/services/foo')`,
  `require('../helpers/memory-db')` (helper is one level up from `services/`/`models/`).
- **Config:** `jest.config.js` — `testEnvironment: node`, `testMatch:
  tests/unit/**/*.test.js`, coverage from `src/**` → `coverage-reports/unit`,
  `clearMocks: true`. Jest 30, **no Babel**. Jest auto-sets `NODE_ENV=test`.
- **Style to copy:** `tests/unit/services/authorization.test.js` (concise `describe`/
  `test`, plain-English names, a few focused `expect`s each).
- **Run:**
  - `npm run test:unit` — all unit tests
  - `npx jest tests/unit/<path>.test.js` — one file
  - `npm run test:unit:coverage` — full coverage
  - Per-module coverage:
    `npx jest --coverage --coverageReporters=text --collectCoverageFrom='src/models/Course.js'`
- CI: `.github/workflows/unit.yml` runs these on every push/PR.

---

## 4. Reusable infrastructure (don't rebuild)

### 4a. In-memory Mongo double — `tests/unit/helpers/memory-db.js`
```js
const { memoryDb, MemoryCollection } = require('../helpers/memory-db');
const db = memoryDb({ courses: [{ courseId: 'C1' }], superchats: [/* ... */] });
db.collection('courses').findOne({ courseId: 'C1' });
```
- **Query ops supported:** `$or`, `$and`, `$ne`, `$in`, `$nin`, `$exists`, `$size`,
  `$gt/$gte/$lt/$lte`, dotted paths (`studentEnrollment.S1.enrolled`), and Mongo's
  scalar-matches-array rule.
- **Update ops supported:** `$set`, `$setOnInsert` (on upsert), `$addToSet` (+`$each`),
  `$pull` (scalar or sub-doc match), `$push` (+`$each`); `{ upsert: true }`.
- **`find()` cursor:** `.project()/.projection()` (no-op), `.sort(spec)` (real,
  multi-key, nulls last), `.limit()/.skip()`, `.toArray()`.
- **⚠️ NO `.aggregate()` yet.** Several model stats helpers use `.aggregate(pipeline)`
  (see tracker notes). To test those, either **(a)** add a minimal `aggregate` to
  `MemoryCollection` for the specific pipeline shape, or **(b)** inject a hand-rolled
  fake collection. Keep any aggregate addition generic-but-small; do not over-engineer.
- **⚠️ Clone gotcha:** the helper uses a realm-local deep clone, NOT `structuredClone`
  — under `jest-environment-node`, `structuredClone` returns host-realm `Date`s that
  fail `toBeInstanceOf(Date)`. Keep it that way.

### 4b. Mocking modules with load-time side effects
`src/services/config.js` is lazy (safe to require), but `qdrantService`, `llm`,
`notesQdrantService` pull heavy libs (and `config`). `mongoService`/`gridfs` open a
Mongo client. **Mock whatever a target drags in that you aren't testing.** Proven recipes:

```js
// llmRegistry test — keep llmKeyStore REAL, stub the rest:
jest.mock('../../../src/services/config', () => ({ getLLMConfig: jest.fn(() => ({ provider: 'openai' })) }));
jest.mock('../../../src/services/llm', () => ({ create: jest.fn(async () => ({ setDbAccessor: jest.fn() })) }));
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => ({
    initialize: jest.fn().mockResolvedValue(undefined), embeddings: {},
})));

// superCourseService test — decouple Qdrant/notes so config never loads:
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => ({ /* ... */ })));
jest.mock('../../../src/services/notesQdrantService', () => jest.fn().mockImplementation(() => ({ /* ... */ })));
jest.mock('../../../src/models/SuperChatNote', () => ({ incrementUsage: jest.fn().mockResolvedValue() }));
```
- `process.env` mutation: snapshot in `beforeEach` (`process.env = { ...OLD_ENV }`),
  restore in `afterAll`. Env is read at call-time by `llmKeyStore`/`config`/`llmRegistry`.
- Silence noisy modules: `jest.spyOn(console, 'log'/'warn'/'error').mockImplementation(() => {})`
  in `beforeAll`, `jest.restoreAllMocks()` in `afterAll` (tracker.js and migrations log a lot).
- Stubs exist if useful: `src/services/llmStub.js`, `src/services/embeddingsStub.js`.

---

## 5. Tracker

Priority: **P1** = high value, mostly pure/db-static, easy wins · **P2** = useful, needs
mocking or aggregate support · **P3** = heavy external integration / prefer e2e.

### ✅ Done
- [x] `src/services/authorization.js` (pre-existing)
- [x] `src/services/llmKeyStore.js`
- [x] `src/services/prompts.js`
- [x] `src/services/superCourseService.js` *(Qdrant retrieval path still uncovered — optional later)*
- [x] `src/services/tracker.js`
- [x] `src/services/llmRegistry.js`
- [x] `src/models/Superchat.js`

### ⬜ Remaining — Models (use `memory-db`)
- [ ] **P1 `src/models/Course.js`** — biggest win. Many PURE normalizers: `normalizeYearLevel`,
  `parseYearLevelFromName`, `normalizeTopicLabel/List/Object/ObjectList`, `normalizeRagTopK`,
  `resolveRagSettings`, `normalizeSuperchatIds`, `getCourseSuperchatIds`,
  `compareCoursesWithInactiveLast`, `generateCourseCode/Distinct`, `normalizeCode`,
  `getAllowInSuperCourse`. Plus db helpers: `getPublishedLectures`, `getLecturePublishStatus`,
  `updateLecturePublishStatus`, `get/updateAssessmentQuestions`, `deleteAssessmentQuestion`,
  `getStudentEnrollment`/`updateStudentEnrollment`, `userHasCourseAccess`, `checkTAPermission`,
  `getTAPermissions`, `updateCourseSuperchats`, `createCourseFromOnboarding`. **Suggest 2 files:**
  `Course.pure.test.js` + `Course.db.test.js`. ~2200 lines — read in pages. Note: some `$set`
  use positional `lectures.$.x` which `memory-db` does NOT apply — test via the
  `find-lecture-by-name` read paths or extend the helper minimally if needed (don't fix source).
- [ ] **P1 `src/models/SuperChatNote.js`** — mirrors Superchat. Pure: `generateNoteId`,
  `autoGenerateTitle`, `normalizeTags`. CRUD + `softDeleteNote` + `incrementUsage`. Easy.
- [ ] **P1 `src/models/QuizAttempt.js`** — `saveAttempt`, `getAttemptsByStudent`,
  `getAttemptStats`. **`getAttemptStats` uses `.aggregate()`** → needs aggregate support (§4a).
- [ ] **P1 `src/models/UserAgreement.js`** — `getUserAgreement` (defaults), `createOrUpdate`,
  `hasUserAgreed`, `getAgreementStats` (**aggregate**). Small.
- [ ] **P2 `src/models/User.js`** — `createOrGetSAMLUser` (rich branching), `getUserByPuid`,
  `updateUserPreferences`, `deactivateUser`, `updateUserStruggleState`/`resetUserStruggleState`,
  `getUsersByRole`. `createUser`/`authenticateUser` use **bcrypt** (real dep works, just slower —
  or focus on the non-bcrypt helpers).
- [ ] **P2 `src/models/Question.js`** — CRUD + `getQuestionStats` (**aggregate**) + `getQuestionsByTags`.
- [ ] **P2 `src/models/FlaggedQuestion.js`** — CRUD + `getFlagStatistics` (**aggregate**).
- [ ] **P2 `src/models/MentalHealthFlag.js`** — CRUD + `getMentalHealthFlagStats` (**aggregate**).
- [ ] **P2 `src/models/StruggleActivity.js`** — `createActivityEntry`, `getActivityByCourse`,
  `getSuperCourseActivity`, `getWeeklyActiveTopics` (likely **aggregate**/grouping).
- [ ] **P2 `src/models/Document.js`** — pure `mapContentTypeToDocumentType` + CRUD +
  `getDocumentStats` (**aggregate**).
- [ ] **P2 `src/models/Onboarding.js`** — `upsertOnboarding`, getters, `updateOnboardingFields`,
  `updateUnitFiles`, `getOnboardingStats`.
- [ ] **P3 `src/models/PersistenceTopic.js`** — small; `incrementStudentCount`, `getPersistenceTopics`.

### ⬜ Remaining — Services
- [ ] **P1 `src/services/systemAdmin.js`** — `listSystemAdmins`, `grant/revokeSystemAdminByEmail`
  (db-backed, normalizes email). Small, clean.
- [ ] **P2 `src/services/config.js`** — `getLLMConfig`/`getServerConfig`/etc. Env-driven; set
  `process.env` per test; throws on unsupported provider. Exported as a singleton instance.
- [ ] **P2 `src/services/authService.js`** — class. PURE session/role helpers
  (`createSessionUser`, `hasRole`, `isStudent/Instructor/SystemAdmin`, `getCurrentCourseId`).
  `loginUser`/`registerUser`/`getUserById` are db+bcrypt (partial).
- [ ] **P2 `src/services/superChatNotesService.js`** — `checkSimilar` (`DUP_THRESHOLD` logic),
  CRUD wrappers. Check what it loads at require-time (may need qdrant/embeddings mocks).
- [ ] **P3 `src/services/llm.js`** — heavy (1070 lines). Only small pure bits worth it
  (model/effort allow-lists, any JSON-extraction helper). Mostly NOT unit-testable.
- [ ] **P3 `src/services/qdrantService.js`, `notesQdrantService.js`** — external vector DB;
  low ROI for unit tests.
- [ ] **SKIP `src/services/mongoService.js`, `gridfs.js`** — open DB connections (load-time
  side effects). `llmStub.js`/`embeddingsStub.js` are test doubles — skip.

### ⬜ Remaining — Middleware
- [ ] **P2 `src/middleware/auth.js`** — `requireAuth`, `requireRole`, `requireInstructorOrTA`,
  `requireSystemAdmin`, `redirectIfAuthenticated`, `requireCourseContext`, `requireTAPermission`.
  Unit-test with fake `req`/`res`/`next` (assert `next()` vs `res.status().json()`). The e2e
  harness exercises these too, but unit coverage is cheap. (`createAuthMiddleware(db)` factory.)

### ⬜ Routes
- [ ] **P3 — generally prefer e2e.** Express routers are integration-level and already covered by
  Playwright + `tests/e2e/helpers/src-route-model-harness.js`. Only pull out *small pure helpers*
  if a route has them (e.g. `src/routes/llmKeyMiddleware.js`, 78 lines). Don't unit-test whole routers.

---

## 6. Findings (DO NOT fix here — log only)

Record real behavior discrepancies surfaced by tests. These are for a *later* deliberate
pass, NOT to be fixed while writing tests.

- **`llmKeyStore.encryptApiKey('')` is not round-trippable.** Encrypting an empty string
  yields an empty trailing base64 segment, which `decryptApiKey` treats as malformed
  (`Unsupported encrypted API key format`). So `buildKeySubdocument(<non-string|empty>)`
  stores a ciphertext that cannot be decrypted. Characterized in
  `tests/unit/services/llmKeyStore.test.js`; not fixed.

*(append new findings below as you go)*

---

## 7. Known helper limitations to extend as needed

- **`aggregate()`** is not implemented in `memory-db.js`. Needed by most `*Stats`/activity
  helpers. Add a minimal, pipeline-shape-specific implementation (or inject a fake) when you
  reach those — keep it small and obviously correct.
- **Positional `$` update operator** (`lectures.$.field`) is not applied by `memory-db`.
  Course unit-update helpers use it; test their read side, or extend the helper minimally.
- **bcrypt**-backed functions (`User.createUser/authenticateUser`, `authService` login/register)
  work with the real dep but are slower; isolate them or test the non-bcrypt helpers.

When you extend the helper, it's shared infra — re-run the **whole** `npm run test:unit`
afterward to make sure existing suites stay green.
