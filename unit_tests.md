# Unit Testing — Continuation Handoff

Working doc for building out the **Jest unit-test layer** for the BiocBot backend
(`src/**`, Node/CommonJS/Express). Hand this file to a fresh session to continue
where the last one stopped. Background lives in project memory
(`testing-overhaul-plan.md`).

---

## 0. Current status (2026-06-25)

- **431 unit tests passing** across 25 suites via `npm run test:unit` (420 new + 11 baseline).
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
| `src/models/Course.js` (pure) | `tests/unit/models/Course.pure.test.js` | exported normalizers/resolvers only (internal helpers reached indirectly) |
| `src/models/Course.js` (db) | `tests/unit/models/Course.db.test.js` | 45% stmts overall; high-value subset (see tracker). Positional `lectures.$.x` writes NOT applied by memory-db → assert return contracts/read paths |
| `src/models/SuperChatNote.js` | `tests/unit/models/SuperChatNote.test.js` | pure + CRUD + soft-delete + `incrementUsage` (added `$inc` to memory-db) |
| `src/models/QuizAttempt.js` | `tests/unit/models/QuizAttempt.test.js` | 100%; `getAttemptStats` (added `aggregate()` to memory-db) |
| `src/models/UserAgreement.js` | `tests/unit/models/UserAgreement.test.js` | 100%; upsert + `getAgreementStats` aggregate |
| `src/models/Document.js` | `tests/unit/models/Document.test.js` | mapper + CRUD/status/delete + aggregate stats |
| `src/models/Question.js` | `tests/unit/models/Question.test.js` | CRUD/soft-delete + tag lookup + aggregate stats + bulk create |
| `src/models/FlaggedQuestion.js` | `tests/unit/models/FlaggedQuestion.test.js` | create/read/update/delete + `getFlagStatistics` aggregate |
| `src/models/MentalHealthFlag.js` | `tests/unit/models/MentalHealthFlag.test.js` | create/list/status transitions + aggregate stats |
| `src/models/StruggleActivity.js` | `tests/unit/models/StruggleActivity.test.js` | create/read helpers + Super Chat scoping + weekly aggregate |
| `src/models/Onboarding.js` | `tests/unit/models/Onboarding.test.js` | upsert/get/update/unit files/delete + stats |
| `src/models/PersistenceTopic.js` | `tests/unit/models/PersistenceTopic.test.js` | unique student counts, topic lookup/sort, fallback branches |
| `src/models/User.js` | `tests/unit/models/User.test.js` | create/auth/SAML/access state/preferences/roles/struggle-state |
| `src/services/systemAdmin.js` | `tests/unit/services/systemAdmin.test.js` | list/grant/revoke + last-admin guard (added `$unset` to memory-db) |
| `src/services/config.js` | `tests/unit/services/config.test.js` | env-driven config + provider validation; singleton `isValidated` reset per test |
| `src/services/authService.js` | `tests/unit/services/authService.test.js` | PURE role/session helpers (db+bcrypt methods left to e2e) |
| `src/middleware/auth.js` | `tests/unit/middleware/auth.test.js` | all guards via fake req/res/next (next vs status().json() vs redirect()) |

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
> for DB-backed code. Model files now all have direct unit tests. Next up:
> **`src/services/systemAdmin.js`** (small DB-backed service).

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
- **Query ops supported:** `$or`, `$and`, `$ne`, `$in`, `$nin`, `$exists`, `$size`, `$regex`,
  `$gt/$gte/$lt/$lte`, dotted paths (`studentEnrollment.S1.enrolled`), and Mongo's
  scalar-matches-array rule.
- **Update ops supported:** `$set`, `$setOnInsert` (on upsert), `$inc`, `$addToSet` (+`$each`),
  `$pull` (scalar or sub-doc match), `$push` (+`$each`); `{ upsert: true }`, `findOneAndUpdate()`.
- **`find()` cursor:** `.project()/.projection()` (no-op), `.sort(spec)` (real,
  multi-key, nulls last), `.limit()/.skip()`, `.toArray()`.
- **`aggregate()`** has minimal support for the stats/activity helpers already covered (`$match`,
  `$group`, `$project`, `$sort`, `$limit`, `$skip` plus common accumulators, common expressions,
  and ISO-week expressions). Extend it only for new pipeline shapes you actually need.
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
- [x] `src/models/Course.js` — split into `Course.pure.test.js` (35 tests: `normalizeYearLevel`,
  `parseYearLevelFromName`, `normalizeTopicList`, `normalizeTopicObjectList`, `normalizeRagTopK`,
  `resolveRagSettings`, `getAllowInSuperCourse`, `normalizeSuperchatIds`, `getCourseSuperchatIds`,
  constants) + `Course.db.test.js` (35 tests: publish status, get/update/deleteAssessmentQuestions,
  enrollment, TA perms, `userHasCourseAccess`, `checkTAPermission`, `updateCourseSuperchats`,
  `createCourseFromOnboarding`). **45% stmts** — the other db helpers (objectives, pass threshold,
  units, documents, join, quiz settings, anonymize, struggle topics, migrations) remain uncovered
  and are fair game for a follow-up. Internal-only helpers (`normalizeTopicLabel`, `normalizeCode`,
  `generateCourseCode/Distinct`, `compareCoursesWithInactiveLast`, `isInactiveCourse`) are **not
  exported**, so they're exercised indirectly rather than directly (didn't add them to exports).

- [x] `src/models/SuperChatNote.js` — pure (`generateNoteId`, `autoGenerateTitle`, `normalizeTags`)
  + CRUD + `softDeleteNote` + `incrementUsage`. Required adding **`$inc`** to `memory-db`.
- [x] `src/models/QuizAttempt.js` — `saveAttempt`, `getAttemptsByStudent`, `getAttemptStats` (100%).
  Required adding **`aggregate()`** ($match/$group/$sort + accumulators) to `memory-db`.
- [x] `src/models/UserAgreement.js` — `getUserAgreement`, `createOrUpdateUserAgreement` (upsert),
  `hasUserAgreed`, `getAgreementStats` (100%). Uses the new `aggregate()`.
- [x] `src/models/Document.js` — `mapContentTypeToDocumentType`, `uploadDocument`,
  lecture/doc lookups, content/status updates, delete, and `getDocumentStats`.
- [x] `src/models/Question.js` — `createQuestion`, lecture/doc lookups, update,
  soft-delete, `getQuestionsByTags`, `getQuestionStats`, and `bulkCreateQuestions`.
- [x] `src/models/FlaggedQuestion.js` — `createFlaggedQuestion`, course/status/student/id lookups,
  instructor response/status updates, `getFlagStatistics`, and hard delete.
- [x] `src/models/MentalHealthFlag.js` — `createMentalHealthFlag`,
  `getMentalHealthFlagsForCourse`, `updateFlagStatus`, and `getMentalHealthFlagStats`.
- [x] `src/models/StruggleActivity.js` — `createActivityEntry`, `getActivityByCourse`,
  `getSuperCourseActivity`, `getActivityByStudent`, and `getWeeklyActiveTopics`.
  Required extending `memory-db` aggregate support for `$project` and ISO-week expressions.
- [x] `src/models/Onboarding.js` — `upsertOnboarding`, course/instructor getters,
  `updateOnboardingFields`, `updateUnitFiles`, `deleteOnboarding`, and `getOnboardingStats`.
- [x] `src/models/PersistenceTopic.js` — `incrementStudentCount`, `getPersistenceTopics`, duplicate
  student handling, failure branches, and regex metacharacter behavior.
- [x] `src/models/User.js` — `createUser`, `authenticateUser`, `getUserById`, `getUserByPuid`,
  `updateUserPreferences`, SAML create/update/TA-preservation, role lookup, deactivation,
  `updateUserStruggleState`, and `resetUserStruggleState`.
- [x] `src/services/systemAdmin.js` — `listSystemAdmins` (filter/sort/shape), `grant/revoke` with
  email normalization, last-admin guard, and `$unset` demotion read-back. Required adding **`$unset`**
  to `memory-db`.
- [x] `src/services/config.js` — env-driven `getLLMConfig`/`getServerConfig`/`getDatabaseConfig`/
  `getVectorDBConfig` + `validateConfig` provider rules + env helpers. Resets the singleton's
  `isValidated` flag and snapshots `process.env` per test.
- [x] `src/services/authService.js` — PURE helpers only: `isValidEmail`, `hasRole`,
  `isInstructor/isStudent/isSystemAdmin`, `getCurrentCourseId`, `createSessionUser` (session-safe
  shaping + admin elevation). db+bcrypt methods (`loginUser`/`registerUser`/`getUserById`/SAML) left to e2e.
- [x] `src/middleware/auth.js` — `requireAuth`, `requireRole`, `requireInstructorOrTA`,
  `requireSystemAdmin`, `redirectIfAuthenticated`, `requireCourseContext`, `requireTAPermission`
  via fake req/res/next (next() vs status().json() vs redirect()).

### ⬜ Remaining — Models (use `memory-db`)
All current `src/models/*.js` files have direct unit-test files.

### ⬜ Remaining — Services
- [ ] **P2 `src/services/superChatNotesService.js`** — `checkSimilar` (`DUP_THRESHOLD` logic),
  CRUD wrappers. Check what it loads at require-time (may need qdrant/embeddings mocks).
- [ ] **P3 `src/services/llm.js`** — heavy (1070 lines). Only small pure bits worth it
  (model/effort allow-lists, any JSON-extraction helper). Mostly NOT unit-testable.
- [ ] **P3 `src/services/qdrantService.js`, `notesQdrantService.js`** — external vector DB;
  low ROI for unit tests.
- [ ] **SKIP `src/services/mongoService.js`, `gridfs.js`** — open DB connections (load-time
  side effects). `llmStub.js`/`embeddingsStub.js` are test doubles — skip.

### ⬜ Remaining — Middleware
- _All middleware covered_ — `src/middleware/auth.js` is done (see ✅ Done).

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

- **`Course.normalizeYearLevel` coerces via `Number()` (lenient).** `'4'` → 4 and, more
  surprisingly, `true` → 1 (since `Number(true) === 1` is an in-range integer). Likely
  intended leniency, but worth knowing callers can pass booleans. Characterized in
  `Course.pure.test.js`; not fixed.

- **`Course.parseYearLevelFromName` treats a bare single digit as its own "first digit".**
  With no 3–4 digit course number it falls back to `(\d+)`, so `'Level 7'` → `min(7,5)` = 5,
  while `'Course 0'` → null (leading digit 0 is rejected). Edge behavior, almost certainly
  fine for real course names; characterized in `Course.pure.test.js`, not fixed.

- **`FlaggedQuestion.createFlaggedQuestion` lets `flagData.flagId` override the stored ID.**
  It generates a new `flagId` and returns that generated value, but spreads `flagData` after it
  in the inserted document, so a caller-provided `flagId` is what actually gets stored. The
  generated return ID then cannot retrieve the inserted flag. Characterized in
  `FlaggedQuestion.test.js`; not fixed.

- **`Onboarding.upsertOnboarding` overwrites `createdAt` during updates when omitted.**
  The comment says `createdAt` is only set for new documents, but the implementation always places
  `createdAt` in `$set` (`now` when the caller does not provide one). Updating an existing document
  without `createdAt` therefore replaces the original creation timestamp. Characterized in
  `Onboarding.test.js`; not fixed.

- **`PersistenceTopic.incrementStudentCount` builds a `RegExp` from unescaped topic text.**
  A topic containing regex metacharacters can match a different stored topic, e.g. input
  `'ATP.se'` matches stored topic `'atpase'` and increments that document instead of creating
  a literal `atp.se` topic. Characterized in `PersistenceTopic.test.js`; not fixed.

- **`User.authenticateUser` accepts a basic-auth user with `passwordHash: null`.**
  The password check runs only when `authProvider === 'basic' && user.passwordHash`; if a basic
  active user has no hash, any password is accepted and `lastLogin` is updated. Characterized in
  `User.test.js`; not fixed.

*(append new findings below as you go)*

---

## 7. Known helper limitations to extend as needed

- **`aggregate()`** has minimal support in `memory-db.js` for the stats/activity helpers already
  covered (`$match`, `$group`, `$project`, `$sort`, `$limit`, `$skip` plus common accumulators,
  common expressions, and ISO-week expressions). Extend it only for new pipeline shapes you
  actually need, and re-run the full unit suite afterward.
- **Positional `$` update operator** (`lectures.$.field`) is not applied by `memory-db`.
  Course unit-update helpers use it; test their read side, or extend the helper minimally.
- **bcrypt**-backed functions (`User.createUser/authenticateUser`, `authService` login/register)
  work with the real dep but are slower; isolate them or test the non-bcrypt helpers.

When you extend the helper, it's shared infra — re-run the **whole** `npm run test:unit`
afterward to make sure existing suites stay green.
