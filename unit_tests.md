# Unit Testing — Continuation Handoff

Working doc for building out the **Jest unit-test layer** for the BiocBot backend
(`src/**`, Node/CommonJS/Express). Hand this file to a fresh session to continue
where the last one stopped. Background lives in project memory
(`testing-overhaul-plan.md`).

---

## 0. Current status (2026-06-26)

> **2026-06-30 coverage update:** 1,367 tests pass across 76 suites. The regenerated
> Monocart report is 84.79% statements, 77.41% branches, 92.84% functions, and
> 85.84% source lines overall. `src/routes/settings.js` now has 100% statements,
> functions, and lines (92.44% branches). `src/routes/chat.js` now has 94.14%
> statements, 86.22% branches, 91.78% functions, and 94.96% lines. No production
> or e2e files were changed by this coverage pass.

**Finding (DO NOT fix here):** `POST /api/chat` logs
`req.body.message?.substring(...)` before validating that `message` is a string.
A numeric message therefore returns 500 instead of the handler's intended 400.

**Finding (DO NOT fix here):** The Shibboleth SAML success callback logs
`req.user.userId` before its `if (req.user)` guard. If Passport advances without
attaching a user, the callback throws and returns 500 instead of a controlled
authentication failure/redirect.

**LLM test boundary:** Every Jest test must mock provider-facing LLM behavior
(including key validation). Unit tests must never make provider/network calls or
consume API credits. Prompt-setting tests may exercise stored configuration only.

- **646 unit tests passing** across 39 suites via `npm run test:unit`.
- **Overall `src/**` statement coverage = 35.4%** (models 87.2%, services 29.3%, routes 25.0%, middleware 41.8%).
  Routes dominate the codebase (6,332 of 9,933 statements) and were 0% until this initiative — now
  being unit-tested in-process with supertest (see Routes below); 8 primary routers covered so far.
- Branch: `more_unit_tests`. Work remains **ADD-ONLY with respect to production code** (new tests,
  test-helper extensions, and this tracker only).
- Shared in-memory Mongo double already built: `tests/unit/helpers/memory-db.js`.

**Modules with unit tests so far:**

| Module | Test file | Notes |
|---|---|---|
| `src/services/authorization.js` | `tests/unit/services/authorization.test.js` | pre-existing (copy its style) |
| `src/services/llmKeyStore.js` | `tests/unit/services/llmKeyStore.test.js` | validateApiKey provider paths now covered via `jest.mock('node-fetch')` — see §6 node-fetch pitfall |
| `src/services/prompts.js` | `tests/unit/services/prompts.test.js` | 100% |
| `src/services/superCourseService.js` | `tests/unit/services/superCourseService.test.js` | settings, enrollment, pool helpers, balanced Qdrant + notes retrieval, formatting/attribution, collaborator failures; **100% statements/branches/functions/lines** |
| `src/services/tracker.js` | `tests/unit/services/tracker.test.js` | 100% |
| `src/services/llmRegistry.js` | `tests/unit/services/llmRegistry.test.js` | 94% (only `onProviderKeyFailure` callback uncovered) |
| `src/models/Superchat.js` | `tests/unit/models/Superchat.test.js` | 100% stmts |
| `src/models/Course.js` | `tests/unit/models/Course.pure.test.js`, `Course.db.test.js`, `Course.coverage.test.js` | all exported helpers/lifecycles; **100% statements/functions/lines, 90.53% branches**. Positional `lectures.$.x` writes NOT applied by memory-db → assert return contracts/read paths |
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
| `src/middleware/auth.js` | `tests/unit/middleware/auth.test.js` | all guards via fake req/res/next (next vs status().json() vs redirect()); session-hydration fallback + catch paths added → **99.02% stmts / 100% funcs** (only two unreachable redirect branches remain, see §6) |

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
- Interactive Monocart unit report:
  - Generate: `npm run test:unit:monocart`
  - Open: `npm run test:report:unit`
  - Output: `coverage-reports/unit-monocart/index.html`
  - This uses the separate `jest.monocart.config.js` with native V8 coverage;
    the regular Jest/Istanbul coverage command and percentages remain unchanged.
- CI: `.github/workflows/unit.yml` runs these on every push/PR.
- Jest uses `maxWorkers: 1`: the many Supertest route suites otherwise produce
  sporadic Node 24 `ECONNRESET` / HTTP parser errors when temporary listeners run
  concurrently. The serialized full suite remains fast (about five seconds).

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
- **Update ops supported:** `$set`, `$setOnInsert` (on upsert), `$inc`, `$unset`, `$addToSet` (+`$each`),
  `$pull` (scalar or sub-doc match), `$push` (+`$each`); `{ upsert: true }`, `findOneAndUpdate()`.
- **`find()` cursor:** `.project()/.projection()` (no-op), `.sort(spec)` (real,
  multi-key, nulls last), `.limit()/.skip()`, `.toArray()`.
- **`aggregate()`** has minimal support for the stats/activity helpers already covered (`$match`,
  `$unwind`, `$group`, `$project`, `$sort`, `$limit`, `$skip` plus common accumulators, common expressions,
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

### 4c. In-process route harness — `tests/unit/helpers/route-app.js`
`makeRouteApp(router, { db, user, locals, mountPath })` mounts a router on a bare Express app
(`express.json()` + injected `app.locals.db` + a middleware that sets `req.user`), returned ready for
`request(app)` (supertest is re-exported). Declare `jest.mock()` for the router's heavy load-time
requires (qdrant/gridfs/llmKeyStore/superCourseService) BEFORE requiring the router; keep the models
real over `memory-db`. See `tests/unit/routes/*.test.js`.

---

## 5. Tracker

Priority: **P1** = high value, mostly pure/db-static, easy wins · **P2** = useful, needs
mocking or aggregate support · **P3** = heavy external integration / prefer e2e.

### ✅ Done
- [x] `src/services/authorization.js` (pre-existing)
- [x] `src/services/llmKeyStore.js`
- [x] `src/services/prompts.js`
- [x] `src/services/superCourseService.js` — 47 focused tests cover settings/buckets,
  enrollment, pools/topics, balanced lecture retrieval, note-slot allocation and donation,
  Qdrant initialization, note failures/key errors, usage accounting, citations/context/source
  attribution, and sparse collaborator data. **100% statements/branches/functions/lines.**
- [x] `src/services/tracker.js`
- [x] `src/services/llmRegistry.js`
- [x] `src/models/Superchat.js`
- [x] `src/models/Course.js` — 126 tests across `Course.pure.test.js`, `Course.db.test.js`,
  and `Course.coverage.test.js` cover every exported normalizer and database lifecycle: surveys,
  RAG/Super Course settings, code migration/upsert, lecture/objective/assessment/pass-threshold
  operations, onboarding, units/documents, membership/permissions/enrollment/join, approved topics,
  quiz settings, and anonymization. **100% statements/functions/lines, 90.53% branches.** Remaining
  branch operands are defensive defaults and Mongo collaborator outcomes constrained by prior checks;
  no test-only exports or coverage exclusions were added.
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
- [x] `src/services/authService.js` — complete direct suite: validation, registration/login/model
  delegation, user and preference reads/writes, SAML handling, course context, session-safe shaping,
  academic-ID backfill, and every default-user initialization outcome. The `User` model boundary is
  mocked here; its bcrypt/DB behavior remains covered by `models/User.test.js`. **100% statements,
  branches, functions, and lines.**
- [x] `src/middleware/auth.js` — `requireAuth`, `requireRole`, `requireInstructor/Student/TA`,
  `requireInstructorOrTA`, `requireSystemAdmin`, `populateUser`, `redirectIfAuthenticated`,
  `requireCourseContext`, `requireTAPermission`, `requireStudentEnrolled`, and
  `requireActiveCourseForNonInstructors` via fake req/res/next (next() vs status().json() vs
  redirect()). Now covers the **session-hydration fallback** (`req.session.userId` →
  `authService.getUserById`: hydrate/unknown-user-destroy/error-catch), every role-redirect
  branch, and the model-backed catch paths (`getUserById`/`checkTAPermission`/
  `getStudentEnrollment`/`getCourseById` forced to throw via `jest.spyOn`). **99.02% statements,
  98.19% branches, 100% functions** — the only two uncovered lines are unreachable dead branches
  (see §6).

### ⬜ Remaining — Models (use `memory-db`)
All current `src/models/*.js` files have direct unit-test files.

### ⬜ Remaining — Services
- [x] `src/services/superChatNotesService.js` — `tests/unit/services/superChatNotesService.test.js`
  (create vector-backfill, re-embed-only-when-content-changes, delete swallow-on-Qdrant-failure,
  `checkSimilar` threshold, `incrementUsage`). `notesQdrantService` mocked with shared spies; model real.
- [x] `src/services/llm.js` — `tests/unit/services/llm.test.js` (58 tests;
  provider toolkit mocked at import time; model/effort settings, option translation,
  image/conversation orchestration, prompt builders, parsers, grading and safety analysis).
  **Deepened 2026-06-30:** added `_performInitialization`/`static create` (test-stub, real-provider,
  failure-reset), every method's lazy-init-on-first-use branch, the provider-error path
  (`mapOpenAIErrorToStatus` → `LlmKeyError` + `onProviderKeyFailure`, handler-throw swallow,
  non-key rethrow), `generate`/`regenerate` orchestration incl. the 2-minute `Promise.race`
  timeout (driven with `jest.advanceTimersByTimeAsync`), and the parser/prompt validation +
  fallback branches. **99.72% statements, 100% functions, 100% lines, 90.53% branches** — the
  branch remainder is defensive `||`/`?.` operands and provider-toolkit failure operands.
- [x] `src/services/notesQdrantService.js` — `tests/unit/services/notesQdrantService.test.js`
  (12 tests; 100% statements/functions/lines with mocked Qdrant, embeddings, and chunker).
- [x] `src/services/qdrantService.js` — `tests/unit/services/qdrantService.test.js`
  (36 tests; constructor/init/config failures, collection lifecycle, document processing,
  embeddings, storage, query normalization and filters, per-course search, scrolling,
  cloning, deletion, stats/status). Deterministic boundary fakes; no live Qdrant.
- [x] `src/services/gridfs.js` — `tests/unit/services/gridfs.test.js` replaces only the Mongo
  `GridFSBucket` boundary; covers ObjectId normalization, upload/download/copy streams, metadata,
  missing files, stream failures, and idempotent deletion without opening a database. **100% all metrics.**
- [x] `src/services/academicApi.js` — `tests/unit/services/academicApi.test.js` covers toolkit loading,
  missing/invalid optional dependency behavior, environment/mock configuration, singleton injection,
  caching, and the fail-closed feature gate. **100% all metrics.**
- [x] `src/services/mongoService.js` — direct mocked-driver suite (no live connection).
- [x] `src/services/llmStub.js`, `embeddingsStub.js` — counted by Jest, therefore tested
  directly in `tests/unit/services/stubs.test.js` (100% statements/functions/lines).

### ⬜ Remaining — Middleware
- _All middleware covered_ — `src/middleware/auth.js` is done (see ✅ Done).

### Routes — in-process supertest tests (strategy added 2026-06-26)
Routers read `db` from `req.app.locals.db` and the user from `req.user`, so they unit-test cleanly
with **supertest** + the shared harness `tests/unit/helpers/route-app.js` (`makeRouteApp(router,
{ db, user, locals })`). Mock only the heavy modules a router pulls at load (qdrant/gridfs/llmKeyStore);
the models run real over `memory-db`. Each test covers a cross-section of endpoints (auth gates +
happy path + the key error branches), not every handler. Seed docs with explicit `_id` when a handler
updates by `_id` (e.g. systemAdmin revoke).
- [x] `src/routes/superchats.js` — `tests/unit/routes/superchats.test.js` (auth gate, CRUD, LLM-key branches)
- [x] `src/routes/students.js` — `tests/unit/routes/students.test.js` (admin gate,
  student-grouping/duration, complete student-facing own-session reads, filtering, rename/delete-own,
  auth/db/race failures) plus `students.deep.test.js` for admin list/single/delete. Focused coverage:
  **98.4% statements, 95.78% branches, 100% functions, and 98.37% lines**; only three
  router-unreachable guards remain (see §6).
- [x] `src/routes/settings.js` — base/deep/chat-survey suites plus
  `settings-keys.test.js`, `settings-errors.test.js`, and `settings-academic-error.test.js`. Covers
  all settings endpoints, ownership/admin gates, persistence and validation edges, stable exception
  contracts, academic API gate, and both dedicated LLM-key lifecycles with provider validation mocked.
  **100% statements/functions/lines; 92.44% branches.**
- [x] `src/routes/courses.js` — `tests/unit/routes/courses.test.js`,
  `courses.deep.test.js`, and `courses.coverage.test.js` (114 tests: list/get, student-safe
  projection, statistics aggregation, approved/extracted topics, available/joinable courses,
  student/TA/instructor joins, TA management and permissions, student enrollment/listing, create,
  update, retrieval mode, soft-delete, unit lifecycle, content stub, API keys, material confirmation,
  and transfer including text/inline/GridFS document cloning and warning paths). Monocart:
  **90.62% statements, 83.88% branches, 100% functions, and 91.02% lines.** Literal
  100% statements/branches/lines would require production test seams or coverage exclusions; see §6.
- [x] `src/routes/quiz.js` — `tests/unit/routes/quiz.test.js` (status, objective grading, attempts, history)
- [x] `src/routes/flags.js` — `tests/unit/routes/flags.test.js` (53 tests: ordinary/Super Course
  creation, normalization, own-flag enrollment filtering/deduplication, instructor/TA/system-admin
  authorization, readers, response/status/delete mutations, model failures, and exception contracts).
  **97.43% statements, 96.05% branches, 100% functions, and 98.08% lines.** The five uncovered
  statements are empty Express path-parameter guards that cannot be reached by a matched route.
- [x] `src/routes/questions.js` — `tests/unit/routes/questions.test.js` (19 tests: create/read/stats,
  embedded-question access, update/delete guards, bulk creation; 33.6% statements)
- [x] `src/routes/documents.js` — `tests/unit/routes/documents.test.js` (21 tests: text upload,
  lecture list/stats, metadata/download, delete cleanup, extraction guards; 46.5% statements)
- [x] `src/routes/auth.js` — `tests/unit/routes/auth.test.js` (login/register validation gates, /me,
  preferences/set-course via injected session, /tas + /users + TA demote/promote, /methods env+settings).
  **Passport paths NOT covered** (successful local login, SAML, logout session.destroy) — e2e. Required a
  `session` option on the route harness (additive).
- [x] `src/routes/onboarding.js` — `tests/unit/routes/onboarding.test.js` (create + key-validation gate,
  read/update/delete access guards, instructor course-list ordering, completion, defaults, exception paths,
  and `/stats` route ordering). Mocks only `validateApiKey` (network);
  `buildKeySubdocument`/`stripPrivateKeyFields` run real under NODE_ENV=test. **49 tests; 100% statements,
  functions, and lines, 95.42% branches.** Remaining branches are fallback operands in private sorting/access
  helpers; all route behavior and defensive path-parameter guards are covered.
- [x] `src/routes/superChatNotes.js` — `tests/unit/routes/superChatNotes.test.js` (16 tests: list/get with
  `isOwn`, check-similar, create/update/delete author guards). Service + model real over memory-db (collection
  is **`superchat_notes`**); only `notesQdrantService` mocked, notes LLM surface injected as `llmRegistry`.
- [x] `src/routes/lectures.js` — `tests/unit/routes/lectures.test.js` (publish toggle + API-key gate,
  publish-status/student-visible readers, pass-threshold validators, published-with-questions filtering).
  llmKeyStore left real (pure `isKeyValid`/`structuredKeyError`); positional `lectures.$.x` write asserted via contract.
- [x] `src/routes/mentalHealthFlags.js` — `tests/unit/routes/mentalHealthFlags.test.js` (anonymization for
  non-admins, admin-only resolve/disregard, escalate/dismiss, db guard).
- [x] `src/routes/struggle-activity.js` — `tests/unit/routes/struggle-activity.test.js` (per-student access
  guard, course/persistence/weekly readers, Super Chat aggregates, prefix-vs-`/:courseId` route ordering).
- [x] `src/routes/student-tracker.js` — `tests/unit/routes/student-tracker.test.js` (auth gate, per-course
  topic scoping, single/ALL reset, revoked-enrollment guard).
- [x] `src/routes/user-agreement.js` — `tests/unit/routes/user-agreement.test.js` (status default vs stored,
  agree upsert + agreedAt stamp, db guard, missing-user 500 characterization).
- [x] `src/routes/learning-objectives.js` — `tests/unit/routes/learning-objectives.test.js` (validation +
  `week`/`lectureName` alias, read path, save echo, swallow-on-not-found characterization).
- [x] `src/routes/llmKeyMiddleware.js` — `tests/unit/routes/llmKeyMiddleware.test.js` (function-level, fake
  req/res: `sendLlmKeyError` translation, registry-missing 503, success pass-through, LlmKeyError-vs-rethrow split).
- [x] `src/routes/instructorChat.js` — `tests/unit/routes/instructorChat.test.js` (session save/list/get/delete
  CRUD and failures, `/pool` mapping + key gate, and the complete `POST /` retrieval/prompt/LLM response
  flow). Provider and vector boundaries remain deterministic mocks. **100% statements, functions, and
  source lines; 96.87% branches** in the focused Jest/Istanbul run. The remaining branch outcomes are
  defensive/default operands that normal Express routing precludes or always supplies explicitly.
  Added `replaceOne()` to `memory-db`.
- [x] **Deepened `src/routes/courses.js`** — lifecycle coverage is in `courses.deep.test.js`; focused
  statistics, student projection, transfer document cloning, cleanup tolerance, and catch contracts are
  in `courses.coverage.test.js`. Provider/Qdrant/GridFS boundaries are deterministic mocks; no network calls.
- [x] **Deepened `src/routes/settings.js`** — complete; prompt, LLM-key, global, course-scoped,
  academic-gate, error, and reset paths are now covered (see the primary settings entry above).
- [x] **Deepened `src/routes/students.js`** — `tests/unit/routes/students.deep.test.js` (instructor/admin
  session list/single/delete; note instructor delete only checks `role`, not systemAdmin).
- [x] **Deepened `src/routes/quiz.js`** — `tests/unit/routes/quiz.deep.test.js` (49 focused tests across
  question filtering/sanitization, objective and AI answer checking, attempt/history contracts,
  material listing plus text/inline/GridFS downloads, quiz-help chat, LLM-key translation, and ordinary
  failure paths). Provider/vector boundaries are deterministic mocks. Focused Istanbul coverage:
  **97.34% statements, 91.76% branches, 100% functions, and 100% source lines.** Remaining statement
  and branch misses are short-circuit/default operands and early-return continuations rather than
  uncovered source lines.
- [x] **Deepened `src/routes/qdrant.js`** — `tests/unit/routes/qdrant.test.js` (27 tests:
  staff/course authorization, status, document processing/search with AI-key translation, document and
  collection maintenance, destructive all-collection outcomes, paginated orphan cleanup and errors).
  Provider/vector boundaries are deterministic mocks. Focused Istanbul coverage: **96.27% statements,
  88.78% branches, 100% functions, and 98% lines**. The four uncovered lines are unreachable through
  Express because earlier guards preclude them or the route requires a nonempty path parameter.
- [ ] Remaining deepening (lower ROI): `courses.js` defensive validation/catch permutations; questions
  `auto-link`/`generate-ai`/`check-answer` and documents `upload`/`cleanup-orphans` (AI/gridfs heavy).
  **Skip/e2e:** `studentSuperCourse.js`, `shibboleth.js` (vector/SAML — low unit fidelity).
- [x] **Deepened `src/routes/chat.js`** — `chat.additional.test.js` and
  `chat-id-fallback.test.js` augment the feedback/survey/core suites. Provider, Qdrant, GridFS, tracker,
  and model boundaries are deterministic mocks. Coverage includes validation and error mappings,
  retrieval/source attribution, custom modes/prompts, struggle/directive tracking, non-blocking mental
  health analysis, summaries and continuation, downloads, feedback/survey review and CSV, service status,
  saved sessions, and both practice-answer modes. **94.14% statements, 86.22% branches, 91.78%
  functions, 94.96% lines; all behavior reachable through the exported router is covered.**

---

## 6. Findings (DO NOT fix here — log only)

Record real behavior discrepancies surfaced by tests. These are for a *later* deliberate
pass, NOT to be fixed while writing tests.

- **✅ Fixed — Quiz material routes did not verify that the requested lecture was published or
  quiz-testable.** Both `GET /api/quiz/materials` and the direct download route now require quiz
  practice and material access to be enabled, and require the document's lecture to be published and
  included in `testableUnits`. Focused route tests cover unpublished and excluded lectures for both
  listing and guessed-document download paths.

- **A GridFS quiz-material failure after piping starts cannot return the advertised JSON error.** The
  stream error handler falls back to ending the partially-started response once headers are sent, so the
  client may receive a truncated/aborted download rather than `{ message: 'Stored file could not be read' }`.
  Both pre-data and post-data stream failures are characterized in `quiz.deep.test.js`; not fixed.

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

- **✅ Fixed — `FlaggedQuestion.createFlaggedQuestion` let `flagData.flagId` override the stored ID.**
  The generated ID is now applied after caller data, so the returned ID always identifies the inserted
  flag. The model regression test verifies that a caller-provided ID is ignored.

- **✅ Fixed — `flags` said instructors may create flags but rejected ordinary-course flags.**
  Instructors may now create a flag only when `userHasCourseAccess` confirms that they teach the
  requested course. Route tests cover both an owning instructor and an unrelated instructor.

- **✅ Fixed — `PUT /api/flags/:flagId/status` accepted arbitrary non-empty status strings.**
  Both status-only updates and response updates now accept only `pending`, `reviewed`, `resolved`, or
  `dismissed`, with validation at both the route and model boundaries. Regression tests verify invalid
  values are rejected without modifying the stored flag.

- **✅ Fixed — `Onboarding.upsertOnboarding` overwrote `createdAt` during updates.**
  `createdAt` now uses `$setOnInsert`, preserving the original timestamp on every update while still
  initializing new records. The model regression test verifies the original date is unchanged.

- **✅ Fixed — `PersistenceTopic.incrementStudentCount` built a `RegExp` from unescaped topic text.**
  Topic text is now escaped before constructing the anchored case-insensitive expression, so regex
  metacharacters are matched literally. The regression test verifies that input `'ATP.se'` creates a
  distinct `atp.se` topic instead of incrementing an existing `atpase` topic.

- **✅ Fixed — `User.authenticateUser` accepted a basic-auth user with `passwordHash: null`.**
  Basic-auth accounts now fail closed when their password hash is missing, returning the same generic
  invalid-credentials response used for unknown users and incorrect passwords. The regression test in
  `User.test.js` also verifies that a rejected attempt does not update `lastLogin`.

- **`GET /api/questions/stats` does not require authentication or course access.** Anyone who knows
  a `courseId` can retrieve aggregate question counts, points, and type breakdown. Characterized in
  `tests/unit/routes/questions.test.js`; not fixed.

- **`POST /api/documents/:documentId/extract-questions` does not require authentication or course
  access.** An anonymous caller who knows a document ID can invoke the course LLM and receive extracted
  questions. Characterized in `tests/unit/routes/documents.test.js`; not fixed.

- **`mentalHealthFlags` handlers carry no role check of their own** (escalate/dismiss). The router relies
  entirely on its mount-time middleware in `server.js`
  (`requireAuth` + `populateUser` + `requireActiveCourseForNonInstructors`), so it is NOT reachable
  unauthenticated. But *within* the router only `resolve`/`disregard` check `isAdmin`; `escalate`/`dismiss`
  (and the `GET /course/:courseId` read) impose no instructor/TA restriction, so any authenticated caller
  that clears the mount middleware can use them. Escalating an unknown flag returns HTTP 200 with
  `{ success: false }` (the model reports not-found, but the route forwards it without a 404).
  Characterized in `tests/unit/routes/mentalHealthFlags.test.js`; not fixed. (Note: the router unit tests
  drive the handlers directly and therefore bypass the mount middleware — they do not assert anonymous access.)

- **`POST /api/student/struggle/reset` returns 500 (not 404) when the authenticated user has no DB
  record.** `User.resetUserStruggleState` returns `{ success: false }` for an unknown user, and the route
  maps any non-success to a 500 with no user-not-found branch. Characterized in
  `tests/unit/routes/student-tracker.test.js`; not fixed.

- **✅ Fixed — `POST /api/lectures/publish` swallowed the model's "lecture not found" result.**
  The route now checks the model result and returns 404 for an unknown course/lecture instead of
  echoing a successful publish response. The focused route test covers the unknown-lecture path.

- **✅ Fixed — `POST /api/learning-objectives` ignored model failures and trusted body identity.**
  The route now authorizes course-management access from `req.user`, uses the session user as the
  mutation actor, and returns 404 when the course or lecture does not exist. Tests cover anonymous,
  unauthorized, spoofed-identity, missing-course, missing-lecture, and successful writes.

- **`user-agreement` handlers destructure `req.user` with no guard.** `GET /status` and `POST /agree`
  both do `const { userId, role } = req.user`, so an unauthenticated request throws and yields a 500
  rather than a 401. Not reachable in production (mounted behind `requireAuth`). Characterized in
  `tests/unit/routes/user-agreement.test.js`; not fixed.

- **✅ Fixed — `POST /api/courses` 500ed after writing when `contentTypes` was omitted.** The route now
  normalizes an omitted value to `[]` before persistence and response generation, and rejects supplied
  non-array values with 400. Regression tests verify both the optional empty path and invalid input.

- **`chat.js` contains private retrieval-analysis code that is unreachable from the exported router.**
  `analyzeChunkSources` and `checkLearningObjectivesMatch` (including their nested callbacks) are
  declared but never called or exported. In addition, `canCreateFeedbackForCourse` has a non-student
  guard that every current caller precludes with its own role guard, and the outer source-attribution
  catch cannot run because `determineSourceAttribution` already catches and converts its own errors.
  These account for the remaining uncovered executable lines/functions after all public router behavior
  was exercised. Reaching literal 100% would require a deliberate production refactor (remove the dead
  helpers, wire them into behavior, or expose an intentional test seam), so this test-only pass left them
  unchanged. Characterized by the focused `chat*.test.js` coverage run; not fixed.

- **`POST /api/chat` assumes Qdrant search returns an array.** If `searchDocuments` resolves `null`
  instead of throwing or returning `[]`, later array operations fail and the route returns its generic
  500 response. Characterized in `tests/unit/routes/chat.additional.test.js`; not fixed.

- **✅ Fixed — Assessment-question writers and evaluators used divergent data shapes.** Instructor and
  onboarding writes now preserve boolean TF answers, ordered MCQ option arrays, and numeric MCQ answer
  indexes. Quiz and chat share `services/objectiveAnswer.js`; instructor/student rendering handles
  structured falsy answers such as index `0`; and `scripts/migrate-question-schema.js` provides dry-run
  and explicit apply modes for existing records. Focused unit and browser tests cover the boundaries.

- **The full Supertest suite has a known transient socket/parser flake.** During this pass, one complete
  run produced `ECONNRESET` / HTTP parse failures in unrelated route suites despite `maxWorkers: 1`;
  the immediate unchanged rerun passed all 1,346 tests across 75 suites, as did the subsequent full
  Monocart run. No source or test change was made in response to the transient failure.

- **`src/routes/courses.js` cannot faithfully reach literal 100% through its exported router alone.**
  The expanded public-route suite invokes all functions. The focused Istanbul run now reports **97%+
  statements/lines and 100% functions** (up from roughly 91% statements and 84% branches); the remaining
  lines are dominated by mutually exclusive fallback
  operands, defensive outcomes precluded by earlier successful checks (for example, an update reporting
  no match after the same course/access was already confirmed), and catch paths inside internal helpers
  that are neither exported nor independently injectable. Literal 100% would require production test
  seams, impossible collaborator state, or coverage-ignore directives. This pass used none of those.

- **`requireInstructorOrTA` has two unreachable redirect branches.** After a user is denied
  (`role !== 'instructor' && role !== 'ta'`), the role-based redirect block still tests
  `user.role === 'instructor'` (→ `/instructor`) and `user.role === 'ta'` (→ `/ta`). Both are
  dead: a user reaching that block can be neither role, so only the `student` and `else → /login`
  arms are reachable. These are the sole two uncovered lines after the coverage pass
  (`auth.js` 258, 262). Reaching literal 100% would require deleting the dead arms (a production
  edit). Characterized in `tests/unit/middleware/auth.test.js`; not fixed.

*(append new findings below as you go)*

- **`PUT /api/onboarding/:courseId` mass-assigns arbitrary request fields.** After checking access against
  the existing course, the route spreads the entire request body into `$set`. An owning instructor can
  therefore overwrite protected fields such as `courseId` and `instructorId`, moving the record and
  transferring ownership. Characterized in `tests/unit/routes/onboarding.test.js`; not fixed.

- **✅ Fixed — Onboarding unit-file updates reported success for a missing unit.** The route now verifies
  that `unitName` exists in the course and returns 404 before attempting the positional update.

- **✅ Fixed — Re-posting onboarding reported an update without updating onboarding fields.** Existing
  owned courses now receive the submitted safe onboarding fields and return the real modification
  count. Reposts against another instructor's course return 403, and the API key/cache update follows
  the actual course ID returned by the model.

- **The student-facing saved-session routes have inconsistent authorization boundaries.**
  `GET /:courseId/:studentId/sessions/own` treats the mere existence of a course as sufficient
  student access and performs no enrollment check. Its instructor branch requires a system admin
  but only recognizes `instructorId` ownership (not the `instructors` array accepted elsewhere).
  Meanwhile, `DELETE .../own` and `PUT .../title` allow any instructor to mutate any matching
  student's session without a system-admin or course-access check. Characterized in
  `tests/unit/routes/students.test.js`; not fixed.

- **Three guards in `src/routes/students.js` are unreachable through the exported Express router.**
  `requireDownloadAdmin`'s missing-user arm is always preceded by each caller's own 401 guard, and
  the delete handlers' missing-path-parameter arms cannot run because Express only matches those
  routes when every required segment is present. Literal 100% line coverage therefore needs a
  production refactor/test seam or coverage-ignore directives. This test-only pass left them unchanged.

- **Qdrant direct document deletion is not course-scoped.** Any authenticated instructor or TA can call
  `DELETE /document/:documentId`; the route does not look up the document's course or check course access,
  and calls `deleteDocumentChunks(documentId)` without a course filter. Characterized in
  `tests/unit/routes/qdrant.test.js`; not fixed.

- **`DELETE /delete-all-collections` can leave partial destructive state while reporting success.** It
  deletes Qdrant before checking whether MongoDB is available. Individual Mongo collection-drop failures
  are recorded in `mongoResults`, but the HTTP response still has status 200, `success: true`, and the
  message `All collections deleted successfully`. Characterized in `qdrant.test.js`; not fixed.

- **Qdrant cleanup overstates removals when deletion fails.** `/cleanup-vectors` says it removed the number
  of identified orphans even when `deleteDocumentChunks` returns `success: false`; only `deletedChunks`
  and `deletedDocIds` reveal that nothing was deleted. Characterized in `qdrant.test.js`; not fixed.

- **Course-scoped Qdrant authorization permits any staff member when the course does not exist.** The
  access helper returns success before the instructor/TA permission check if the course lookup misses.
  This may support course provisioning, but also means callers can search/process/clean arbitrary new
  course IDs. Characterized in `qdrant.test.js`; not fixed.

- **`superCourseService.searchSuperCourse` trusted the notes retriever too strongly.** A `null`
  response caused a `.length` crash, and a provider returning more notes than requested could exceed
  the total retrieval budget and make the computed lecture count negative. The service now treats
  non-array responses as empty and caps consumed notes to the allocated slot count. It also skips the
  fire-and-forget usage update when retrieved notes have no persistent IDs. Covered in
  `tests/unit/services/superCourseService.test.js`.

- **✅ Fixed — Course code generation returned a known collision after exhausting retries.**
  `generateDistinctCourseCode` now throws after 20 colliding candidates, preventing `upsertCourse` and
  onboarding course creation from writing a course with duplicate student/instructor codes. Tests use
  deterministic RNG collisions and verify that exhaustion rejects without inserting the course. A
  database-wide unique constraint remains a possible future defense-in-depth improvement.

- **Four empty-path-parameter guards in `src/routes/struggle-activity.js` are unreachable through the
  exported router.** The `if (!userId)` / `if (!courseId)` 400 branches in `/student/:userId`,
  `/persistence/:courseId`, `/weekly/:courseId`, and `/:courseId` can never run: Express only matches
  those routes when the segment is present and non-empty. Same pattern already logged for
  `students.js`/`flags.js`. These are the only uncovered lines left in the file (29, 73, 112, 232);
  literal 100% would need a production edit or coverage-ignore directives. Not fixed.

- **Three 401 guards in `src/routes/studentSuperCourse.js` are unreachable.** `/save`, `/sessions`,
  and `DELETE /sessions/:sessionId` re-check `req.user.userId` after `resolveStudentSuperchat` has
  already returned 401 for a missing student, so their `Authentication required` arms (lines 316,
  358, 426) can never execute. Only these dead guards keep the file from 100% line coverage. Not fixed.

- **`User.toSessionUser`'s null branch is unreachable through the model's exports.** The helper is
  private, and every call site (`authenticateUser`, `createOrGetSAMLUser`) only reaches it with a
  non-null user, while `applyAccessState` returns null solely for falsy input. Line 52 is therefore
  dead through the public API — the last uncovered line in `User.js`. Not fixed.

- **`user-agreement.js` and route modules that destructure model functions at require time cannot be
  failure-injected with `jest.spyOn` on the model module.** `const { createOrUpdateUserAgreement } =
  require(...)` binds the function reference at load, so spying on the module object later has no
  effect on the router. Catch-path tests for such routers must inject the failure a level down
  (e.g. a db whose `collection()` throws). Testability note, not a bug.

- **⚠️ `llmKeyStore` binds `require('node-fetch')` at load — mocking `global.fetch` silently makes
  REAL network calls.** A first attempt at covering `validateApiKey`'s provider paths replaced
  `global.fetch` with a jest mock; the module ignored it and the tests hit `api.openai.com` for real
  (the failures echoed OpenAI's genuine 401 body). Any test touching `validateApiKey`/`openaiPost`
  MUST `jest.mock('node-fetch', () => jest.fn())` before requiring the module (now done in
  `llmKeyStore.test.js`). Rule of thumb for this codebase: check whether the module imports
  `node-fetch` before assuming the global-fetch seam works. Testing note, not a source bug.

- **`Onboarding.js` computes the collection handle before each `try` block**, so a failing
  `db.collection()` rejects the promise without ever reaching the model's catch/log/rethrow paths.
  The catch blocks are only reachable when the collection *operation* fails (covered that way in
  `Onboarding.test.js`). Behavior note, not a bug.

- **`src/routes/testLlmStub.js` line 55 (addRule catch) is unreachable.** The route already 400s
  when both matchers are missing, and `LLMStub.addRule` throws only for exactly that condition, so
  the route-level try/catch around `addRule` can never fire. The single uncovered line in the file;
  a production edit would be required for literal 100%. Not fixed.

- **`src/routes/academicSync.js`'s db-missing 503 (lines 97-99) is unreachable through the mounted
  router.** The router-level academic-API gate runs first and `isAcademicApiEnabled(null)` fails
  closed, so a request with no db is answered by the gate (`disabled` read / 403 write) before
  `requireInstructorCourse` can produce its 503. Not fixed.

- **Five spots in `src/routes/questions.js` are unreachable through the exported router.**
  (a) `canReadCourseQuestions`/`canMutateCourseQuestions` missing-user arms and the mutate
  fallthrough (lines 97, 113, 128): `requireCourseQuestionAccess` 401s unauthenticated requests and
  403s non-staff roles before either helper runs, and it only calls `canMutate` for roles that match
  one of its arms. (b) `linkQuestionsToLearningObjectives`'s empty-input early return (199-201):
  both callers (auto-link and bulk) pre-guard empty objectives/questions with their own responses.
  (c) The empty-`questionId` guard at 847 (Express path-parameter pattern). These keep the file at
  ~98.6% lines; literal 100% would need production edits or coverage-ignore directives. Not fixed.

- **✅ Fixed — Course positional-update helpers could report false success during a race.**
  `updateLecturePublishStatus`, `updateLearningObjectives`, `updatePassThreshold`,
  `updateUnitDisplayName`, and both `addDocumentToUnit` branches now require the conditional write's
  `matchedCount` to be nonzero. Focused model tests simulate the unit/document disappearing between the
  initial read and write and verify that each helper fails instead of reporting success.

- **✅ Fixed — PUT could recreate a missing assessment question.**
  The question PUT route now selects the model's `requireExisting` mode, which returns 404 for an
  unknown `questionId` and conditionally matches the existing embedded question during the write.
  This prevents stale editors from silently recreating a deleted question; POST and bulk creation
  continue to use the model's create-capable default. Route and model regression tests cover both
  the HTTP response and the no-insert guarantee.

---

## 7. Known helper limitations to extend as needed

- **`aggregate()`** has minimal support in `memory-db.js` for the stats/activity helpers already
  covered (`$match`, `$group`, `$project`, `$sort`, `$limit`, `$skip` plus common accumulators,
  common expressions, and ISO-week expressions). Extend it only for new pipeline shapes you
  actually need, and re-run the full unit suite afterward.
- **Dotted queries through embedded arrays** are supported (added for question-route lookups such as
  `lectures.assessmentQuestions.questionId`). **Positional `$` update operator** (`lectures.$.field`)
  is not applied by `memory-db`.
  Course unit-update helpers use it; test their read side, or extend the helper minimally.
- **bcrypt**-backed functions (`User.createUser/authenticateUser`, `authService` login/register)
  work with the real dep but are slower; isolate them or test the non-bcrypt helpers.
- **`replaceOne(query, doc, { upsert })`** is supported (added for `instructorChat` session save): replaces
  the matched doc in place (preserving `_id`), or upserts a new doc seeded with the filter's equality fields.
- **`session` option on the route harness** (`makeRouteApp(router, { session })`) injects `req.session` for
  routers that read it directly (e.g. `auth.js` preferences/set-course).

When you extend the helper, it's shared infra — re-run the **whole** `npm run test:unit`
afterward to make sure existing suites stay green.
