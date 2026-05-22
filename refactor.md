# Refactor Roadmap

This repo now has a strong e2e safety net, so the refactor should proceed in
small behavior-preserving slices. The goal is not "make files smaller" by
itself; the goal is to remove repeated behavior, side-effect coupling, dead
surface area, and drift-prone contracts without losing the coverage baseline.

Primary reference docs:

- `tests/e2e/FINDINGS.md`
- `tests/e2e/Redundancies.md`
- `tests/e2e/AGENTS.md`
- `tests/e2e/REPORTING.md`

Test policy from AGENTS:

- When writing tests, do not change production code in the same step unless the
  task is explicitly to fix the discovered fault.
- Tests should capture existing faults or protect behavior before a refactor.
- For pure refactors, keep API responses, DOM ids/classes, localStorage keys,
  script load order, route URLs, and session behavior stable unless a tracked
  finding explicitly says the old behavior is wrong.

## Current Inventory

Large files worth splitting after shared helpers are extracted:

- `public/instructor/scripts/instructor.js` - 7141 lines
- `public/student/scripts/student.js` - 6904 lines
- `public/instructor/scripts/onboarding.js` - 4568 lines
- `src/routes/courses.js` - 3406 lines
- `src/models/Course.js` - 1982 lines
- `public/styles/documents.css` - 2397 lines
- `public/instructor/scripts/home.js` - 2824 lines
- `public/instructor/scripts/flagged.js` - 1846 lines
- `src/routes/questions.js` - 1595 lines
- `src/routes/chat.js` - 1347 lines
- `src/routes/documents.js` - 1166 lines

High-confidence duplicate helper clusters:

- `showNotification` appears as 11 top-level implementations.
- `waitForAuth` appears as 11 top-level implementations.
- `getCurrentCourseId` appears in common auth plus multiple page scripts.
- TA helpers repeat across instructor and TA pages:
  `loadTAPermissions`, `hasPermissionForFeature`,
  `setupTANavigationHandlers`, `updateTANavigationBasedOnPermissions`.
- Course display helpers repeat across instructor onboarding/home and TA pages:
  `isCourseInactive`, `getCourseDisplayName`, `dedupeCourses`,
  `appendCourseGroup`.
- Topic helpers repeat across `home.js`, `instructor.js`, `onboarding.js`, and
  `src/models/Course.js`: `normalizeTopicLabel`, `normalizeTopicSource`,
  `normalizeTopicUnitId`, topic dedupe/object normalization.
- Question modal and AI-question helpers are substantially duplicated between
  `instructor.js` and `onboarding.js`: `saveQuestion`, `updateQuestionForm`,
  `setupMCQValidation`, `populateFormWithAIContent`,
  `generateAIQuestionContent`, modal open/close/reset helpers, auto-link
  helpers, and fallback AI content helpers.
- Download helper trio is duplicated in `chat.js`, `documents.js`, and
  `quiz.js`: `inferExtensionFromMimeType`, `resolveDownloadFilename`,
  `setAttachmentHeaders`.

Known coupling issue:

- `public/instructor/settings.html` loads `public/instructor/scripts/instructor.js`
  before `settings.js`. Settings therefore inherits document/upload side
  effects, publish-status polling, course lookup, and duplicate helper globals.

Server/static route constraints:

- Public shared assets are mounted separately:
  - `/assets` -> `public/assets`
  - `/styles` -> `public/styles`
  - `/common` -> `public/common`
- Role-protected static mounts are broad:
  - `/student` -> `public/student`
  - `/instructor` -> `public/instructor`
  - `/ta` -> `public/ta`
- Specific page routes sometimes override or complement static mounts:
  - `/student`, `/student/history`, `/student/flagged`, `/student/quiz`
  - `/instructor`, `/instructor/`, `/instructor/documents`
  - `/instructor/home`, `/instructor/settings`, `/instructor/onboarding`
  - `/instructor/flagged`, `/instructor/downloads`, `/instructor/ta-hub`
  - `/instructor/student-hub`
  - `/ta`, `/ta/onboarding`, `/ta/settings`
- Some `.html` aliases have different protection than the broad static mount:
  `/instructor/student-hub.html` must stay instructor-only and is intentionally
  declared before the `/instructor` static mount.
- TA redirects are route-level behavior, not just frontend nav behavior:
  `/instructor/home` -> `/ta`, `/instructor/settings` -> `/ta/settings`,
  `/instructor/downloads` -> `/ta`.
- Legacy/test routes exist and are covered:
  `/settings`, `/test-qdrant`, `/qdrant-test`.
- Refactors that move public files must update both HTML references and server
  route/static assumptions.

API middleware constraints:

- `src/server.js` applies shared middleware before route modules. A route file
  may rely on these already having run:
  - `/api/auth`: `populateUser`
  - most APIs: `requireAuth`
  - course-sensitive APIs: `requireActiveCourseForNonInstructors`
  - student-facing APIs: `requireStudentEnrolled`
  - selected APIs: `populateUser`
- Many route-level `if (!req.user)` branches are defensive or unreachable under
  the live server because `requireAuth` already ran. Do not force coverage by
  weakening middleware.
- Splitting route files must preserve mount order and static-before-param route
  ordering.

Browser global/inline-handler constraints:

- Many pages still use inline handlers such as `onclick="nextStep()"`,
  `onclick="toggleSection(this)"`, `onclick="closeStudentModal()"`, and
  download modal handlers.
- During extraction, keep compatibility exports on `window` until all inline
  handlers and tests are migrated.
- Prefer namespaced internals plus temporary aliases:
  `window.BiocBotInstructor.foo = foo; window.foo = foo;`.
- Avoid new top-level `function foo()` declarations in shared scripts when a
  page script also defines `foo`; non-module scripts alias those names onto
  `window` and can shadow replacement helpers.

Browser storage contract:

- These keys are part of current behavior and tests:
  - `selectedCourseId`
  - `selectedCourseName`
  - `selectedUnitName`
  - `studentMode`
  - `lastModeChange`
  - `currentUser`
  - `userId`
  - `biocbot_current_chat_<studentId>`
  - `biocbot_session_<studentId>_<courseId>_<unitName>`
  - `biocbot_chat_history_<studentId>`
  - `biocbot_last_known_flags`
  - `settingsFlashMessage`
  - `loadChatData`
  - `sessionId`
- URL `?courseId=` generally wins over localStorage. Preserve this unless a
  tracked finding says otherwise.
- Stale localStorage is a known bug pattern; shared course helpers must validate
  stored course ids against the current user's actual course set.

Whole-file deletion inventory:

- The first static reference pass did not show obvious public JS/CSS files that
  can be deleted wholesale. Most scripts/stylesheets are referenced by at least
  one HTML page.
- The safer deletion target is unused code inside large scripts/stylesheets,
  not whole files.
- Before deleting any whole file, check all of:
  - HTML `<script>` / `<link>` references.
  - Express static aliases and redirects in `src/server.js`.
  - Dynamic JS references, inline handlers, and test harness pages.
  - Coverage report entries after a full `npm test`.

Dead/unreachable-code candidates to audit separately:

- `src/routes/auth.js` has a commented deprecated UBC Shibboleth block.
- `src/models/UserAgreement.js` exports `hasUserAgreed` and
  `getAgreementStats`, but current route usage only imports
  `getUserAgreement` and `createOrUpdateUserAgreement`.
- `src/routes/shibboleth.js` has SLO placeholder routes.
- `public/student/scripts/student.js` has placeholder helpers:
  `getCurrentUnitName()` and `getAuthToken()`.
- `/test-qdrant` and `/qdrant-test` are test/diagnostic surfaces, but they are
  covered; remove only as an explicit product decision.
- Some defensive branches are unreachable because Express route params or
  server middleware guarantee presence. Document rather than contort tests.

CSS cleanup candidates:

- `tests/e2e/FINDINGS.md` already lists dead candidates in
  `public/styles/documents.css`.
- A rough text-reference scan found 55 selectors in `documents.css` with no
  text hit in current HTML/JS, including the same families from FINDINGS:
  legacy upload table/list UI, prototype browsing UI, superseded modal steps,
  and prototype question editor selectors.
- Smaller possible dead-selector pockets:
  - `public/styles/chat.css`: `calibration-score-box`, `more-messages`,
    `no-messages`, `score-info`, `search-container`, `three-dots`.
  - `public/styles/home.css`: digest/activity/stat selector groups.
  - `public/instructor/styles/onboarding.css`: `content-types`,
    `generate-section`, `questions-input-section`, `onboarding-accordion`.
- Do not delete selectors from text-search alone. Dynamic DOM construction is
  common in this repo.

Logging/noise inventory:

- `rg` found roughly 1900 console/debug statements across `public` and `src`.
- This should become its own cleanup phase. Do not mix logging removal into
  behavior refactors unless the logs are directly blocking tests or leaking
  sensitive data.

## Working Rule

Every refactor slice should follow this loop:

1. Identify the exact finding/redundancy being addressed.
2. Run the narrow relevant Playwright spec(s) before editing.
3. Make one small extraction/deletion.
4. Run the same spec(s), then the broader impacted group.
5. Update `FINDINGS.md` or `Redundancies.md` only when a tracked item is truly
   fixed or superseded.

Use `npm test` as the final gate before merging a larger slice. Use
`npm run test:report:coverage` only to inspect an already-generated report; it
does not run tests.

## Phase 0: Baseline and Refactor Harness

Before code changes:

- Run `npm test` and save the passing baseline.
- Keep a list of specs used for each slice in the PR/commit notes.
- Prefer a new helper plus compatibility wrapper over a breaking rename.
- If adding a shared browser helper, load it before page scripts and keep the
  existing global function name stable until all page scripts are migrated.

Baseline checks to know:

- Full suite: `npm test`
- Instructor document/controller: `tests/e2e/instructor-js-focused.spec.js`,
  `tests/e2e/instructor-js-deep-branches.spec.js`,
  `tests/e2e/instructor.spec.js`
- Instructor settings: `tests/e2e/instructor-settings.spec.js`,
  `tests/e2e/routes-settings-api.spec.js`,
  `tests/e2e/settings-css-coverage.spec.js`
- Onboarding: `tests/e2e/instructor-onboarding-focused.spec.js`,
  `tests/e2e/instructor-onboarding.spec.js`,
  `tests/e2e/instructor-boot-status-course-setup-branches.spec.js`,
  `tests/e2e/instructor-onboarding-save-upload-modal-branches.spec.js`
- Student chat: `tests/e2e/student-chat.spec.js`,
  `tests/e2e/student-js-focused.spec.js`,
  `tests/e2e/student-js-coverage.spec.js`,
  `tests/e2e/student-js-deep-branches.spec.js`,
  `tests/e2e/student-session-course-branches.spec.js`,
  `tests/e2e/student-calibration-units-branches.spec.js`
- Courses API/model: `tests/e2e/routes-courses-api.spec.js`,
  `tests/e2e/routes-courses-api-branches.spec.js`,
  `tests/e2e/routes-courses-api-error-branches.spec.js`,
  `tests/e2e/course-model-branch-coverage.spec.js`

Pre-edit checklist for the first real slice:

- Confirm `git status --short` and avoid mixing unrelated local changes.
- Run the narrow spec for the selected slice.
- If editing tests, type-check changed JS tests with
  `npx tsc --noEmit --allowJs --checkJs <changed-test-files>`.
- If editing browser scripts loaded by HTML, list every page that includes the
  script before changing load order.
- If editing route modules, list the server middleware stack from
  `src/server.js` for that mount.
- If deleting CSS, search both HTML and JS for each selector stem.

## Phase 1: Shared Browser Utilities

This is the best first phase because it reduces global collisions before
splitting the giant files.

### 1A. Notifications

Status: started. Simple message/type notification helpers now use
`public/common/scripts/notifications.js`; the student flag notification module
is intentionally separate because it has a different object-based API.

Target:

- Add `public/common/scripts/notifications.js`.
- Keep `window.showNotification(message, type = 'info')` as the public API.
- Support the existing `.notification`, `.success`, `.error`, `.warning`,
  `.info` DOM/CSS behavior used by current tests.
- Load it before page scripts that call `showNotification`.
- Remove local `showNotification` implementations one page at a time.

Known local implementations:

- `public/instructor/scripts/downloads.js` — migrated
- `public/instructor/scripts/flagged.js` — migrated
- `public/instructor/scripts/instructor.js` twice — migrated
- `public/instructor/scripts/onboarding.js` — migrated
- `public/instructor/scripts/student-hub.js` — migrated
- `public/instructor/scripts/ta-hub.js` — migrated
- `public/student/scripts/flag-notifications.js`
- `public/ta/scripts/ta-home.js` — migrated
- `public/ta/scripts/ta-onboarding.js` — migrated
- `public/ta/scripts/ta-settings.js` — migrated

Risk notes:

- `flag-notifications.js` may need to stay separate or be adapted carefully
  because it accepts a notification object and stacks notifications.
- Migrate simple message/type implementations first.

Suggested tests:

- `tests/e2e/instructor-unit1-content-persistence-notifications-branches.spec.js`
- `tests/e2e/instructor-downloads-branches.spec.js`
- `tests/e2e/flagged-coverage.spec.js`
- `tests/e2e/student-hub.spec.js`
- `tests/e2e/ta-hub.spec.js`
- `tests/e2e/ta-settings-coverage.spec.js`
- `tests/e2e/flag-notifications.spec.js` only when touching the student flag
  notification object implementation.

### 1B. Auth Wait / Current User

Target:

- Move `waitForAuth` into `public/common/scripts/auth.js` or a small
  `public/common/scripts/auth-ready.js`.
- Keep the existing timeout behavior while the migration is in progress.
- Cache `/api/auth/me` in the common `getCurrentUser()` path so page scripts
  stop repeatedly fetching auth state.

Risk notes:

- `history.js` already documents a top-level `getCurrentUser` aliasing issue.
  Avoid new top-level declarations that shadow common helpers.
- Pages currently rely on global script order rather than imports.

Suggested tests:

- `tests/e2e/auth-stack-branches.spec.js`
- `tests/e2e/middleware-auth-coverage.spec.js`
- `tests/e2e/instructor-course-list-auth-wait-branches.spec.js`
- `tests/e2e/student-chat.spec.js`
- `tests/e2e/student-history-storage-branches.spec.js`
- `tests/e2e/ta-settings-coverage.spec.js`

### 1C. Course Selection / Course Display Helpers

Target:

- Extract shared browser helpers for:
  - selected course from URL/localStorage/current user
  - `selectedCourseId` validation against available courses
  - `isCourseInactive`
  - `getCourseDisplayName`
  - `dedupeCourses`
  - `appendCourseGroup`
- Keep URL `?courseId=` priority and existing `localStorage.selectedCourseId`
  behavior stable.

Risk notes:

- Several recent findings were stale-course bugs. Any change here needs tests
  that prove stale localStorage does not override URL/session course context.

Suggested tests:

- `tests/e2e/instructor-home.spec.js`
- `tests/e2e/student-session-course-branches.spec.js`
- `tests/e2e/student-chat.spec.js`
- `tests/e2e/ta.spec.js`
- `tests/e2e/ta-settings-coverage.spec.js`
- `tests/e2e/student-hub.spec.js`
- `tests/e2e/ta-hub.spec.js`

### 1D. TA Permission Navigation Helpers

Target:

- Extract shared browser helpers for TA course permissions:
  - `loadTAPermissions`
  - `hasPermissionForFeature`
  - `setupTANavigationHandlers`
  - `updateTANavigationBasedOnPermissions`
- Preserve route behavior where TA pages link into instructor pages with
  `?courseId=...`.
- Keep route-level permission enforcement authoritative; frontend nav hiding is
  only presentation.

Risk notes:

- `/instructor/documents` and `/instructor/flagged` are intentionally shared
  instructor/TA surfaces with `requireTAPermission`.
- `/instructor/home`, `/instructor/settings`, and `/instructor/downloads` are
  intentionally not shared with TAs.

Suggested tests:

- `tests/e2e/ta.spec.js`
- `tests/e2e/ta-hub.spec.js`
- `tests/e2e/ta-settings-coverage.spec.js`
- `tests/e2e/flagged-coverage.spec.js`
- `tests/e2e/auth-stack-branches.spec.js`

## Phase 2: Remove Settings Page Coupling

Target:

- Identify exactly which globals `settings.js` currently gets from
  `instructor.js`: likely `waitForAuth`, `showNotification`,
  `getCurrentCourseId`, maybe course helper behavior.
- Move only those helpers into common scripts.
- Update `public/instructor/settings.html` so it loads common helpers plus
  `settings.js`, not the full `instructor.js`.
- Verify that settings no longer starts document-page polling or publish-status
  calls.

Why this should happen early:

- It addresses `Redundancies.md` R18.
- It reduces blast radius before splitting `instructor.js`.
- It gives a clean pattern for extracting page-independent browser helpers.

Suggested tests:

- `tests/e2e/instructor-settings.spec.js`
- `tests/e2e/routes-settings-api.spec.js`
- `tests/e2e/instructor-quiz-settings.spec.js`
- `tests/e2e/settings-css-coverage.spec.js`
- Then rerun instructor document/upload specs:
  `tests/e2e/instructor-js-focused.spec.js`,
  `tests/e2e/instructor.spec.js`,
  `tests/e2e/rag-documents-coverage-branches.spec.js`

## Phase 3: Backend Shared Utilities

### 3A. Objective Answer Evaluation

Target:

- Extract `evaluateObjectiveAnswer(question, studentAnswer)` into a shared
  module, probably under `src/services/` or `src/utils/`.
- Use it from:
  - `src/routes/quiz.js` `/check-answer`
  - `src/routes/chat.js` `/check-practice-answer`
  - later `src/routes/questions.js` `/check-answer`
- Preserve current defensive coercion while legacy data exists.

Risk notes:

- Do not remove support for legacy string/letter/object question shapes until
  the assessment-question schema migration is complete.

Suggested tests:

- `tests/e2e/quiz-api.spec.js`
- `tests/e2e/quiz-api-errors.spec.js`
- `tests/e2e/student-quiz.spec.js`
- `tests/e2e/student-chat.spec.js`
- `tests/e2e/routes-chat-api.spec.js`

### 3B. Download Response Helpers

Target:

- Extract `inferExtensionFromMimeType`, `resolveDownloadFilename`, and
  `setAttachmentHeaders` from `chat.js`, `documents.js`, and `quiz.js`.
- Keep header names, filenames, and content-type behavior stable.

Suggested tests:

- `tests/e2e/routes-documents-api.spec.js`
- `tests/e2e/documents-api-error-branches.spec.js`
- `tests/e2e/student-chat.spec.js` source-document download section
- `tests/e2e/quiz-api.spec.js`
- `tests/e2e/rag-documents-coverage-branches.spec.js`

### 3C. Error Response Shape

Target:

- Add a small response helper:
  - `sendError(res, status, message, extra = {})`
  - later `sendNotFound(res, message, extra = {})`
- Standardize on `{ success: false, message }` for new/migrated route errors.
- Migrate routes in small groups and update tests deliberately.

Risk notes:

- `auth.js` and parts of `settings.js` still use `error`.
- Some frontend code reads `result.error`; migrate clients before flipping
  those route responses.
- `Redundancies.md` R12b notes that some tests currently expect 400 for
  "not found" branches. Treat 404 migration as a separate intentional change.

Suggested route order:

1. `src/routes/settings.js` internal consistency.
2. `src/routes/auth.js` plus login client handling.
3. Low-risk API modules with few clients.
4. Large route files (`courses.js`, `questions.js`) last.

### 3D. Course Access and Active-Course Lookup

Target:

- Create one canonical server helper for course access checks.
- Decide and document active-course lookup:
  - either `getCourseById(db, courseId, { includeDeleted = false })`
  - or explicit `getActiveCourseById` and `getCourseByIdIncludingDeleted`
- Remove local duplicates:
  - `hasInstructorAccess`
  - `hasInstructorOrTAAccess`
  - `hasCourseManagementAccess`
  - repeated `isInactiveCourse` / sort helpers

Risk notes:

- Some routes intentionally allow TAs to access inactive courses if still
  assigned. Do not collapse "inactive" and "deleted" behavior without tests.
- `src/routes/settings.js` has direct `findOne({ courseId })` calls that do
  not consistently filter deleted courses.

Suggested tests:

- `tests/e2e/routes-courses-api.spec.js`
- `tests/e2e/routes-courses-api-branches.spec.js`
- `tests/e2e/routes-courses-api-error-branches.spec.js`
- `tests/e2e/course-model-branch-coverage.spec.js`
- `tests/e2e/routes-settings-api.spec.js`
- `tests/e2e/routes-onboarding-api.spec.js`
- `tests/e2e/routes-questions-api.spec.js`

### 3E. ID Generation

Target:

- Add `idFor(entity)` backed by `crypto.randomUUID()`.
- Migrate one entity family at a time.
- Keep existing prefixes if clients/tests infer entity type from prefixes.

Known ad-hoc patterns:

- `courseId` slug plus `Date.now()`
- `practiceId` as `pq_${Date.now()}_${Math.random(...)}`
- document/user/flag/session style ids in multiple modules

Suggested tests:

- Route/model specs for the exact entity being migrated.
- Avoid broad ID changes in the same slice as schema or access-control changes.

### 3F. Assessment Question Schema Contract

Target:

- Finish standardizing assessment questions on the structured shape documented
  in `tests/e2e/FINDINGS.md`:
  - true/false `correctAnswer` as boolean
  - multiple-choice `options` as ordered array
  - multiple-choice `correctAnswer` as numeric index
  - short-answer `correctAnswer` as string
- Keep temporary compatibility readers until existing stored data is migrated.
- Extract a shared `buildQuestionPayload(formInputs)` or
  `normalizeQuestionPayload(raw)` helper used by instructor and onboarding
  save paths.
- Add a Mongo migration script under `scripts/` for legacy stored questions.
- After migration, remove student-side dual-shape branches and legacy wire
  protocol fallbacks.

Risk notes:

- `false` and `0` are valid answers; validation must not reject them as
  missing.
- Do not clean up `student.js` compatibility branches until API writes and
  stored data are both standardized.

Suggested tests:

- `tests/e2e/routes-questions-api.spec.js`
- `tests/e2e/questions-api-coverage.spec.js`
- `tests/e2e/questions-api-error-branches.spec.js`
- `tests/e2e/instructor-unit1-objectives-questions-branches.spec.js`
- `tests/e2e/instructor-onboarding-focused.spec.js`
- `tests/e2e/student-calibration-units-branches.spec.js`
- `tests/e2e/student-quiz.spec.js`
- `tests/e2e/quiz-api.spec.js`

## Phase 4: Split `instructor.js`

Do not split this file until Phase 1 notifications/auth helpers are stable and
settings no longer loads it.

Suggested extraction order:

1. Topic normalization and topic-review UI.
2. Upload/document modal controller.
3. Publish status and polling controller.
4. Learning objective helpers.
5. Assessment question modal helpers.
6. AI question generation/regeneration helpers.
7. Remaining unit management/orchestrator code.

Potential file layout:

- `public/instructor/scripts/course-context.js`
- `public/instructor/scripts/topic-review.js`
- `public/instructor/scripts/document-upload.js`
- `public/instructor/scripts/publish-status.js`
- `public/instructor/scripts/question-modal.js`
- `public/instructor/scripts/ai-question-modal.js`
- `public/instructor/scripts/instructor.js` as the page orchestrator

Guardrails:

- Keep existing global callbacks temporarily for inline `onclick` handlers.
- Do not change DOM ids/classes while extracting.
- Move code, then remove the old copy only after tests pass.

Suggested tests:

- `tests/e2e/instructor-js-focused.spec.js`
- `tests/e2e/instructor-js-deep-branches.spec.js`
- `tests/e2e/instructor-topic-review-branches.spec.js`
- `tests/e2e/instructor-ai-question-generation-branches.spec.js`
- `tests/e2e/instructor-unit1-objectives-questions-branches.spec.js`
- `tests/e2e/instructor-publish-ta-course-branches.spec.js`
- `tests/e2e/rag-documents-coverage-branches.spec.js`
- `tests/e2e/instructor.spec.js`

## Phase 5: Split `onboarding.js`

Do this after the shared course-display, notification, auth, topic, and question
modal helpers exist.

Suggested extraction order:

1. Onboarding boot/status and course creation/join.
2. Instructor course-code join flow shared with `home.js`.
3. Objective and probing-question list helpers.
4. Assessment question modal and payload builder.
5. Unit 1 save/persistence helpers.
6. Upload/document helpers.
7. AI question generation/regeneration.

Important schema note:

- `FINDINGS.md` still tracks assessment-question shape divergence. Do not
  remove legacy/dual-shape reader code until the API contract and stored data
  migration are finished.

Suggested tests:

- `tests/e2e/instructor-onboarding-focused.spec.js`
- `tests/e2e/instructor-onboarding.spec.js`
- `tests/e2e/instructor-boot-status-course-setup-branches.spec.js`
- `tests/e2e/instructor-onboarding-save-upload-modal-branches.spec.js`
- `tests/e2e/instructor-topic-review-branches.spec.js`
- `tests/e2e/instructor-unit1-objectives-questions-branches.spec.js`

## Phase 6: Split `student.js`

This should happen after shared auth/current-user/course selection helpers are
stable.

Suggested extraction order:

1. Course selection and enrollment/revoked-access UI.
2. Chat rendering and source attribution.
3. Chat autosave/session serialization.
4. Practice question handling.
5. Struggle reset handling.
6. Assessment/calibration flow.
7. Mode toggle and restored-mode rendering.
8. Flagging UI.
9. History/localStorage compatibility helpers.

Guardrails:

- Preserve `localStorage` keys:
  - `selectedCourseId`
  - `studentMode`
  - `biocbot_current_chat_*`
  - `biocbot_session_*`
- Preserve `sessionStorage.loadChatData` behavior.
- Preserve existing globals used by inline handlers or tests until callers are
  migrated.

Suggested tests:

- `tests/e2e/student-chat.spec.js`
- `tests/e2e/student-js-focused.spec.js`
- `tests/e2e/student-js-coverage.spec.js`
- `tests/e2e/student-js-deep-branches.spec.js`
- `tests/e2e/student-session-course-branches.spec.js`
- `tests/e2e/student-calibration-units-branches.spec.js`
- `tests/e2e/student-quiz.spec.js`
- `tests/e2e/flag-notifications.spec.js`

## Phase 7: Split `src/routes/courses.js`

Do this after shared backend helpers exist. `courses.js` is route-heavy and has
high API blast radius.

Suggested module layout:

- `src/routes/courses/index.js` - mounts subrouters and preserves URLs.
- `src/routes/courses/access.js` - server access helpers or imports from a
  shared service.
- `src/routes/courses/codes.js` - course-code generation/normalization.
- `src/routes/courses/topics.js` - approved-topic extraction/review endpoints.
- `src/routes/courses/content.js` - content/document/unit endpoints.
- `src/routes/courses/transfer.js` - course/document transfer.
- `src/routes/courses/ta.js` - TA assignment/permissions endpoints.
- `src/routes/courses/students.js` - student lists and enrollment endpoints.

Guardrails:

- Preserve all URL paths and method semantics.
- Keep route ordering explicit, especially static paths before `/:courseId`
  paths.
- Do not change 400/403/404 contracts unless the slice is explicitly the
  response-shape migration.

Suggested tests:

- `tests/e2e/routes-courses-api.spec.js`
- `tests/e2e/routes-courses-api-branches.spec.js`
- `tests/e2e/routes-courses-api-error-branches.spec.js`
- `tests/e2e/course-model-branch-coverage.spec.js`
- `tests/e2e/ta.spec.js`
- `tests/e2e/student-chat.spec.js`
- `tests/e2e/instructor-home.spec.js`

## Phase 7B: Split `src/models/Course.js`

Do this after `courses.js` route behavior is stable. The model mixes course
creation, lecture state, objectives/questions, documents, TA permissions,
student enrollment, topic normalization, and quiz settings.

Suggested module layout:

- `src/models/course/base.js` - collection access, create/upsert, active lookup.
- `src/models/course/codes.js` - course code generation and normalization.
- `src/models/course/lectures.js` - publish status, pass thresholds, unit names.
- `src/models/course/questions.js` - assessment questions and schema helpers.
- `src/models/course/documents.js` - document add/remove from units.
- `src/models/course/access.js` - instructors/TAs/students access helpers.
- `src/models/course/topics.js` - approved struggle topic normalization.
- `src/models/course/settings.js` - quiz/anonymization settings.
- `src/models/Course.js` remains a compatibility facade while routes migrate.

Guardrails:

- Keep the current `require('../models/Course')` export shape until all callers
  are migrated.
- Extract pure helpers first, then DB mutation helpers.
- Do not mix model splitting with schema migration in the same slice.

Suggested tests:

- `tests/e2e/course-model-branch-coverage.spec.js`
- `tests/e2e/routes-courses-api.spec.js`
- `tests/e2e/routes-courses-api-branches.spec.js`
- `tests/e2e/routes-courses-api-error-branches.spec.js`
- Specs for the route surface using the moved model helper.

## Phase 8: Document Ingest and RAG Refactors

Targets:

- Extract shared document ingest flow from:
  - `POST /api/documents/upload`
  - `POST /api/documents/text`
- Keep extraction/parsing mode as the only branch-specific step.
- Use shared download helpers from Phase 3B.
- Keep Qdrant indexing and `CourseModel.addDocumentToUnit` behavior stable.

Related candidates:

- `src/routes/documents.js`
- `src/routes/chat.js`
- `src/routes/quiz.js`
- `src/services/qdrantService.js`
- `src/services/llm.js`

Risk notes:

- Qdrant and LLM services are log-heavy and have many harnessed error paths.
  Keep service logging cleanup separate from behavior extraction.

Suggested tests:

- `tests/e2e/routes-documents-api.spec.js`
- `tests/e2e/documents-api-error-branches.spec.js`
- `tests/e2e/rag-documents-coverage-branches.spec.js`
- `tests/e2e/chat-rag-documents.spec.js`
- `tests/e2e/qdrant-service-coverage.spec.js`
- `tests/e2e/qdrant-service-error-branches.spec.js`
- `tests/e2e/llm-service-coverage.spec.js`

## Phase 9: CSS Cleanup

Start with `public/styles/documents.css` because it is large and already has
documented dead-selector candidates.

Delete in small groups:

1. Legacy document-list/table upload UI:
   `.upload-box`, `.upload-button`, `.documents-list`, `.document-filters`,
   `#document-search`, `#document-filter`, `.documents-table`, `.status`,
   `.empty-state-icon`.
2. Prototype browsing/selection UI:
   `.document-cards`, `.document-card`, `.folder-structure`, `.folder-item`,
   `.file-type-section`, `.file-type-options`, `.week-selection`,
   `.form-group`.
3. Superseded upload/modal flow selectors:
   `.modal-step`, `.step-indicators`, `.step-dot`, `.file-upload-area`,
   `.upload-zone`, `.objectives-checkbox`, `.objectives-input`,
   `.content-preview`, `.preview-section`, `.validation-actions`.
4. Calibration/prototype question editor selectors:
   `.delete-question`, `.option-item`, `.score-box`,
   `.generate-questions-container`, `.generate-btn`,
   `.generate-help-text`.

Then inspect smaller CSS pockets:

- `public/styles/chat.css`
- `public/styles/home.css`
- `public/instructor/styles/onboarding.css`
- `public/styles/style.css`

Guardrails:

- Text-search is not enough. Confirm selectors are not created by JS.
- Run the CSS harness spec and at least one real page spec for each stylesheet.
- For visible layout changes, open the page in a browser and inspect desktop
  and mobile widths.

Suggested tests:

- `tests/e2e/documents-css-coverage.spec.js`
- `tests/e2e/documents-css-coverage-branches.spec.js`
- `tests/e2e/chat-css-coverage.spec.js`
- `tests/e2e/home-css-coverage.spec.js`
- `tests/e2e/settings-css-coverage.spec.js`
- Page specs that load the stylesheet being touched.

## Phase 10: Logging Cleanup

Target:

- Replace noisy `console.log` debug traces with a small logger or remove them.
- Keep `console.error`/`console.warn` where they provide operational value.
- Redact or remove logs that expose prompts, raw LLM outputs, user data, or
  document content.

Suggested order:

1. Browser page scripts with obvious debug traces.
2. Middleware/auth debug logs.
3. Qdrant/LLM verbose request/response logs.
4. Server startup logs last.

Guardrails:

- Do not remove logs in the same slice as behavior changes.
- Run relevant route/service harness specs because some tests may indirectly
  observe error behavior, timing, or service initialization.

## First Ten Tickets

1. Shared notifications for simple message/type pages.
2. Shared `waitForAuth` and cached `getCurrentUser`.
3. Remove `instructor.js` from `settings.html`.
4. Shared objective-answer evaluator for quiz/chat/questions.
5. Shared course display/selection helpers for instructor/TA/student pages.
6. Assessment-question schema contract and migration plan.
7. Shared TA permission/navigation helpers.
8. Shared download header/filename helpers.
9. Course access/active-course server helper.
10. `documents.css` dead-selector cleanup group 1.

These should come before splitting the giant files because they reduce global
collision risk and make later moves mostly mechanical.

Recommended first implementation sequence:

1. Start with notifications only for instructor pages that use simple
   `showNotification(message, type)` and are not `flag-notifications.js`.
2. Then extract common auth readiness, because many later browser helpers rely
   on the same auth/current-user state.
3. Then remove `instructor.js` from settings. This proves the shared-helper
   approach and shrinks side effects before the larger splits.
4. Only then touch schema, route helpers, or large file splitting.

## Future Agent Prompt

Use this prompt when handing a slice to a future session:

```text
We are refactoring tlef-biocbot with e2e coverage currently expected to pass.
Follow AGENTS.md: when writing tests, do not change production code in the same
test-writing step unless explicitly fixing the discovered fault. Tests should
capture existing faults or protect behavior before a refactor.

Use tests/e2e/FINDINGS.md, tests/e2e/Redundancies.md, and refactor.md.
Make one small behavior-preserving refactor slice. Keep public APIs, DOM ids,
CSS classes, localStorage keys, sessionStorage keys, route URLs, response
shapes, and script load order stable unless a tracked finding explicitly says
the old behavior is wrong.

Before editing, identify the exact finding/redundancy being addressed and the
narrow tests to run. Run those tests before and after if feasible. Do not
delete unrelated code or broad CSS without proving it is unused by both HTML
and dynamic JS. After editing, report changed files, tests run, and residual
risk.
```
