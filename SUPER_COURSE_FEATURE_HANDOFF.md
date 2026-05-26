# Super Course Feature — Handoff for Next Agent

## What we're building (1-paragraph TL;DR)

A **Super Course chat** for BiocBot — a separate chat page (instructor-only and
student-facing variants) that retrieves from a **pool of multiple biochemistry
courses' material at once**, plus general biochemistry knowledge. Plus a small
admin-only **"AI Settings"** section on each course's Settings page that
(a) lets admins tune that course's own student-chat Top-K, and (b) controls
whether that course's uploaded material is included in the Super Course pool.

Reference issue: **#338**.

---

## Core mental model — read this first

**The Super Course is NOT a course doc with `isSuperCourse: true`.**
It is just a **chat page** (URL) that aggregates chunks across courses. Do
not build a "designate this course as the super course" action. Do not
create a special course doc. The Super Course's retrieval pool is just
`Qdrant.search({ courseId: { $in: [all courseIds where allowInSuperCourse=true] } })`.

### Per-course settings (admin-only section on each course's Settings page)

- **Include in Super Course** toggle → writes `course.allowInSuperCourse` (default `true`)
- **Student Chat — Top-K** number input → writes `course.ragSettings.student.topK` (default 3)

That's it for per-course. Nothing else belongs here.

### Super Course chat settings (platform-wide, NOT per-course)

- Top-K for super course retrieval (default 8)
- Instructor super course system prompt
- Student super course system prompt
- These live in a **global settings doc**, e.g. `db.settings._id = 'superCourseChat'`
- Edited from a separate admin section, NOT per-course

### Super Course chat pages

- Instructor: `/instructor/chat` (new page). Peer-level tone, no tutor framing,
  no protégé toggle, no unit dropdown, no assessment questions. Saved history.
- Student: `/student/super-chat` (new page). Same stripped UI. Slightly softer
  prompt than the instructor one. Saved history.
- Both show flag button. Flags integrate with existing
  `src/routes/flags.js` + `public/instructor/flagged.html` system; surface
  to system admins (Maz + Rich) only.

---

## Decisions already locked in (don't re-litigate these)

| Decision                                 | Value                                                                                                                           |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Admin gate                               | `user.permissions.systemAdmin === true` (same gate as "Delete All")                                                           |
| Who has admin                            | Maz + Rich only — confirmed with the prof                                                                                      |
| Default Top-K (regular course)           | 3 (matches project memory `right now we return 12`)                                                                           |
| Default Top-K (super course retrieval)   | 8                                                                                                                               |
|                                          |                                                                                                                                 |
| Tutor / protégé toggle on super course | No                                                                                                                              |
| Flag button on super course              | Yes, both student + instructor side, integrates into existing flag system                                                       |
| Persistence of super course chats        | Yes, with history sidebar — new collection `superCourseChats` (or extend existing chat collection with a type discriminator) |
| Super course chat scope                  | Course materials AND general biochemistry (when retrieval is thin)                                                              |
| Default Instructor super course prompt   | See `src/services/prompts.js` → `INSTRUCTOR_SUPERCOURSE_SYSTEM_PROMPT` (already written, keep it)                          |
| Default Student super course prompt      | See `src/services/prompts.js` → `STUDENT_SUPERCOURSE_SYSTEM_PROMPT` (already written, keep it)                             |

---

## Recommended build order (clean, from scratch)

### Step 1 — Per-course AI Settings (small, additive)

1. Add `ragSettings.student.{topK, threshold}` and `allowInSuperCourse` fields
   to the Course model. Pure passive schema (defaults when missing).
2. Add a small pure helper `resolveRagSettings(courseDoc)` that returns
   `{ student: { topK, threshold } }` with defaults filled in.
3. Add `GET /api/settings/ai-settings?courseId=...` and `PUT /api/settings/ai-settings`
   in `src/routes/settings.js` — admin-only (use existing `requireSystemAdmin`).
4. Add an **AI Settings** section to `public/instructor/settings.html`,
   gated visible in `public/instructor/scripts/settings.js` →
   `checkDeleteAllPermission()`.
5. UI fields: one toggle ("Include in Super Course"), one number input
   ("Student Chat — Top-K"), save + reset buttons. Nothing else.
6. **Tests**: `tests/e2e/course-model-branch-coverage.spec.js` for the model
   helpers; `tests/e2e/instructor-settings.spec.js` for the API + UI.

### Step 2 — Wire per-course Top-K into existing student chat

1. `src/routes/chat.js` ~line 684 has a hardcoded `12` passed to
   `qdrant.searchDocuments(...)`. Replace with
   `CourseModel.resolveRagSettings(course).student.topK`.
2. Honor threshold too (filter results below `student.threshold` when > 0).
3. **Tests**: extend `chat-rag-documents.spec.js` to seed a course with
   `ragSettings.student.topK = 5` and verify retrieval limit (optional but
   nice — needs Qdrant running).

### Step 3 — Super Course retrieval helper

1. New service or helper: `getSuperCourseRetrievalPool(db)` →
   returns the list of courseIds where `allowInSuperCourse !== false`.
2. New wrapper: `searchSuperCourse(query, limit, threshold)` that uses that
   list as the courseId filter when calling Qdrant.
3. **Tests**: model-level, no chat infra needed.

### Step 4 — Global super course chat settings

1. Add a singleton settings doc (`db.settings._id = 'superCourseChat'`) with
   `{ studentTopK, instructorTopK, studentPrompt, instructorPrompt }`.
2. Reuse the platform-default prompts from `src/services/prompts.js`
   (already-written constants `INSTRUCTOR_SUPERCOURSE_SYSTEM_PROMPT`,
   `STUDENT_SUPERCOURSE_SYSTEM_PROMPT`).
3. Add a new section to `public/instructor/settings.html` called
   **"Super Course Chat Settings"** (admin-only, same gate as AI Settings).
4. New routes: `GET /api/settings/super-course-chat`,
   `PUT /api/settings/super-course-chat`.
5. **Tests**: API gating + round-trip.

### Step 5 — Instructor super course chat page (`/instructor/chat`)

1. New files: `public/instructor/chat.html`, `scripts/chat.js`, `styles/chat.css`.
2. Sidebar nav entry "Chat" in instructor sidebar (`home.html`, `settings.html`,
   `documents.html`, `flagged.html`, etc. — every page that has the instructor
   nav block).
3. New backend route `src/routes/instructorChat.js` →
   `POST /api/instructor/chat`. Uses `searchSuperCourse` (step 3) and the
   global super course chat settings (step 4) for Top-K + prompt.
4. UI: model the chat layout on `public/student/chat.*`, then strip
   protégé toggle, unit dropdown, assessment questions, flag-reason
   filtering. Keep the flag button.
5. **Tests**: open page, send message, receive response, flag a response.

### Step 6 — Student super course chat page (`/student/super-chat`)

1. Same shape as step 5 but for students.
2. Sidebar entry "Super Course Chat" in student nav.
3. Uses student-side prompt + Top-K from the global super course chat settings.
4. **Tests**: parallel to step 5.

### Step 7 — Conversation history sidebar

1. Persist both chats in `superCourseChats` collection (or extend existing
   `chat_sessions` with a `chatType` discriminator).
2. History sidebar pattern: copy from existing student chat history sidebar.
3. Users only see their own history.
4. **Tests**: persistence across reload, isolation between users.

### Step 8 — Flag integration

1. Extend `FlaggedQuestion` schema with `sourceCourseIds[]`, `sourceCourseNames[]`,
   `isSuperCourseFlag` boolean.
2. Capture cited source courseIds when the super course chat answers — pass
   them to `POST /api/flags` when the user flags a response.
3. Loosen `POST /api/flags` to allow instructors to flag (currently
   student-only). Make `unitName` optional.
4. Add a "supercourse-student" / "supercourse-instructor" `botMode`.
5. Update `public/instructor/flagged.html` + `scripts/flagged.js` to show
   the source-course breadcrumbs row when `isSuperCourseFlag === true`.
6. Visibility relies on existing `canReadCourseFlags` — only system admins
   will have access to the super course's flags because regular instructors
   aren't admins. No new gate needed.
7. **Tests**: flag from both chats, breadcrumbs render, non-admin can't
   retrieve them.

---

## Anti-patterns — things to NOT do (we burnt time on these)

1. **DON'T add a `isSuperCourse` flag on Course docs.** The super course is
   not a course. It's a chat surface that aggregates. The old design where
   one course got marked as "the super course" was scrapped.
2. **DON'T add a `setIsSuperCourse` / "Designate as Super Course" UI.**
   No designation action exists. The super course is implicit in the
   aggregated chat page.
3. **DON'T put super-course prompts on `course.prompts`.** They are global,
   not per-course. They live in the platform-wide settings doc (step 4).
4. **DON'T put a "Source courses" multi-select on a course doc.** The pool
   is auto-derived from `allowInSuperCourse=true` across all courses.
5. **DON'T add a similarity-threshold input to the UI yet.** The field
   exists for future use but the prof didn't ask for tuning it. Skip.
6. **DON'T add an "Instructor Chat — Top-K" input on per-course settings.**
   Per-course settings only configure the regular per-course student chat.
   Instructor super-course Top-K lives in the platform-wide settings doc.
7. **DON'T silently change existing course retrieval behavior.** The
   pre-existing hardcoded value in `chat.js` was `12`, not `3`. If you
   default to 3 you'll cut every existing course's chat context by 75%.
   Confirm with Maz before changing the default.
8. **DON'T conflate "Include in Super Course" with "Mark as Super Course".**
   They're different concepts. We tried merging them and it was confusing.
   Only the "Include" toggle exists in the UI now.

---

## File map — where things live

| Layer               | File                                                        | Status                                                                                                                                                                                                                                                                                         |
| ------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Course schema       | `src/models/Course.js`                                    | Has `ragSettings`, `allowInSuperCourse` fields and helpers (`resolveRagSettings`, `getRagSettings`, `updateRagSettings`, `getAllowInSuperCourse`, `updateAllowInSuperCourse`). Currently includes leftover plumbing from the scrapped designation design — clean up or rewrite. |
| Default prompts     | `src/services/prompts.js`                                 | Has `INSTRUCTOR_SUPERCOURSE_SYSTEM_PROMPT` and `STUDENT_SUPERCOURSE_SYSTEM_PROMPT` constants — **keep these**, they're well-written.                                                                                                                                                |
| Settings routes     | `src/routes/settings.js`                                  | Has `/ai-settings` GET + PUT routes. Currently in a half-cleaned state — easier to rewrite the AI settings block from scratch.                                                                                                                                                              |
| Chat route          | `src/routes/chat.js` ~line 684                            | Hardcoded `12` was replaced with `resolveRagSettings(course).student.topK`. Verify the wiring is intact post-cleanup.                                                                                                                                                                      |
| Qdrant service      | `src/services/qdrantService.js`                           | `searchDocuments(query, filters, limit)` — `filters.courseId` accepts a single id. For super course retrieval you'll need to extend this to accept an array (`$in` filter), or build a new method.                                                                                      |
| Settings page HTML  | `public/instructor/settings.html`                         | "AI Settings" section currently exists with a toggle + Top-K input. Section description and other markup may be stale post-rip; verify.                                                                                                                                                        |
| Settings page JS    | `public/instructor/scripts/settings.js`                   | `loadAiSettings`, `saveAiSettings`, `applyAiSettingsFallbackDefaults`, `resetAiSettingsToDefaults` exist. Verify they only handle the surviving fields (toggle + student Top-K).                                                                                                       |
| Existing flag route | `src/routes/flags.js`                                     | Read this before step 8. Has `canReadCourseFlags` gating logic that's relevant.                                                                                                                                                                                                              |
| Existing flag UI    | `public/instructor/flagged.html` + `scripts/flagged.js` | Reuse for super course flags; just add breadcrumb rendering.                                                                                                                                                                                                                                   |
| Tests — model      | `tests/e2e/course-model-branch-coverage.spec.js`          | Has a section at the bottom for the new helpers. Verify it only covers the surviving surface.                                                                                                                                                                                                  |
| Tests — API/UI     | `tests/e2e/instructor-settings.spec.js`                   | Has API + UI tests for the AI Settings section. Same caveat.                                                                                                                                                                                                                                   |

---

## Open questions for Maz before building

1. **Real default Top-K for regular courses**: 3 (per project memory) or 12
   (per actual current hardcode)? Picking 3 is a 75% context cut for every
   existing course. Confirm.
2. **Default Top-K for super course retrieval**: 8 was agreed but worth a
   sanity check.
3. **Multiple super courses?** Currently the design assumes one. If multiple
   topical super courses are wanted (e.g. "Biochem", "Mol bio"), the
   global settings doc becomes a collection.
4. **Source course opt-out**: today `allowInSuperCourse` defaults true and
   admins can flip it off via the AI Settings panel. Does the prof want
   regular instructors (not just admins) to control this for their own
   course? If yes, the AI Settings section needs a non-admin variant
   that shows ONLY this toggle.

---

## Existing repo conventions to match

- Frontend is vanilla JS, no framework. Each page = `.html` + `.js` + `.css`.
- CSS variables for theming (`--primary-color`, `--card-bg`, `--border-color`).
- Auth via `auth.js` loaded on every page; fires `auth:ready` event; sets
  `currentUser` global.
- `getCurrentCourseId()` checks URL params > localStorage > user preferences.
- API responses: `{ success: boolean, data/message/... }`.
- Toggle switches: `<label class="toggle-switch"><input type="checkbox"><span class="toggle-slider"></span></label>`.
- Notifications: `showNotification(msg, type)` creates toasts in `.notification-container`.
- Admin gating pattern: existing `checkDeleteAllPermission()` in
  `settings.js` hides/shows admin-only sections. Add new admin section IDs
  to its show/hide lists.
- Tests use Playwright, run via `npm test`. Helpers: `tests/e2e/helpers/{users,courses-test}.js`.
- Mongo settings docs use `_id` as a string (e.g. `'global'`, `'llm'`).
  Follow that pattern for `'superCourseChat'`.
