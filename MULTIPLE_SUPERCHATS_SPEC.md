# Multiple Superchats — Implementation Spec

Status: Draft for implementation
Issue: #353 (FEATURE: Multiple Superchats)
Date: 2026-06-02

---

## 1. Overview

Today the platform has **one** global Super Course chat. This spec generalizes it
into **multiple instructor-curated superchats ("buckets")**, each composed of a set
of courses. Examples: "2nd Year Biochem", "3rd Year Biochem", "Graduate".

### Product decisions (locked)

1. **Students see and pick from multiple superchats.** They can switch between any
   superchat they have access to. They **cannot** change which courses are inside a
   superchat — composition is instructor/admin-controlled.
2. **Membership is per-course (decentralized).** Each instructor decides, in their
   own course's settings, which bucket(s) that course belongs to (a checklist that
   replaces today's single "Include in Super Course" toggle).
3. **Bucket definitions are admin-managed.** Buckets (name + year level + chat
   settings) are created/renamed/deleted centrally. Course→bucket assignment is
   per-instructor.
4. **Student visibility is enrollment-derived.** A student sees a superchat if they
   are enrolled (`studentEnrollment.<id>.enrolled === true`) in at least one course
   that belongs to that superchat. No separate per-superchat roster.
5. **`yearLevel` is a labeling/seed dimension, not the access gate.** It seeds the
   default buckets, labels them ("2nd Year"), and orders/marks them relative to the
   student's own level. Enrollment gates access.

### The through-line

Introduce one new concept — **`superchatId`** — and thread it through the three
places that currently assume a single super course:
- **Membership:** `course.superchatIds: []` (replaces `allowInSuperCourse`).
- **Struggle records:** `StruggleActivity.superchatId`.
- **Flags:** flagged-question `superchatId`.

Everything else (Qdrant retrieval, citations, context building, notes) already
operates on an arbitrary set of course IDs and needs no structural change — only
the *source* of that set changes (from a global boolean to a per-bucket query).

---

## 2. Data model

### 2.1 New collection: `superchats`

One document per bucket. This is essentially today's `superCourseChat` settings doc,
multiplied — **without** a `courseIds` field (membership lives course-side, see 2.2).

```js
{
  _id: "<superchatId>",            // stable string id, e.g. "year-2" or an ObjectId string
  name: "2nd Year Biochem",        // shown to students in the picker
  description: "",                 // optional, for card UI / tooltips
  yearLevel: 2,                    // 1-5 (5 = Graduate) or null; label + seed + ordering
  showToStudents: true,            // per-bucket student visibility (replaces global showStudentSuperCourse)

  // Chat settings (same shape/normalization as today's resolveSuperCourseChatSettings)
  studentTopK: 8,
  instructorTopK: 8,
  includeInactiveCourses: false,
  includeNotesInRetrieval: true,   // instructor chat only
  noteRetrievalRatio: 0.25,
  noteMinScore: 0.25,
  studentPrompt: "...",
  instructorPrompt: "...",
  studentLevelModifiers: { ... },
  instructorLevelModifiers: { ... },

  createdBy: "<userId>",
  createdAt: Date,
  updatedAt: Date,
  isDeleted: false                 // soft-delete to preserve historical flags/struggle refs
}
```

Resolution/normalization reuses the existing `resolveSuperCourseChatSettings()` logic
(`superCourseService.js`) applied per-document, with defaults from
`prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS`.

### 2.2 `courses` collection — membership

- **Add** `superchatIds: [ "<superchatId>", ... ]` (array, default `[]`).
- **Deprecate** `allowInSuperCourse` (kept readable for migration/back-compat only;
  no longer written by new code).

A course may belong to multiple buckets simultaneously (core course in Year 2 + 3).

### 2.3 `struggle_activity` collection (`StruggleActivity`)

- **Add** `superchatId: "<superchatId>" | null` to records written from a superchat.
  (`source: 'superCourse'` stays — it marks origin; `superchatId` scopes *which* one.)

### 2.4 Flagged questions (`FlaggedQuestion`)

- **Add** `superchatId: "<superchatId>" | null` to super-course flags.
- `courseId` stays `'SUPER_COURSE'` (sentinel — still not a real course).

---

## 3. Migration

One-time, idempotent migration script (run on deploy):

1. **Create seed buckets from `yearLevel`.** For each distinct `yearLevel` present
   among courses with legacy `allowInSuperCourse === true`, create a `superchats`
   doc: id `year-<n>`, name from a label map (`1→"1st Year"`, … `5→"Graduate"`),
   `yearLevel: n`. Copy chat settings from the existing `superCourseChat` settings
   doc (so prompts/topK/visibility carry over). Set `showToStudents` from the old
   global `showStudentSuperCourse`.
   - Courses with `allowInSuperCourse === true` but `yearLevel == null` → assign to
     an "Ungrouped" / default bucket so nothing is dropped.
2. **Populate `course.superchatIds`.** For each course with `allowInSuperCourse === true`,
   push the id of the bucket matching its (resolved) `yearLevel`.
3. **Backfill flags & struggle.** Existing `'SUPER_COURSE'` flags and
   `source:'superCourse'` struggle rows get `superchatId: null` (surfaced under a
   "Legacy / All" filter entry — see 7.3, 8.2).
4. Leave `allowInSuperCourse` in place but stop writing it.

Migration must be safe to re-run (upsert buckets by id, `$addToSet` for superchatIds).

---

## 4. Backend — services

### 4.1 `superCourseService.js`

- **New** `getSuperchat(db, superchatId)` → resolved settings for one bucket (reuses
  `resolveSuperCourseChatSettings`). Returns null if missing/deleted.
- **New** `listSuperchats(db, { studentVisibleOnly })` → array of bucket summaries
  (`_id, name, description, yearLevel, showToStudents`).
- **Change** `buildSuperCoursePoolQuery(superchatId, includeInactiveCourses)` →
  filter becomes `{ superchatIds: superchatId, status: ... }` (was
  `{ allowInSuperCourse: true }`).
- **Change** `getSuperCourseRetrievalPool(db, { superchatId, includeInactiveCourses })`
  → pass `superchatId` through to the query.
- **Change** `searchSuperCourse(db, query, limit, { superchatId, ... })` → resolve the
  bucket, use its `courseIds` (derived via the query), topK, and note settings. Qdrant
  call is unchanged (already accepts a course-id array).
- **Change** `getSuperCourseApprovedTopics(db, { superchatId, includeInactiveCourses })`
  → scope to the bucket's courses only (this *improves* struggle attribution: fewer
  candidate topics per analysis).
- Context/citation/attribution builders: **no change** (pool-driven).
- Keep `SUPER_COURSE_SETTINGS_ID` only for migration; new code is per-bucket.

### 4.2 `tracker.js`

- No signature change needed: `analyzeMessageAcrossCourses(message, courseTopics)`
  already takes a scoped list. The route now passes **only the active bucket's**
  course topics.

---

## 5. Backend — routes

### 5.1 Student: `src/routes/studentSuperCourse.js`

Every endpoint becomes superchat-scoped. `ensureStudentSuperCourseEnabled` is
replaced by a resolver that (a) loads the bucket, (b) confirms `showToStudents`,
(c) confirms the student is enrolled in ≥1 of the bucket's courses.

- **NEW** `GET /api/student-super-course/list`
  → buckets the student can access (enrollment-derived + `showToStudents:true`),
  each with `{ superchatId, name, description, yearLevel }`, sorted by the student's
  effective `yearLevel` (their year first), with an `aboveStudentLevel` flag computed
  from existing `getStudentYearLevel` logic.
- `GET /pool?superchatId=` → existing pool response, scoped to the bucket. Keep the
  existing `studentYearLevel` / `poolMaxYearLevel` / `hasHigherLevelCourses` fields.
- `POST /chat` → body gains `superchatId`. Validate access, scope retrieval + struggle
  tracking to that bucket. Struggle rows written here include `superchatId`.
- `POST /save`, `GET /sessions`, `GET /sessions/:id`, `DELETE /sessions/:id` → add
  `superchatId` to the saved session docs and to the query keys so chat history is
  per-bucket. (`student_super_course_chat_sessions` gains a `superchatId` field.)

**Access helper** (new): `getEnrolledCourseIds(db, studentId)` — scan `courses` for
`studentEnrollment.<id>.enrolled === true`, return their `courseId`s. Used by `/list`
and the per-request access check. (Generalizes the query already in
`getStudentYearLevel`.)

Visibility rule (the gate):
```js
const myCourseIds = await getEnrolledCourseIds(db, studentId);
const visible = await listSuperchats(db, { studentVisibleOnly: true })
  .then(buckets => filterBucketsWithCourseOverlap(buckets, myCourseIds));
// overlap = bucket has ≥1 course whose id ∈ myCourseIds
```

### 5.2 Instructor chat: `src/routes/instructorChat.js`

- Add `superchatId` to its `searchSuperCourse` / settings calls. Instructor chat may
  expose a bucket selector too (same `/list` minus the `showToStudents` filter — an
  instructor can chat any bucket). Notes retrieval stays instructor-only and now uses
  the per-bucket `includeNotesInRetrieval`.

### 5.3 Buckets CRUD (admin): `src/routes/settings.js` (or new `superchats.js`)

- `GET    /api/superchats` → list all buckets (admin).
- `POST   /api/superchats` → create `{ name, yearLevel, ...settings }`.
- `PUT    /api/superchats/:id` → update name / yearLevel / chat settings / showToStudents.
- `DELETE /api/superchats/:id` → soft-delete (`isDeleted:true`); also `$pull` the id
  from every `course.superchatIds`.
- Authz: admin/system-admin only (mirrors today's `super-course-chat-section` gating).

### 5.4 Per-course membership: `src/routes/settings.js` / `courses.js`

- The existing course-settings save path that writes `allowInSuperCourse`
  (`settings.js` ~308) is replaced by writing `superchatIds: []` for that course.
- `GET /api/courses/:courseId` (and the course settings load) returns `superchatIds`
  plus the list of available buckets so the checklist can render with current state.
- Authz: the course's instructor (existing course-ownership checks).

### 5.5 Struggle: `src/routes/struggle-activity.js`

- `GET /api/struggle-activity/super-course?superchatId=&limit=` → filter by
  `superchatId` (omit/`all` → every superchat, the legacy global view).
- Same for the `/super-course/weekly` aggregate.
- `StruggleActivity.getSuperCourseActivity(db, { superchatId, ... })` and
  `getWeeklyActiveTopics(db, null, { source, superchatId })` gain the filter.

### 5.6 Flags: `src/routes/flags.js`

- On create (`POST /api/flags`): when `isSuperCourseFlag`, read `superchatId` from the
  body and store it (still `courseId = 'SUPER_COURSE'`).
- Instructor review listing: support filtering super-course flags by `superchatId`.
- `GET /api/flags/my` (student): fold-in logic stays; flags now carry `superchatId` for
  display grouping.

---

## 6. Frontend — instructor (per-course checklist + admin bucket mgmt)

### 6.1 Per-course bucket checklist (primary membership UI)

Location: `public/instructor/settings.html` ~line 124, where the **"Include in Super
Course"** toggle is today. Replace the single toggle with a **checklist of buckets**:

> **Super Course membership**
> Include this course in:
> ☑ 2nd Year Biochem  ☐ 3rd Year Biochem  ☐ Graduate

- Populated from `GET /api/superchats`; checked state from the course's `superchatIds`.
- On save, send the selected ids as `superchatIds` (replaces the
  `allowInSuperCourse` field in the save payload — `settings.js` ~1093/1099).
- Empty selection = course is in no superchat (equivalent to old `false`).

### 6.2 Admin bucket management

Location: the existing `#super-course-chat-section` (admin-only) becomes a **list of
buckets** with create / rename / delete and a per-bucket settings editor (the same
fields that are global today: prompts, topK, includeInactive, includeNotes,
showToStudents, plus the new `yearLevel`). Drives the CRUD endpoints in 5.3.

---

## 7. Frontend — student (the picker)

### 7.1 Superchat picker

Location: `public/student/super-course.html` header, replacing the static
**"Scope: Opted-in biochemistry courses"** text (lines 47–49).

- Render a `<select id="superchat-picker">` populated from
  `GET /api/student-super-course/list`.
- Selecting a bucket sets the active `superchatId` and reloads: Sources panel (`/pool`),
  history (`/sessions`), and uses it in `/chat` calls.
- Single-bucket students: auto-select; render as a static label (no interaction).
- No accessible bucket: show an empty-state message ("No Super Course is available for
  your courses yet.") and disable the input.
- Optional polish: mark buckets above the student's level (using `aboveStudentLevel`
  from `/list`) with a small "(ahead of your year)" hint — reuses existing
  `hasHigherLevelCourses` signal.

### 7.2 Nav

Keep the single `#super-course-nav-item`. (No per-bucket nav entries.) Nav visibility:
show the item if `/list` returns ≥1 bucket (generalizes today's `/status` check).

### 7.3 Student flagged page

Super-course flags display grouped/labeled by their `superchatId`'s bucket name
(falling back to "Super Course" for legacy `null`).

---

## 8. Frontend — flag review & struggle dashboards (instructor)

### 8.1 Struggle (home): `public/instructor/scripts/home.js`

- The single `__super_course__` dropdown entry (line 17) becomes **one entry per
  bucket** (`__super_course__::<superchatId>`), sourced from `GET /api/superchats`,
  plus a "Super Chat — All" aggregate (legacy/global).
- `buildActivityUrl` / `buildWeeklyUrl` append `superchatId` to the
  `/api/struggle-activity/super-course[...]` calls.

### 8.2 Flag review page: `public/instructor/scripts/flagged.js`

- Where super-course flags are currently shown as one blob (`SUPER_COURSE`), present a
  **per-bucket filter** using the same bucket list. Legacy flags (`superchatId == null`)
  appear under "Super Course — Legacy / All".
- Source breadcrumb (the existing `source-breadcrumb-row`) now reflects the bucket name.

---

## 9. Visibility & authorization summary

| Actor | Can do | Gate |
|-------|--------|------|
| Student | See/pick a superchat, chat, flag, save sessions | Enrolled in ≥1 of bucket's courses AND `showToStudents` |
| Instructor | Assign their own course to bucket(s) | Course ownership |
| Instructor | Chat any bucket (instructor chat), view its struggle/flags | Instructor role |
| Admin | Create/rename/delete buckets, edit bucket chat settings | Admin/system-admin |

---

## 10. Edge cases

- **Course removed from a bucket / bucket deleted:** historical flags & struggle rows
  keep their `superchatId` (soft-delete buckets so the name still resolves; show
  "(archived)" if `isDeleted`). Students lose access immediately on next `/list`.
- **Student enrolled in a course that's in 3 buckets:** they see all 3 in the picker.
- **Bucket with zero courses:** never appears for students (no overlap); admin sees it
  in management with a "0 courses" note.
- **Student loses enrollment (banned):** `enrolled:false` → bucket disappears from
  `/list` (existing enrollment logic already returns `enrolled:false`).
- **`yearLevel` null on a course:** still assignable to any bucket via checklist;
  just isn't auto-seeded.
- **Notes** remain instructor-chat-only and are never retrieved in student chat
  (current behavior preserved per-bucket via `includeNotesInRetrieval`).

---

## 11. Testing (extend existing e2e suites)

- `course-year-level.spec.js` — unaffected; year level still derives/normalizes.
- New: bucket CRUD (create/rename/delete, soft-delete pulls course refs).
- New: per-course `superchatIds` save round-trip; empty selection.
- New: student `/list` enrollment-derivation (enrolled→visible, banned→hidden,
  multi-bucket overlap, no-overlap→empty).
- New: `/chat` + `/pool` scoping — retrieval limited to bucket's courses.
- Extend `superCourseStruggle-harness.js` — struggle rows carry correct `superchatId`;
  attribution scoped to bucket courses; per-bucket weekly aggregation.
- Extend `flags-api-coverage.spec.js` — super-course flag stores `superchatId`;
  per-bucket filtering; legacy `null` backfill surfaces under "All".
- Migration idempotency test (re-run produces no duplicates).

---

## 12. Build order (suggested)

1. Schema + migration (buckets, `course.superchatIds`, backfill).
2. `superCourseService` per-bucket functions + `getEnrolledCourseIds`.
3. Buckets CRUD route + admin management UI.
4. Per-course checklist UI + save path.
5. Student `/list` + picker + scoped `/pool` `/chat` `/sessions`.
6. Struggle `superchatId` thread (model, route, home.js dropdown).
7. Flags `superchatId` thread (route, flagged.js filter, student display).
8. Tests at each step; migration idempotency last.
