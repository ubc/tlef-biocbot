# Super Chat Notes — Feature Spec

Shared, instructor-authored knowledge layer that feeds into Super Chat retrieval alongside parsed lecture material. Lets instructors write notes ("corrections", "teaching analogies", "things students keep asking", etc.) that the bot retrieves from when answering Super Chat questions. Designed to be friendly for non-technical instructors (e.g. Eden).

---

## 1. Decisions (locked)

### Permissions
- **Read:** Instructors only. Notes feed only **instructor** Super Chat. Student Super Chat is unaffected.
- **Write:** Any instructor. No course-scoping; it's a shared notebook.
- **Edit/delete:** Authors edit/delete their own notes. No admin override at MVP.

### Storage
- **Separate Qdrant collection:** `superchat_notes` (NOT mixed into the existing course-content collection).
- **MongoDB collection:** `superchat_notes`.

### MongoDB schema (`superchat_notes` collection)
```js
{
  noteId: String,             // uuid, primary
  authorId: String,           // userId of creator
  authorName: String,         // snapshot of displayName at create time
  title: String,              // optional; auto-generated from first sentence if blank
  content: String,            // plain text, soft-capped at 5000 chars
  tags: [String],             // free-form, optional
  qdrantPointIds: [String],   // ids of chunks owned by this note in Qdrant
  usageCount: Number,         // increments on each retrieval hit
  isDeleted: Boolean,         // soft delete
  createdAt: Date,
  updatedAt: Date,
  deletedAt: Date | null
}
```

### Editing / content
- **Inline expandable editor** (no modal, no separate page). Editor lives at top of list, expands on "New note" or "Edit".
- **Title:** optional. If blank on save, auto-generate from first sentence of `content`.
- **Content format:** plain text only. No markdown, no rich text.
- **Length:** soft cap **5,000 chars** with visible character counter (turns red near limit).
- **Tags:** free-form, optional, multiple per note.
- **On edit:** delete old Qdrant point IDs for this `noteId`, re-chunk, re-embed, upsert new points, update `qdrantPointIds` array. Edits take effect immediately for retrieval.
- **On delete:** soft delete in MongoDB (`isDeleted: true`, `deletedAt`), **hard remove** all corresponding Qdrant points so retrieval stops immediately.

### Chunking
- If `content.length <= 1000` chars → **single chunk** (no splitting).
- If `content.length > 1000` chars → use existing chunker (`ChunkingModule` from UBC GenAI toolkit) with project defaults (`CHUNK_SIZE=1000`, `CHUNK_OVERLAP=200`).
- **Note:** chunking ≠ embedding. Every chunk (single or otherwise) is still embedded into a vector via the existing `EmbeddingsModule` and stored in Qdrant. "Don't chunk short notes" just means the whole note becomes one chunk → one vector. Dedup search and retrieval both operate over these vectors normally.

### Duplicate detection
- On save (create or update), embed the new content (or use existing chunk embedding), search the `superchat_notes` Qdrant collection for similar existing notes (excluding the note being edited).
- **Threshold:** `0.88` cosine similarity.
- **Behavior:** soft warn. Show a panel in the editor with preview of the closest match (title + author + date + content excerpt) and three actions:
  - **View [author]'s note** → opens the existing note in read view
  - **Add mine anyway** → proceeds with save
  - **Cancel** → closes editor without saving
- **Never block.** Authors can always proceed.

### Retrieval mix (notes ↔ lectures)
- **75/25 split (1/4 of slots go to notes)** scaling with `instructorTopK`:
  - `topK=4` → 3 lecture + 1 note
  - `topK=8` (current default) → 6 lecture + 2 notes
  - `topK=12` → 9 lecture + 3 notes
  - `topK=20` → 15 lecture + 5 notes
  - General formula: `noteSlots = round(topK * 0.25)`, `lectureSlots = topK - noteSlots`
- **Min-similarity floor on notes:** `0.5` cosine. If fewer note candidates above the floor than `noteSlots`, **donate unused slots back to lecture retrieval** (re-query lecture with `lectureSlots + leftover`).
- **Settings-configurable ratio:** new field `noteRetrievalRatio` (default `0.25`) on the `superCourseChat` settings doc. **Admin-only** to change (gated through `systemAdmin.js`).
- **Settings toggle:** new field `includeNotesInRetrieval` (default `true`). When `false`, skip note retrieval entirely.

### Citations
- Notes are mixed into the same citations list returned by Super Chat, but **distinctly labeled**:
  - Lecture chunk → existing format (`From [Course] / [Lecture] ([file])`)
  - Note chunk → `Note by [authorName], [createdAt date]`
- Citation objects gain a `sourceType: 'lecture' | 'note'` field.
- Context block passed to LLM marks note sources clearly so the model can attribute correctly.

### Usage counter
- Increments on **every retrieval hit** (cheap, simple). Even if the LLM doesn't end up referencing the note, "the bot considered this" counts.
- Displayed on note cards as "Used in N answers".
- Implementation: bump in `notesQdrantService.searchNotes()` after retrieval — update `usageCount` on the underlying note docs (one update per unique noteId per query, batched).

### UI scope (MVP)
- Inline editor (described above).
- List grouped by **My notes** vs **Notes by other instructors**.
- Note card shows: title, author, date, content excerpt, tags, usage counter.
- **No search/filter toolbar in MVP.** Just the list + "+ New note" button.
- **Empty state:** friendly copy explaining what notes are, with a "Write your first note" CTA.
- Sidebar nav entry "Super Chat Notes" added to all instructor pages.

---

## 2. Implementation work breakdown

### 2.1 Model
- `src/models/SuperChatNote.js` — Mongoose-style or plain-object model matching schema above. Index on `authorId`, `createdAt`, `isDeleted`.

### 2.2 Qdrant service (separate class)
- `src/services/notesQdrantService.js` — new `NotesQdrantService` class, mirrors `QdrantService` but operates on `superchat_notes` Qdrant collection.
- Reuses shared embeddings + chunker init (extract to helper if duplication grows).
- Methods:
  - `initialize()` — ensure collection exists, init embeddings/chunker
  - `addNote(noteId, content, payloadMeta)` → returns `qdrantPointIds[]`
  - `updateNote(noteId, content, payloadMeta)` — delete old points, add new
  - `deleteNote(noteId)` — remove all points for this noteId
  - `searchNotes(query, limit, options)` — returns chunks with score
  - `findSimilarTo(content, options)` — for dedup check

### 2.3 Service layer
- `src/services/superChatNotesService.js`:
  - `createNote({ authorId, authorName, title, content, tags })`
  - `getNoteById(noteId)`
  - `listNotes({ includeDeleted: false })`
  - `updateNote(noteId, authorId, { title, content, tags })` — auth check: author only
  - `deleteNote(noteId, authorId)` — auth check: author only
  - `checkSimilar(content, excludeNoteId)` — returns top match if >0.88
  - `incrementUsage(noteIds[])` — batched increment
  - `autoGenerateTitle(content)` — first sentence, capped at ~80 chars

### 2.4 Routes
- `src/routes/superChatNotes.js`:
  - `POST   /api/superchat-notes`           → create
  - `GET    /api/superchat-notes`           → list (all visible)
  - `GET    /api/superchat-notes/:id`       → fetch one
  - `PUT    /api/superchat-notes/:id`       → update (author only)
  - `DELETE /api/superchat-notes/:id`       → soft delete (author only)
  - `POST   /api/superchat-notes/check-similar` → dedup probe; body `{ content, excludeNoteId? }`
- All routes require authenticated instructor role.
- Wire in `server.js`.

### 2.5 Integration into Super Chat retrieval
Modify `src/services/superCourseService.js`:
- `searchSuperCourse(db, query, limit, options)`:
  - Read `noteRetrievalRatio` and `includeNotesInRetrieval` from settings.
  - If notes disabled → existing behavior unchanged.
  - Else:
    - Compute `noteSlots = round(limit * ratio)`, `lectureSlots = limit - noteSlots`.
    - Query lecture collection with `lectureSlots`.
    - Query notes collection with `noteSlots`, filter by floor (0.5).
    - If actual note results < `noteSlots`, top up lecture results.
    - Tag each result with `sourceType: 'lecture' | 'note'`.
    - Call `incrementUsage(noteIds)` for retrieved notes.
    - Return merged results.
- Update `buildSuperCourseContext`, `buildSuperCourseCitations`, `buildSuperCourseSourceAttribution` to handle `sourceType: 'note'` (different label format).

### 2.6 Settings
- Extend `superCourseChat` settings doc with:
  - `includeNotesInRetrieval: Boolean` (default `true`)
  - `noteRetrievalRatio: Number` (default `0.30`, range 0.0–1.0)
- Update `resolveSuperCourseChatSettings` in `superCourseService.js`.
- Add UI to `public/instructor/settings.html`:
  - Toggle for "Include shared notes in Super Chat retrieval"
  - Ratio slider/input (visible to admins only — gate via `systemAdmin.js` check on the page)

### 2.7 Frontend
- `public/instructor/notes.html` — finalize from existing mockup; extract inline `<style>` block to `public/styles/notes.css`.
- `public/instructor/scripts/notes.js` — new file:
  - Load notes on page load (`GET /api/superchat-notes`)
  - "New note" → expand inline editor
  - Character counter on textarea
  - Debounced `check-similar` call as the user types (or on blur) to populate the duplicate warning
  - Tag chip input
  - Save → POST/PUT, refresh list
  - Edit (own notes) → repopulate editor with note data
  - Delete (own notes) → confirm dialog → DELETE
  - Empty state rendering
- Sidebar nav: add `<li><a href="/instructor/notes">Super Chat Notes</a></li>` to all instructor HTML pages.
- Page route in `server.js`: `GET /instructor/notes` → serve `notes.html`.

---

## 3. Non-goals (explicitly deferred)

- Search/filter toolbar (search by keyword, tag filter, scope filter, sort)
- Student-side visibility (no "publish to students" flag)
- Markdown or rich text support
- Version history on edits
- Admin override for editing/deleting others' notes
- TA write access
- Per-department / per-course scoping of notes
- Analytics dashboards beyond the per-note usage counter
- Bulk import/export
- Concurrency handling for simultaneous edits

---

## 4. Open items to verify during build

- How `systemAdmin.js` exposes the admin check (for gating `noteRetrievalRatio` setting). May need a small helper if it's not already extractable.
- Exact route mounting pattern in `server.js` — match how `instructorChat` routes are wired.
- Whether `EmbeddingsModule` / `ChunkingModule` init can be shared cleanly between `QdrantService` and `NotesQdrantService`, or whether they should be initialized independently (small duplication, fine for MVP).
- Confirm `userId` field name on `req.user` matches what `instructorChat.js` uses (`req.user.userId`).

---

## 5. UI reference

A working mockup exists at `public/instructor/notes.html` showing the target look:
- Sidebar nav with "Super Chat Notes" active
- Header + plain-language subtitle for non-technical instructors
- Expanded editor state with title, textarea, hint text, tag chips, save/cancel
- Duplicate-warning panel inside the editor (with preview + 3 actions)
- Note cards grouped by "My notes" / "Notes by other instructors"
- Each card: title, author + date, excerpt, tags, edit/delete (own) or view (others)

Inline `<style>` block in `notes.html` should be extracted to `public/styles/notes.css` during build.

---

## 6. Framing for non-technical instructors (e.g. Eden)

> "Super Chat Notes is a shared notebook the bot reads. You type notes in — corrections, clarifications, things students keep asking, useful examples — and from then on, when anyone asks Super Chat about that topic, the bot uses your note alongside the lecture material."

Key things to surface in the UI:
- "Your notes are visible to other instructors, not students."
- "The bot doesn't quote you literally — it reads your note and answers in its own words."
- "You can edit or delete your own notes any time. Changes take effect right away."
- Placeholder hint in the textarea: *"Write this the way you'd explain it to a student."*
- Soft duplicate warning (not blocking) so instructors aren't gatekept from adding their own framing of a topic.
