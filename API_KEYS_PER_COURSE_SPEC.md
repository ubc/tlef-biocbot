# API Keys Per Course — Implementation Spec

Status: Draft for implementation
Issue: #354 (FUTURE FEATURE: API KEYS PER COURSE)
Date: 2026-06-11

---

## 1. Overview

Today the platform runs every OpenAI call — chat, quiz evaluation, question
generation, image descriptions, and document embedding — against **one global
`OPENAI_API_KEY`** env var, through a single `LLMService` instance
(`app.locals.llm`) and a singleton embeddings module (`qdrantService`).

This spec moves to **per-surface API keys**: every OpenAI call is billed to a
key owned by the place where the call happens.

### Product decisions (locked)

1. **Scope = everything.** The key covers chat/answers AND document
   indexing/embeddings, quiz short-answer evaluation, question generation,
   image descriptions on upload, and instructor chat.
2. **No fallback or universal key.** If a surface lacks a working key, all AI
   features on that surface stop. There is no env-key fallback code path in
   any environment (staging convenience comes from a shared *key value* the
   team pastes in, never from a fallback mechanism).
3. **Three key types:**
   - **Course key** — one per course, entered by the instructor during
     onboarding.
   - **Bucket key** — one per superchat bucket, required at bucket creation.
   - **Notes key** — one dedicated key for the instructor notes superchat
     (notes live in a single global Qdrant collection, owned by no course or
     bucket), admin-managed.
4. **A course cannot be made visible to students without a valid key**
   (publish gate), and a key that dies later flips the course into a
   visible-but-disabled state.
5. **Hard cutover for existing courses.** No backfill migration; instructors
   of live courses (e.g. Eden's) enter their key on next login, or an admin
   enters it for them.
6. **Keys are validated live on entry** (cheap test call against OpenAI);
   entry is rejected if validation fails. Settings has a "Test key" button.
7. **Instructors are fully blocked too.** No key → no uploads, no question
   generation, no instructor chat. Non-LLM features (editing course info,
   viewing flags, managing the key itself) stay available.
8. **Keys are issued by the team** (dev team / Richard Tape). UI guidance
   tells instructors to contact the team for a new/replacement key.
   Recommended provisioning: one OpenAI **Project** per course with its own
   key and monthly budget cap (per-course spend visibility + easy
   revoke/reissue for free).
9. **Already-indexed content stays retrievable.** If a course goes
   inactive/keyless, its existing vectors remain searchable in supercourse
   retrieval (retrieval is free); only *new* indexing is blocked.
10. **Deferred / out of scope:** per-course model selection (model stays a
    global admin setting); AI monitoring & contributor filtering for notes
    (separate ticket).

### The billing rule (through-line)

> **The surface where the OpenAI call happens pays for it.**

| Call | Key charged |
|------|-------------|
| Student course chat, quiz short-answer eval | Course key |
| Question generation, instructor course chat | Course key |
| Document upload: embedding + image descriptions | Course key |
| Supercourse chat: query embedding + answer generation (including the notes-search query embedding) | Bucket key |
| Instructor notes upload: chunk embedding; `check-similar` probe embedding | Notes key |
| Qdrant retrieval (searching existing vectors) | **Free — no key involved** |

Consequences worth noting:
- Supercourse chat **never touches course keys** — cross-course retrieval is
  free, so only the bucket key is needed per request.
- A single supercourse answer is billed to exactly one key (the bucket's),
  even when it pulls from notes.

---

## 2. Data model

### 2.1 Key subdocument (shared shape)

Stored wherever a key lives. The plaintext key is **encrypted at rest**
(AES-256-GCM) with a new server env secret `BIOCBOT_KEY_ENCRYPTION_SECRET`.
The API never returns the full key after save — only `last4` + status.

```js
llmApiKey: {
  ciphertext: "<encrypted>",      // AES-256-GCM, never sent to clients
  last4: "abcd",                  // for masked display ("•••• abcd")
  status: "valid",                // "valid" | "invalid" | "quota_exhausted"
                                  // (absence of the subdoc ⇒ "missing")
  validatedAt: Date,              // last successful live validation
  updatedAt: Date,
  updatedBy: "<userId>"
}
```

Status semantics:
- `valid` — passed live validation; calls assumed to work.
- `invalid` — OpenAI returned 401 (revoked/wrong key) at entry or call time.
- `quota_exhausted` — OpenAI returned 429 `insufficient_quota` at call time.
- *missing* — subdoc absent (new field default; all pre-cutover courses).

### 2.2 `courses` collection

- **Add** `llmApiKey` subdoc (2.1).
- Existing courses have no subdoc ⇒ implicitly `missing` ⇒ blocked. This *is*
  the hard cutover; no migration script needed.

### 2.3 `superchats` collection

- **Add** `llmApiKey` subdoc (2.1).
- `POST /api/superchats` (bucket creation) **requires** a key that passes
  live validation. This doubles as the anti-spam measure: you cannot create
  a bucket without a real funded key.

### 2.4 `settings` collection — notes key

- New doc `{ _id: "notesLlm", llmApiKey: { ...subdoc } }`, admin-managed.

---

## 3. Key lifecycle

1. **Entry** (onboarding, settings, bucket creation, admin notes settings):
   live-validate with a cheap call (1-token embedding request), then encrypt
   and store with `status: "valid"`. Validation failure ⇒ save rejected with
   the specific reason (invalid vs quota).
2. **Call-time failure detection:** every LLM/embedding call site maps OpenAI
   errors → key status. 401 `invalid_api_key` ⇒ `invalid`; 429
   `insufficient_quota` ⇒ `quota_exhausted`. Status is flipped on the owning
   doc, the scoped service instance is evicted from the registry (4.1), and
   the structured error (5.2) propagates to the UI.
3. **Test/recovery:** "Test key" button re-runs live validation on the stored
   key; success resets status to `valid` (covers OpenAI-side fixes like
   topping up credits, without re-entering the key).
4. **No background polling.** Detection is at entry and call time only.

---

## 4. Backend — service refactor

### 4.1 Scoped LLM/embeddings registry (replaces the global singleton)

Today: `server.js` creates one `LLMService` at boot (`app.locals.llm`);
`qdrantService` holds one `EmbeddingsModule`; `notesQdrantService` shares it
(`this.embeddings = this.base.embeddings`).

New: a **registry** that resolves a ready-to-use service per scope:

```js
llmRegistry.forCourse(db, courseId)      // → { llm, embeddings } or throws KeyError
llmRegistry.forSuperchat(db, superchatId)
llmRegistry.forNotes(db)
```

- Looks up + decrypts the scope's key, constructs `LLMModule` /
  `EmbeddingsModule` with it, caches by scope id (TTL/LRU), evicts on key
  change or call-time failure.
- Throws a typed error carrying the status (`missing` / `invalid` /
  `quota_exhausted`) when no working key exists — route guards convert this
  to the structured API error (5.2).
- The **Qdrant client stays a singleton** (server infra); only the *embed*
  step becomes scoped. Collections, vector size, and the embedding model are
  unchanged and global.
- The global model settings doc (`settings._id: 'llm'`, model + reasoning
  effort) continues to apply to all scopes.

Call sites to convert from `req.app.locals.llm` / shared embeddings:
`chat.js`, `quiz.js`, `questions.js`, `instructorChat.js`,
`documents.js` (describeImage + embedding pipeline),
`studentSuperCourse.js`, `qdrantService.js` (embed paths),
`notesQdrantService.js` (note indexing → notes scope; **query embedding at
chat time → bucket scope**, passed in by the caller).

### 4.2 Boot & config changes

- `config.validateConfig()` no longer requires `OPENAI_API_KEY` for the
  openai provider — there is no global key. (`OPENAI_MODEL` etc. still
  validated.)
- Provider bypasses, unchanged in spirit:
  - `BIOCBOT_TEST_LLM_STUB=1` (e2e): the registry returns the stub for every
    scope, but **key-gating logic still runs** so tests can exercise it.
    Stub-mode validation accepts/rejects by pattern (e.g. `sk-test-…` passes,
    `sk-bad-…` fails as invalid, `sk-quota-…` fails as quota) — no network.
  - `ollama` provider (local dev): no per-scope keys required; gating
    disabled (calls are free/local).

---

## 5. Backend — routes

### 5.1 Key management endpoints

| Endpoint | Authz | Purpose |
|----------|-------|---------|
| `PUT  /api/courses/:courseId/llm-key` | course's instructor OR admin | Set/replace key (live-validates first) |
| `POST /api/courses/:courseId/llm-key/test` | same | Re-validate stored key |
| `PUT  /api/superchats/:id/llm-key` + `/test` | instructor-or-admin (matches bucket CRUD) | Bucket key |
| `PUT  /api/settings/notes-llm-key` + `/test` | admin | Notes key |

- All GETs that return course/bucket settings include
  `llmKey: { last4, status, validatedAt }` (never the key itself).
- `POST /api/superchats` gains a required `apiKey` field, validated before
  the bucket is created.

### 5.2 Gating + structured errors

Every LLM-calling route resolves its scope through the registry first and
returns a structured error when the key isn't working:

```js
{ success: false, code: "LLM_KEY_MISSING" | "LLM_KEY_INVALID" | "LLM_KEY_QUOTA",
  message: "<human-readable>" }
```

- **Onboarding** (`POST /api/onboarding`): payload includes `apiKey`;
  server live-validates **before** `createCourseFromOnboarding`. No key, no
  course. (Onboarding's own LLM steps — question generation — then run on the
  course key.)
- **Publish gate:** any endpoint that makes a course student-visible
  (status → active, lecture publish) rejects unless key status is `valid`.
- **Uploads** (`documents.js`): reject *before* accepting the file when the
  key isn't valid — don't ingest and then fail at the embedding step.
- **Student course surface** (chat, quiz): blocked with the structured error;
  course list endpoints include `aiAvailable: boolean` so the UI can render
  the disabled state without a failed call.
- **Supercourse:** student `/list` marks (or omits) buckets whose key isn't
  valid; `/chat` re-checks per request.
- **Notes:** note create/update and `check-similar` are gated on the notes
  key. Notes *retrieval* during instructor supercourse chat is NOT gated on
  the notes key (query embedding is a chat-time call on the bucket key) — a
  dead notes key blocks new notes, not the use of existing ones.

---

## 6. Frontend

### 6.1 Onboarding (instructor) — new first step

"Course API key" step before anything else: key input + **Validate** button;
"Next" disabled until validation passes. Copy explains keys are issued by the
BiocBot team and who to contact. The validated key is submitted with the
course-creation payload.

### 6.2 Instructor settings — key section

New section in `settings.html`:
- Masked display (`•••• abcd`) + status chip: **Valid / Invalid / Out of
  credits / Missing**, with `validatedAt`.
- Replace-key input (live-validated on save) + **Test key** button.
- Guidance text: "Keys are issued by the BiocBot team — contact us for a new
  key." (This is the dead-key recovery path.)

### 6.3 Blocked states — instructor

When the course key isn't `valid`:
- Persistent banner on instructor course pages: which problem it is
  (missing / revoked / out of credits), what's blocked, link to the settings
  key section + team contact.
- Upload controls, question generation, and instructor chat inputs disabled
  (not hidden), each with a short "why" hint.
- Existing-course cutover UX is exactly this: on first post-deploy login the
  instructor sees the missing-key banner and fills it in.

### 6.4 Blocked states — student

- Course stays visible in their list. Chat and quiz inputs disabled with a
  banner: "AI features are unavailable for this course — contact your
  instructor." Driven by `aiAvailable` from the course list / status calls.
- A mid-chat key death returns the structured error; the chat UI shows the
  friendly message and disables input (next page load shows the banner
  state).
- Supercourse picker: buckets without a working key are hidden (or shown
  disabled with "(unavailable)").

### 6.5 Admin

- Bucket manager (`#super-course-chat-section`): per-bucket key field
  (masked + status + test), and the create-bucket flow requires a key.
- New admin settings field for the **notes key** (masked + status + test).

---

## 7. Cutover plan

1. Deploy. All pre-existing courses have no key subdoc ⇒ status `missing` ⇒
   instructor + student surfaces show the blocked states from §6. No data
   migration.
2. Instructors of live courses log in and enter their team-issued key (or an
   admin does it via the same endpoint).
3. Existing Qdrant content is untouched: already-indexed material keeps
   serving supercourse retrieval throughout (decision 9).
4. Existing buckets created before this feature: treated like courses —
   `missing` status, disabled for students, admin/instructor enters a key in
   the bucket manager. (Bucket creation requiring a key applies to *new*
   buckets.)

---

## 8. Edge cases

- **Key dies mid-semester:** first failing call flips status, evicts the
  cached service, and every surface shows the right blocked state. "Test key"
  un-flips it after the underlying problem is fixed.
- **Dead course key inside a healthy bucket:** supercourse chat still
  retrieves that course's already-indexed content (bucket key pays chat
  time). New uploads to that course stay blocked until fixed.
- **Dead bucket key:** bucket disappears/disabled for students; visible
  error in the admin bucket manager. Course chats unaffected.
- **Dead notes key:** note uploads + similar-checks blocked; existing notes
  still retrievable in instructor supercourse chat (see 5.2).
- **Same key pasted into multiple courses:** technically allowed (we don't
  dedupe), but team-issued one-key-per-course is the policy; the per-course
  budget benefit disappears if keys are shared.
- **Encryption secret:** `BIOCBOT_KEY_ENCRYPTION_SECRET` must be stable;
  rotating/losing it invalidates all stored keys (everyone re-enters).
  Rotation tooling is out of scope.
- **Quiz MC/TF:** moot — the whole course surface is disabled for students
  when the key isn't valid, so no per-question-type special casing.

---

## 9. Testing

Stub mode (`BIOCBOT_TEST_LLM_STUB=1`) keeps gating active with
pattern-based validation (4.2), so all of this runs without OpenAI:

- **Harness updates:** `src-route-model-harness.js` and
  `tests/e2e/helpers/superchats-test.js` seed `llmApiKey` subdocs (valid
  test pattern) on created courses/buckets so existing suites keep passing.
  New helper to seed/clear/corrupt a key on a course or bucket.
- **New specs:**
  - Onboarding: cannot create a course without a key; invalid pattern
    rejected with reason; valid pattern proceeds.
  - Publish gate: course can't go student-visible with missing/invalid key.
  - Instructor blocked state: banner + disabled upload/question-gen/chat on
    missing key; restored after key set.
  - Student blocked state: course visible, chat/quiz disabled with banner;
    `aiAvailable:false` in list payloads.
  - Bucket creation requires a valid key; bucket with dead key hidden from
    student picker; bucket key replace/test endpoints.
  - Notes: upload + check-similar blocked without notes key; instructor
    supercourse chat still retrieves existing notes.
  - Call-time death: stub returns a 401/429-shaped failure once → status
    flips → subsequent requests get the structured error → Test key resets.
- **Staging (manual):** real end-to-end with the team's capped dev key —
  enter at onboarding, live validation rejects a bad key, remove a key from
  a test course and confirm lockout, swap in an invalid key to rehearse the
  dead-key flow.

---

## 10. Out of scope (tracked separately)

- Per-course model selection (model remains the global admin setting).
- AI monitoring / contributor filtering for the notes superchat — separate
  ticket; motivated by the notes key being one shared budget any instructor
  can spend against.
- Automated key provisioning through the OpenAI API.
- Background key health polling (entry- and call-time detection only).
- Encryption-secret rotation tooling.

---

## 11. Build order (suggested)

1. Crypto helper + key subdoc + course key endpoints (set/test, masked GET).
2. Registry refactor (scoped LLM/embeddings instances; stub-mode validation
   patterns; boot no longer requires `OPENAI_API_KEY`).
3. Route gating + structured errors across course surfaces (chat, quiz,
   questions, uploads, instructor chat).
4. Onboarding key step + publish gate.
5. Instructor settings section + blocked banners; student disabled states +
   `aiAvailable`.
6. Buckets: key at creation, key endpoints, manager UI, student picker
   filtering.
7. Notes key: admin settings + gating (uploads/check-similar only).
8. Harness updates + new e2e specs at each step.
