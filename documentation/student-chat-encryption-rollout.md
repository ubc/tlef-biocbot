# Student chat encryption rollout

BiocBot uses `@ubc/genai-toolkit-encryption` to encrypt the `chatData` field of
its chat-transcript collections in MongoDB. Application code continues to read
and write normal JavaScript objects; MongoDB stores an authenticated
AES-256-GCM envelope instead of the transcript payload.

## Protected collections

One policy, one key, one namespace covers all three:

| Collection | Encrypted field | Written by |
| --- | --- | --- |
| `chat_sessions` | `chatData` | student course chat |
| `student_super_course_chat_sessions` | `chatData` | student Super Course chat |
| `instructor_chat_sessions` | `chatData` | instructor Super Course chat |

The list lives in `ENCRYPTED_CHAT_COLLECTIONS` in `src/config/chatEncryption.js`
and is the single source the config, the synthetic canary, and the tests all
read. Add a collection there and it is protected everywhere at once.

Nothing else is encrypted. `mentalHealthFlags`, `quizAttempts`, `users`,
`documents`, Qdrant payloads, and LMS tokens are all out of scope for this
rollout.

The rollout deliberately leaves `courseId`, `studentId`, `instructorId`,
`superchatId`, `sessionId`, `studentName`, `instructorName`, `unitName`,
`title`, `messageCount`, `duration`, `savedAt`, timestamps, and deletion flags
in plaintext. They remain available for existing filters, sorts, retention jobs,
pseudonymization, and dashboards — including the `distinct('studentId', …)`
query behind Super Course pseudonyms. Expanding the schema to names or
identifiers requires a separate query/index review.

Each envelope's additional authenticated data binds it to its own namespace,
collection, field, and key id, so a ciphertext cannot be moved between these
three collections even though they share a key.

## Security boundary

A person with MongoDB access but without the application key cannot decrypt the
configured chat payload. Someone who compromises both the running application
and its key can decrypt it because BiocBot must possess the key to show chat
history. The wrapper does not protect plaintext in logs, exports, browser
storage, Qdrant, application memory, or third-party calls.

The assessment-summary repair script now uses the protected database wrapper,
but its pre-change JSON backup is still an intentional plaintext export. The
file is created with owner-only permissions and must be handled under the
applicable data-retention and transfer policy.

The chat encryption key must be independent from
`BIOCBOT_KEY_ENCRYPTION_SECRET`, MongoDB credentials, and any future blind-index
key. Keep it outside source control and separate from database backups.

## Local canary

Run the synthetic real-MongoDB canary first:

```bash
npm run encryption:canary
```

It creates a uniquely named temporary database, writes one synthetic chat
through the wrapper **into every collection in `ENCRYPTED_CHAT_COLLECTIONS`**,
verifies the raw envelope and protected round trip for each, reports only
non-sensitive structural metadata, and drops the temporary database. A
collection added to the policy but not actually protected fails the canary
instead of passing it silently.

1. Generate a dedicated key:

   ```bash
   node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
   ```

2. Put the value in the local secret environment as
   `BIOCBOT_CHAT_ENCRYPTION_KEY`. Set:

   ```text
   BIOCBOT_CHAT_ENCRYPTION_ENABLED=true
   BIOCBOT_CHAT_ENCRYPTION_READ_POLICY=mixed
   BIOCBOT_CHAT_ENCRYPTION_QUERY_POLICY=mixed
   ```

3. Start BiocBot and save a new student chat. Chat history and instructor views
   should look unchanged because reads are decrypted transparently.

4. Inspect MongoDB only for structure. `chatData` should be an object containing
   `__ubc_enc`, `alg`, `kid`, `iv`, `tag`, and `ct`; it must not contain the
   original `messages` or other transcript fields. Do not copy ciphertext,
   binary fields, or source documents into tickets or logs.

## Existing-data workflow

All commands load `.env` through `src/config/encryption.js`. `plan`, dry-run,
and verify are read-only for application data. Run them from the repository
root.

### Every command names its own collection

The npm scripts **no longer hardcode a collection**. Each invocation must state
its scope with `-- --collection <name>`.

This is deliberate. The toolkit declares `--collection` as a repeatable option,
so passing the flag twice *accumulates* rather than overriding:

```bash
# What the old hardcoded script did with an extra flag:
#   plan --collection chat_sessions --collection student_super_course_chat_sessions
#   -> scope resolves to BOTH collections
```

For `plan` that is merely surprising. For `migrate` it silently widens the blast
radius to a collection the operator never named. With the flag removed from the
scripts, a bare invocation now fails loudly instead:

```text
collection scope is required: pass --collection <name> one or more times,
or --all-configured to opt in to every configured collection
```

`--all-configured` is available for the read-only commands
(`encryption:plan:all`, `encryption:verify:all`) and refuses to combine with
`--collection`. Migrations are intentionally left one collection at a time.

### `student_super_course_chat_sessions`

```bash
# 1. Plan and dry-run (read-only)
npm run encryption:plan -- --collection student_super_course_chat_sessions
npm run encryption:migrate:dry-run -- --collection student_super_course_chat_sessions

# 2. Bounded canary, after a tested backup that does not contain the key
npm run encryption:migrate -- --collection student_super_course_chat_sessions --max-documents 25 --backup-confirmed --verify
npm run encryption:status
npm run encryption:verify -- --collection student_super_course_chat_sessions

# 3. Full migration, then verification
npm run encryption:migrate -- --collection student_super_course_chat_sessions --backup-confirmed --verify
npm run encryption:verify -- --collection student_super_course_chat_sessions
```

### `instructor_chat_sessions`

```bash
# 1. Plan and dry-run (read-only)
npm run encryption:plan -- --collection instructor_chat_sessions
npm run encryption:migrate:dry-run -- --collection instructor_chat_sessions

# 2. Bounded canary, after a tested backup that does not contain the key
npm run encryption:migrate -- --collection instructor_chat_sessions --max-documents 25 --backup-confirmed --verify
npm run encryption:status
npm run encryption:verify -- --collection instructor_chat_sessions

# 3. Full migration, then verification
npm run encryption:migrate -- --collection instructor_chat_sessions --backup-confirmed --verify
npm run encryption:verify -- --collection instructor_chat_sessions
```

### `chat_sessions`

Unchanged apart from naming the collection explicitly:

```bash
npm run encryption:plan -- --collection chat_sessions
npm run encryption:migrate:dry-run -- --collection chat_sessions
npm run encryption:migrate -- --collection chat_sessions --max-documents 25 --backup-confirmed --verify
npm run encryption:migrate -- --collection chat_sessions --backup-confirmed --verify
npm run encryption:verify -- --collection chat_sessions
```

Run each collection's canary, review it, and only then remove `--max-documents`.
Migrate one collection at a time so a failure is scoped to one dataset.

The toolkit migration is idempotent, resumable, lease-protected, and checks for
concurrent changes before updating a document. Its checkpoint collection is
`_ubc_encryption_migrations` and contains operational metadata, not chat data or
keys.

### Schema fingerprint change

Adding the two collections changes the configuration's schema fingerprint
(`02379b2de95ff204…` to `b5cf92b20420346a…`). Two consequences:

- The default migration id derives from the fingerprint, so it changes too. Any
  checkpoint from the earlier `chat_sessions` migration is not resumed by
  default, and `npm run encryption:status` reports it with
  `schemaMatchesCurrentConfig: false`. That row is historical; it is not an
  error. Passing an explicit `--migration-id` from before the change would raise
  a lease error — start a new id instead.
- **Existing ciphertext is unaffected.** The fingerprint is migration metadata
  only; it is not part of the additional authenticated data. Envelopes written
  under the previous single-collection policy still decrypt, which
  `tests/unit/services/chatEncryption.test.js` asserts directly.

## Moving from mixed to strict

Keep mixed reads while plaintext and encrypted documents coexist. The policies
are global, not per collection, so strict mode requires **all three**
collections to be fully migrated and verified first. Only then should staging
change to:

```text
BIOCBOT_CHAT_ENCRYPTION_READ_POLICY=strict
BIOCBOT_CHAT_ENCRYPTION_QUERY_POLICY=encrypted
```

Both switches move together: the toolkit rejects a `strict` read policy
alongside a `mixed` query policy at configuration time.

Restart and exercise save, history, continue-chat, instructor download, student
analytics, deletion, title update, and pseudonym flows — for the course chat,
the student Super Course chat, and the instructor Super Course chat. Strict
reads fail closed if any configured `chatData` value is plaintext, malformed,
tampered with, or encrypted under an unavailable key.

## Staging gate

Before staging deployment:

- Pin and install toolkit version `0.1.0` from UBC GitHub Packages.
- Inject the dedicated key through the staging secret manager; never commit it.
- Confirm the key and MongoDB backup are stored separately.
- Capture a tested pre-migration backup and a restore point.
- Run the test suite and a local encrypted-write/raw-storage canary.
- Deploy mixed-read/encrypted-write mode first.
- Confirm a newly saved chat is encrypted at rest and readable in every UI, for
  all three transcript collections.
- Run plan, dry-run, a small migration canary, full migration, and verification
  — separately for `chat_sessions`, `student_super_course_chat_sessions`, and
  `instructor_chat_sessions`.
- Switch to strict/encrypted policies in a later deployment after verification.
- Monitor typed toolkit authentication and plaintext-rejection failures.

Turning the feature flag off does not decrypt records already migrated. Recovery
requires keeping the key and mixed decryption available, using the toolkit's
guarded `decrypt` workflow with explicit plaintext confirmation, or restoring a
pre-migration backup.
