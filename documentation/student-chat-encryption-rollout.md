# Student chat encryption rollout

BiocBot uses `@ubc/genai-toolkit-encryption` to encrypt the `chatData` field in
MongoDB's `chat_sessions` collection. Application code continues to read and
write normal JavaScript objects; MongoDB stores an authenticated AES-256-GCM
envelope instead of the transcript payload.

The first rollout deliberately leaves `courseId`, `studentId`, `sessionId`,
`studentName`, `unitName`, `title`, timestamps, counts, and deletion flags in
plaintext. They remain available for existing filters, sorts, retention jobs,
pseudonymization, and dashboards. Expanding the schema to names or identifiers
requires a separate query/index review.

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
through the wrapper, verifies the raw envelope and protected round trip, reports
only non-sensitive structural metadata, and drops the temporary database.

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
root:

```bash
npm run encryption:plan
npm run encryption:migrate:dry-run
```

Before any migration write, take and test a current backup that does not contain
the encryption key. Then run a bounded canary:

```bash
npm run encryption:migrate -- --max-documents 25 --backup-confirmed --verify
npm run encryption:status
npm run encryption:verify
```

Review the canary, then resume the same collection without the limit:

```bash
npm run encryption:migrate -- --backup-confirmed --verify
npm run encryption:verify
```

The toolkit migration is idempotent, resumable, lease-protected, and checks for
concurrent changes before updating a document. Its checkpoint collection is
`_ubc_encryption_migrations` and contains operational metadata, not chat data or
keys.

## Moving from mixed to strict

Keep mixed reads while plaintext and encrypted documents coexist. Only after a
full verification succeeds should staging change to:

```text
BIOCBOT_CHAT_ENCRYPTION_READ_POLICY=strict
BIOCBOT_CHAT_ENCRYPTION_QUERY_POLICY=encrypted
```

Restart and exercise save, history, continue-chat, instructor download, student
analytics, deletion, title update, and pseudonym flows. Strict reads fail closed
if any configured `chatData` value is plaintext, malformed, tampered with, or
encrypted under an unavailable key.

## Staging gate

Before staging deployment:

- Pin and install toolkit version `0.1.0` from UBC GitHub Packages.
- Inject the dedicated key through the staging secret manager; never commit it.
- Confirm the key and MongoDB backup are stored separately.
- Capture a tested pre-migration backup and a restore point.
- Run the test suite and a local encrypted-write/raw-storage canary.
- Deploy mixed-read/encrypted-write mode first.
- Confirm a newly saved chat is encrypted at rest and readable in every UI.
- Run plan, dry-run, a small migration canary, full migration, and verification.
- Switch to strict/encrypted policies in a later deployment after verification.
- Monitor typed toolkit authentication and plaintext-rejection failures.

Turning the feature flag off does not decrypt records already migrated. Recovery
requires keeping the key and mixed decryption available, using the toolkit's
guarded `decrypt` workflow with explicit plaintext confirmation, or restoring a
pre-migration backup.
