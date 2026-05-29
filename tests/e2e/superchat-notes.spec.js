// @ts-check
/**
 * Super Chat Notes (#345) — API + behavior coverage.
 *
 * Exercises the platform-level shared instructor notes feature:
 *   - /api/superchat-notes  CRUD (create / list / get / update / delete)
 *   - Authorization: an instructor can edit/delete ONLY their own notes; a
 *     second instructor is denied (403) and the data is not mutated.
 *   - Role gating: students and TAs cannot reach the notes API at all.
 *   - Duplicate detection probe (/check-similar).
 *   - Super Chat retrieval behavior with the LLM + embeddings STUBBED (no
 *     OpenAI traffic): notes blend into instructor answers when enabled, are
 *     excluded when the admin toggle is off, and NEVER surface in the student
 *     Super Course chat.
 *
 * The web server runs with BIOCBOT_TEST_LLM_STUB=1 (see playwright.config.js),
 * so the LLM returns scripted content and embeddings are deterministic
 * bag-of-words vectors (src/services/embeddingsStub.js). That lets us assert
 * retrieval deterministically: a query that shares distinctive tokens with a
 * note scores high enough to clear the similarity floor.
 */

require('dotenv').config();
const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const { withDb, getUserIdByUsername } = require('./helpers/courses-test');
const { resetLlmStub, enqueueLlmResponses } = require('./helpers/llm-stub');

const NOTES = '/api/superchat-notes';
const SETTINGS_ID = 'superCourseChat';

let instructorId;
let instructorFreshId;
let originalSuperCourseSettings = null;

async function readSetting(id) {
    return withDb((db) => db.collection('settings').findOne({ _id: id }));
}

async function restoreSettingDoc(id, originalDoc) {
    await withDb(async (db) => {
        if (originalDoc) {
            await db.collection('settings').replaceOne({ _id: id }, originalDoc, { upsert: true });
        } else {
            await db.collection('settings').deleteOne({ _id: id });
        }
    });
}

async function setNotesSettings(overrides = {}) {
    await withDb(async (db) => {
        await db.collection('settings').updateOne(
            { _id: SETTINGS_ID },
            {
                $set: {
                    studentTopK: 8,
                    instructorTopK: 8,
                    includeInactiveCourses: false,
                    showStudentSuperCourse: false,
                    includeNotesInRetrieval: true,
                    noteRetrievalRatio: 0.25,
                    noteMinScore: 0.1,
                    instructorPrompt: 'E2E instructor super prompt',
                    studentPrompt: 'E2E student super prompt',
                    updatedAt: new Date(),
                    ...overrides,
                },
                $setOnInsert: { createdAt: new Date() },
            },
            { upsert: true }
        );
    });
}

// Remove every note authored by the two test instructors from Mongo so list
// assertions and counts stay deterministic across runs. (Qdrant stub vectors
// use distinctive per-test tokens, so any residue can't cause false matches.)
async function cleanupTestNotes() {
    await withDb((db) =>
        db.collection('superchat_notes').deleteMany({
            authorId: { $in: [instructorId, instructorFreshId].filter(Boolean) },
        })
    );
}

function ctx(baseURL, role) {
    return request.newContext({ baseURL, storageState: storageStatePath(role) });
}

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    instructorFreshId = await getUserIdByUsername(TEST_USERS.instructor_fresh.username);
    originalSuperCourseSettings = await readSetting(SETTINGS_ID);
});

test.beforeEach(async () => {
    await cleanupTestNotes();
});

test.afterAll(async () => {
    await cleanupTestNotes();
    await restoreSettingDoc(SETTINGS_ID, originalSuperCourseSettings);
});

// ---------------------------------------------------------------------------
// Section 1 — CRUD happy paths + auto-title + validation
// ---------------------------------------------------------------------------
test.describe('Super Chat Notes CRUD', () => {
    test('instructor can create, fetch, edit, and delete their own note', async ({ baseURL }) => {
        const api = await ctx(baseURL, 'instructor');
        try {
            // Create
            const createRes = await api.post(NOTES, {
                data: {
                    title: 'Km vs Vmax',
                    content: 'Km is the substrate concentration at half of Vmax, not a binding affinity.',
                    tags: ['enzyme kinetics', 'common confusion'],
                },
            });
            expect(createRes.status()).toBe(201);
            const created = (await createRes.json()).note;
            expect(created.noteId).toBeTruthy();
            expect(created.isOwn).toBe(true);
            expect(created.authorId).toBe(instructorId);
            expect(created.tags).toEqual(['enzyme kinetics', 'common confusion']);

            // Fetch by id
            const getRes = await api.get(`${NOTES}/${created.noteId}`);
            expect(getRes.status()).toBe(200);
            expect((await getRes.json()).note.title).toBe('Km vs Vmax');

            // Edit
            const putRes = await api.put(`${NOTES}/${created.noteId}`, {
                data: { content: 'Updated: Km is the [S] at half Vmax.', tags: ['kinetics'] },
            });
            expect(putRes.status()).toBe(200);
            const updated = (await putRes.json()).note;
            expect(updated.content).toContain('Updated: Km');
            expect(updated.tags).toEqual(['kinetics']);

            // Delete
            const delRes = await api.delete(`${NOTES}/${created.noteId}`);
            expect(delRes.status()).toBe(200);

            // Gone (soft-deleted → hidden from GET)
            const goneRes = await api.get(`${NOTES}/${created.noteId}`, { failOnStatusCode: false });
            expect(goneRes.status()).toBe(404);
        } finally {
            await api.dispose();
        }
    });

    test('blank title auto-generates from the first sentence', async ({ baseURL }) => {
        const api = await ctx(baseURL, 'instructor');
        try {
            const res = await api.post(NOTES, {
                data: { content: 'Proton gradients drive ATP synthase. The rest is detail.' },
            });
            expect(res.status()).toBe(201);
            const note = (await res.json()).note;
            expect(note.title).toBe('Proton gradients drive ATP synthase.');
        } finally {
            await api.dispose();
        }
    });

    test('empty content is rejected with 400', async ({ baseURL }) => {
        const api = await ctx(baseURL, 'instructor');
        try {
            const res = await api.post(NOTES, { data: { content: '   ' }, failOnStatusCode: false });
            expect(res.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('list shows isOwn correctly for the author vs another instructor', async ({ baseURL }) => {
        const authorApi = await ctx(baseURL, 'instructor');
        const otherApi = await ctx(baseURL, 'instructor_fresh');
        try {
            const created = (await (await authorApi.post(NOTES, {
                data: { content: 'A shared platform-level note about lipids.' },
            })).json()).note;

            // Author sees it as their own
            const mineList = (await (await authorApi.get(NOTES)).json()).data.notes;
            const mineEntry = mineList.find((n) => n.noteId === created.noteId);
            expect(mineEntry).toBeTruthy();
            expect(mineEntry.isOwn).toBe(true);

            // The other instructor sees the SAME note (platform-level) but not as own
            const otherList = (await (await otherApi.get(NOTES)).json()).data.notes;
            const otherEntry = otherList.find((n) => n.noteId === created.noteId);
            expect(otherEntry).toBeTruthy();
            expect(otherEntry.isOwn).toBe(false);
        } finally {
            await authorApi.dispose();
            await otherApi.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// Section 2 — Authorization: instructors cannot mutate each other's notes
// ---------------------------------------------------------------------------
test.describe('Super Chat Notes authorization', () => {
    test('a second instructor cannot EDIT another instructor\'s note (403, no mutation)', async ({ baseURL }) => {
        const authorApi = await ctx(baseURL, 'instructor');
        const attackerApi = await ctx(baseURL, 'instructor_fresh');
        try {
            const created = (await (await authorApi.post(NOTES, {
                data: { title: 'Owned note', content: 'Original protected content.' },
            })).json()).note;

            const res = await attackerApi.put(`${NOTES}/${created.noteId}`, {
                data: { content: 'Vandalized by another instructor' },
                failOnStatusCode: false,
            });
            expect(res.status()).toBe(403);

            // Content must be unchanged
            const after = (await (await authorApi.get(`${NOTES}/${created.noteId}`)).json()).note;
            expect(after.content).toBe('Original protected content.');
        } finally {
            await authorApi.dispose();
            await attackerApi.dispose();
        }
    });

    test('a second instructor cannot DELETE another instructor\'s note (403, still present)', async ({ baseURL }) => {
        const authorApi = await ctx(baseURL, 'instructor');
        const attackerApi = await ctx(baseURL, 'instructor_fresh');
        try {
            const created = (await (await authorApi.post(NOTES, {
                data: { content: 'Do not delete me.' },
            })).json()).note;

            const res = await attackerApi.delete(`${NOTES}/${created.noteId}`, { failOnStatusCode: false });
            expect(res.status()).toBe(403);

            // Note must still be retrievable by its author
            const stillThere = await authorApi.get(`${NOTES}/${created.noteId}`);
            expect(stillThere.status()).toBe(200);
        } finally {
            await authorApi.dispose();
            await attackerApi.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// Section 3 — Role gating (notes API is instructor-only)
// ---------------------------------------------------------------------------
test.describe('Super Chat Notes role gating', () => {
    for (const role of ['student', 'ta']) {
        test(`${role} cannot list or create notes`, async ({ baseURL }) => {
            const api = await ctx(baseURL, role);
            try {
                const listRes = await api.get(NOTES, { failOnStatusCode: false });
                expect([401, 403]).toContain(listRes.status());

                const createRes = await api.post(NOTES, {
                    data: { content: 'Should never be created by a non-instructor.' },
                    failOnStatusCode: false,
                });
                expect([401, 403]).toContain(createRes.status());
            } finally {
                await api.dispose();
            }
        });
    }
});

// ---------------------------------------------------------------------------
// Section 4 — Duplicate detection probe
// ---------------------------------------------------------------------------
test.describe('Super Chat Notes duplicate detection', () => {
    test('check-similar flags a near-duplicate and ignores unrelated content', async ({ baseURL }) => {
        const api = await ctx(baseURL, 'instructor');
        try {
            const content = 'Glycolysis converts glucose into pyruvate and yields ATP and NADH.';
            await api.post(NOTES, { data: { title: 'Glycolysis basics', content } });

            // Near-identical content should match (stub embeddings: high token overlap)
            const dupe = await api.post(`${NOTES}/check-similar`, { data: { content } });
            expect(dupe.status()).toBe(200);
            const dupeBody = await dupe.json();
            expect(dupeBody.success).toBe(true);
            expect(dupeBody.similar).not.toBeNull();
            expect(dupeBody.similar.title).toBe('Glycolysis basics');

            // Totally unrelated content should not match
            const unrelated = await api.post(`${NOTES}/check-similar`, {
                data: { content: 'Quarterly budget spreadsheet reconciliation procedures.' },
            });
            expect((await unrelated.json()).similar).toBeNull();
        } finally {
            await api.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// Section 5 — Super Chat retrieval behavior (LLM + embeddings stubbed)
// ---------------------------------------------------------------------------
test.describe('Super Chat retrieval with notes (stubbed LLM)', () => {
    test('instructor chat returns the stubbed answer and cites a matching note', async ({ baseURL }) => {
        await setNotesSettings({ includeNotesInRetrieval: true });
        const api = await ctx(baseURL, 'instructor');
        try {
            // Distinctive nonsense tokens guarantee this note is the only match.
            await api.post(NOTES, {
                data: {
                    title: 'Zorblaxine protocol',
                    content: 'Zorblaxine zinabolic catalysis requires careful membrane flux handling.',
                },
            });

            await resetLlmStub(api);
            await enqueueLlmResponses(api, ['Stubbed instructor answer about zorblaxine.']);

            const res = await api.post('/api/instructor/chat', {
                data: { message: 'Tell me about zorblaxine zinabolic catalysis', conversationMessages: [] },
            });
            expect(res.status()).toBe(200);
            const body = await res.json();
            expect(body.success).toBe(true);
            expect(body.message).toBe('Stubbed instructor answer about zorblaxine.');

            // A note citation should be present and labelled as a note.
            const noteCitations = (body.citations || []).filter((c) => c.sourceType === 'note');
            expect(noteCitations.length).toBeGreaterThan(0);
            expect(noteCitations[0].label).toContain('Note by');
        } finally {
            await api.dispose();
        }
    });

    test('notes are excluded when the admin toggle is off', async ({ baseURL }) => {
        await setNotesSettings({ includeNotesInRetrieval: false });
        const api = await ctx(baseURL, 'instructor');
        try {
            await api.post(NOTES, {
                data: {
                    title: 'Quibblefax note',
                    content: 'Quibblefax transduction modulates the snarfblat receptor cascade.',
                },
            });

            await resetLlmStub(api);
            await enqueueLlmResponses(api, ['Answer with notes disabled.']);

            const res = await api.post('/api/instructor/chat', {
                data: { message: 'Explain quibblefax snarfblat transduction', conversationMessages: [] },
            });
            expect(res.status()).toBe(200);
            const body = await res.json();
            const noteCitations = (body.citations || []).filter((c) => c.sourceType === 'note');
            expect(noteCitations.length).toBe(0);
        } finally {
            await api.dispose();
        }
    });

    test('student Super Chat never surfaces instructor notes', async ({ baseURL }) => {
        // Notes enabled for instructors AND the student page enabled — students
        // should still never see notes (gated at the retrieval call site).
        await setNotesSettings({ includeNotesInRetrieval: true, showStudentSuperCourse: true });

        const instructorApi = await ctx(baseURL, 'instructor');
        const studentApi = await ctx(baseURL, 'student');
        try {
            await instructorApi.post(NOTES, {
                data: {
                    title: 'Wuzzleforp note',
                    content: 'Wuzzleforp grindlewax binds the florbnak active site irreversibly.',
                },
            });

            await resetLlmStub(studentApi);
            await enqueueLlmResponses(studentApi, ['Student answer about wuzzleforp.']);

            const res = await studentApi.post('/api/student/super-course/chat', {
                data: { message: 'What does wuzzleforp grindlewax do to florbnak?' },
                failOnStatusCode: false,
            });
            expect(res.status()).toBe(200);
            const body = await res.json();

            const citationHasNote = (body.citations || []).some((c) => c.sourceType === 'note');
            const attributionHasNote = (body.sourceAttribution?.documents || []).some((d) => d.sourceType === 'note');
            expect(citationHasNote).toBe(false);
            expect(attributionHasNote).toBe(false);
        } finally {
            await instructorApi.dispose();
            await studentApi.dispose();
        }
    });
});
