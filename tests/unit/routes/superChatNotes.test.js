/**
 * In-process route tests for src/routes/superChatNotes.js (supertest).
 *
 * Real: superChatNotesService + the SuperChatNote model over the in-memory Mongo
 * double, so create/update/delete + the `isOwn` ownership flag are exercised end
 * to end. Mocked: notesQdrantService (the heavy vector dep — pulls config) so the
 * service's Qdrant calls are no-ops. The notes LLM surface is injected as an
 * `llmRegistry` stub on app.locals (consumed via resolveNotesAi).
 */
jest.mock('../../../src/services/notesQdrantService', () => {
    const Mock = jest.fn().mockImplementation(() => ({
        initialize: jest.fn().mockResolvedValue(undefined),
        addNote: jest.fn().mockResolvedValue(['pt-1']),
        updateNote: jest.fn().mockResolvedValue(['pt-2']),
        deleteNote: jest.fn().mockResolvedValue(undefined),
        findSimilarTo: jest.fn().mockResolvedValue({ noteId: 'n-dup', score: 0.95 }),
    }));
    Mock.DEFAULT_DUP_THRESHOLD = 0.88;
    return Mock;
});

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const router = require('../../../src/routes/superChatNotes');

const instructor = { userId: 'i1', displayName: 'Dr. Smith', role: 'instructor' };
const llmRegistry = { forNotes: jest.fn(async () => ({ qdrant: {} })) };
const app = (opts) => makeRouteApp(router, { locals: { llmRegistry }, ...opts });

const noteDoc = (over = {}) => ({
    noteId: 'n1', authorId: 'i1', authorName: 'Dr. Smith', title: 'Tip',
    content: 'Explain ATP simply', tags: ['atp'], usageCount: 3, isDeleted: false,
    createdAt: new Date('2026-06-20T10:00:00Z'), updatedAt: new Date('2026-06-20T10:00:00Z'),
    ...over,
});

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

describe('GET / — list notes', () => {
    test('503 when the db is unavailable', async () => {
        const res = await request(app({ db: null, user: instructor })).get('/');
        expect(res.status).toBe(503);
    });

    test('returns public note fields with an isOwn flag per viewer', async () => {
        const db = memoryDb({ superchat_notes: [
            noteDoc({ noteId: 'n1', authorId: 'i1' }),
            noteDoc({ noteId: 'n2', authorId: 'other', authorName: 'Prof X' }),
        ] });
        const res = await request(app({ db, user: instructor })).get('/');
        expect(res.status).toBe(200);
        const byId = Object.fromEntries(res.body.data.notes.map(n => [n.noteId, n]));
        expect(byId.n1.isOwn).toBe(true);
        expect(byId.n2.isOwn).toBe(false);
        // publicNote shape — usageCount surfaced, internal qdrantPointIds omitted.
        expect(byId.n1).toMatchObject({ title: 'Tip', usageCount: 3 });
        expect(byId.n1).not.toHaveProperty('qdrantPointIds');
    });
});

describe('GET /:id — single note', () => {
    test('404 for an unknown note', async () => {
        const res = await request(app({ db: memoryDb({ superchat_notes: [] }), user: instructor })).get('/nope');
        expect(res.status).toBe(404);
    });

    test('returns the note with isOwn for the author', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).get('/n1');
        expect(res.status).toBe(200);
        expect(res.body.note).toMatchObject({ noteId: 'n1', isOwn: true });
    });
});

describe('POST /check-similar', () => {
    test('returns similar:null for empty content without touching the AI surface', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/check-similar').send({ content: '   ' });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, similar: null });
    });

    test('returns the nearest match for real content', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/check-similar').send({ content: 'ATP energy' });
        expect(res.status).toBe(200);
        expect(res.body.similar).toMatchObject({ noteId: 'n-dup' });
    });
});

describe('POST / — create note', () => {
    test('401 when the request has no authenticated userId', async () => {
        const res = await request(app({ db: memoryDb({}) })).post('/').send({ content: 'hi' });
        expect(res.status).toBe(401);
    });

    test('400 when content is empty', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ content: '   ' });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/content is required/i);
    });

    test('400 when content exceeds the hard limit (2× the 5000 soft limit)', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ content: 'x'.repeat(10001) });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/too long/i);
    });

    test('201 persists the note and stamps the author from the session', async () => {
        const db = memoryDb({});
        const res = await request(app({ db, user: instructor })).post('/').send({ content: 'Explain glycolysis', tags: ['bio'] });
        expect(res.status).toBe(201);
        expect(res.body.note).toMatchObject({ authorId: 'i1', authorName: 'Dr. Smith', content: 'Explain glycolysis', isOwn: true });
        const saved = await db.collection('superchat_notes').findOne({ noteId: res.body.note.noteId });
        expect(saved).toBeTruthy();
        expect(saved.qdrantPointIds).toEqual(['pt-1']); // backfilled from the (mocked) vector store
    });
});

describe('PUT /:id — update note (author only)', () => {
    test('404 when the note does not exist', async () => {
        const res = await request(app({ db: memoryDb({ superchat_notes: [] }), user: instructor })).put('/nope').send({ title: 'x' });
        expect(res.status).toBe(404);
    });

    test('403 when a non-author tries to edit', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc({ authorId: 'someone-else' })] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ title: 'Hijack' });
        expect(res.status).toBe(403);
    });

    test('400 when content is provided but blank', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ content: '   ' });
        expect(res.status).toBe(400);
    });

    test('200 updates the author\'s own note', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ title: 'Better title' });
        expect(res.status).toBe(200);
        expect(res.body.note).toMatchObject({ noteId: 'n1', title: 'Better title', isOwn: true });
    });
});

describe('DELETE /:id — soft delete (author only)', () => {
    test('403 when a non-author tries to delete', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc({ authorId: 'someone-else' })] });
        const res = await request(app({ db, user: instructor })).delete('/n1');
        expect(res.status).toBe(403);
    });

    test('200 soft-deletes the author\'s note (hidden from later reads)', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).delete('/n1');
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ noteId: 'n1' });
        const saved = await db.collection('superchat_notes').findOne({ noteId: 'n1' });
        expect(saved.isDeleted).toBe(true);
    });
});

describe('failure paths (service throws, key errors)', () => {
    const notesService = require('../../../src/services/superChatNotesService');
    const { LlmKeyError } = require('../../../src/services/llmKeyStore');

    test('GET / 500 when the service fails', async () => {
        const spy = jest.spyOn(notesService, 'listNotes').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/');
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to load notes');
        spy.mockRestore();
    });

    test('GET /:id 500 when the service fails', async () => {
        const spy = jest.spyOn(notesService, 'getNoteById').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).get('/n1');
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to load note');
        spy.mockRestore();
    });

    test('check-similar: a key error is translated to the structured 403', async () => {
        const spy = jest.spyOn(notesService, 'checkSimilar').mockRejectedValueOnce(new LlmKeyError('invalid'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/check-similar').send({ content: 'ATP' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_INVALID');
        spy.mockRestore();
    });

    test('check-similar: an ordinary failure is swallowed (advisory success, similar:null)', async () => {
        const spy = jest.spyOn(notesService, 'checkSimilar').mockRejectedValueOnce(new Error('qdrant down'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/check-similar').send({ content: 'ATP' });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, similar: null });
        spy.mockRestore();
    });

    test('POST /: a key error from the service is translated to the structured 403', async () => {
        const spy = jest.spyOn(notesService, 'createNote').mockRejectedValueOnce(new LlmKeyError('quota_exhausted'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ content: 'note' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_QUOTA');
        spy.mockRestore();
    });

    test('POST /: an ordinary service failure returns 500', async () => {
        const spy = jest.spyOn(notesService, 'createNote').mockRejectedValueOnce(new Error('mongo down'));
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/').send({ content: 'note' });
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to create note');
        spy.mockRestore();
    });

    test('PUT /:id: 400 when the new content exceeds the hard limit', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ content: 'x'.repeat(10001) });
        expect(res.status).toBe(400);
        expect(res.body.message).toMatch(/too long/i);
    });

    test('PUT /:id: a content edit resolves the notes AI surface and re-embeds', async () => {
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ content: 'Fresh content' });
        expect(res.status).toBe(200);
        expect(res.body.note).toMatchObject({ noteId: 'n1', content: 'Fresh content', isOwn: true });
        expect(llmRegistry.forNotes).toHaveBeenCalled();
    });

    test('PUT /:id: a key error while resolving the notes AI blocks the content edit (403)', async () => {
        const failingRegistry = { forNotes: jest.fn(async () => { throw new LlmKeyError('missing'); }) };
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(makeRouteApp(router, { db, user: instructor, locals: { llmRegistry: failingRegistry } }))
            .put('/n1').send({ content: 'Fresh content' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_MISSING');
    });

    test('PUT /:id: a key error thrown by the service is translated to the structured 403', async () => {
        const spy = jest.spyOn(notesService, 'updateNote').mockRejectedValueOnce(new LlmKeyError('invalid'));
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ title: 'New' });
        expect(res.status).toBe(403);
        expect(res.body.code).toBe('LLM_KEY_INVALID');
        spy.mockRestore();
    });

    test('PUT /:id: an ordinary service failure returns 500', async () => {
        const spy = jest.spyOn(notesService, 'updateNote').mockRejectedValueOnce(new Error('mongo down'));
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).put('/n1').send({ title: 'New' });
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to update note');
        spy.mockRestore();
    });

    test('DELETE /:id: an ordinary service failure returns 500', async () => {
        const spy = jest.spyOn(notesService, 'deleteNote').mockRejectedValueOnce(new Error('mongo down'));
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        const res = await request(app({ db, user: instructor })).delete('/n1');
        expect(res.status).toBe(500);
        expect(res.body.message).toBe('Failed to delete note');
        spy.mockRestore();
    });
});

describe('coverage: db/auth/registry guards and default shaping', () => {
    test('503 on every endpoint when the db is unavailable', async () => {
        const noDb = app({ db: null, user: instructor });
        expect((await request(noDb).post('/check-similar').send({ content: 'x' })).status).toBe(503);
        expect((await request(noDb).get('/n1')).status).toBe(503);
        expect((await request(noDb).post('/').send({ content: 'x' })).status).toBe(503);
        expect((await request(noDb).put('/n1').send({ title: 'x' })).status).toBe(503);
        expect((await request(noDb).delete('/n1')).status).toBe(503);
    });

    test('401 on PUT and DELETE when unauthenticated', async () => {
        const anon = app({ db: memoryDb({}) });
        expect((await request(anon).put('/n1').send({ title: 'x' })).status).toBe(401);
        expect((await request(anon).delete('/n1')).status).toBe(401);
    });

    test('503 when the llmRegistry is missing (check-similar, create, content edit)', async () => {
        const noRegistry = makeRouteApp(router, { db: memoryDb({ superchat_notes: [noteDoc()] }), user: instructor, locals: {} });
        expect((await request(noRegistry).post('/check-similar').send({ content: 'x' })).status).toBe(503);
        expect((await request(noRegistry).post('/').send({ content: 'x' })).status).toBe(503);
        expect((await request(noRegistry).put('/n1').send({ content: 'x' })).status).toBe(503);
    });

    test('author name falls back to "Instructor" and note fields default when absent', async () => {
        const bareUser = { userId: 'i9' };
        const db = memoryDb({ superchat_notes: [noteDoc({ noteId: 'n-bare', authorId: 'i9', tags: undefined, usageCount: undefined })] });
        const created = await request(app({ db, user: bareUser })).post('/').send({ content: 'note body' });
        expect(created.status).toBe(201);
        expect(created.body.note.authorName).toBe('Instructor');

        const listed = await request(app({ db, user: bareUser })).get('/');
        const bare = listed.body.data.notes.find(n => n.noteId === 'n-bare');
        expect(bare).toMatchObject({ tags: [], usageCount: 0 });
    });

    test('service rejections without a status map to 400', async () => {
        const notesService = require('../../../src/services/superChatNotesService');
        const updateSpy = jest.spyOn(notesService, 'updateNote').mockResolvedValueOnce({ ok: false, message: 'nope' });
        const db = memoryDb({ superchat_notes: [noteDoc()] });
        expect((await request(app({ db, user: instructor })).put('/n1').send({ title: 'x' })).status).toBe(400);
        updateSpy.mockRestore();

        const deleteSpy = jest.spyOn(notesService, 'deleteNote').mockResolvedValueOnce({ ok: false, message: 'nope' });
        expect((await request(app({ db, user: instructor })).delete('/n1')).status).toBe(400);
        deleteSpy.mockRestore();
    });
});
