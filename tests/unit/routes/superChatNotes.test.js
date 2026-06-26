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
