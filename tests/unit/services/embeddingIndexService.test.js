/**
 * Per-profile index tracking: what counts as current, what counts as stale, and
 * which collections a piece of content must be deleted from. Adding random comment.
 */
const { buildEmbeddingProfile } = require('../../../src/services/embeddingConfig');
const {
    INDEX_STATUSES,
    buildIndexRecord,
    clearIndexRecord,
    contentHash,
    deleteDocumentFromAllCollections,
    deleteNoteFromAllCollections,
    indexFingerprint,
    indexedCollections,
    indexesOf,
    indexingReason,
    markDocumentIndexFailed,
    markDocumentIndexReady,
    markIndexPending,
    markNoteIndexFailed,
    markNoteIndexReady,
    needsIndexing,
    normalizeContent,
    partitionByIndexState,
} = require('../../../src/services/embeddingIndexService');
const { memoryDb } = require('../helpers/memory-db');

const GPT = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
const SANDBOX = buildEmbeddingProfile({ provider: 'ubc-llm-sandbox', embeddingModel: 'qwen3-embedding-0.6b' });
const PROXY = buildEmbeddingProfile({ provider: 'ubc-llm-proxy', embeddingModel: 'text-embedding-3-small' });

const OLD_ENV = process.env;
beforeEach(() => {
    process.env = { ...OLD_ENV };
    delete process.env.CHUNK_SIZE;
});
afterAll(() => { process.env = OLD_ENV; });

/** A document already indexed for one profile. */
function indexedDoc(profile, content, overrides = {}) {
    const hash = contentHash(content);
    return {
        documentId: 'doc-1',
        courseId: 'C1',
        content,
        embeddingIndexes: {
            [profile.storageKey]: buildIndexRecord({
                profile, hash, status: INDEX_STATUSES.READY, indexedAt: new Date(),
            }),
        },
        ...overrides,
    };
}

describe('content hashing', () => {
    test('normalizes line endings, trailing spaces and a BOM before hashing', () => {
        expect(contentHash('a\r\nb')).toBe(contentHash('a\nb'));
        expect(contentHash('a  \nb')).toBe(contentHash('a\nb'));
        expect(contentHash('﻿abc')).toBe(contentHash('abc'));
        expect(contentHash('  abc  ')).toBe(contentHash('abc'));
    });

    test('different content hashes differently, and it is a SHA-256 hex digest', () => {
        expect(contentHash('one')).not.toBe(contentHash('two'));
        expect(contentHash('one')).toMatch(/^[a-f0-9]{64}$/);
    });

    test('normalizeContent tolerates null/undefined', () => {
        expect(normalizeContent(null)).toBe('');
        expect(normalizeContent(undefined)).toBe('');
    });
});

describe('index fingerprint', () => {
    test('changes with the embedding profile', () => {
        const hash = contentHash('same text');
        expect(indexFingerprint({ contentHash: hash, profile: GPT }))
            .not.toBe(indexFingerprint({ contentHash: hash, profile: SANDBOX }));
    });

    test('changes with the chunking configuration', () => {
        const hash = contentHash('same text');
        const before = indexFingerprint({ contentHash: hash, profile: buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' }) });
        process.env.CHUNK_SIZE = '500';
        const after = indexFingerprint({ contentHash: hash, profile: buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' }) });
        expect(after).not.toBe(before);
    });

    test('changes with the profile revision', () => {
        const hash = contentHash('same text');
        const v2 = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small', revision: 'v2' });
        expect(indexFingerprint({ contentHash: hash, profile: v2 }))
            .not.toBe(indexFingerprint({ contentHash: hash, profile: GPT }));
    });
});

describe('needsIndexing', () => {
    test('a current index is skipped — no blind re-indexing', () => {
        const doc = indexedDoc(GPT, 'cell biology');
        expect(needsIndexing(doc, GPT, contentHash(doc.content))).toBe(false);
        expect(indexingReason(doc, GPT, contentHash(doc.content))).toBeNull();
    });

    test('a missing index for the target profile needs work', () => {
        const doc = indexedDoc(GPT, 'cell biology');
        expect(needsIndexing(doc, SANDBOX, contentHash(doc.content))).toBe(true);
        expect(indexingReason(doc, SANDBOX, contentHash(doc.content))).toBe('missing');
    });

    test('edited content makes the existing index stale', () => {
        const doc = indexedDoc(GPT, 'original text');
        doc.content = 'edited text';
        expect(needsIndexing(doc, GPT, contentHash(doc.content))).toBe(true);
        expect(indexingReason(doc, GPT, contentHash(doc.content))).toBe('content-changed');
    });

    test('a chunking change makes an otherwise-current index stale', () => {
        const doc = indexedDoc(GPT, 'cell biology');
        process.env.CHUNK_SIZE = '250';
        const rechunked = buildEmbeddingProfile({ provider: 'openai', embeddingModel: 'text-embedding-3-small' });
        expect(needsIndexing(doc, rechunked, contentHash(doc.content))).toBe(true);
        expect(indexingReason(doc, rechunked, contentHash(doc.content))).toBe('profile-changed');
    });

    test('a legacy Proxy record in the shared OpenAI collection is stale', () => {
        const doc = indexedDoc(PROXY, 'cell biology');
        doc.embeddingIndexes[PROXY.storageKey].collection = GPT.collection;

        expect(needsIndexing(doc, PROXY, contentHash(doc.content))).toBe(true);
        expect(indexingReason(doc, PROXY, contentHash(doc.content))).toBe('collection-changed');
    });

    test('moving Proxy out of a shared collection invalidates the colliding OpenAI record', async () => {
        const content = 'cell biology';
        const hash = contentHash(content);
        const proxyInOldSharedCollection = buildIndexRecord({
            profile: PROXY,
            hash,
            status: INDEX_STATUSES.READY,
            indexedAt: new Date(),
            collection: GPT.collection,
        });
        const db = memoryDb({
            documents: [{
                documentId: 'doc-1',
                courseId: 'C1',
                content,
                embeddingIndexes: {
                    [GPT.storageKey]: buildIndexRecord({
                        profile: GPT, hash, status: INDEX_STATUSES.READY, indexedAt: new Date(),
                    }),
                    [PROXY.storageKey]: proxyInOldSharedCollection,
                },
            }],
        });

        await markDocumentIndexReady(db, 'doc-1', PROXY, hash);

        const stored = await db.collection('documents').findOne({ documentId: 'doc-1' });
        expect(stored.embeddingIndexes[PROXY.storageKey]).toMatchObject({
            status: INDEX_STATUSES.READY,
            collection: PROXY.collection,
        });
        expect(stored.embeddingIndexes[GPT.storageKey]).toMatchObject({
            status: INDEX_STATUSES.MISSING,
            collection: GPT.collection,
        });
        expect(stored.embeddingIndexes[GPT.storageKey].error).toMatch(/previously shared/);
    });

    test.each([
        [INDEX_STATUSES.FAILED, 'failed'],
        [INDEX_STATUSES.PENDING, 'not-ready'],
        [INDEX_STATUSES.MISSING, 'not-ready'],
    ])('a %s index needs work', (status, reason) => {
        const doc = indexedDoc(GPT, 'cell biology');
        doc.embeddingIndexes[GPT.storageKey].status = status;
        expect(needsIndexing(doc, GPT, contentHash(doc.content))).toBe(true);
        expect(indexingReason(doc, GPT, contentHash(doc.content))).toBe(reason);
    });

    test('partitionByIndexState separates reusable from stale documents', () => {
        const current = indexedDoc(GPT, 'already embedded');
        const stale = { documentId: 'doc-2', courseId: 'C1', content: 'never embedded' };
        const { stale: needsWork, current: reusable } = partitionByIndexState([current, stale], GPT);

        expect(reusable.map(entry => entry.doc.documentId)).toEqual(['doc-1']);
        expect(needsWork.map(entry => entry.doc.documentId)).toEqual(['doc-2']);
        expect(needsWork[0].reason).toBe('missing');
    });
});

describe('legacy content with no embeddingIndexes', () => {
    test.each(['uploaded', 'parsed'])('document status %s never claims an embedding index', (status) => {
        const doc = { documentId: 'old-1', courseId: 'C1', content: 'legacy text', status };
        expect(indexesOf(doc)).toEqual({});
        expect(needsIndexing(doc, GPT, contentHash(doc.content))).toBe(true);
    });

    test('a legacy note with stored point ids reads as an OpenAI notes index', () => {
        const note = { noteId: 'note-1', content: 'legacy note', qdrantPointIds: ['p1', 'p2'] };
        const records = indexesOf(note);
        expect(records['openai:text-embedding-3-small:v1']).toMatchObject({ collection: 'superchat_notes' });
        expect(needsIndexing(note, GPT, contentHash(note.content))).toBe(false);
    });

    test('a note with no point ids claims no index', () => {
        expect(indexesOf({ noteId: 'note-2', content: 'x', qdrantPointIds: [] })).toEqual({});
    });

    test('stored records always win over the legacy synthesis', () => {
        const hash = contentHash('note text');
        const note = {
            noteId: 'note-3', content: 'note text', qdrantPointIds: ['legacy-point'],
            embeddingIndexes: {
                [SANDBOX.storageKey]: buildIndexRecord({
                    profile: SANDBOX, hash, status: INDEX_STATUSES.READY,
                    collection: SANDBOX.notesCollection,
                }),
            },
        };
        expect(Object.keys(indexesOf(note))).toEqual([SANDBOX.storageKey]);
    });
});

describe('indexedCollections', () => {
    test('lists every collection a document was indexed into, de-duplicated', () => {
        const hash = contentHash('multi');
        const doc = {
            documentId: 'doc-1',
            content: 'multi',
            embeddingIndexes: {
                [GPT.storageKey]: buildIndexRecord({ profile: GPT, hash, status: INDEX_STATUSES.READY }),
                [SANDBOX.storageKey]: buildIndexRecord({ profile: SANDBOX, hash, status: INDEX_STATUSES.READY }),
            },
        };
        expect(indexedCollections(doc).map(entry => entry.collection).sort())
            .toEqual(['biocbot_documents', 'biocbot_documents_qwen3_embedding_0_6b']);
    });

    test('records with no collection are ignored', () => {
        expect(indexedCollections({ embeddingIndexes: { 'a:b:v1': { status: 'ready' } } })).toEqual([]);
        expect(indexedCollections(null)).toEqual([]);
    });
});

describe('persisting index state', () => {
    test('markDocumentIndexReady writes a per-profile record without touching others', async () => {
        const db = memoryDb({ documents: [indexedDoc(GPT, 'text')] });
        await markDocumentIndexReady(db, 'doc-1', SANDBOX, contentHash('text'));

        const stored = await db.collection('documents').findOne({ documentId: 'doc-1' });
        expect(stored.embeddingIndexes[GPT.storageKey].status).toBe('ready');
        expect(stored.embeddingIndexes[SANDBOX.storageKey]).toMatchObject({
            provider: 'ubc-llm-sandbox',
            model: 'qwen3-embedding-0.6b',
            collection: 'biocbot_documents_qwen3_embedding_0_6b',
            status: 'ready',
        });
        expect(stored.embeddingIndexes[SANDBOX.storageKey].indexedAt).toBeInstanceOf(Date);
    });

    test('adding Sandbox tracking does not invent a GPT index from document status', async () => {
        const db = memoryDb({
            documents: [{
                documentId: 'legacy-doc', courseId: 'C1', content: 'legacy text', status: 'uploaded',
            }],
        });

        await markDocumentIndexReady(db, 'legacy-doc', SANDBOX, contentHash('legacy text'));

        const stored = await db.collection('documents').findOne({ documentId: 'legacy-doc' });
        expect(stored.embeddingIndexes[GPT.storageKey]).toBeUndefined();
        expect(stored.embeddingIndexes[SANDBOX.storageKey]).toMatchObject({ status: 'ready' });
        expect(needsIndexing(stored, GPT, contentHash(stored.content))).toBe(true);
    });

    test('markDocumentIndexFailed records a truncated error and leaves other profiles alone', async () => {
        const db = memoryDb({ documents: [indexedDoc(GPT, 'text')] });
        await markDocumentIndexFailed(db, 'doc-1', SANDBOX, contentHash('text'), new Error('x'.repeat(900)));

        const stored = await db.collection('documents').findOne({ documentId: 'doc-1' });
        expect(stored.embeddingIndexes[SANDBOX.storageKey].status).toBe('failed');
        expect(stored.embeddingIndexes[SANDBOX.storageKey].error).toHaveLength(500);
        expect(stored.embeddingIndexes[GPT.storageKey].status).toBe('ready');
    });

    test('a failure with no Error object still records a reason', async () => {
        const db = memoryDb({ documents: [{ documentId: 'doc-1', content: 'text' }] });
        await markDocumentIndexFailed(db, 'doc-1', GPT, contentHash('text'), null);
        const stored = await db.collection('documents').findOne({ documentId: 'doc-1' });
        expect(stored.embeddingIndexes[GPT.storageKey].error).toBe('Unknown error');
    });

    test('notes get the same treatment in their own Mongo collection', async () => {
        const db = memoryDb({ superchat_notes: [{ noteId: 'n1', content: 'note text' }] });
        await markNoteIndexReady(db, 'n1', SANDBOX, contentHash('note text'));
        await markNoteIndexFailed(db, 'n1', GPT, contentHash('note text'), new Error('nope'));

        const stored = await db.collection('superchat_notes').findOne({ noteId: 'n1' });
        expect(stored.embeddingIndexes[SANDBOX.storageKey].status).toBe('ready');
        expect(stored.embeddingIndexes[GPT.storageKey]).toMatchObject({ status: 'failed', error: 'nope' });
    });

    test("a note's record names the notes collection, not the documents one", async () => {
        const db = memoryDb({ superchat_notes: [{ noteId: 'n1', content: 'note text' }] });
        await markNoteIndexReady(db, 'n1', SANDBOX, contentHash('note text'));
        await markNoteIndexFailed(db, 'n1', GPT, contentHash('note text'), new Error('nope'));

        // The record is what deletion sweeps, so it has to point at the
        // collection the note's vectors actually live in.
        const stored = await db.collection('superchat_notes').findOne({ noteId: 'n1' });
        expect(stored.embeddingIndexes[SANDBOX.storageKey].collection)
            .toBe(SANDBOX.notesCollection);
        expect(stored.embeddingIndexes[GPT.storageKey].collection).toBe(GPT.notesCollection);
        expect(indexedCollections(stored).map(entry => entry.collection))
            .toEqual([SANDBOX.notesCollection, GPT.notesCollection]);
    });

    test('markIndexPending and clearIndexRecord round-trip', async () => {
        const db = memoryDb({ documents: [{ documentId: 'doc-1', content: 'text' }] });
        await markIndexPending(db, {
            collectionName: 'documents', filter: { documentId: 'doc-1' }, profile: GPT, hash: contentHash('text'),
        });
        expect((await db.collection('documents').findOne({ documentId: 'doc-1' })).embeddingIndexes[GPT.key].status)
            .toBe('pending');

        await clearIndexRecord(db, { collectionName: 'documents', filter: { documentId: 'doc-1' }, profileKey: GPT.storageKey });
        expect((await db.collection('documents').findOne({ documentId: 'doc-1' })).embeddingIndexes[GPT.key])
            .toBeUndefined();
    });
});

describe('deleting from every indexed collection', () => {
    function serviceFactory(calls, failOn = null) {
        return async (target, profile) => ({
            deleteDocumentChunks: async (documentId, courseId) => {
                if (failOn === profile.collection) throw new Error(`cannot reach ${profile.collection}`);
                calls.push({ collection: profile.collection, documentId, courseId });
                return { success: true, deletedCount: 2 };
            },
        });
    }

    test('sweeps both profiles, not just the active one', async () => {
        const hash = contentHash('multi');
        const doc = {
            documentId: 'doc-1',
            courseId: 'C1',
            content: 'multi',
            embeddingIndexes: {
                [GPT.storageKey]: buildIndexRecord({ profile: GPT, hash, status: INDEX_STATUSES.READY }),
                [SANDBOX.storageKey]: buildIndexRecord({ profile: SANDBOX, hash, status: INDEX_STATUSES.READY }),
            },
        };
        const db = memoryDb({ documents: [doc] });
        const calls = [];

        const result = await deleteDocumentFromAllCollections(db, doc, serviceFactory(calls));

        expect(calls.map(call => call.collection).sort())
            .toEqual(['biocbot_documents', 'biocbot_documents_qwen3_embedding_0_6b']);
        expect(calls.every(call => call.documentId === 'doc-1' && call.courseId === 'C1')).toBe(true);
        expect(result.errors).toEqual([]);
        // Tracking is cleared so nothing claims a stale index afterwards.
        expect((await db.collection('documents').findOne({ documentId: 'doc-1' })).embeddingIndexes).toEqual({});
    });

    test('a document with no tracking still sweeps the legacy collection', async () => {
        const doc = { documentId: 'doc-old', courseId: 'C1', content: 'legacy' };
        const db = memoryDb({ documents: [doc] });
        const calls = [];

        await deleteDocumentFromAllCollections(db, doc, serviceFactory(calls));
        expect(calls.map(call => call.collection)).toEqual(['biocbot_documents']);
    });

    test('a Sandbox-only record still sweeps the untracked legacy GPT collection', async () => {
        const doc = indexedDoc(SANDBOX, 'legacy then sandbox', {
            documentId: 'doc-old', courseId: 'C1', status: 'uploaded',
        });
        const db = memoryDb({ documents: [doc] });
        const calls = [];

        await deleteDocumentFromAllCollections(db, doc, serviceFactory(calls));

        expect(calls.map(call => call.collection).sort())
            .toEqual(['biocbot_documents', 'biocbot_documents_qwen3_embedding_0_6b']);
    });

    test('one unreachable collection does not stop the others', async () => {
        const hash = contentHash('multi');
        const doc = {
            documentId: 'doc-1',
            courseId: 'C1',
            content: 'multi',
            embeddingIndexes: {
                [GPT.storageKey]: buildIndexRecord({ profile: GPT, hash, status: INDEX_STATUSES.READY }),
                [SANDBOX.storageKey]: buildIndexRecord({ profile: SANDBOX, hash, status: INDEX_STATUSES.READY }),
            },
        };
        const db = memoryDb({ documents: [doc] });
        const calls = [];

        const result = await deleteDocumentFromAllCollections(db, doc, serviceFactory(calls, 'biocbot_documents'));

        expect(calls.map(call => call.collection)).toEqual(['biocbot_documents_qwen3_embedding_0_6b']);
        expect(result.errors).toHaveLength(1);
        expect(result.errors[0]).toMatchObject({ collection: 'biocbot_documents' });
    });

    test('a factory returning null (collection absent) is skipped quietly', async () => {
        const doc = { documentId: 'doc-1', courseId: 'C1', content: 'x' };
        const db = memoryDb({ documents: [doc] });
        const result = await deleteDocumentFromAllCollections(db, doc, async () => null);
        expect(result.deleted).toEqual([]);
        expect(result.errors).toEqual([]);
    });
});

describe('deleting a note from every indexed collection', () => {
    function noteIndexedIn(...profiles) {
        const hash = contentHash('note text');
        const embeddingIndexes = {};
        for (const profile of profiles) {
            embeddingIndexes[profile.storageKey] = buildIndexRecord({
                profile, hash, status: INDEX_STATUSES.READY, collection: profile.notesCollection,
            });
        }
        return { noteId: 'n1', content: 'note text', embeddingIndexes };
    }

    test('a deleted note is removed from both platforms, not just the active one', async () => {
        const note = noteIndexedIn(GPT, SANDBOX);
        const db = memoryDb({ superchat_notes: [note] });
        const calls = [];

        const result = await deleteNoteFromAllCollections(db, note, async (collection, noteId) => {
            calls.push({ collection, noteId });
            return true;
        });

        expect(calls.map(call => call.collection).sort())
            .toEqual(['superchat_notes', 'superchat_notes_qwen3_embedding_0_6b']);
        expect(result.errors).toEqual([]);
        expect((await db.collection('superchat_notes').findOne({ noteId: 'n1' })).embeddingIndexes)
            .toEqual({});
    });

    test('a note with no tracking still sweeps the legacy notes collection', async () => {
        const note = { noteId: 'n-old', content: 'legacy', qdrantPointIds: ['p1'] };
        const db = memoryDb({ superchat_notes: [note] });
        const calls = [];

        await deleteNoteFromAllCollections(db, note, async (collection) => { calls.push(collection); return true; });
        expect(calls).toEqual(['superchat_notes']);
    });

    test('one unreachable collection does not stop the others', async () => {
        const note = noteIndexedIn(GPT, SANDBOX);
        const db = memoryDb({ superchat_notes: [note] });

        const result = await deleteNoteFromAllCollections(db, note, async (collection) => {
            if (collection === 'superchat_notes') throw new Error('unreachable');
            return true;
        });

        expect(result.deleted).toEqual([
            { collection: 'superchat_notes_qwen3_embedding_0_6b', profileKey: SANDBOX.storageKey },
        ]);
        expect(result.errors).toMatchObject([{ collection: 'superchat_notes', error: 'unreachable' }]);
    });

    test('a collection that does not exist is skipped quietly', async () => {
        const note = noteIndexedIn(SANDBOX);
        const db = memoryDb({ superchat_notes: [note] });
        const result = await deleteNoteFromAllCollections(db, note, async () => false);
        expect(result.deleted).toEqual([]);
        expect(result.errors).toEqual([]);
    });
});
