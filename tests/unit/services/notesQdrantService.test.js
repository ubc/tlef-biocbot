const mockBaseInitialize = jest.fn();
const mockBaseConstructor = jest.fn();

jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => {
    const instance = mockBaseConstructor();
    instance.initialize = mockBaseInitialize;
    return instance;
}));

const NotesQdrantService = require('../../../src/services/notesQdrantService');

function makeBase(overrides = {}) {
    return {
        client: {
            getCollections: jest.fn(async () => ({ collections: [{ name: 'superchat_notes' }] })),
            createCollection: jest.fn(async () => {}),
            upsert: jest.fn(async () => {}),
            delete: jest.fn(async () => {}),
            search: jest.fn(async () => []),
            ...overrides.client,
        },
        embeddings: overrides.embeddings || { embed: jest.fn(async () => [[1, 2, 3]]) },
        chunker: overrides.chunker || { chunkDocuments: jest.fn(async () => ({ chunks: [] })) },
        vectorSize: 3,
        generateEmbeddings: overrides.generateEmbeddings || jest.fn(async chunks => chunks.map(() => [1, 2, 3])),
    };
}

describe('NotesQdrantService with mocked vector boundaries', () => {
    beforeAll(() => jest.spyOn(console, 'log').mockImplementation(() => {}));
    afterAll(() => jest.restoreAllMocks());

    test('initializes from a shared base and creates a missing collection', async () => {
        const base = makeBase({ client: { getCollections: jest.fn(async () => ({ collections: [] })) } });
        const service = new NotesQdrantService();
        await service.initialize(base);
        expect(service).toMatchObject({ base, client: base.client, embeddings: base.embeddings, vectorSize: 3, initialized: true });
        expect(base.client.createCollection).toHaveBeenCalledWith(service.collectionName, { vectors: { size: 3, distance: 'Cosine' } });
        await service.initialize(base);
        expect(base.client.getCollections).toHaveBeenCalledTimes(1);
    });

    test('creates and initializes its own mocked base when one is not supplied', async () => {
        const base = makeBase();
        mockBaseConstructor.mockReturnValueOnce(base);
        const service = new NotesQdrantService();
        await service.initialize();
        expect(mockBaseInitialize).toHaveBeenCalled();
        expect(service.initialized).toBe(true);
    });

    test('chunkNote handles empty, short, and sorted long notes', async () => {
        const base = makeBase({ chunker: { chunkDocuments: jest.fn(async () => ({ chunks: [
            { text: 'second', metadata: { chunkNumber: 2 } },
            { text: 'first', metadata: { chunkNumber: 1 } },
            { text: ' ', metadata: { chunkNumber: 3 } },
        ] })) } });
        const service = new NotesQdrantService();
        await service.initialize(base);
        await expect(service.chunkNote('   ')).resolves.toEqual([]);
        await expect(service.chunkNote(' short note ')).resolves.toEqual(['short note']);
        await expect(service.chunkNote('x'.repeat(1001))).resolves.toEqual(['first', 'second']);
    });

    test.each([
        [[[1, 2, 3]], [1, 2, 3]],
        [{ embedding: [1, 2, 3] }, [1, 2, 3]],
        [{ data: [[1, 2, 3]] }, [1, 2, 3]],
        [[1, 2, 3], [1, 2, 3]],
    ])('embedQuery normalizes provider shape %#', async (raw, expected) => {
        const base = makeBase({ embeddings: { embed: jest.fn(async () => raw) } });
        const service = new NotesQdrantService();
        await service.initialize(base);
        await expect(service.embedQuery('query')).resolves.toEqual(expected);
    });

    test('embedQuery rejects invalid provider shapes', async () => {
        const service = new NotesQdrantService();
        await service.initialize(makeBase({ embeddings: { embed: jest.fn(async () => ({ nope: true })) } }));
        await expect(service.embedQuery('query')).rejects.toThrow('Invalid embedding shape');
    });

    test('addNote stores chunks and normalized metadata', async () => {
        const base = makeBase();
        const service = new NotesQdrantService();
        await service.initialize(base);
        const ids = await service.addNote('n1', 'Note content', { authorId: 'a1', title: 'Title', tags: ['tag'], createdAt: 'now' });
        expect(ids).toHaveLength(1);
        expect(base.client.upsert.mock.calls[0][1].points[0]).toMatchObject({
            vector: [1, 2, 3],
            payload: { noteId: 'n1', sourceType: 'note', authorId: 'a1', title: 'Title', tags: ['tag'], createdAt: 'now', chunkIndex: 0 },
        });
        await expect(service.addNote('empty', '   ')).resolves.toEqual([]);
    });

    test('deleteNote and updateNote use filtered deletion before replacement', async () => {
        const base = makeBase();
        const service = new NotesQdrantService();
        await service.initialize(base);
        await service.deleteNote('n1');
        expect(base.client.delete).toHaveBeenCalledWith(service.collectionName, { filter: { must: [{ key: 'noteId', match: { value: 'n1' } }] } });
        const ids = await service.updateNote('n1', 'replacement');
        expect(ids).toHaveLength(1);
        expect(base.client.delete).toHaveBeenCalledTimes(2);
    });

    test('searchNotes maps results and applies minScore', async () => {
        const base = makeBase({ client: { search: jest.fn(async () => [
            { id: 'p1', score: 0.9, payload: { noteId: 'n1', tags: ['a'], chunkText: 'high' } },
            { id: 'p2', score: 0.4, payload: { noteId: 'n2', chunkText: 'low' } },
        ]) } });
        const service = new NotesQdrantService();
        await service.initialize(base);
        await expect(service.searchNotes('', 5)).resolves.toEqual([]);
        const result = await service.searchNotes('ATP', 5, { minScore: 0.8 });
        expect(result).toEqual([expect.objectContaining({ id: 'p1', noteId: 'n1', sourceType: 'note', tags: ['a'] })]);
    });

    test('findSimilarTo returns null below threshold and maps a top match', async () => {
        const search = jest.fn()
            .mockResolvedValueOnce([{ score: 0.5, payload: { noteId: 'low' } }])
            .mockResolvedValueOnce([{ score: 0.95, payload: { noteId: 'n1', authorName: 'A', title: 'T', createdAt: 'now', chunkText: 'x'.repeat(300) } }]);
        const service = new NotesQdrantService();
        await service.initialize(makeBase({ client: { search } }));
        await expect(service.findSimilarTo('   ')).resolves.toBeNull();
        await expect(service.findSimilarTo('content')).resolves.toBeNull();
        const result = await service.findSimilarTo('content', { excludeNoteId: 'self', threshold: 0.9 });
        expect(result).toMatchObject({ noteId: 'n1', score: 0.95 });
        expect(result.excerpt).toHaveLength(240);
        expect(search.mock.calls[1][1].filter).toEqual({ must_not: [{ key: 'noteId', match: { value: 'self' } }] });
    });
});
