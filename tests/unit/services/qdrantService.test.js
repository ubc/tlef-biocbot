const mockCreateEmbeddings = jest.fn();

jest.mock('@qdrant/js-client-rest', () => ({
    QdrantClient: jest.fn(),
}));
jest.mock('ubc-genai-toolkit-embeddings', () => ({
    EmbeddingsModule: { create: (...args) => mockCreateEmbeddings(...args) },
}));
jest.mock('ubc-genai-toolkit-chunking', () => ({
    ChunkingModule: jest.fn(),
}));
jest.mock('ubc-genai-toolkit-core', () => ({
    ConsoleLogger: jest.fn(),
}));
jest.mock('../../../src/services/config', () => ({
    getVectorDBConfig: jest.fn(() => ({ host: 'localhost', port: 6333 })),
    getLLMConfig: jest.fn(() => ({ provider: 'openai', defaultModel: 'model' })),
}));

const originalConsoleLog = console.log;
console.log = jest.fn();
const QdrantService = require('../../../src/services/qdrantService');
console.log = originalConsoleLog;
const { QdrantClient } = require('@qdrant/js-client-rest');
const { ChunkingModule } = require('ubc-genai-toolkit-chunking');
const config = require('../../../src/services/config');

const hit = (overrides = {}) => ({
    id: 'point-1',
    score: 0.91,
    payload: {
        courseId: 'BIOC-1', lectureName: 'Unit 1', documentId: 'doc-1',
        fileName: 'notes.txt', documentType: 'notes', type: 'text',
        chunkText: 'cell biology', chunkIndex: 0, timestamp: 'now',
        ...overrides,
    },
});

function makeService(overrides = {}) {
    const service = new QdrantService({
        embeddings: overrides.embeddings || { embed: jest.fn(async () => [[1, 2, 3]]) },
        llmConfig: overrides.llmConfig,
        onProviderKeyFailure: overrides.onProviderKeyFailure,
    });
    service.vectorSize = 3;
    service.client = {
        getCollections: jest.fn(async () => ({ collections: [{ name: service.collectionName }] })),
        getCollection: jest.fn(async () => ({
            name: service.collectionName,
            config: { params: { vectors: { size: 3, distance: 'Cosine' } } },
            points_count: 4, segments_count: 2, status: 'green',
        })),
        createCollection: jest.fn(async () => {}),
        deleteCollection: jest.fn(async () => {}),
        upsert: jest.fn(async () => {}),
        search: jest.fn(async () => []),
        scroll: jest.fn(async () => ({ points: [], next_page_offset: null })),
        delete: jest.fn(async () => {}),
        ...overrides.client,
    };
    service.chunker = overrides.chunker || {
        getDefaultStrategyName: jest.fn(() => 'recursiveCharacter'),
        chunkDocuments: jest.fn(async () => ({
            chunks: [{ text: 'second chunk', metadata: { chunkNumber: 2 } }, { text: 'first chunk', metadata: { chunkNumber: 1 } }],
            strategy: 'recursiveCharacter',
        })),
    };
    return service;
}

describe('QdrantService', () => {
    const originalEnv = process.env;

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'warn').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    beforeEach(() => {
        process.env = { ...originalEnv };
        delete process.env.BIOCBOT_TEST_LLM_STUB;
        delete process.env.LLM_EMBEDDING_MODEL;
        delete process.env.QDRANT_VECTOR_SIZE;
        config.getVectorDBConfig.mockReturnValue({ host: 'localhost', port: 6333 });
        config.getLLMConfig.mockReturnValue({ provider: 'openai', defaultModel: 'model' });
    });

    afterAll(() => {
        process.env = originalEnv;
        jest.restoreAllMocks();
    });

    test.each([
        ['text-embedding-3-small', 1536],
        ['text-embedding-ada-002', 1536],
        ['nomic-embed-text', 768],
        ['other-model', '42'],
    ])('initialize configures clients, chunking, and vector size for %s', async (model, expectedSize) => {
        process.env.LLM_EMBEDDING_MODEL = model;
        process.env.QDRANT_VECTOR_SIZE = '42';
        const client = {
            getCollections: jest.fn(async () => ({ collections: [{ name: 'biocbot_documents' }] })),
            getCollection: jest.fn(async () => ({ config: { params: { vectors: { size: expectedSize } } } })),
        };
        QdrantClient.mockImplementation(() => client);
        ChunkingModule.mockImplementation(() => ({ getDefaultStrategyName: () => 'recursiveCharacter' }));
        const embeddings = { embed: jest.fn(async () => [Array(Number(expectedSize) || 42).fill(0)]) };
        const service = new QdrantService({ embeddings });
        await service.initialize();
        expect(service.vectorSize).toBe(expectedSize);
        expect(QdrantClient).toHaveBeenCalledWith({ url: 'http://localhost:6333', apiKey: 'super-secret-dev-key' });
        expect(service.chunker.getDefaultStrategyName()).toBe('recursiveCharacter');
    });

    test('initialize can skip embeddings for maintenance operations', async () => {
        const client = {
            getCollections: jest.fn(async () => ({ collections: [] })),
            createCollection: jest.fn(async () => {}),
        };
        QdrantClient.mockImplementation(() => client);
        const service = new QdrantService({ skipEmbeddings: true });
        await service.initialize();
        expect(service.embeddings).toBeNull();
        expect(service.chunker).toBeNull();
        expect(client.createCollection).toHaveBeenCalled();
    });

    test('initialize creates embeddings when none are injected and tolerates a failed probe', async () => {
        const client = {
            getCollections: jest.fn(async () => ({ collections: [{ name: 'biocbot_documents' }] })),
            getCollection: jest.fn(async () => ({ config: { params: { vectors: { size: 768 } } } })),
        };
        QdrantClient.mockImplementation(() => client);
        ChunkingModule.mockImplementation(() => ({ getDefaultStrategyName: () => 'custom' }));
        mockCreateEmbeddings.mockResolvedValueOnce({ embed: jest.fn(async () => { throw new Error('probe failed'); }) });
        const service = new QdrantService();
        await expect(service.initialize()).resolves.toBeUndefined();
        expect(mockCreateEmbeddings).toHaveBeenCalled();
    });

    test.each([
        ['vector config', () => config.getVectorDBConfig.mockImplementationOnce(() => { throw new Error('bad vectors'); }), 'Vector DB configuration error'],
        ['client connection', () => QdrantClient.mockImplementationOnce(() => ({ getCollections: jest.fn(async () => { throw new Error('offline'); }) })), 'offline'],
        ['LLM config', () => config.getLLMConfig.mockImplementationOnce(() => { throw new Error('bad llm'); }), 'LLM configuration error'],
        ['embedding creation', () => mockCreateEmbeddings.mockRejectedValueOnce(new Error('provider down')), 'Embeddings initialization error'],
    ])('initialize exposes %s failures with context', async (_name, arrange, message) => {
        const defaultClient = {
            getCollections: jest.fn(async () => ({ collections: [{ name: 'biocbot_documents' }] })),
            getCollection: jest.fn(async () => ({ config: { params: { vectors: { size: 768 } } } })),
        };
        QdrantClient.mockImplementation(() => defaultClient);
        ChunkingModule.mockImplementation(() => ({ getDefaultStrategyName: () => 'recursiveCharacter' }));
        mockCreateEmbeddings.mockResolvedValue({ embed: jest.fn(async () => [[1, 2, 3]]) });
        arrange();
        await expect(new QdrantService().initialize()).rejects.toThrow(message);
    });

    test('constructor reflects stub mode and injected options', () => {
        const previous = process.env.BIOCBOT_TEST_LLM_STUB;
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        const callback = jest.fn();
        const service = new QdrantService({ embeddings: {}, llmConfig: { provider: 'x' }, skipEmbeddings: true, onProviderKeyFailure: callback });
        expect(service).toMatchObject({ collectionName: 'biocbot_documents_stub', skipEmbeddings: true, onProviderKeyFailure: callback });
        if (previous === undefined) delete process.env.BIOCBOT_TEST_LLM_STUB;
        else process.env.BIOCBOT_TEST_LLM_STUB = previous;
    });

    test('ensureCollectionExists creates a missing collection', async () => {
        const service = makeService({ client: { getCollections: jest.fn(async () => ({ collections: [] })) } });
        await service.ensureCollectionExists();
        expect(service.client.createCollection).toHaveBeenCalledWith(service.collectionName, { vectors: { size: 3, distance: 'Cosine' } });
    });

    test('ensureCollectionExists leaves a compatible collection alone', async () => {
        const service = makeService();
        await service.ensureCollectionExists();
        expect(service.client.deleteCollection).not.toHaveBeenCalled();
        expect(service.client.createCollection).not.toHaveBeenCalled();
    });

    test('ensureCollectionExists recreates an incompatible collection and propagates errors', async () => {
        const service = makeService({ client: { getCollection: jest.fn(async () => ({ config: { params: { vectors: { size: 99 } } } })) } });
        await service.ensureCollectionExists();
        expect(service.client.deleteCollection).toHaveBeenCalledWith(service.collectionName);
        expect(service.client.createCollection).toHaveBeenCalled();
        service.client.getCollections.mockRejectedValueOnce(new Error('offline'));
        await expect(service.ensureCollectionExists()).rejects.toThrow('offline');
    });

    test.each([
        [{ content: null }, 'content must be a non-empty string'],
        [{ content: '   ' }, 'empty or contains only whitespace'],
        [{ content: 'short' }, 'too short'],
    ])('processAndStoreDocument rejects invalid content %#', async (data, message) => {
        const result = await makeService().processAndStoreDocument({ fileName: 'x', lectureName: 'u', ...data });
        expect(result).toEqual({ success: false, error: expect.stringContaining(message) });
    });

    test('processAndStoreDocument sanitizes, orders, embeds, and stores chunks', async () => {
        const service = makeService();
        service.generateEmbeddings = jest.fn(async chunks => chunks.map(() => [1, 2, 3]));
        service.storeChunks = jest.fn(async (_doc, chunks) => chunks.map((_, id) => ({ id })));
        const result = await service.processAndStoreDocument({
            courseId: 'C', lectureName: 'U', documentId: 'D', fileName: 'f',
            content: `control\u0000 ${'a'.repeat(15)} content long enough`,
        });
        expect(service.generateEmbeddings).toHaveBeenCalledWith(['first chunk', 'second chunk']);
        expect(result).toMatchObject({ success: true, chunksProcessed: 2, chunksStored: 2 });
    });

    test('processAndStoreDocument reports missing chunker, empty chunks, and empty embeddings', async () => {
        const noChunker = makeService(); noChunker.chunker = null;
        await expect(noChunker.processAndStoreDocument({ content: 'long enough content', fileName: 'f' })).resolves.toMatchObject({ success: false, error: 'Chunking service is not initialized' });
        const noChunks = makeService({ chunker: { chunkDocuments: jest.fn(async () => ({ chunks: [] })), getDefaultStrategyName: jest.fn(() => 'fallback') } });
        await expect(noChunks.processAndStoreDocument({ content: 'long enough content', fileName: 'f' })).resolves.toMatchObject({ success: false, error: expect.stringContaining('No chunks') });
        const noEmbeddings = makeService(); noEmbeddings.generateEmbeddings = jest.fn(async () => []);
        await expect(noEmbeddings.processAndStoreDocument({ content: 'long enough content', fileName: 'f' })).resolves.toMatchObject({ success: false, error: expect.stringContaining('No embeddings') });
    });

    test('generateEmbeddings skips blank chunks and returns provider vectors', async () => {
        const service = makeService();
        await expect(service.generateEmbeddings(['one', '', 'three'])).resolves.toEqual([[1, 2, 3], [1, 2, 3]]);
        expect(service.embeddings.embed).toHaveBeenCalledTimes(2);
    });

    test('generateEmbeddings rejects invalid input and provider results', async () => {
        const service = makeService();
        await expect(service.generateEmbeddings([])).rejects.toThrow('Invalid chunks array');
        service.embeddings.embed.mockResolvedValueOnce(null);
        await expect(service.generateEmbeddings(['x'])).rejects.toThrow('Invalid embedding returned');
        service.embeddings.embed.mockResolvedValueOnce([1, 2, 3]);
        await expect(service.generateEmbeddings(['x'])).rejects.toThrow('Embedding vector is not an array');
    });

    test('storeChunks preserves metadata and supplies defaults', async () => {
        const service = makeService();
        const stored = await service.storeChunks({ courseId: 'C', lectureName: 'U', documentId: 'D', fileName: 'f', mimeType: 'text', chunkMetadata: [{ page: 4 }] }, ['hello'], [[1, 2, 3]]);
        const point = service.client.upsert.mock.calls[0][1].points[0];
        expect(point.payload).toMatchObject({ page: 4, courseId: 'C', documentType: 'unknown', type: 'unknown', chunkIndex: 0, totalChunks: 1, chunkText: 'hello' });
        expect(stored[0]).toMatchObject({ documentId: 'D', chunkIndex: 0 });
    });

    test.each([
        [[[1, 2, 3]], [1, 2, 3]],
        [{ embedding: [1, 2, 3] }, [1, 2, 3]],
        [{ data: [[1, 2, 3]] }, [1, 2, 3]],
        [[1, 2, 3], [1, 2, 3]],
    ])('generateQueryVector normalizes provider shape %#', async (raw, expected) => {
        const service = makeService({ embeddings: { embed: jest.fn(async () => raw) } });
        await expect(service.generateQueryVector('query')).resolves.toEqual(expected);
    });

    test('generateQueryVector rejects malformed values', async () => {
        const service = makeService({ embeddings: { embed: jest.fn(async () => ({ data: [] })) } });
        await expect(service.generateQueryVector('query')).rejects.toThrow('Invalid query embedding shape');
    });

    test('searchDocuments builds all supported filters and transforms hits', async () => {
        const service = makeService({ client: { search: jest.fn(async () => [hit()]) } });
        const result = await service.searchDocuments('cells', { courseId: ['C1', 'C2'], lectureNames: ['U1'], excludeAdditionalMaterials: true }, 7);
        expect(result[0]).toMatchObject({ id: 'point-1', courseId: 'BIOC-1', chunkText: 'cell biology' });
        expect(service.client.search.mock.calls[0][1]).toMatchObject({ limit: 7, filter: { must: [
            { key: 'courseId', match: { any: ['C1', 'C2'] } },
            { key: 'lectureName', match: { any: ['U1'] } },
        ], must_not: expect.any(Array) } });
    });

    test('searchDocuments supports scalar and additional-only filters', async () => {
        const service = makeService();
        await service.searchDocuments('cells', { courseId: 'C', lectureName: 'U', additionalMaterialsOnly: true });
        expect(service.client.search.mock.calls[0][1].filter.must).toHaveLength(3);
    });

    test('searchDocumentsByCourse embeds once and maps each course result', async () => {
        const service = makeService({ client: { search: jest.fn(async (_name, params) => [hit({ courseId: params.filter.must[0].match.value })]) } });
        await expect(service.searchDocumentsByCourse('q', [])).resolves.toEqual(new Map());
        const result = await service.searchDocumentsByCourse('q', ['A', 'B'], 2);
        expect([...result.keys()]).toEqual(['A', 'B']);
        expect(service.embeddings.embed).toHaveBeenCalledTimes(1);
        expect(service.client.search).toHaveBeenCalledTimes(2);
    });

    test('getDocumentChunks scrolls pages and sorts chunks', async () => {
        const scroll = jest.fn()
            .mockResolvedValueOnce({ points: [{ payload: { chunkIndex: 2, chunkText: 'two' } }], next_page_offset: 'next' })
            .mockResolvedValueOnce({ points: [{ payload: { chunkIndex: 1, chunkText: 'one' } }], next_page_offset: null });
        const service = makeService({ client: { scroll } });
        await expect(service.getDocumentChunks('D')).resolves.toEqual(['one', 'two']);
    });

    test('cloneDocumentChunks validates input and handles no source points', async () => {
        const service = makeService();
        await expect(service.cloneDocumentChunks({})).resolves.toMatchObject({ success: false, error: expect.stringContaining('Missing required') });
        await expect(service.cloneDocumentChunks({ sourceDocumentId: 'S', targetDocumentId: 'T', targetCourseId: 'C', targetLectureName: 'U' })).resolves.toMatchObject({ success: true, clonedCount: 0 });
    });

    test('cloneDocumentChunks copies vectors and overrides target metadata', async () => {
        const service = makeService({ client: { scroll: jest.fn(async () => ({ points: [{ vector: [1, 2, 3], payload: { documentType: 'notes', type: 'pdf' } }], next_page_offset: null })) } });
        const result = await service.cloneDocumentChunks({ sourceDocumentId: 'S', targetDocumentId: 'T', targetCourseId: 'C', targetLectureName: 'U', targetFileName: 'new.pdf' });
        expect(result).toMatchObject({ success: true, clonedCount: 1 });
        expect(service.client.upsert.mock.calls[0][1].points[0]).toMatchObject({ vector: [1, 2, 3], payload: { courseId: 'C', lectureName: 'U', documentId: 'T', fileName: 'new.pdf', documentType: 'notes', type: 'pdf' } });
    });

    test('deleteDocumentChunks handles empty, paged, scoped, and failed deletes', async () => {
        const service = makeService();
        await expect(service.deleteDocumentChunks('D')).resolves.toMatchObject({ success: true, deletedCount: 0 });
        service.client.scroll
            .mockResolvedValueOnce({ points: [{ id: '1' }], next_page_offset: 'next' })
            .mockResolvedValueOnce({ points: [{ id: '2' }], next_page_offset: null });
        await expect(service.deleteDocumentChunks('D', 'C')).resolves.toMatchObject({ success: true, deletedCount: 2 });
        expect(service.client.scroll.mock.calls[1][1].filter.must).toContainEqual({ key: 'courseId', match: { value: 'C' } });
        service.client.scroll.mockRejectedValueOnce(new Error('scroll failed'));
        await expect(service.deleteDocumentChunks('D')).resolves.toEqual({ success: false, error: 'scroll failed' });
    });

    test('collection maintenance returns stats and delete outcomes', async () => {
        const service = makeService();
        await expect(service.getCollectionStats()).resolves.toEqual({ name: service.collectionName, vectorSize: 3, distance: 'Cosine', pointsCount: 4, segmentsCount: 2, status: 'green' });
        await expect(service.deleteCollection()).resolves.toMatchObject({ success: true, deletedCount: 'all' });
        service.client.getCollections.mockResolvedValueOnce({ collections: [] });
        await expect(service.deleteCollection()).resolves.toMatchObject({ success: true, deletedCount: 0 });
        service.client.getCollections.mockRejectedValueOnce(new Error('offline'));
        await expect(service.deleteCollection()).resolves.toEqual({ success: false, error: 'offline' });
    });

    test('status and LLM connection report initialized and failure states', async () => {
        const service = makeService({ llmConfig: { provider: 'custom' } });
        expect(service.getStatus()).toMatchObject({ qdrant: { isConnected: true }, embeddings: { isInitialized: true, provider: 'custom' }, chunking: { isInitialized: true } });
        await expect(service.testLLMConnection()).resolves.toBe(true);
        service.embeddings.embed.mockRejectedValueOnce(new Error('down'));
        await expect(service.testLLMConnection()).resolves.toBe(false);
    });
});

describe('QdrantService coverage: stub embeddings, probe warnings, key failures, filter defaults, loop breaks, lazy init', () => {
    const originalEnv = process.env;

    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'warn').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });
    beforeEach(() => {
        process.env = { ...originalEnv };
        delete process.env.BIOCBOT_TEST_LLM_STUB;
        delete process.env.LLM_EMBEDDING_MODEL;
        config.getVectorDBConfig.mockReturnValue({ host: 'localhost', port: 6333 });
        config.getLLMConfig.mockReturnValue({ provider: 'openai', defaultModel: 'model' });
    });
    afterAll(() => {
        process.env = originalEnv;
        jest.restoreAllMocks();
    });

    test('initialize uses the local embeddings stub under BIOCBOT_TEST_LLM_STUB=1 (no provider creation)', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        process.env.LLM_EMBEDDING_MODEL = 'text-embedding-3-small';
        const client = {
            getCollections: jest.fn(async () => ({ collections: [{ name: 'biocbot_documents_stub' }] })),
            getCollection: jest.fn(async () => ({ config: { params: { vectors: { size: 1536 } } } })),
        };
        QdrantClient.mockImplementation(() => client);
        ChunkingModule.mockImplementation(() => ({ getDefaultStrategyName: () => 'recursiveCharacter' }));
        mockCreateEmbeddings.mockClear();
        const service = new QdrantService();
        await service.initialize();
        expect(mockCreateEmbeddings).not.toHaveBeenCalled();
        // The stub produces deterministic vectors of the configured size.
        const probe = await service.embed('hello');
        expect(probe[0]).toHaveLength(1536);
    });

    test('initialize warns on the [1] fallback probe and on an unexpected probe shape', async () => {
        const client = {
            getCollections: jest.fn(async () => ({ collections: [{ name: 'biocbot_documents' }] })),
            getCollection: jest.fn(async () => ({ config: { params: { vectors: { size: 768 } } } })),
        };
        QdrantClient.mockImplementation(() => client);
        ChunkingModule.mockImplementation(() => ({ getDefaultStrategyName: () => 'recursiveCharacter' }));

        // [1] fallback (nested, then flattened) — indicates silent embedding failure.
        await new QdrantService({ embeddings: { embed: jest.fn(async () => [[1]]) } }).initialize();
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('fallback value [1]'));

        // Empty result — unexpected shape, still continues on model-based size.
        await new QdrantService({ embeddings: { embed: jest.fn(async () => []) } }).initialize();
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('unexpected result'));
    });

    test('generateEmbeddings warns (but keeps) a vector whose size mismatches the collection', async () => {
        const service = makeService({ embeddings: { embed: jest.fn(async () => [[1, 2]]) } });
        await expect(service.generateEmbeddings(['text'])).resolves.toEqual([[1, 2]]);
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("doesn't match expected size"));
    });

    test('storeChunks rethrows an upsert failure', async () => {
        const service = makeService({ client: { upsert: jest.fn(async () => { throw new Error('qdrant write failed'); }) } });
        await expect(service.storeChunks({ documentId: 'D', fileName: 'f' }, ['hello'], [[1, 2, 3]]))
            .rejects.toThrow('qdrant write failed');
    });

    test('generateQueryVector uses the first vector of an unexpected batch and warns', async () => {
        const service = makeService({ embeddings: { embed: jest.fn(async () => [[1, 2, 3], [4, 5, 6]]) } });
        await expect(service.generateQueryVector('q')).resolves.toEqual([1, 2, 3]);
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('vectors for a single query'));
    });

    test('generateQueryVector warns when the query vector size mismatches the collection', async () => {
        const service = makeService({ embeddings: { embed: jest.fn(async () => [[1, 2]]) } });
        await expect(service.generateQueryVector('q')).resolves.toEqual([1, 2]);
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('does not match expected collection size'));
    });

    test('embed maps provider key failures to LlmKeyError and notifies the scope handler', async () => {
        const keyError = Object.assign(new Error('Incorrect API key'), { status: 401 });
        const onProviderKeyFailure = jest.fn(async () => {});
        const service = makeService({
            embeddings: { embed: jest.fn(async () => { throw keyError; }) },
            onProviderKeyFailure,
        });
        service.onProviderKeyFailure = onProviderKeyFailure;
        await expect(service.embed('q')).rejects.toMatchObject({ code: 'LLM_KEY_INVALID' });
        expect(onProviderKeyFailure).toHaveBeenCalledWith('invalid', keyError);

        // A throwing handler is swallowed; the LlmKeyError still propagates.
        service.onProviderKeyFailure = jest.fn(async () => { throw new Error('handler broke'); });
        await expect(service.embed('q')).rejects.toMatchObject({ code: 'LLM_KEY_INVALID' });
    });

    test('searchDocuments initializes the filter for each filter type used alone', async () => {
        const filterFor = async (filters) => {
            const service = makeService();
            await service.searchDocuments('q', filters);
            return service.client.search.mock.calls[0][1].filter;
        };
        expect(await filterFor({ lectureName: 'U1' })).toEqual({ must: [{ key: 'lectureName', match: { value: 'U1' } }] });
        expect(await filterFor({ lectureNames: ['U1', 'U2'] })).toEqual({ must: [{ key: 'lectureName', match: { any: ['U1', 'U2'] } }] });
        expect(await filterFor({ excludeAdditionalMaterials: true })).toMatchObject({ must: [], must_not: expect.any(Array) });
        expect((await filterFor({ additionalMaterialsOnly: true })).must[0].should).toHaveLength(2);
    });

    test('searchDocuments and getDocumentChunks rethrow client failures', async () => {
        const searchFail = makeService({ client: { search: jest.fn(async () => { throw new Error('search down'); }) } });
        await expect(searchFail.searchDocuments('q', {})).rejects.toThrow('search down');
        const scrollFail = makeService({ client: { scroll: jest.fn(async () => { throw new Error('scroll down'); }) } });
        await expect(scrollFail.getDocumentChunks('D')).rejects.toThrow('scroll down');
    });

    test('deleteDocumentChunks stops on a later empty page and on the safety break', async () => {
        // First page has points and promises more; second page is empty → break (not the "no chunks" return).
        const service = makeService();
        service.client.scroll
            .mockResolvedValueOnce({ points: [{ id: '1' }], next_page_offset: 'more' })
            .mockResolvedValueOnce({ points: [], next_page_offset: 'more' });
        await expect(service.deleteDocumentChunks('D')).resolves.toMatchObject({ success: true, deletedCount: 1 });

        // A scroll that always reports more pages trips the MAX_LOOPS safety break.
        const runaway = makeService();
        runaway.client.scroll.mockResolvedValue({ points: [{ id: 'x' }], next_page_offset: 'forever' });
        const result = await runaway.deleteDocumentChunks('D');
        expect(result.success).toBe(true);
        expect(result.deletedCount).toBe(100); // one point per loop × MAX_LOOPS
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('Safety break'));
    });

    test('stats, collection deletion, and the LLM probe lazily initialize when needed', async () => {
        const stats = makeService();
        const statsClient = stats.client;
        stats.client = null;
        stats.initialize = jest.fn(async () => { stats.client = statsClient; });
        await expect(stats.getCollectionStats()).resolves.toMatchObject({ pointsCount: 4 });
        expect(stats.initialize).toHaveBeenCalled();

        const del = makeService();
        const delClient = del.client;
        del.client = null;
        del.initialize = jest.fn(async () => { del.client = delClient; });
        await expect(del.deleteCollection()).resolves.toMatchObject({ success: true });

        const probe = makeService();
        const probeEmbeddings = probe.embeddings;
        probe.embeddings = null;
        probe.initialize = jest.fn(async () => { probe.embeddings = probeEmbeddings; });
        await expect(probe.testLLMConnection()).resolves.toBe(true);

        // getCollectionStats rethrows an underlying failure.
        const failing = makeService({ client: { getCollection: jest.fn(async () => { throw new Error('stats down'); }) } });
        await expect(failing.getCollectionStats()).rejects.toThrow('stats down');
    });
});
