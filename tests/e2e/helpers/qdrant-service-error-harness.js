// @ts-check
/**
 * Direct service harness for src/services/qdrantService.js.
 *
 * The production service is required normally, but its network/toolkit
 * boundary modules are replaced with deterministic fakes before require().
 * This keeps the real service logic under V8 coverage without a live Qdrant
 * instance or embedding provider.
 */

const Module = require('module');
const express = require('express');
const path = require('path');

const servicePath = path.resolve(__dirname, '../../../src/services/qdrantService.js');
const moduleWithLoad = /** @type {any} */ (Module);
const originalLoad = moduleWithLoad._load;

const baseVector = [0.1, 0.2, 0.3];

/** @type {any} */
let state;

function resetState(overrides = {}) {
    state = {
        clientConstructorThrows: false,
        getCollectionsThrows: false,
        collectionExists: true,
        existingVectorSize: 3,
        vectorDBConfigThrows: false,
        llmConfigThrows: false,
        embeddingCreateThrows: false,
        embeddingReturn: [baseVector],
        embeddingThrows: false,
        chunkResponses: [],
        chunkStrategy: 'recursiveCharacter',
        createCollectionThrows: false,
        deleteCollectionThrows: false,
        upsertThrows: false,
        searchThrows: false,
        searchResults: [],
        scrollResponses: [],
        deleteThrows: false,
        calls: {
            createCollection: [],
            deleteCollection: [],
            upsert: [],
            search: [],
            scroll: [],
            delete: [],
        },
        ...overrides,
    };
}

class FakeQdrantClient {
    constructor(options) {
        if (state.clientConstructorThrows) throw new Error('harness client constructor failure');
        this.options = options;
    }

    async getCollections() {
        if (state.getCollectionsThrows) throw new Error('harness getCollections failure');
        return {
            collections: state.collectionExists ? [{ name: 'biocbot_documents' }] : [],
        };
    }

    async getCollection(name) {
        return {
            name,
            config: { params: { vectors: { size: state.existingVectorSize, distance: 'Cosine' } } },
            points_count: 7,
            segments_count: 2,
            status: 'green',
        };
    }

    async createCollection(name, body) {
        state.calls.createCollection.push({ name, body });
        if (state.createCollectionThrows) throw new Error('harness createCollection failure');
    }

    async deleteCollection(name) {
        state.calls.deleteCollection.push(name);
        if (state.deleteCollectionThrows) throw new Error('harness deleteCollection failure');
    }

    async upsert(name, body) {
        state.calls.upsert.push({ name, body });
        if (state.upsertThrows) throw new Error('harness collection not found during upsert');
    }

    async search(name, params) {
        state.calls.search.push({ name, params });
        if (state.searchThrows) throw new Error('harness collection not found during search');
        return state.searchResults;
    }

    async scroll(name, params) {
        state.calls.scroll.push({ name, params });
        return state.scrollResponses.shift() || { points: [], next_page_offset: null };
    }

    async delete(name, body) {
        state.calls.delete.push({ name, body });
        if (state.deleteThrows) throw new Error('harness delete failure');
    }
}

class FakeChunkingModule {
    constructor(config) {
        this.config = config;
    }

    getDefaultStrategyName() {
        return state.chunkStrategy;
    }

    async chunkDocuments() {
        return state.chunkResponses.shift() || {
            chunks: [{ text: 'default chunk text', metadata: { chunkNumber: 0 } }],
            strategy: state.chunkStrategy,
        };
    }
}

class FakeConsoleLogger {
    constructor(name) {
        this.name = name;
    }
}

function fakeEmbeddings() {
    return {
        async embed() {
            if (state.embeddingThrows) throw new Error('harness embedding failure');
            return state.embeddingReturn;
        },
    };
}

moduleWithLoad._load = function patchedLoad(request, parent, isMain) {
    if (request === '@qdrant/js-client-rest') {
        return { QdrantClient: FakeQdrantClient };
    }
    if (request === 'ubc-genai-toolkit-embeddings') {
        return {
            EmbeddingsModule: {
                create: async () => {
                    if (state.embeddingCreateThrows) {
                        throw new Error('harness embedding create failure');
                    }
                    return fakeEmbeddings();
                },
            },
        };
    }
    if (request === 'ubc-genai-toolkit-chunking') {
        return { ChunkingModule: FakeChunkingModule };
    }
    if (request === 'ubc-genai-toolkit-core') {
        return { ConsoleLogger: FakeConsoleLogger };
    }
    if (parent && parent.filename === servicePath && request === './config') {
        return {
            getVectorDBConfig() {
                if (state.vectorDBConfigThrows) throw new Error('harness vector config failure');
                return { host: '127.0.0.1', port: 6333 };
            },
            getLLMConfig() {
                if (state.llmConfigThrows) throw new Error('harness llm config failure');
                return {
                    provider: 'harness-provider',
                    endpoint: 'http://llm.example.test',
                    apiKey: '',
                    defaultModel: 'harness-model',
                };
            },
        };
    }
    if (parent && parent.filename === servicePath && request === './llm') {
        return {
            getProviderName: () => 'harness-provider',
            isReady: () => true,
        };
    }
    return originalLoad.apply(this, arguments);
};

function loadService() {
    delete require.cache[servicePath];
    return require(servicePath);
}

function readyService(overrides = {}) {
    resetState(overrides);
    const QdrantService = loadService();
    const service = new QdrantService();
    service.client = new FakeQdrantClient({});
    service.embeddings = fakeEmbeddings();
    service.chunker = new FakeChunkingModule({});
    service.vectorSize = overrides.vectorSize || 3;
    return service;
}

async function withEnv(env, fn) {
    const old = {};
    for (const key of Object.keys(env)) {
        old[key] = process.env[key];
        if (env[key] === undefined) delete process.env[key];
        else process.env[key] = env[key];
    }
    try {
        return await fn();
    } finally {
        for (const key of Object.keys(env)) {
            if (old[key] === undefined) delete process.env[key];
            else process.env[key] = old[key];
        }
    }
}

const docData = {
    courseId: 'BIOC-H',
    lectureName: 'Unit 1',
    documentId: 'doc-harness',
    content: 'Long enough document content for deterministic chunking.',
    fileName: 'doc.txt',
    mimeType: 'text/plain',
};

async function initializeBranches() {
    const results = {};

    async function initOne(name, env, overrides) {
        resetState({ existingVectorSize: overrides.expectedVectorSize || 3, ...overrides });
        const QdrantService = loadService();
        const service = new QdrantService();
        return withEnv(env, async () => {
            await service.initialize();
            results[name] = {
                vectorSize: service.vectorSize,
                created: state.calls.createCollection.length,
            };
        });
    }

    await initOne('ada', {
        QDRANT_URL: undefined,
        QDRANT_API_KEY: undefined,
        CHUNK_SIZE: undefined,
        CHUNK_OVERLAP: undefined,
        CHUNK_MIN: undefined,
        LLM_EMBEDDING_MODEL: 'text-embedding-ada-002',
    }, {
        expectedVectorSize: 1536,
        existingVectorSize: 1536,
        embeddingReturn: [[...Array(1536)].map(() => 0.1)],
    });

    await initOne('nomicFallbackEmbedding', {
        LLM_EMBEDDING_MODEL: 'nomic-embed-text',
    }, {
        expectedVectorSize: 768,
        existingVectorSize: 768,
        embeddingReturn: [[1]],
    });

    await initOne('envFallbackUnexpectedTestEmbedding', {
        LLM_EMBEDDING_MODEL: 'unknown-model',
        QDRANT_VECTOR_SIZE: '5',
    }, {
        expectedVectorSize: 5,
        existingVectorSize: 5,
        embeddingReturn: null,
    });

    const errors = {};
    for (const [name, overrides] of Object.entries({
        clientConstructor: { clientConstructorThrows: true },
        getCollections: { getCollectionsThrows: true },
        vectorConfig: { vectorDBConfigThrows: true },
        llmConfig: { llmConfigThrows: true },
        embeddingCreate: { embeddingCreateThrows: true },
        embeddingTest: { embeddingThrows: true },
    })) {
        resetState(overrides);
        const QdrantService = loadService();
        const service = new QdrantService();
        try {
            await service.initialize();
            errors[name] = null;
        } catch (error) {
            errors[name] = error.message;
        }
    }

    return { results, errors };
}

async function ensureMismatch() {
    const service = readyService({ existingVectorSize: 2, vectorSize: 3 });
    await service.ensureCollectionExists();
    return {
        deleted: state.calls.deleteCollection.length,
        created: state.calls.createCollection.length,
        createSize: state.calls.createCollection[0].body.vectors.size,
    };
}

async function processBranches() {
    const outputs = {};

    let service = readyService({});
    service.chunker = null;
    outputs.noChunker = await service.processAndStoreDocument(docData);

    service = readyService({
        chunkResponses: [{ chunks: [], strategy: 'empty' }],
    });
    outputs.noChunks = await service.processAndStoreDocument(docData);

    service = readyService({
        chunkResponses: [{ chunks: [{ text: '   ', metadata: { chunkNumber: 0 } }] }],
    });
    outputs.noEmbeddings = await service.processAndStoreDocument(docData);

    service = readyService({
        embeddingThrows: true,
        chunkResponses: [{ chunks: [{ text: 'valid chunk text', metadata: { chunkNumber: 0 } }] }],
    });
    outputs.embeddingFailure = await service.processAndStoreDocument(docData);

    service = readyService({
        upsertThrows: true,
        chunkResponses: [{ chunks: [{ text: 'valid chunk text', metadata: { chunkNumber: 0 } }] }],
        embeddingReturn: [[0.1, 0.2, 0.3]],
    });
    outputs.upsertMissingCollection = await service.processAndStoreDocument(docData);

    service = readyService({
        chunkStrategy: 'fallback-strategy',
        chunkResponses: [{
            chunks: [{ text: 'valid chunk text', metadata: { chunkNumber: 0 } }],
        }],
        embeddingReturn: [[0.1, 0.2, 0.3]],
    });
    outputs.strategyFallback = await service.processAndStoreDocument({
        ...docData,
        documentType: undefined,
        type: undefined,
    });

    return outputs;
}

async function embeddingBranches() {
    const outputs = {};

    let service = readyService({});
    try {
        await service.generateEmbeddings(null);
    } catch (error) {
        outputs.invalidChunks = error.message;
    }

    service = readyService({ embeddingReturn: null });
    try {
        await service.generateEmbeddings(['valid chunk text']);
    } catch (error) {
        outputs.invalidEmbedding = error.message;
    }

    service = readyService({ embeddingReturn: [42] });
    try {
        await service.generateEmbeddings(['valid chunk text']);
    } catch (error) {
        outputs.vectorNotArray = error.message;
    }

    service = readyService({ embeddingReturn: [[0.1, 0.2]], vectorSize: 3 });
    outputs.sizeMismatch = await service.generateEmbeddings(['valid chunk text']);

    return outputs;
}

async function searchBranches() {
    const calls = {};

    let service = readyService({ embeddingReturn: [0.1, 0.2, 0.3], searchResults: [] });
    const empty = await service.searchDocuments('empty', {}, 4);
    calls.emptyNoFilters = state.calls.search[0].params;

    service = readyService({
        embeddingReturn: [[0.1, 0.2, 0.3]],
        searchResults: [{
            id: 'pt-1',
            score: 0.8,
            payload: {
                courseId: 'BIOC-H',
                lectureName: 'Unit 1',
                documentId: 'doc-1',
                fileName: 'doc.txt',
                documentType: 'notes',
                type: 'pdf',
                chunkText: 'chunk',
                chunkIndex: 0,
                timestamp: 'now',
            },
        }],
    });
    const withCourseAndLecture = await service.searchDocuments('cells', {
        courseId: 'BIOC-H',
        lectureName: 'Unit 1',
    }, 2);
    calls.courseAndLecture = state.calls.search[0].params;

    service = readyService({ embeddingReturn: [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]] });
    await service.searchDocuments('lecture only', { lectureName: 'Unit 2' }, 3);
    calls.lectureOnly = state.calls.search[0].params;

    service = readyService({ embeddingReturn: { embedding: [0.1, 0.2, 0.3] } });
    await service.searchDocuments('lecture names only', { lectureNames: ['Unit 1', 'Unit 3'] }, 3);
    calls.lectureNamesOnly = state.calls.search[0].params;

    service = readyService({ embeddingReturn: { data: [[0.1, 0.2, 0.3]] } });
    await service.searchDocuments('course lecture names', {
        courseId: 'BIOC-H',
        lectureNames: ['Unit 1'],
    }, 3);
    calls.courseAndLectureNames = state.calls.search[0].params;

    service = readyService({ embeddingReturn: [0.1, 0.2, 0.3] });
    await service.searchDocuments('course pool', {
        courseId: ['BIOC-202', 'BIOC-302'],
    }, 8);
    calls.courseIdPool = state.calls.search[0].params;

    service = readyService({ embeddingReturn: [0.1, 0.2], vectorSize: 3 });
    await service.searchDocuments('size mismatch', { lectureNames: [] }, 1);
    calls.emptyLectureNames = state.calls.search[0].params;

    service = readyService({ collectionExists: false, embeddingReturn: [0.1, 0.2, 0.3] });
    await service.searchDocuments('missing collection recreated', {}, 1);
    calls.createBeforeSearch = state.calls.createCollection.length;

    service = readyService({ searchThrows: true, embeddingReturn: [0.1, 0.2, 0.3] });
    try {
        await service.searchDocuments('missing collection throws', {}, 1);
    } catch (error) {
        calls.searchMissingCollectionError = error.message;
    }

    service = readyService({ embeddingReturn: { data: [] } });
    try {
        await service.searchDocuments('bad shape', {}, 1);
    } catch (error) {
        calls.invalidShape = error.message;
    }

    return { empty, withCourseAndLecture, calls };
}

async function scrollCloneDeleteBranches() {
    const outputs = {};

    let service = readyService({
        scrollResponses: [
            { points: [{ payload: { chunkIndex: 2, chunkText: 'second' } }], next_page_offset: 'next' },
            { points: [{ payload: { chunkIndex: 1, chunkText: 'first' } }], next_page_offset: 'done' },
            { next_page_offset: null },
        ],
    });
    outputs.chunks = await service.getDocumentChunks('doc-1');

    service = readyService({});
    outputs.cloneMissing = await service.cloneDocumentChunks({
        sourceDocumentId: '',
        targetDocumentId: 'target',
        targetCourseId: 'BIOC-H',
        targetLectureName: 'Unit 1',
    });

    service = readyService({ scrollResponses: [{ points: [], next_page_offset: null }] });
    outputs.cloneEmpty = await service.cloneDocumentChunks({
        sourceDocumentId: 'source',
        targetDocumentId: 'target',
        targetCourseId: 'BIOC-H',
        targetLectureName: 'Unit 1',
    });

    service = readyService({
        scrollResponses: [{
            points: [{ id: 'source-point', vector: [0.1, 0.2, 0.3] }],
            next_page_offset: null,
        }],
    });
    outputs.cloneFallbackPayload = await service.cloneDocumentChunks({
        sourceDocumentId: 'source',
        targetDocumentId: 'target',
        targetCourseId: 'BIOC-H',
        targetLectureName: 'Unit 1',
        targetFileName: 'target.txt',
        targetMimeType: 'text/plain',
    });
    outputs.clonedPayload = state.calls.upsert[0].body.points[0].payload;

    service = readyService({ scrollResponses: [{ points: [], next_page_offset: null }] });
    outputs.deleteEmpty = await service.deleteDocumentChunks('doc-1');

    service = readyService({
        scrollResponses: [
            { points: [{ id: 'a' }], next_page_offset: 'next' },
            { points: [{ id: 'b' }, { id: 'c' }], next_page_offset: null },
        ],
    });
    outputs.deleteWithCourse = await service.deleteDocumentChunks('doc-1', 'BIOC-H');
    outputs.deleteFilter = state.calls.scroll[0].params.filter;

    service = readyService({ deleteThrows: true, scrollResponses: [{ points: [{ id: 'a' }], next_page_offset: null }] });
    outputs.deleteFailure = await service.deleteDocumentChunks('doc-1');

    service = readyService({});
    outputs.statusWithChunker = service.getStatus().chunking;

    service = readyService({});
    service.chunker = null;
    outputs.statusWithoutChunker = service.getStatus().chunking;

    service = readyService({});
    outputs.llmTrue = await service.testLLMConnection();

    service = readyService({ embeddingReturn: null });
    outputs.llmFalse = await service.testLLMConnection();

    return outputs;
}

async function runCase(name) {
    switch (name) {
        case 'initialize-branches':
            return initializeBranches();
        case 'ensure-mismatch':
            return ensureMismatch();
        case 'process-branches':
            return processBranches();
        case 'embedding-branches':
            return embeddingBranches();
        case 'search-branches':
            return searchBranches();
        case 'scroll-clone-delete-branches':
            return scrollCloneDeleteBranches();
        default:
            throw new Error(`Unknown qdrant harness case: ${name}`);
    }
}

resetState();

const app = express();
app.use(express.json());

app.get('/__ping', (_req, res) => res.json({ ok: true }));

app.post('/__case/:name', async (req, res) => {
    try {
        res.json({ ok: true, result: await runCase(req.params.name) });
    } catch (error) {
        res.status(500).json({ ok: false, error: error.message, stack: error.stack });
    }
});

const port = Number(process.env.QDRANT_SERVICE_HARNESS_PORT || 0);
const server = app.listen(port, '127.0.0.1', () => {
    const address = server.address();
    console.log(`[qdrant-service-error-harness] listening on ${typeof address === 'object' && address ? address.port : port}`);
});

process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
});
