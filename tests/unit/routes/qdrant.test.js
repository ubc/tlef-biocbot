const mockService = {
    client: null,
    collectionName: 'documents',
    initialize: jest.fn(async function initialize() { mockService.client = mockClient; }),
    getCollectionStats: jest.fn(),
    deleteDocumentChunks: jest.fn(),
    deleteCollection: jest.fn(),
};
const mockClient = { scroll: jest.fn() };

jest.mock('../../../src/services/qdrantService', () => jest.fn(() => mockService));
jest.mock('../../../src/models/Course', () => ({
    userHasCourseAccess: jest.fn(),
    checkTAPermission: jest.fn(),
}));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({
    resolveCourseAi: jest.fn(),
    sendLlmKeyError: jest.fn(() => false),
}));

const { memoryDb } = require('../helpers/memory-db');
const { makeRouteApp, request } = require('../helpers/route-app');
const Course = require('../../../src/models/Course');
const { resolveCourseAi } = require('../../../src/routes/llmKeyMiddleware');
const router = require('../../../src/routes/qdrant');

const instructor = { userId: 'i1', role: 'instructor' };
const ta = { userId: 't1', role: 'ta' };
const student = { userId: 's1', role: 'student' };
const admin = { userId: 'a1', role: 'instructor', permissions: { systemAdmin: true } };
const app = options => makeRouteApp(router, options);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});

beforeEach(() => {
    mockService.client = null;
    mockService.initialize.mockClear();
    mockService.getCollectionStats.mockReset().mockResolvedValue({ name: 'documents', pointsCount: 3 });
    mockService.deleteDocumentChunks.mockReset().mockResolvedValue({ success: true, message: 'deleted', deletedCount: 2 });
    mockService.deleteCollection.mockReset().mockResolvedValue({ success: true, message: 'deleted', deletedCount: 'all' });
    mockClient.scroll.mockReset().mockResolvedValue({ points: [], next_page_offset: null });
    Course.userHasCourseAccess.mockReset().mockResolvedValue(true);
    Course.checkTAPermission.mockReset().mockResolvedValue(true);
    resolveCourseAi.mockReset();
});

afterAll(() => jest.restoreAllMocks());

describe('Qdrant route access and status', () => {
    test('status initializes the maintenance service and returns stats', async () => {
        const res = await request(app({})).get('/status');
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ status: 'connected', collection: { pointsCount: 3 } });
        expect(mockService.initialize).toHaveBeenCalled();
    });

    test('status maps initialization failures', async () => {
        mockService.initialize.mockRejectedValueOnce(new Error('offline'));
        const res = await request(app({})).get('/status');
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('offline');
    });

    test('direct operations require authentication and staff role', async () => {
        expect((await request(app({})).post('/search').send({ courseId: 'C1', query: 'ATP' })).status).toBe(401);
        expect((await request(app({ user: student })).post('/search').send({ courseId: 'C1', query: 'ATP' })).status).toBe(403);
    });

    test('existing courses require instructor access or TA permission', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1' }] });
        Course.userHasCourseAccess.mockResolvedValueOnce(false);
        expect((await request(app({ db, user: instructor })).post('/search').send({ courseId: 'C1', query: 'ATP' })).status).toBe(403);
        Course.checkTAPermission.mockResolvedValueOnce(false);
        expect((await request(app({ db, user: ta })).post('/search').send({ courseId: 'C1', query: 'ATP' })).status).toBe(403);
    });
});

describe('document processing and search with mocked AI/vector service', () => {
    test('process-document validates required fields', async () => {
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/process-document').send({ courseId: 'C1' });
        expect(res.status).toBe(400);
    });

    test('process-document delegates to the resolved mocked course vector service', async () => {
        const qdrant = { processAndStoreDocument: jest.fn(async () => ({ success: true, message: 'stored', chunksProcessed: 2, chunksStored: 2 })) };
        resolveCourseAi.mockResolvedValueOnce({ qdrant });
        const payload = { courseId: 'C1', lectureName: 'Unit 1', documentId: 'd1', content: 'ATP content', fileName: 'notes.txt' };
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/process-document').send(payload);
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ chunksStored: 2, documentId: 'd1' });
        expect(qdrant.processAndStoreDocument).toHaveBeenCalledWith(expect.objectContaining({ ...payload, mimeType: 'text/plain' }));
    });

    test('process-document maps a vector processing failure', async () => {
        resolveCourseAi.mockResolvedValueOnce({ qdrant: { processAndStoreDocument: jest.fn(async () => ({ success: false, error: 'embedding failed' })) } });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/process-document').send({ courseId: 'C1', lectureName: 'U', documentId: 'd', content: 'text', fileName: 'f' });
        expect(res.status).toBe(500);
        expect(res.body.error).toBe('embedding failed');
    });

    test('search validates course and query', async () => {
        expect((await request(app({ user: instructor })).post('/search').send({ query: 'ATP' })).status).toBe(400);
        expect((await request(app({ db: memoryDb({ courses: [] }), user: instructor })).post('/search').send({ courseId: 'C1' })).status).toBe(400);
    });

    test('search delegates with scoped filters and limit', async () => {
        const qdrant = { searchDocuments: jest.fn(async () => [{ id: 'p1' }]) };
        resolveCourseAi.mockResolvedValueOnce({ qdrant });
        const res = await request(app({ db: memoryDb({}), user: instructor })).post('/search').send({ query: 'ATP', courseId: 'C1', lectureName: 'Unit 1', limit: 4 });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ totalResults: 1, filters: { courseId: 'C1', lectureName: 'Unit 1' } });
        expect(qdrant.searchDocuments).toHaveBeenCalledWith('ATP', { courseId: 'C1', lectureName: 'Unit 1' }, 4);
    });
});

describe('maintenance operations', () => {
    test('document deletion initializes and reports success or failure', async () => {
        let res = await request(app({ user: instructor })).delete('/document/d1');
        expect(res.status).toBe(200);
        expect(res.body.data).toEqual({ documentId: 'd1', deletedCount: 2 });
        mockService.client = mockClient;
        mockService.deleteDocumentChunks.mockResolvedValueOnce({ success: false, error: 'delete failed' });
        res = await request(app({ user: instructor })).delete('/document/d1');
        expect(res.status).toBe(500);
    });

    test('collection stats require staff and return mocked stats', async () => {
        expect((await request(app({ user: student })).get('/collection-stats')).status).toBe(403);
        const res = await request(app({ user: instructor })).get('/collection-stats');
        expect(res.status).toBe(200);
        expect(res.body.data.pointsCount).toBe(3);
    });

    test('collection deletion is system-admin only', async () => {
        expect((await request(app({ user: instructor })).delete('/collection')).status).toBe(403);
        let res = await request(app({ user: admin })).delete('/collection');
        expect(res.status).toBe(200);
        mockService.client = mockClient;
        mockService.deleteCollection.mockResolvedValueOnce({ success: false, error: 'cannot delete' });
        res = await request(app({ user: admin })).delete('/collection');
        expect(res.status).toBe(500);
    });

    test('cleanup-vectors removes only IDs absent from Mongo', async () => {
        mockService.client = mockClient;
        mockClient.scroll.mockResolvedValueOnce({
            points: [{ payload: { documentId: 'valid' } }, { payload: { documentId: 'orphan' } }],
            next_page_offset: null,
        });
        mockService.deleteDocumentChunks.mockResolvedValueOnce({ success: true, deletedCount: 3 });
        const db = memoryDb({ documents: [{ _id: 'mongo-id', documentId: 'valid', courseId: 'C1' }] });
        const res = await request(app({ db, user: instructor })).post('/cleanup-vectors').send({ courseId: 'C1' });
        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({ validMongoDocs: 2, qdrantDocs: 2, orphanedDocs: 1, deletedChunks: 3, deletedDocIds: ['orphan'] });
        expect(mockService.deleteDocumentChunks).toHaveBeenCalledWith('orphan', 'C1');
    });
});
