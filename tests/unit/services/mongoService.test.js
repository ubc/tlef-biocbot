const mockClient = {
    connect: jest.fn(),
    db: jest.fn(),
    close: jest.fn(),
};

jest.mock('mongodb', () => ({ MongoClient: jest.fn(() => mockClient) }));

const { MongoClient } = require('mongodb');
const MongoService = require('../../../src/services/mongoService');

function fakeDb({ names = [], stats = {}, failures = {} } = {}) {
    return {
        listCollections: jest.fn(filter => ({
            toArray: jest.fn(async () => filter && filter.name
                ? (names.includes(filter.name) ? [{ name: filter.name }] : [])
                : names.map(name => ({ name }))),
        })),
        collection: jest.fn(name => ({
            stats: jest.fn(async () => {
                if (failures[name]) throw new Error(failures[name]);
                return stats[name] || {};
            }),
        })),
        dropCollection: jest.fn(async name => {
            if (failures[`drop:${name}`]) throw new Error(failures[`drop:${name}`]);
        }),
    };
}

describe('MongoService with mocked MongoClient', () => {
    const originalEnv = process.env;
    beforeAll(() => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });
    beforeEach(() => {
        process.env = { ...originalEnv };
        mockClient.connect.mockReset().mockResolvedValue(undefined);
        mockClient.db.mockReset();
        mockClient.close.mockReset().mockResolvedValue(undefined);
        MongoClient.mockClear();
    });
    afterAll(() => {
        process.env = originalEnv;
        jest.restoreAllMocks();
    });

    test('initialize uses configured connection values', async () => {
        process.env.MONGODB_URI = 'mongodb://mock-host';
        process.env.MONGODB_DB = 'mock-db';
        const db = fakeDb();
        mockClient.db.mockReturnValueOnce(db);
        const service = new MongoService();
        await service.initialize();
        expect(MongoClient).toHaveBeenCalledWith('mongodb://mock-host');
        expect(mockClient.db).toHaveBeenCalledWith('mock-db');
        expect(service.db).toBe(db);
    });

    test('initialize propagates mocked connection failures', async () => {
        mockClient.connect.mockRejectedValueOnce(new Error('mock connection failed'));
        await expect(new MongoService().initialize()).rejects.toThrow('mock connection failed');
    });

    test('deleteAllCollections reports successful and failed drops', async () => {
        const service = new MongoService();
        service.db = fakeDb({ names: ['courses', 'documents'], stats: { courses: { count: 2 }, documents: { count: 3 } }, failures: { 'drop:documents': 'locked' } });
        const result = await service.deleteAllCollections();
        expect(result).toMatchObject({ success: true, totalDeleted: 2 });
        expect(result.results.courses).toEqual({ exists: true, deleted: 2, success: true });
        expect(result.results.documents).toMatchObject({ exists: true, deleted: 0, success: false, error: 'locked' });
    });

    test('deleteAllCollections initializes lazily and maps list failures', async () => {
        const service = new MongoService();
        service.initialize = jest.fn(async () => { service.db = { listCollections: () => ({ toArray: async () => { throw new Error('list failed'); } }) }; });
        await expect(service.deleteAllCollections()).resolves.toEqual({ success: false, error: 'list failed' });
        expect(service.initialize).toHaveBeenCalled();
    });

    test('collectionExists returns false on lookup failure', async () => {
        const service = new MongoService();
        service.db = fakeDb({ names: ['courses'] });
        await expect(service.collectionExists('courses')).resolves.toBe(true);
        await expect(service.collectionExists('missing')).resolves.toBe(false);
        service.db.listCollections.mockImplementationOnce(() => ({ toArray: async () => { throw new Error('failed'); } }));
        await expect(service.collectionExists('courses')).resolves.toBe(false);
    });

    test('getDatabaseStats reports existing, absent, and failed collections', async () => {
        const service = new MongoService();
        service.collections = ['courses', 'documents', 'questions'];
        service.db = fakeDb({ names: ['courses', 'documents'], stats: { courses: { count: 4, size: 40 } }, failures: { documents: 'stats failed' } });
        const result = await service.getDatabaseStats();
        expect(result.data.courses).toEqual({ exists: true, documentCount: 4, size: 40 });
        expect(result.data.documents).toMatchObject({ exists: false, error: 'stats failed' });
        expect(result.data.questions).toEqual({ exists: false, documentCount: 0, size: 0 });
    });

    test('close only touches an initialized mocked client', async () => {
        const service = new MongoService();
        await service.close();
        expect(mockClient.close).not.toHaveBeenCalled();
        service.client = mockClient;
        await service.close();
        expect(mockClient.close).toHaveBeenCalled();
    });

    test('getDatabaseStats lazily initializes the connection when none exists yet', async () => {
        const service = new MongoService();
        mockClient.db.mockReturnValue(fakeDb({ names: ['courses'], stats: { courses: { count: 2, size: 10 } } }));
        const result = await service.getDatabaseStats();
        expect(mockClient.connect).toHaveBeenCalledTimes(1);
        expect(result.success).toBe(true);
        expect(result.data.courses).toEqual({ exists: true, documentCount: 2, size: 10 });
    });

    test('getDatabaseStats returns success:false with the message when initialization fails', async () => {
        const service = new MongoService();
        mockClient.connect.mockRejectedValueOnce(new Error('no mongo'));
        expect(await service.getDatabaseStats()).toEqual({ success: false, error: 'no mongo' });
    });
});
