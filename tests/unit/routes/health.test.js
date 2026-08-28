const express = require('express');
const request = require('supertest');
const http = require('http');

const mockGetCollections = jest.fn();
jest.mock('@qdrant/js-client-rest', () => ({
    QdrantClient: jest.fn().mockImplementation(() => ({
        getCollections: (...args) => mockGetCollections(...args)
    }))
}));

const { QdrantClient } = require('@qdrant/js-client-rest');
const config = require('../../../src/services/config');
const { createHealthRouter } = require('../../../src/routes/health');

const ORIGINAL_ENV = { ...process.env };

function makeApp({ rawDb, locals = {}, getRawDb, ...options } = {}) {
    const ping = jest.fn().mockResolvedValue({ ok: 1 });
    if (rawDb === undefined) rawDb = { admin: () => ({ ping }) };
    const app = express();
    Object.assign(app.locals, {
        startupComplete: true,
        db: rawDb,
        passport: {},
        authService: {},
        llmRegistry: {},
        ...locals
    });
    app.use('/api/health', createHealthRouter({
        getRawDb: getRawDb || (() => rawDb),
        ...options
    }));
    return { app, ping };
}

beforeEach(() => {
    process.env = { ...ORIGINAL_ENV };
    for (const key of [
        'BIOCBOT_CHAT_ENCRYPTION_ENABLED', 'BIOCBOT_TEST_LLM_STUB',
        'QDRANT_URL', 'QDRANT_HOST', 'QDRANT_PORT', 'QDRANT_API_KEY',
        'LLM_API_KEY', 'UBC_LLM_PROXY_API_KEY', 'OPENAI_API_KEY'
    ]) delete process.env[key];
    config.isValidated = false;
    mockGetCollections.mockReset().mockResolvedValue({ collections: [] });
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'info').mockImplementation(() => {});
});

afterEach(() => {
    process.env = { ...ORIGINAL_ENV };
    config.isValidated = false;
    jest.restoreAllMocks();
});

describe('public health contract', () => {
    test.each(['/api/health', '/api/health/ready', '/api/health/live'])(
        '%s answers anonymously with only a status and no cache validators',
        async path => {
            const { app } = makeApp();
            const res = await request(app).get(path).set('If-None-Match', '*').expect(200);
            expect(res.body).toEqual({ status: path.endsWith('/live') ? 'ok' : 'healthy' });
            expect(res.headers['cache-control']).toBe('no-store');
            expect(res.headers.etag).toBeUndefined();
            expect(res.headers['set-cookie']).toBeUndefined();
        }
    );

    test('liveness never accesses configuration, the database or sessions', async () => {
        const getRawDb = jest.fn(() => { throw new Error('database unavailable'); });
        const { app } = makeApp({ getRawDb, locals: { startupComplete: false } });
        const middleware = jest.fn((_req, res) => res.sendStatus(500));
        app.use(express.json());
        app.use(middleware);
        const vectorConfig = jest.spyOn(config, 'getVectorDBConfig');
        const res = await request(app).get('/api/health/live')
            .set('Cookie', 'biocbot.sid=stale-cookie')
            .set('Content-Type', 'application/json').send('{').expect(200);
        expect(res.body).toEqual({ status: 'ok' });
        expect(getRawDb).not.toHaveBeenCalled();
        expect(vectorConfig).not.toHaveBeenCalled();
        expect(mockGetCollections).not.toHaveBeenCalled();
        expect(middleware).not.toHaveBeenCalled();
    });

    test('HEAD returns a status without a response body', async () => {
        const { app } = makeApp();
        const res = await request(app).head('/api/health').expect(200);
        expect(res.text).toBeUndefined();
        expect(res.headers['cache-control']).toBe('no-store');
    });

    test.each(['/api/health', '/api/health/ready'])(
        '%s hides arbitrary credentials, internal details and upstream errors on failure',
        async path => {
            mockGetCollections.mockRejectedValue(new Error(
                'mongodb://user:dummy-password@private-db:27017/private-db api-key=custom-secret'
            ));
            const { app } = makeApp();
            const res = await request(app).get(path).expect(503);
            expect(res.body).toEqual({ status: 'unhealthy' });
            expect(res.headers['cache-control']).toBe('no-store');
            expect(console.warn).toHaveBeenCalledWith('[health] Readiness checks failed: qdrant');
        }
    );
});

describe('readiness gates', () => {
    test.each([
        { startupComplete: false },
        { passport: null },
        { authService: null },
        { llmRegistry: null },
        { db: null }
    ])('fails when required initialization is missing: %j', async locals => {
        const { app, ping } = makeApp({ locals });
        const res = await request(app).get('/api/health').expect(503);
        expect(res.body).toEqual({ status: 'unhealthy' });
        expect(ping).not.toHaveBeenCalled();
        expect(mockGetCollections).not.toHaveBeenCalled();
    });

    test('fails when the raw database is absent or its accessor throws', async () => {
        for (const options of [
            { rawDb: null },
            { getRawDb: () => { throw new Error('private-internal-error'); } }
        ]) {
            const { app } = makeApp(options);
            const res = await request(app).get('/api/health').expect(503);
            expect(res.body).toEqual({ status: 'unhealthy' });
        }
    });

    test.each([undefined, null, 'raw'])(
        'enabled encryption fails closed without its wrapper (%s)', async wrapper => {
            process.env.BIOCBOT_CHAT_ENCRYPTION_ENABLED = 'true';
            const { app } = makeApp();
            if (wrapper !== 'raw') app.locals.db = wrapper;
            const res = await request(app).get('/api/health').expect(503);
            expect(res.body).toEqual({ status: 'unhealthy' });
            expect(mockGetCollections).not.toHaveBeenCalled();
        }
    );

    test('pings the raw database when encryption is enabled', async () => {
        process.env.BIOCBOT_CHAT_ENCRYPTION_ENABLED = 'true';
        const { app, ping } = makeApp({ locals: { db: { protected: true } } });
        await request(app).get('/api/health').expect(200);
        expect(ping).toHaveBeenCalledWith({ timeoutMS: 2000 });
    });

    test('an invalid encryption flag returns only an unhealthy status', async () => {
        process.env.BIOCBOT_CHAT_ENCRYPTION_ENABLED = 'typo';
        const { app } = makeApp();
        const res = await request(app).get('/api/health').expect(503);
        expect(res.body).toEqual({ status: 'unhealthy' });
    });

    test('does not let cached success override failed local initialization', async () => {
        const { app } = makeApp();
        await request(app).get('/api/health').expect(200);
        app.locals.startupComplete = false;
        await request(app).get('/api/health/ready').expect(503);
    });

    test.each(['ubc-llm-sandbox', 'ubc-llm-proxy', 'openai'])(
        'does not validate global LLM settings or probe providers (%s)', async provider => {
            process.env.LLM_PROVIDER = provider;
            const getLLMConfig = jest.spyOn(config, 'getLLMConfig');
            const llm = {
                testConnection: jest.fn(),
                getAvailableModels: jest.fn(),
                sendMessage: jest.fn()
            };
            const { app } = makeApp({ locals: { llm } });
            await request(app).get('/api/health').expect(200);
            expect(getLLMConfig).not.toHaveBeenCalled();
            for (const method of Object.values(llm)) expect(method).not.toHaveBeenCalled();
        }
    );
});

describe('dependency probes', () => {
    test('a MongoDB failure is a 503', async () => {
        const { app, ping } = makeApp();
        ping.mockRejectedValue(new Error('connection refused'));
        await request(app).get('/api/health').expect(503);
        expect(console.warn).toHaveBeenCalledWith('[health] Readiness checks failed: mongodb');
    });

    test.each([{ collections: [] }, { collections: [{ name: 'biocbot_documents__provider_model_revision' }] }])(
        'does not require any legacy collection name (%j)', async ({ collections }) => {
            mockGetCollections.mockResolvedValue({ collections });
            const { app } = makeApp();
            await request(app).get('/api/health').expect(200);
        }
    );

    test('reuses a read-only Qdrant client with a real I/O timeout', async () => {
        process.env.QDRANT_URL = 'http://qdrant.example:6333';
        process.env.QDRANT_API_KEY = 'test-key';
        const { app } = makeApp({ cacheTtlMs: 0 });
        await request(app).get('/api/health').expect(200);
        await request(app).get('/api/health/ready').expect(200);
        expect(QdrantClient).toHaveBeenCalledTimes(1);
        expect(QdrantClient).toHaveBeenCalledWith({
            url: 'http://qdrant.example:6333', apiKey: 'test-key',
            timeout: 2000, checkCompatibility: false
        });
        expect(mockGetCollections).toHaveBeenCalledTimes(2);
    });

    test('both endpoints return 503 promptly if dependencies never settle', async () => {
        mockGetCollections.mockImplementation(() => new Promise(() => {}));
        const { app, ping } = makeApp({ probeTimeoutMs: 25 });
        ping.mockImplementation(() => new Promise(() => {}));
        await Promise.all([
            request(app).get('/api/health').expect(503),
            request(app).get('/api/health/ready').expect(503)
        ]);
        expect(ping).toHaveBeenCalledWith({ timeoutMS: 25 });
        expect(mockGetCollections).toHaveBeenCalledTimes(1);
    });

    test('the real Qdrant client aborts a stalled HTTP request', async () => {
        let onClosed;
        const closed = new Promise(resolve => { onClosed = resolve; });
        const upstream = http.createServer((_req, res) => res.on('close', onClosed));
        await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
        process.env.QDRANT_URL = `http://127.0.0.1:${upstream.address().port}`;
        const RealClient = jest.requireActual('@qdrant/js-client-rest').QdrantClient;
        QdrantClient.mockImplementationOnce(options => new RealClient(options));
        const { app } = makeApp({ probeTimeoutMs: 100 });
        let timer;
        try {
            await request(app).get('/api/health').expect(503);
            await Promise.race([
                closed,
                new Promise((_resolve, reject) => {
                    timer = setTimeout(() => reject(new Error('Upstream request was not aborted')), 1000);
                })
            ]);
        } finally {
            clearTimeout(timer);
            upstream.closeAllConnections();
            await new Promise(resolve => upstream.close(resolve));
        }
    });
});

describe('probe caching', () => {
    test('simultaneous requests to either readiness route share one probe', async () => {
        mockGetCollections.mockImplementation(() =>
            new Promise(resolve => setTimeout(() => resolve({ collections: [] }), 20))
        );
        const { app, ping } = makeApp();
        await Promise.all(Array.from({ length: 12 }, (_, i) =>
            request(app).get(i % 2 ? '/api/health' : '/api/health/ready').expect(200)
        ));
        expect(ping).toHaveBeenCalledTimes(1);
        expect(mockGetCollections).toHaveBeenCalledTimes(1);
    });

    test('caches success and failure briefly, then observes outage and recovery', async () => {
        const now = jest.spyOn(Date, 'now').mockReturnValue(1000);
        const { app, ping } = makeApp();
        await request(app).get('/api/health').expect(200);
        ping.mockRejectedValue(new Error('offline'));
        await request(app).get('/api/health/ready').expect(200);
        expect(ping).toHaveBeenCalledTimes(1);
        now.mockReturnValue(6001);
        await request(app).get('/api/health').expect(503);
        ping.mockResolvedValue({ ok: 1 });
        await request(app).get('/api/health/ready').expect(503);
        expect(ping).toHaveBeenCalledTimes(2);
        now.mockReturnValue(11002);
        await request(app).get('/api/health/ready').expect(200);
        expect(ping).toHaveBeenCalledTimes(3);
        expect(console.warn).toHaveBeenCalledTimes(1);
        expect(console.info).toHaveBeenCalledWith('[health] Readiness recovered');
    });
});
