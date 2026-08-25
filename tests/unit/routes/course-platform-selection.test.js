/**
 * Instructor-facing platform selection on the course surface: GPT and Sandbox
 * onboarding, provider-specific validation, switching in both directions, and
 * the guarantee that model names never reach an instructor.
 */
const startedMigrations = [];
jest.mock('../../../src/services/providerMigrationRunner', () => ({
    startMigration: jest.fn((db, migrationId) => { startedMigrations.push(migrationId); }),
    resumePendingMigrations: jest.fn(async () => []),
}));
jest.mock('../../../src/services/config', () => ({
    getProviderInfra: jest.fn((provider) => ({
        provider,
        endpoint: provider === 'ubc-llm-sandbox' ? 'https://sandbox.example/v1' : null,
        bootstrapApiKey: undefined,
    })),
    getVectorDBConfig: jest.fn(() => ({ host: 'localhost', port: 6333 })),
    getLLMConfig: jest.fn(() => ({ provider: 'openai' })),
}));
jest.mock('../../../src/services/qdrantService', () => jest.fn().mockImplementation(() => ({
    initialize: jest.fn(async () => {}),
    cloneDocumentChunks: jest.fn(async () => ({ success: true, clonedCount: 1 })),
    deleteDocumentChunks: jest.fn(async () => ({ success: true, deletedCount: 1 })),
})));
jest.mock('../../../src/services/gridfs', () => ({ copyFile: jest.fn(async () => 'copied') }));
jest.mock('../../../src/routes/llmKeyMiddleware', () => ({ resolveCourseAi: jest.fn() }));

const mockValidateProviderKey = jest.fn();
jest.mock('../../../src/services/llmKeyStore', () => {
    const actual = jest.requireActual('../../../src/services/llmKeyStore');
    return { ...actual, validateProviderKey: (...args) => mockValidateProviderKey(...args) };
});

const adminModelSettings = require('../../../src/services/adminModelSettings');
const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');
const coursesRouter = require('../../../src/routes/courses');
const onboardingRouter = require('../../../src/routes/onboarding');
const { makeRouteApp, request } = require('../helpers/route-app');
const { memoryDb } = require('../helpers/memory-db');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';
const PROXY = 'ubc-llm-proxy';
const instructor = { userId: 'i1', role: 'instructor' };

const courses = (opts) => makeRouteApp(coursesRouter, opts);
const onboarding = (opts) => makeRouteApp(onboardingRouter, opts);

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());
beforeEach(() => {
    startedMigrations.length = 0;
    adminModelSettings.invalidateCache();
    mockValidateProviderKey.mockReset().mockResolvedValue({ ok: true, status: 'valid', provider: OPENAI });
});

describe('onboarding: choosing a platform then entering its key', () => {
    test('GPT onboarding stores the OpenAI credential and activates GPT', async () => {
        const db = memoryDb({});
        const res = await request(onboarding({ db, user: instructor })).post('/').send({
            courseId: 'C1', courseName: 'BIOC 202', apiKey: 'sk-gpt-key', llmProvider: OPENAI,
            courseStructure: { weeks: 1, lecturesPerWeek: 1 },
        });

        expect(res.status).toBe(200);
        expect(res.body.data.llmProvider).toBe(OPENAI);
        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({
            provider: OPENAI, apiKey: 'sk-gpt-key', embeddingModel: 'text-embedding-3-small',
        }));

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(OPENAI);
        expect(course.llmCredentials[OPENAI].provider).toBe(OPENAI);
    });

    test('Sandbox onboarding validates against the Sandbox endpoint and Qwen', async () => {
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });
        const db = memoryDb({});

        const res = await request(onboarding({ db, user: instructor })).post('/').send({
            courseId: 'C1', courseName: 'BIOC 202', apiKey: 'sbx-key', llmProvider: SANDBOX,
            courseStructure: { weeks: 1, lecturesPerWeek: 1 },
        });

        expect(res.status).toBe(200);
        expect(res.body.data.llmProvider).toBe(SANDBOX);
        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({
            provider: SANDBOX,
            apiKey: 'sbx-key',
            chatModel: 'qwen3.6-35b-a3b',
            embeddingModel: 'qwen3-embedding-0.6b',
            endpoint: 'https://sandbox.example/v1',
        }));

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(SANDBOX);
        // A Sandbox key never lands in the legacy OpenAI field.
        expect(course.llmApiKey).toBeUndefined();
    });

    test('omitting the platform defaults to GPT — existing behaviour is preserved', async () => {
        const db = memoryDb({});
        await request(onboarding({ db, user: instructor })).post('/').send({
            courseId: 'C1', courseName: 'BIOC 202', apiKey: 'sk-key',
            courseStructure: { weeks: 1, lecturesPerWeek: 1 },
        });

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(OPENAI);
        expect(course.llmCredentials[OPENAI]).toMatchObject({
            provider: OPENAI,
            status: 'valid',
        });
    });

    test('a rejected Sandbox key names the Sandbox platform', async () => {
        mockValidateProviderKey.mockResolvedValue({
            ok: false, status: 'invalid', message: 'The Sandbox API key for this AI surface is invalid.', provider: SANDBOX,
        });
        const db = memoryDb({});

        const res = await request(onboarding({ db, user: instructor })).post('/').send({
            courseId: 'C1', courseName: 'BIOC 202', apiKey: 'bad', llmProvider: SANDBOX,
            courseStructure: { weeks: 1, lecturesPerWeek: 1 },
        });

        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ code: 'LLM_KEY_INVALID', llmProvider: SANDBOX });
        expect(await db.collection('courses').findOne({ courseId: 'C1' })).toBeNull();
    });

    test('the platform catalog carries help text but no model names', async () => {
        const res = await request(onboarding({ db: memoryDb({}), user: instructor })).get('/platforms');

        expect(res.status).toBe(200);
        expect(res.body.providers).toEqual([
            expect.objectContaining({
                provider: OPENAI,
                label: 'OpenAI Chat GPT',
                helpText: 'Feel free to use your own OpenAI API key, or contact the support team for assistance.',
                supportEmail: 'LT.hub@ubc.ca',
            }),
            expect.objectContaining({
                provider: SANDBOX,
                label: 'UBC On-Premise LLM',
                helpText: 'Contact the LTIC team to request a UBC LLM Sandbox API key.',
            }),
            expect.objectContaining({
                provider: PROXY,
                label: 'UBC LLM Proxy',
            }),
        ]);
        const serialised = JSON.stringify(res.body);
        for (const modelName of ['gpt-4.1-mini', 'qwen3.6-35b-a3b', 'text-embedding-3-small', 'qwen3-embedding-0.6b']) {
            expect(serialised).not.toContain(modelName);
        }
    });
});

describe('course key settings', () => {
    function keyedCourse(active = OPENAI, credentials = { [OPENAI]: 'sk-gpt-key-1111' }) {
        return {
            courseId: 'C1',
            instructorId: 'i1',
            instructors: ['i1'],
            activeLlmProvider: active,
            llmCredentials: Object.fromEntries(
                Object.entries(credentials).map(([provider, key]) => [provider, buildKeySubdocument(key, 'i1', provider)])
            ),
        };
    }

    test('GET reports the platform, per-platform status and the catalog — no models', async () => {
        const db = memoryDb({
            courses: [keyedCourse(SANDBOX, { [OPENAI]: 'sk-gpt-1111', [SANDBOX]: 'sbx-key-2222' })],
        });

        const res = await request(courses({ db, user: instructor })).get('/C1/llm-key');

        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({ llmProvider: SANDBOX, aiAvailable: true });
        expect(res.body.llmKeysByProvider[OPENAI].last4).toBe('1111');
        expect(res.body.llmKeysByProvider[SANDBOX].last4).toBe('2222');
        expect(res.body.providers.map(provider => provider.label)).toEqual([
            'OpenAI Chat GPT', 'UBC On-Premise LLM', 'UBC LLM Proxy'
        ]);

        const serialised = JSON.stringify(res.body);
        expect(serialised).not.toContain('ciphertext');
        expect(serialised).not.toContain('qwen3-embedding');
    });

    test('saving a key for another platform is separate from preparing and switching', async () => {
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });
        const db = memoryDb({
            courses: [keyedCourse(OPENAI)],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'course text' }],
        });

        const res = await request(courses({ db, user: instructor }))
            .put('/C1/llm-key').send({ apiKey: 'sbx-new-key', llmProvider: SANDBOX });

        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Course API key saved');
        expect(startedMigrations).toHaveLength(0);

        const course = await db.collection('courses').findOne({ courseId: 'C1' });
        expect(course.activeLlmProvider).toBe(OPENAI);
        expect(course.pendingLlmProvider).toBeUndefined();

        const prepare = await request(courses({ db, user: instructor }))
            .post('/C1/llm-provider/prepare').send({ llmProvider: SANDBOX });
        expect(prepare.status).toBe(202);
        expect(prepare.body.migration.kind).toBe('prepare');
        expect(startedMigrations).toHaveLength(1);
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider).toBe(OPENAI);
    });

    test('replacing the key for the current platform is immediate', async () => {
        const db = memoryDb({ courses: [keyedCourse(OPENAI)] });

        const res = await request(courses({ db, user: instructor }))
            .put('/C1/llm-key').send({ apiKey: 'sk-replacement', llmProvider: OPENAI });

        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Course API key saved');
        expect(startedMigrations).toEqual([]);
    });

    test('switching back needs no key and prepares missing material in the same call', async () => {
        const db = memoryDb({
            courses: [keyedCourse(SANDBOX, { [OPENAI]: 'sk-gpt-1111', [SANDBOX]: 'sbx-key-2222' })],
            documents: [{ documentId: 'd1', courseId: 'C1', content: 'text' }],
        });

        const res = await request(courses({ db, user: instructor }))
            .post('/C1/llm-provider').send({ llmProvider: OPENAI });

        expect(res.status).toBe(202);
        expect(res.body.migration).toMatchObject({ kind: 'prepare', toProvider: OPENAI, total: 1 });
        expect(startedMigrations).toHaveLength(1);
        // The platform only flips once the job finishes.
        expect((await db.collection('courses').findOne({ courseId: 'C1' })).activeLlmProvider).toBe(SANDBOX);
        expect(mockValidateProviderKey).not.toHaveBeenCalled();
    });

    test('testing the saved key probes the active platform', async () => {
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });
        const db = memoryDb({ courses: [keyedCourse(SANDBOX, { [SANDBOX]: 'sbx-key-2222' })] });

        const res = await request(courses({ db, user: instructor })).post('/C1/llm-key/test').send({});

        expect(res.status).toBe(200);
        expect(res.body.message).toBe('Course API key is valid');
        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({ provider: SANDBOX }));
    });

    test('testing with no saved key reports the course-specific message', async () => {
        const db = memoryDb({ courses: [{ courseId: 'C1', instructorId: 'i1', instructors: ['i1'] }] });
        const res = await request(courses({ db, user: instructor })).post('/C1/llm-key/test').send({});

        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ code: 'LLM_KEY_MISSING', message: 'No API key is saved for this course.' });
    });
});

describe('course transfer carries the platform', () => {
    test('the new course is created on the selected platform', async () => {
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                courseName: 'Source',
                instructorId: 'i1',
                instructors: ['i1'],
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI) },
                lectures: [{ name: 'Unit 1', documents: [] }],
            }],
        });

        const res = await request(courses({ db, user: instructor }))
            .post('/C1/transfer').send({ newCourseName: 'Clone', apiKey: 'sbx-key', llmProvider: SANDBOX });

        expect(res.status).toBe(200);
        const clone = await db.collection('courses').findOne({ courseId: res.body.data.courseId });
        expect(clone.activeLlmProvider).toBe(SANDBOX);
        expect(clone.llmCredentials[SANDBOX].provider).toBe(SANDBOX);
        expect(clone.llmApiKey).toBeUndefined();
    });

    test('an OpenAI course copied to Sandbox automatically prepares missing Sandbox vectors', async () => {
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                courseName: 'Source',
                instructorId: 'i1',
                instructors: ['i1'],
                activeLlmProvider: OPENAI,
                llmCredentials: { [OPENAI]: buildKeySubdocument('sk-gpt-key', 'i1', OPENAI) },
                lectures: [{ name: 'Unit 1', documents: [] }],
            }],
            documents: [{
                documentId: 'd1',
                courseId: 'C1',
                lectureName: 'Unit 1',
                contentType: 'text',
                content: 'ATP synthase uses a proton gradient.',
                filename: 'atp.txt',
                originalName: 'atp.txt',
                mimeType: 'text/plain',
                status: 'uploaded',
            }],
        });

        const res = await request(courses({ db, user: instructor }))
            .post('/C1/transfer').send({
                newCourseName: 'Sandbox Clone',
                apiKey: 'sbx-key',
                llmProvider: SANDBOX,
            });

        expect(res.status).toBe(200);
        expect(res.body.data).toMatchObject({
            aiAvailable: false,
            preparation: {
                started: true,
                provider: SANDBOX,
                providerLabel: 'UBC On-Premise LLM',
                migration: { status: 'queued', total: 1, toProvider: SANDBOX },
            },
        });
        expect(startedMigrations).toEqual([res.body.data.preparation.migration.migrationId]);

        const clone = await db.collection('courses').findOne({ courseId: res.body.data.courseId });
        expect(clone).toMatchObject({
            activeLlmProvider: SANDBOX,
            pendingLlmProvider: SANDBOX,
            aiPreparationRequired: true,
            providerMigrationId: res.body.data.preparation.migration.migrationId,
        });
    });

    test('transfer defaults to the source course\'s platform', async () => {
        mockValidateProviderKey.mockResolvedValue({ ok: true, status: 'valid', provider: SANDBOX });
        const db = memoryDb({
            courses: [{
                courseId: 'C1',
                courseName: 'Source',
                instructorId: 'i1',
                instructors: ['i1'],
                activeLlmProvider: SANDBOX,
                llmCredentials: { [SANDBOX]: buildKeySubdocument('sbx-key', 'i1', SANDBOX) },
                lectures: [],
            }],
        });

        const res = await request(courses({ db, user: instructor }))
            .post('/C1/transfer').send({ newCourseName: 'Clone', apiKey: 'sbx-key-2' });

        expect(res.status).toBe(200);
        expect(mockValidateProviderKey).toHaveBeenCalledWith(expect.objectContaining({ provider: SANDBOX }));
        const clone = await db.collection('courses').findOne({ courseId: res.body.data.courseId });
        expect(clone.activeLlmProvider).toBe(SANDBOX);
    });
});
