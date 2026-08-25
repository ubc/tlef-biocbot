const adminModelSettings = require('../../../src/services/adminModelSettings');
const scopeModelSettings = require('../../../src/services/scopeModelSettings');
const { memoryDb } = require('../helpers/memory-db');

const OPENAI = 'openai';
const SANDBOX = 'ubc-llm-sandbox';
const PROXY = 'ubc-llm-proxy';

beforeEach(() => adminModelSettings.invalidateCache());

function dbWithCourses() {
    return memoryDb({
        settings: [{
            _id: 'llm',
            providers: {
                [OPENAI]: {
                    chatModel: 'gpt-4.1-mini',
                    reasoningEffort: 'minimal',
                    embeddingModel: 'text-embedding-3-small'
                },
                [SANDBOX]: {
                    chatModel: 'qwen3.6-35b-a3b',
                    reasoningEffort: 'none',
                    embeddingModel: 'qwen3-embedding-0.6b'
                }
            }
        }],
        courses: [{ courseId: 'A' }, { courseId: 'B' }],
        superchats: []
    });
}

test('materializing defaults creates independent provider snapshots', async () => {
    const db = dbWithCourses();
    await scopeModelSettings.materialize(db, { type: 'course', id: 'A' });
    await scopeModelSettings.materialize(db, { type: 'course', id: 'B' });

    await scopeModelSettings.saveChatSettings(db, { type: 'course', id: 'A' }, OPENAI, {
        chatModel: 'gpt-5.6-luna',
        reasoningEffort: 'low',
        backendInheritsFrontend: true
    });

    const a = await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'A' }, OPENAI);
    const b = await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'B' }, OPENAI);
    expect(a.chatModel).toBe('gpt-5.6-luna');
    expect(b.chatModel).toBe('gpt-4.1-mini');
});

test('a key roster that excludes the copied default requires admin configuration', async () => {
    const db = dbWithCourses();
    const settings = await scopeModelSettings.materialize(db, { type: 'course', id: 'A' }, {
        availableModelsByProvider: {
            [OPENAI]: ['gpt-5.6-luna', 'text-embedding-3-large']
        }
    });

    expect(settings.providers[OPENAI].configurationStatus).toBe(scopeModelSettings.NEEDS_ADMIN);
    expect(settings.providers[OPENAI].configured).toBe(false);
});

test('a compatible key roster makes the copied defaults ready immediately', async () => {
    const db = dbWithCourses();
    const settings = await scopeModelSettings.materialize(db, { type: 'course', id: 'A' }, {
        availableModelsByProvider: {
            [OPENAI]: ['gpt-4.1-mini', 'text-embedding-3-small']
        }
    });

    expect(settings.providers[OPENAI].configurationStatus).toBe(scopeModelSettings.READY);
    expect(settings.providers[OPENAI].configured).toBe(true);
});

test('validated proxy defaults make a newly keyed course ready immediately', async () => {
    const db = dbWithCourses();
    await scopeModelSettings.materialize(db, { type: 'course', id: 'A' });
    const settings = await scopeModelSettings.applyCredentialRoster(
        db,
        { type: 'course', id: 'A' },
        PROXY,
        ['gpt-5.6-luna', 'text-embedding-3-small'],
        'admin@x',
        {
            chatModel: 'gpt-5.6-luna',
            reasoningEffort: 'low',
            embeddingModel: 'text-embedding-3-small',
            vectorSize: 1536
        }
    );

    expect(settings).toMatchObject({
        chatModel: 'gpt-5.6-luna',
        reasoningEffort: 'low',
        embeddingModel: 'text-embedding-3-small',
        vectorSize: 1536,
        backendInheritsFrontend: true,
        configurationStatus: scopeModelSettings.READY,
        configured: true
    });
});

test('changing the default template later does not change a materialized course', async () => {
    const db = dbWithCourses();
    await scopeModelSettings.materialize(db, { type: 'course', id: 'A' });
    await adminModelSettings.saveChatSettings(db, OPENAI, {
        chatModel: 'gpt-5.6-luna', reasoningEffort: 'low'
    });

    const course = await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'A' }, OPENAI);
    expect(course.chatModel).toBe('gpt-4.1-mini');
});

test('pending embedding settings and activation belong to one scope', async () => {
    const db = dbWithCourses();
    await scopeModelSettings.materialize(db, { type: 'course', id: 'A' });
    await scopeModelSettings.materialize(db, { type: 'course', id: 'B' });
    await scopeModelSettings.stagePendingEmbedding(db, { type: 'course', id: 'A' }, OPENAI, {
        embeddingModel: 'text-embedding-3-large', migrationId: 'm1'
    });
    await scopeModelSettings.activatePendingEmbedding(db, { type: 'course', id: 'A' }, OPENAI, {
        embeddingModel: 'text-embedding-3-large', embeddingRevision: 'v1'
    });

    const a = await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'A' }, OPENAI);
    const b = await scopeModelSettings.getProviderSettings(db, { type: 'course', id: 'B' }, OPENAI);
    expect(a.embeddingModel).toBe('text-embedding-3-large');
    expect(b.embeddingModel).toBe('text-embedding-3-small');
});
