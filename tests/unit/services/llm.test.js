const mockToolkitInstance = {
    sendMessage: jest.fn(),
    sendConversation: jest.fn(),
    createConversation: jest.fn(),
    getAvailableModels: jest.fn(),
    getProviderName: jest.fn(() => 'mock-provider'),
};

jest.mock('ubc-genai-toolkit-llm', () => ({
    LLMModule: jest.fn(() => mockToolkitInstance),
}));
jest.mock('../../../src/services/config', () => ({
    getLLMConfig: jest.fn(() => ({ provider: 'openai', defaultModel: 'gpt-4.1-mini' })),
}));

const LLMService = require('../../../src/services/llm');
const { memoryDb } = require('../helpers/memory-db');

function readyService(config = { provider: 'openai', defaultModel: 'gpt-4.1-mini' }) {
    const service = new LLMService({ llmConfig: config });
    service.llmConfig = config;
    service.llm = mockToolkitInstance;
    service.isInitialized = true;
    return service;
}

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});

beforeEach(() => {
    mockToolkitInstance.sendMessage.mockReset();
    mockToolkitInstance.sendConversation.mockReset();
    mockToolkitInstance.createConversation.mockReset();
    mockToolkitInstance.getAvailableModels.mockReset();
    mockToolkitInstance.getProviderName.mockReset().mockReturnValue('mock-provider');
});

afterAll(() => jest.restoreAllMocks());

describe('LLM model settings without provider traffic', () => {
    test('reads allowed DB settings, caches them, and invalidates explicitly', async () => {
        const service = readyService();
        const db = memoryDb({ settings: [{ _id: 'llm', model: 'gpt-5.4-nano', reasoningEffort: 'high' }] });
        service.setDbAccessor(() => db);
        await expect(service._getModelSettings()).resolves.toEqual({ model: 'gpt-5.4-nano', reasoningEffort: 'high' });
        await db.collection('settings').updateOne({ _id: 'llm' }, { $set: { model: 'gpt-5-nano' } });
        await expect(service._getModelSettings()).resolves.toEqual({ model: 'gpt-5.4-nano', reasoningEffort: 'high' });
        service.invalidateModelSettingsCache();
        await expect(service._getModelSettings()).resolves.toEqual({ model: 'gpt-5-nano', reasoningEffort: 'high' });
    });

    test('rejects unsupported stored and environment model settings', async () => {
        const service = readyService({ provider: 'openai', defaultModel: 'not-allowed' });
        service.setDbAccessor(() => memoryDb({ settings: [{ _id: 'llm', model: 'bad', reasoningEffort: 'extreme' }] }));
        await expect(service._getModelSettings()).resolves.toEqual({ model: 'gpt-4.1-mini', reasoningEffort: 'minimal' });
    });

    test('applies GPT-5 token and reasoning options', async () => {
        const service = readyService({ provider: 'openai', defaultModel: 'gpt-5.4-nano' });
        const result = await service._applyModelOptions({ temperature: 0.7, maxTokens: 20 });
        expect(result).toEqual({ model: 'gpt-5.4-nano', max_completion_tokens: 2000, reasoning_effort: 'low' });
        expect(service._coerceReasoningEffort('gpt-5-nano', 'xhigh')).toBe('high');
        expect(service._coerceReasoningEffort('unknown', 'custom')).toBe('custom');
    });

    test.each([
        ['ollama', { num_ctx: 2048 }],
        ['openai', { max_tokens: 32768 }],
        ['ubc-llm-sandbox', { num_ctx: 2048 }],
        ['unknown', {}],
    ])('returns provider-specific options for %s', (provider, expected) => {
        expect(readyService({ provider })._getProviderSpecificOptions()).toEqual(expected);
    });
});

describe('mocked message and conversation orchestration', () => {
    test('sendMessage forwards transformed options to the mocked toolkit', async () => {
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: 'mock response' });
        const service = readyService();
        const result = await service.sendMessage('hello', { temperature: 0.2, maxTokens: 50 });
        expect(result.content).toBe('mock response');
        expect(mockToolkitInstance.sendMessage).toHaveBeenCalledWith('hello', expect.objectContaining({ model: 'gpt-4.1-mini', temperature: 0.2, maxTokens: 50 }));
    });

    test('describeImage sends base64 image content and suppresses sentinel replies', async () => {
        mockToolkitInstance.sendConversation.mockResolvedValueOnce({ content: 'NO_CONTENT' });
        const service = readyService();
        await expect(service.describeImage(Buffer.from('image'), 'image/png', { slideNumber: 2 })).resolves.toBe('');
        expect(mockToolkitInstance.sendConversation.mock.calls[0][0][0]).toMatchObject({ role: 'user', images: [{ data: Buffer.from('image').toString('base64'), mimeType: 'image/png' }] });
        mockToolkitInstance.sendConversation.mockResolvedValueOnce({ content: '  A labelled enzyme diagram.  ' });
        await expect(service.describeImage('base64', 'image/jpeg')).resolves.toBe('A labelled enzyme diagram.');
    });

    test('creates and sends a mocked multi-turn conversation', async () => {
        const conversation = { addMessage: jest.fn(), send: jest.fn(async () => ({ content: 'reply' })) };
        mockToolkitInstance.createConversation.mockReturnValueOnce(conversation);
        const service = readyService();
        expect(await service.createConversation()).toBe(conversation);
        expect(conversation.addMessage).toHaveBeenCalledWith('system', expect.any(String));
        await expect(service.sendConversationMessage(conversation, 'question')).resolves.toEqual({ content: 'reply' });
        expect(conversation.addMessage).toHaveBeenCalledWith('user', 'question');
    });

    test('models, provider, readiness, status, and connection use only the mock', async () => {
        const service = readyService();
        mockToolkitInstance.getAvailableModels.mockResolvedValueOnce(['mock-model']);
        await expect(service.getAvailableModels()).resolves.toEqual(['mock-model']);
        expect(service.getProviderName()).toBe('mock-provider');
        expect(service.isReady()).toBe(true);
        expect(service.getStatus()).toMatchObject({ provider: 'mock-provider', isConnected: true, isInitialized: true });
        jest.spyOn(service, 'sendMessage').mockResolvedValueOnce({ content: 'ok' }).mockResolvedValueOnce({});
        await expect(service.testConnection()).resolves.toBe(true);
        await expect(service.testConnection()).resolves.toBe(false);
    });
});

describe('assessment prompt and parser logic', () => {
    test.each(['true-false', 'multiple-choice', 'short-answer'])('builds default %s prompts and schemas', type => {
        const service = readyService();
        expect(service.createQuestionGenerationPrompt(type, 'material', 'Unit 1', 'objective')).toContain('material');
        expect(service.getJsonSchemaForQuestionType(type)).toContain(`"type": "${type}"`);
    });

    test('substitutes placeholders in custom prompts', () => {
        const service = readyService();
        const prompt = service.createQuestionGenerationPrompt('short-answer', 'MAT', 'UNIT', 'OBJ', { shortAnswer: '{{questionType}} {{unitName}} {{learningObjectives}} {{courseMaterial}}' });
        expect(prompt).toBe('short-answer UNIT OBJ MAT');
        expect(() => service.createQuestionGenerationPrompt('essay', '', '')).toThrow('Unsupported question type');
    });

    test('builds regeneration prompts for each question type', () => {
        const service = readyService();
        expect(service.createQuestionRegenerationPrompt('multiple-choice', 'material', 'U', 'objectives', { question: 'Q', options: { A: 'a', B: 'b', C: 'c', D: 'd' }, answer: 'A' }, 'improve')).toContain('A) a');
        expect(service.createQuestionRegenerationPrompt('true-false', 'material', 'U', '', { question: 'Q', answer: true }, 'improve')).toContain('Correct Answer: true');
        expect(service.createQuestionRegenerationPrompt('short-answer', 'material', 'U', '', { question: 'Q', answer: 'answer' }, 'improve')).toContain('Expected Answer: answer');
    });

    test('parses all supported generated question shapes', () => {
        const service = readyService();
        expect(service.parseGeneratedQuestion('prefix {"type":"true-false","question":"Q","correctAnswer":true,"explanation":"E"}', 'true-false')).toMatchObject({ answer: 'true' });
        expect(service.parseGeneratedQuestion('{"type":"multiple-choice","question":"Q","options":{"A":"a","B":"b","C":"c","D":"d"},"correctAnswer":"b","explanation":"E"}', 'multiple-choice')).toMatchObject({ answer: 'B' });
        expect(service.parseGeneratedQuestion('{"type":"short-answer","question":"Q","expectedAnswer":"A","keyPoints":["K"],"explanation":"E"}', 'short-answer')).toMatchObject({ answer: 'A', keyPoints: ['K'] });
    });

    test('returns a safe fallback for malformed or incomplete generated questions', () => {
        const service = readyService();
        expect(service.parseGeneratedQuestion('not json', 'multiple-choice')).toMatchObject({ type: 'multiple-choice', answer: 'A', options: { A: 'Option A' } });
        expect(service.parseGeneratedQuestion('{"type":"true-false","question":"Q"}', 'true-false').question).toContain('Error parsing');
    });
});

describe('mocked evaluation and safety analysis', () => {
    test('evaluateStudentAnswer parses JSON and falls back to raw mocked content', async () => {
        const service = readyService();
        jest.spyOn(service, 'sendMessage')
            .mockResolvedValueOnce({ content: 'prefix {"correct":true,"feedback":"Good"}' })
            .mockResolvedValueOnce({ content: 'not-json but correct": true' });
        await expect(service.evaluateStudentAnswer('Q', 'A', 'A', 'short-answer', 'Sam')).resolves.toEqual({ correct: true, feedback: 'Good' });
        await expect(service.evaluateStudentAnswer('Q', 'A', 'A', 'short-answer')).resolves.toEqual({ correct: true, feedback: 'not-json but correct": true' });
    });

    test('analyzeMentalHealth parses mocked JSON and fails closed', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: '{"concernLevel":"high","reason":"explicit"}' });
        await expect(service.analyzeMentalHealth([{ role: 'user', content: 'message' }], 'detect')).resolves.toEqual({ concernLevel: 'high', reason: 'explicit' });
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: 'invalid' });
        await expect(service.analyzeMentalHealth([], 'detect')).resolves.toMatchObject({ concernLevel: 'no concern', reason: 'Failed to parse detection response' });
        mockToolkitInstance.sendMessage.mockRejectedValueOnce(new Error('mock offline'));
        await expect(service.analyzeMentalHealth([], 'detect')).resolves.toMatchObject({ concernLevel: 'no concern', reason: 'Detection error: mock offline' });
    });
});
