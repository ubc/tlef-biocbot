const mockToolkitInstance = {
    sendMessage: jest.fn(),
    sendConversation: jest.fn(),
    createConversation: jest.fn(),
    getAvailableModels: jest.fn(),
    getProviderName: jest.fn(() => 'mock-provider'),
};

const { LLMModule } = require('ubc-genai-toolkit-llm');
jest.mock('ubc-genai-toolkit-llm', () => ({
    LLMModule: jest.fn(() => mockToolkitInstance),
}));
jest.mock('../../../src/services/config', () => ({
    getLLMConfig: jest.fn(() => ({ provider: 'openai', defaultModel: 'gpt-4.1-mini' })),
}));

const LLMService = require('../../../src/services/llm');
const { LlmKeyError } = require('../../../src/services/llmKeyStore');
const { memoryDb } = require('../helpers/memory-db');

function readyService(config = { provider: 'openai', defaultModel: 'gpt-4.1-mini' }) {
    const service = new LLMService({ llmConfig: config });
    service.llmConfig = config;
    service.llm = mockToolkitInstance;
    service.isInitialized = true;
    return service;
}

// A valid generated-question JSON payload for a given type (parses cleanly).
function questionJson(type) {
    if (type === 'true-false') return '{"type":"true-false","question":"Q","correctAnswer":true,"explanation":"E"}';
    if (type === 'multiple-choice') return '{"type":"multiple-choice","question":"Q","options":{"A":"a","B":"b","C":"c","D":"d"},"correctAnswer":"b","explanation":"E"}';
    return '{"type":"short-answer","question":"Q","expectedAnswer":"A","explanation":"E"}';
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
    LLMModule.mockClear().mockImplementation(() => mockToolkitInstance);
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

    test('analyzeMentalHealth lazy-inits, fails closed on empty content, and on broken JSON', async () => {
        const fresh = new LLMService({ llmConfig: { provider: 'openai' } });
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: '' });
        await expect(fresh.analyzeMentalHealth([{ role: 'user', content: 'hi' }], 'detect'))
            .resolves.toEqual({ concernLevel: 'no concern', reason: 'No response from detection model' });
        expect(fresh.isInitialized).toBe(true);
        // Content that contains braces but is not valid JSON exercises the JSON.parse catch.
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: '{ not: valid }' });
        await expect(fresh.analyzeMentalHealth([], 'detect'))
            .resolves.toEqual({ concernLevel: 'no concern', reason: 'Failed to parse detection response' });
    });

    test('analyzeMentalHealth defaults missing JSON fields to no-concern/empty', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: '{"foo":"bar"}' });
        await expect(service.analyzeMentalHealth([], 'detect')).resolves.toEqual({ concernLevel: 'no concern', reason: '' });
    });
});

describe('initialization', () => {
    afterEach(() => { delete process.env.BIOCBOT_TEST_LLM_STUB; });

    test('static create wires the toolkit module for the configured provider', async () => {
        const service = await LLMService.create({ llmConfig: { provider: 'openai', defaultModel: 'gpt-4.1-mini' } });
        expect(service.isInitialized).toBe(true);
        expect(service.llm).toBe(mockToolkitInstance);
        expect(LLMModule).toHaveBeenCalledWith({ provider: 'openai', defaultModel: 'gpt-4.1-mini' });
    });

    test('test-stub mode skips real provider wiring', async () => {
        process.env.BIOCBOT_TEST_LLM_STUB = '1';
        const service = await LLMService.create({});
        expect(service.isInitialized).toBe(true);
        expect(service.llmConfig).toMatchObject({ provider: 'test-stub' });
        expect(LLMModule).not.toHaveBeenCalled();
    });

    test('initialization failure resets state and rethrows', async () => {
        LLMModule.mockImplementationOnce(() => { throw new Error('toolkit boom'); });
        await expect(LLMService.create({ llmConfig: { provider: 'openai' } })).rejects.toThrow('toolkit boom');
    });

    test('lazy-initializes on first sendMessage when not yet initialized', async () => {
        const service = new LLMService({ llmConfig: { provider: 'openai', defaultModel: 'gpt-4.1-mini' } });
        expect(service.isInitialized).toBe(false);
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: 'hi' });
        await expect(service.sendMessage('hello')).resolves.toEqual({ content: 'hi' });
        expect(service.isInitialized).toBe(true);
    });

    test('getProviderName reports not-initialized before wiring', () => {
        expect(new LLMService({}).getProviderName()).toBe('Not initialized');
    });
});

describe('provider error handling', () => {
    test('sendMessage maps an invalid-key provider error to LlmKeyError and notifies the scope callback', async () => {
        const onProviderKeyFailure = jest.fn().mockResolvedValue();
        const service = readyService();
        service.onProviderKeyFailure = onProviderKeyFailure;
        service.scope = { courseId: 'C1' };
        const err = Object.assign(new Error('Incorrect API key provided'), { status: 401 });
        mockToolkitInstance.sendMessage.mockRejectedValueOnce(err);
        await expect(service.sendMessage('hi')).rejects.toBeInstanceOf(LlmKeyError);
        expect(onProviderKeyFailure).toHaveBeenCalledWith('invalid', err);
    });

    test('a throwing key-failure handler is swallowed but the LlmKeyError is still raised', async () => {
        const service = readyService();
        service.onProviderKeyFailure = jest.fn().mockRejectedValue(new Error('handler boom'));
        const err = Object.assign(new Error('invalid api key'), { status: 401 });
        mockToolkitInstance.sendMessage.mockRejectedValueOnce(err);
        await expect(service.sendMessage('hi')).rejects.toBeInstanceOf(LlmKeyError);
    });

    test('a non-key provider error is rethrown unchanged', async () => {
        const service = readyService();
        service.onProviderKeyFailure = jest.fn();
        mockToolkitInstance.sendMessage.mockRejectedValueOnce(new Error('network blip'));
        await expect(service.sendMessage('hi')).rejects.toThrow('network blip');
        expect(service.onProviderKeyFailure).not.toHaveBeenCalled();
    });

    test('_sendRawConversation surfaces an LlmKeyError when describeImage hits an invalid key', async () => {
        const service = readyService();
        service.onProviderKeyFailure = jest.fn().mockResolvedValue();
        mockToolkitInstance.sendConversation.mockRejectedValueOnce(Object.assign(new Error('x'), { status: 401 }));
        await expect(service.describeImage('b64', 'image/png')).rejects.toBeInstanceOf(LlmKeyError);
    });

    test('_sendRawConversation rethrows a non-key error unchanged', async () => {
        const service = readyService();
        mockToolkitInstance.sendConversation.mockRejectedValueOnce(new Error('conversation network blip'));
        await expect(service.describeImage('b64', 'image/png')).rejects.toThrow('conversation network blip');
    });
});

describe('lazy-init and error propagation across helpers', () => {
    test('createConversation lazy-inits, then propagates a thrown error', async () => {
        const fresh = new LLMService({ llmConfig: { provider: 'openai' } });
        const conversation = { addMessage: jest.fn(), send: jest.fn() };
        mockToolkitInstance.createConversation.mockReturnValueOnce(conversation);
        await expect(fresh.createConversation()).resolves.toBe(conversation);

        const service = readyService();
        mockToolkitInstance.createConversation.mockImplementationOnce(() => { throw new Error('convo boom'); });
        await expect(service.createConversation()).rejects.toThrow('convo boom');
    });

    test('sendConversationMessage lazy-inits and propagates a send error', async () => {
        const fresh = new LLMService({ llmConfig: { provider: 'openai' } });
        const conversation = { addMessage: jest.fn(), send: jest.fn().mockRejectedValueOnce(new Error('send boom')) };
        await expect(fresh.sendConversationMessage(conversation, 'q')).rejects.toThrow('send boom');
        expect(fresh.isInitialized).toBe(true);
    });

    test('getAvailableModels lazy-inits and propagates a lookup error', async () => {
        const fresh = new LLMService({ llmConfig: { provider: 'openai' } });
        mockToolkitInstance.getAvailableModels.mockRejectedValueOnce(new Error('models boom'));
        await expect(fresh.getAvailableModels()).rejects.toThrow('models boom');
    });

    test('describeImage lazy-inits before describing', async () => {
        const fresh = new LLMService({ llmConfig: { provider: 'openai' } });
        mockToolkitInstance.sendConversation.mockResolvedValueOnce({ content: 'A real figure.' });
        await expect(fresh.describeImage('b64', 'image/png')).resolves.toBe('A real figure.');
        expect(fresh.isInitialized).toBe(true);
    });

    test('evaluateStudentAnswer lazy-inits and propagates a send error', async () => {
        const fresh = new LLMService({ llmConfig: { provider: 'openai' } });
        mockToolkitInstance.sendMessage.mockRejectedValueOnce(new Error('eval boom'));
        await expect(fresh.evaluateStudentAnswer('Q', 'A', 'A', 'short-answer')).rejects.toThrow('eval boom');
    });

    test('testConnection returns false when sendMessage throws', async () => {
        const service = readyService();
        jest.spyOn(service, 'sendMessage').mockRejectedValueOnce(new Error('down'));
        await expect(service.testConnection()).resolves.toBe(false);
    });
});

describe('model-settings edge branches', () => {
    test('falls back to defaults when the DB lookup throws', async () => {
        const service = readyService();
        service.setDbAccessor(() => ({ collection: () => ({ findOne: () => { throw new Error('db down'); } }) }));
        await expect(service._getModelSettings()).resolves.toEqual({ model: 'gpt-4.1-mini', reasoningEffort: 'minimal' });
    });

    test('_coerceReasoningEffort falls back to the first supported value', () => {
        // 'none' is unsupported for gpt-5-nano and matches no special-case mapping → first supported ('minimal').
        expect(readyService()._coerceReasoningEffort('gpt-5-nano', 'none')).toBe('minimal');
    });

    test('_applyModelOptions translates max_tokens to max_completion_tokens for gpt-5', async () => {
        const service = readyService({ provider: 'openai', defaultModel: 'gpt-5-nano' });
        const result = await service._applyModelOptions({ temperature: 0.3, max_tokens: 5000 });
        expect(result).toEqual({ model: 'gpt-5-nano', max_completion_tokens: 5000, reasoning_effort: 'minimal' });
        expect(result.temperature).toBeUndefined();
    });
});

describe('assessment question generation orchestration', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    test('generateAssessmentQuestion builds the prompt, sends it, and parses the result', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: questionJson('true-false') });
        const result = await service.generateAssessmentQuestion('true-false', 'material', 'Unit 1', 'objectives');
        expect(result).toMatchObject({ type: 'true-false', answer: 'true' });
    });

    test('generateAssessmentQuestion honours custom system/template prompts', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: questionJson('multiple-choice') });
        const custom = {
            systemPrompt: 'system for {{questionType}}',
            multipleChoice: 'mc {{unitName}} {{courseMaterial}}',
        };
        const result = await service.generateAssessmentQuestion('multiple-choice', 'MAT', 'U2', 'OBJ', custom);
        expect(result).toMatchObject({ type: 'multiple-choice' });
        expect(mockToolkitInstance.sendMessage).toHaveBeenCalledWith('mc U2 MAT', expect.objectContaining({ systemPrompt: 'system for multiple-choice' }));
    });

    test('generateAssessmentQuestion throws when the model returns no content', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({});
        await expect(service.generateAssessmentQuestion('short-answer', 'm', 'U')).rejects.toThrow('No response content received from LLM');
    });

    test('regenerateAssessmentQuestion builds a feedback prompt, sends it, and parses', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: questionJson('short-answer') });
        const prev = { question: 'old', answer: 'old answer' };
        const result = await service.regenerateAssessmentQuestion('short-answer', 'material', 'U', 'objectives', prev, 'make it harder');
        expect(result).toMatchObject({ type: 'short-answer', answer: 'A' });
        expect(mockToolkitInstance.sendMessage.mock.calls[0][0]).toContain('make it harder');
    });

    test('regenerateAssessmentQuestion throws when the model returns no content', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: '' });
        const prev = { question: 'old', answer: 'a' };
        await expect(service.regenerateAssessmentQuestion('true-false', 'm', 'U', '', prev, 'fb'))
            .rejects.toThrow('No response content received from LLM during regeneration');
    });

    test('generateAssessmentQuestion rejects when the provider call exceeds the 2-minute timeout', async () => {
        const service = readyService();
        // A response that never resolves lets the timeout win the Promise.race.
        mockToolkitInstance.sendMessage.mockReturnValue(new Promise(() => {}));
        // Attach the rejection handler before advancing timers so the rejection is never "unhandled".
        const assertion = expect(service.generateAssessmentQuestion('true-false', 'm', 'U'))
            .rejects.toThrow('LLM request timed out after 2 minutes');
        await jest.advanceTimersByTimeAsync(120000);
        await assertion;
    });

    test('regenerateAssessmentQuestion rejects when the provider call exceeds the 2-minute timeout', async () => {
        const service = readyService();
        mockToolkitInstance.sendMessage.mockReturnValue(new Promise(() => {}));
        const assertion = expect(service.regenerateAssessmentQuestion('short-answer', 'm', 'U', '', { question: 'q', answer: 'a' }, 'fb'))
            .rejects.toThrow('LLM regeneration request timed out after 2 minutes');
        await jest.advanceTimersByTimeAsync(120000);
        await assertion;
    });

    test('generate and regenerate lazy-initialize when first used', async () => {
        const g = new LLMService({ llmConfig: { provider: 'openai' } });
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: questionJson('true-false') });
        await expect(g.generateAssessmentQuestion('true-false', 'm', 'U')).resolves.toMatchObject({ type: 'true-false' });
        expect(g.isInitialized).toBe(true);

        const r = new LLMService({ llmConfig: { provider: 'openai' } });
        mockToolkitInstance.sendMessage.mockResolvedValueOnce({ content: questionJson('short-answer') });
        await expect(r.regenerateAssessmentQuestion('short-answer', 'm', 'U', '', { question: 'q', answer: 'a' }, 'fb')).resolves.toMatchObject({ type: 'short-answer' });
        expect(r.isInitialized).toBe(true);
    });
});

describe('custom prompt template branches and parser validation', () => {
    test('custom true-false / multiple-choice templates substitute placeholders', () => {
        const service = readyService();
        expect(service.createQuestionGenerationPrompt('true-false', 'MAT', 'U', 'OBJ', { trueFalse: 'tf {{unitName}} {{courseMaterial}}' })).toBe('tf U MAT');
        expect(service.createQuestionGenerationPrompt('multiple-choice', 'MAT', 'U', '', { multipleChoice: 'mc {{courseMaterial}}' })).toBe('mc MAT');
    });

    test('custom prompts with no matching template fall back to the default prompt', () => {
        const service = readyService();
        // customPrompts provided but the trueFalse template is absent → default template path.
        const prompt = service.createQuestionGenerationPrompt('true-false', 'MATERIAL', 'Unit 9', 'obj', { multipleChoice: 'x' });
        expect(prompt).toContain('MATERIAL');
    });

    test('custom prompts with an unsupported question type throw', () => {
        const service = readyService();
        expect(() => service.createQuestionGenerationPrompt('essay', 'm', 'U', '', { trueFalse: 'x' }))
            .toThrow('Unsupported question type: essay');
    });

    test('getJsonSchemaForQuestionType returns an empty object for unknown types', () => {
        expect(readyService().getJsonSchemaForQuestionType('essay')).toBe('{}');
    });

    test('parser accepts an unknown-but-matching question type via the default branch', () => {
        const service = readyService();
        const result = service.parseGeneratedQuestion('{"type":"essay","question":"Q","explanation":"E"}', 'essay');
        expect(result).toEqual({ type: 'essay', question: 'Q', explanation: 'E' });
    });

    test('parser warns on a type mismatch but still parses', () => {
        const service = readyService();
        const result = service.parseGeneratedQuestion('{"type":"short-answer","question":"Q","expectedAnswer":"A","explanation":"E"}', 'true-false');
        // Mismatch warns; returns the safe fallback because a boolean correctAnswer is required for true-false.
        expect(result.question).toContain('Error parsing');
    });

    test.each([
        ['multiple-choice', '{"type":"multiple-choice","question":"Q","correctAnswer":"A","explanation":"E"}'],
        ['multiple-choice', '{"type":"multiple-choice","question":"Q","options":{"A":"a","B":"b"},"correctAnswer":"A","explanation":"E"}'],
        ['short-answer', '{"type":"short-answer","question":"Q","explanation":"E"}'],
    ])('returns the safe fallback when a %s payload is missing required fields', (type, payload) => {
        expect(readyService().parseGeneratedQuestion(payload, type).question).toContain('Error parsing');
    });
});
