// @ts-check
/**
 * Browser-driven harness for src/services/llm.js coverage.
 *
 * The live app wires the service to real provider/config modules. For focused
 * service coverage, this harness loads the real LLMService class with local
 * test doubles for those expensive dependencies, then exposes small HTTP
 * actions that Playwright drives from a browser page. It runs with the same
 * NODE_V8_COVERAGE directory as the main server so global teardown merges the
 * service coverage into Monocart.
 */

const express = require('express');
const Module = require('module');
const path = require('path');
const v8 = require('v8');

// This harness exercises the REAL LLMService initialization path against the
// FakeLLMModule installed via the require override below. Stub mode
// (BIOCBOT_TEST_LLM_STUB=1, inherited from the test runner's env) makes
// _performInitialization short-circuit to the llm-stub and never touch
// FakeLLMModule, so the lifecycle probe's sends go unrecorded. Clear it for
// this child process so init wires up the fake module as intended.
delete process.env.BIOCBOT_TEST_LLM_STUB;

const harnessState = {
    provider: 'openai',
    defaultModel: 'gpt-4.1-mini',
    configThrows: false,
    constructThrows: false,
    sendThrows: false,
    availableThrows: false,
    conversationCreateThrows: false,
    conversationSendThrows: false,
    sendQueue: /** @type {Array<any>} */ ([]),
    availableModels: ['gpt-4.1-mini', 'gpt-5-nano'],
    sends: /** @type {Array<any>} */ ([]),
    conversations: /** @type {Array<any>} */ ([]),
    constructedConfigs: /** @type {Array<any>} */ ([]),
};

function resetHarnessState() {
    harnessState.provider = 'openai';
    harnessState.defaultModel = 'gpt-4.1-mini';
    harnessState.configThrows = false;
    harnessState.constructThrows = false;
    harnessState.sendThrows = false;
    harnessState.availableThrows = false;
    harnessState.conversationCreateThrows = false;
    harnessState.conversationSendThrows = false;
    harnessState.sendQueue = [];
    harnessState.availableModels = ['gpt-4.1-mini', 'gpt-5-nano'];
    harnessState.sends = [];
    harnessState.conversations = [];
    harnessState.constructedConfigs = [];
}

class FakeLLMModule {
    constructor(config) {
        if (harnessState.constructThrows) {
            throw new Error('harness construct failure');
        }
        this.config = config;
        harnessState.constructedConfigs.push(config);
    }

    async sendMessage(message, options) {
        harnessState.sends.push({ message, options });
        if (harnessState.sendThrows) {
            throw new Error('harness send failure');
        }
        const next = harnessState.sendQueue.length
            ? harnessState.sendQueue.shift()
            : { content: 'stub llm response' };
        if (next instanceof Error) throw next;
        return next;
    }

    createConversation() {
        if (harnessState.conversationCreateThrows) {
            throw new Error('harness conversation creation failure');
        }
        const record = {
            messages: /** @type {Array<{role: string, content: string}>} */ ([]),
            sendOptions: /** @type {Array<any>} */ ([]),
        };
        harnessState.conversations.push(record);
        return {
            addMessage(role, content) {
                record.messages.push({ role, content });
            },
            async send(options) {
                record.sendOptions.push(options);
                if (harnessState.conversationSendThrows) {
                    throw new Error('harness conversation send failure');
                }
                return { content: 'conversation reply' };
            },
        };
    }

    async getAvailableModels() {
        if (harnessState.availableThrows) {
            throw new Error('harness models failure');
        }
        return harnessState.availableModels;
    }

    getProviderName() {
        return `fake-${this.config.provider}`;
    }
}

const fakeConfig = {
    getLLMConfig() {
        if (harnessState.configThrows) {
            throw new Error('harness config failure');
        }
        return {
            provider: harnessState.provider,
            defaultModel: harnessState.defaultModel,
            endpoint: 'http://llm.example.test',
        };
    },
};

const fakePrompts = {
    BASE_SYSTEM_PROMPT: 'Base system prompt from harness',
    createQuestionGenerationSystemPrompt(questionType, schema) {
        return `system:${questionType}:${schema}`;
    },
    QUESTION_GENERATION_PROMPT_TEMPLATE: {
        trueFalse(learningObjectives, courseMaterialContent, unitName) {
            return `default true-false ${learningObjectives} ${courseMaterialContent} ${unitName}`;
        },
        multipleChoice(learningObjectives, courseMaterialContent, unitName) {
            return `default multiple-choice ${learningObjectives} ${courseMaterialContent} ${unitName}`;
        },
        shortAnswer(learningObjectives, courseMaterialContent, unitName) {
            return `default short-answer ${learningObjectives} ${courseMaterialContent} ${unitName}`;
        },
    },
};

const moduleLoader = /** @type {any} */ (Module);
const originalLoad = moduleLoader._load;
moduleLoader._load = function patchedLoad(request, parent, isMain) {
    const parentFile = parent && parent.filename ? parent.filename.replace(/\\/g, '/') : '';
    if (request === 'ubc-genai-toolkit-llm') {
        return { LLMModule: FakeLLMModule };
    }
    if (parentFile.endsWith('/src/services/llm.js') && request === './config') {
        return fakeConfig;
    }
    if (parentFile.endsWith('/src/services/llm.js') && request === './prompts') {
        return fakePrompts;
    }
    return originalLoad.apply(this, [request, parent, isMain]);
};

const dynamicRequire = /** @type {NodeRequire} */ (eval('require'));
const LLMService = dynamicRequire('../../../src/services/llm');

function makeInitializedService(provider = 'openai', defaultModel = 'gpt-4.1-mini') {
    harnessState.provider = provider;
    harnessState.defaultModel = defaultModel;
    const service = new LLMService();
    service.llmConfig = { provider, defaultModel };
    service.llm = new FakeLLMModule(service.llmConfig);
    service.isInitialized = true;
    return service;
}

function dbWithDoc(doc) {
    return {
        collection: () => ({
            findOne: async () => doc,
        }),
    };
}

function dbThatThrows() {
    return {
        collection: () => ({
            findOne: async () => {
                throw new Error('settings read failure');
            },
        }),
    };
}

function jsonQuestion(questionType, overrides = {}) {
    if (questionType === 'true-false') {
        return JSON.stringify({
            type: 'true-false',
            question: 'Harness true false?',
            correctAnswer: true,
            explanation: 'Harness explanation',
            ...overrides,
        });
    }
    if (questionType === 'multiple-choice') {
        return JSON.stringify({
            type: 'multiple-choice',
            question: 'Harness multiple choice?',
            options: { A: 'Alpha', B: 'Beta', C: 'Gamma', D: 'Delta' },
            correctAnswer: 'b',
            explanation: 'Harness explanation',
            ...overrides,
        });
    }
    return JSON.stringify({
        type: 'short-answer',
        question: 'Harness short answer?',
        expectedAnswer: 'Expected harness answer',
        keyPoints: ['point one'],
        explanation: 'Harness explanation',
        ...overrides,
    });
}

async function withImmediateTimeout(fn) {
    const originalSetTimeout = global.setTimeout;
    global.setTimeout = /** @type {any} */ ((callback) => {
        callback();
        return { unref() {} };
    });
    try {
        return await fn();
    } finally {
        global.setTimeout = originalSetTimeout;
    }
}

async function captureError(fn) {
    try {
        await fn();
        return '';
    } catch (error) {
        return error && error.message ? error.message : String(error);
    }
}

async function runSettingsAndOptionsCase() {
    resetHarnessState();
    const originalOpenAIModel = process.env.OPENAI_MODEL;
    const service = new LLMService();
    const results = /** @type {Record<string, any>} */ ({});

    try {
        delete process.env.OPENAI_MODEL;
        service.setDbAccessor('not a function');
        results.noEnvDefault = await service._getModelSettings();
        results.cacheHit = await service._getModelSettings();

        service.invalidateModelSettingsCache();
        process.env.OPENAI_MODEL = 'not-allowed';
        results.invalidEnvDefault = await service._getModelSettings();

        service.invalidateModelSettingsCache();
        service.llmConfig = { defaultModel: 'gpt-5-nano' };
        service.setDbAccessor(() => null);
        results.configDefault = await service._getModelSettings();

        service.invalidateModelSettingsCache();
        service.setDbAccessor(() => dbWithDoc({ model: 'gpt-5.4-nano', reasoningEffort: 'high' }));
        results.dbOverride = await service._getModelSettings();

        service.invalidateModelSettingsCache();
        service.setDbAccessor(() => dbWithDoc({ model: 'bad-model', reasoningEffort: 'extreme' }));
        results.invalidDbOverride = await service._getModelSettings();

        service.invalidateModelSettingsCache();
        service.setDbAccessor(() => dbWithDoc(null));
        results.noDbDoc = await service._getModelSettings();

        service.invalidateModelSettingsCache();
        service.setDbAccessor(() => dbThatThrows());
        results.dbFailure = await service._getModelSettings();

        const openAiService = makeInitializedService('openai', 'gpt-4.1-mini');
        results.nonGptOptions = await openAiService._applyModelOptions({ temperature: 0.2, max_tokens: 123 });

        const gpt5Service = makeInitializedService('openai', 'gpt-5-nano');
        gpt5Service.setDbAccessor(() => dbWithDoc({ model: 'gpt-5-nano', reasoningEffort: 'minimal' }));
        results.gpt5FloorOptions = await gpt5Service._applyModelOptions({ temperature: 0.7, max_tokens: 100 });

        gpt5Service.invalidateModelSettingsCache();
        gpt5Service.setDbAccessor(() => dbWithDoc({ model: 'gpt-5-nano', reasoningEffort: 'high' }));
        results.gpt5LargeBudget = await gpt5Service._applyModelOptions({ temperature: 0.7, max_tokens: 5000 });

        const gpt54Service = makeInitializedService('openai', 'gpt-5.4-nano');
        gpt54Service.setDbAccessor(() => dbWithDoc({ model: 'gpt-5.4-nano', reasoningEffort: 'minimal' }));
        results.gpt54CoercedOptions = await gpt54Service._applyModelOptions({ temperature: 0.7, maxTokens: 333 });

        gpt5Service._modelSettingsCache = { model: 'gpt-5-nano', reasoningEffort: 'xhigh' };
        gpt5Service._modelSettingsCacheAt = Date.now();
        results.xhighCoerced = await gpt5Service._applyModelOptions({ maxTokens: 5000 });

        gpt5Service._modelSettingsCache = { model: 'gpt-5-nano', reasoningEffort: 'weird' };
        gpt5Service._modelSettingsCacheAt = Date.now();
        results.unknownEffortFallback = await gpt5Service._applyModelOptions({});

        gpt5Service._modelSettingsCache = { model: 'gpt-5-nano' };
        gpt5Service._modelSettingsCacheAt = Date.now();
        results.missingEffortFallback = await gpt5Service._applyModelOptions({});

        results.coerceUnknownModel = service._coerceReasoningEffort('future-model', 'minimal');
        results.gptChecks = [
            service._isGpt5Family('gpt-5-nano'),
            service._isGpt5Family('gpt-4.1-mini'),
            service._isGpt5Family(5),
        ];
        results.providerOptions = {
            ollama: makeInitializedService('ollama')._getProviderSpecificOptions(),
            openai: makeInitializedService('openai')._getProviderSpecificOptions(),
            sandbox: makeInitializedService('ubc-llm-sandbox')._getProviderSpecificOptions(),
            unknown: makeInitializedService('other-provider')._getProviderSpecificOptions(),
            missing: new LLMService()._getProviderSpecificOptions(),
        };
    } finally {
        if (originalOpenAIModel === undefined) {
            delete process.env.OPENAI_MODEL;
        } else {
            process.env.OPENAI_MODEL = originalOpenAIModel;
        }
    }

    return results;
}

async function runLifecycleCase() {
    resetHarnessState();
    const results = /** @type {Record<string, any>} */ ({});

    const created = await LLMService.create();
    results.createdReady = created.isReady();
    results.createdProvider = created.getProviderName();

    resetHarnessState();
    harnessState.configThrows = true;
    results.createFailure = await captureError(() => LLMService.create());

    resetHarnessState();
    harnessState.sendQueue = [{ content: 'hello from send' }];
    const sendService = new LLMService();
    const sendResponse = await sendService.sendMessage('hello'.repeat(12), { custom: true });
    results.sendResponse = sendResponse.content;
    results.sendOptions = harnessState.sends[0].options;

    harnessState.sendQueue = [{ content: 'second response' }];
    const secondResponse = await sendService.sendMessage('second message');
    results.secondResponse = secondResponse.content;

    resetHarnessState();
    harnessState.sendQueue = [new Error('send boom')];
    results.sendFailure = await captureError(() => new LLMService().sendMessage('fail'));

    resetHarnessState();
    const conversationService = new LLMService();
    const conversation = await conversationService.createConversation();
    results.conversationMessages = harnessState.conversations[0].messages;
    const conversationResponse = await conversationService.sendConversationMessage(conversation, 'user turn', { local: true });
    results.conversationResponse = conversationResponse.content;
    results.conversationSendOptions = harnessState.conversations[0].sendOptions[0];

    const initializedConversationService = makeInitializedService('openai');
    await initializedConversationService.createConversation();
    results.initializedConversationMessages = harnessState.conversations[harnessState.conversations.length - 1].messages;

    const externalConversationRecord = {
        messages: /** @type {Array<{role: string, content: string}>} */ ([]),
        sendOptions: /** @type {Array<any>} */ ([]),
    };
    const externalConversation = {
        addMessage(role, content) {
            externalConversationRecord.messages.push({ role, content });
        },
        async send(options) {
            externalConversationRecord.sendOptions.push(options);
            return { content: 'external conversation reply' };
        },
    };
    const uninitializedConversationService = new LLMService();
    const externalResponse = await uninitializedConversationService.sendConversationMessage(externalConversation, 'first user turn');
    results.externalConversationResponse = externalResponse.content;
    results.externalConversationRecord = externalConversationRecord;

    resetHarnessState();
    harnessState.conversationCreateThrows = true;
    results.conversationCreateFailure = await captureError(() => new LLMService().createConversation());

    resetHarnessState();
    harnessState.conversationSendThrows = true;
    const failingConversationService = new LLMService();
    const failingConversation = await failingConversationService.createConversation();
    results.conversationSendFailure = await captureError(() =>
        failingConversationService.sendConversationMessage(failingConversation, 'fail')
    );

    resetHarnessState();
    const modelService = new LLMService();
    results.models = await modelService.getAvailableModels();

    resetHarnessState();
    harnessState.availableThrows = true;
    results.modelsFailure = await captureError(() => new LLMService().getAvailableModels());

    const uninitialized = new LLMService();
    results.notInitializedProvider = uninitialized.getProviderName();
    results.systemPrompt = uninitialized.getSystemPrompt();
    results.readyFalse = uninitialized.isReady();
    results.statusBefore = uninitialized.getStatus();

    resetHarnessState();
    harnessState.sendQueue = [{ content: 'connection ok' }];
    results.connectionTrue = await new LLMService().testConnection();

    resetHarnessState();
    harnessState.sendQueue = [{}];
    results.connectionFalse = await new LLMService().testConnection();

    const noContentConnectionService = new LLMService();
    noContentConnectionService.sendMessage = async () => ({});
    results.connectionFalseNoContent = await noContentConnectionService.testConnection();

    resetHarnessState();
    harnessState.sendThrows = true;
    results.connectionCatch = await new LLMService().testConnection();

    return results;
}

async function runAssessmentCase() {
    resetHarnessState();
    const results = /** @type {Record<string, any>} */ ({});

    harnessState.sendQueue = [{ content: `prefix ${jsonQuestion('true-false')} suffix` }];
    results.generatedTrueFalse = await new LLMService().generateAssessmentQuestion(
        'true-false',
        'Cells contain membranes.',
        'Unit 1',
        'Explain membranes'
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: jsonQuestion('true-false') }];
    results.generatedInitialized = await makeInitializedService('openai').generateAssessmentQuestion(
        'true-false',
        'Cells contain membranes.',
        'Unit 1'
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: jsonQuestion('multiple-choice') }];
    results.generatedCustom = await new LLMService().generateAssessmentQuestion(
        'multiple-choice',
        'ATP powers cellular work.',
        'Unit 2',
        '',
        {
            multipleChoice: '{{questionType}} {{courseMaterial}} {{unitName}} {{learningObjectives}}',
            systemPrompt: 'custom {{questionType}} system',
        }
    );
    results.generatedCustomSend = harnessState.sends[0];

    resetHarnessState();
    harnessState.sendQueue = [{}];
    results.generatedEmptyFailure = await captureError(() =>
        new LLMService().generateAssessmentQuestion('short-answer', 'Material', 'Unit 3')
    );

    resetHarnessState();
    harnessState.sendQueue = [new Promise(() => {})];
    results.generatedTimeoutFailure = await withImmediateTimeout(() =>
        captureError(() => new LLMService().generateAssessmentQuestion('short-answer', 'Material', 'Unit 3'))
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: jsonQuestion('short-answer') }];
    results.regenerated = await new LLMService().regenerateAssessmentQuestion(
        'short-answer',
        'Course material',
        'Unit 4',
        'Learning goal',
        { question: 'Old question?', answer: 'Old answer' },
        'Make it clearer'
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: jsonQuestion('true-false') }];
    results.regeneratedInitialized = await makeInitializedService('openai').regenerateAssessmentQuestion(
        'true-false',
        'Course material',
        'Unit 4',
        '',
        { question: 'Old question?', answer: 'false' },
        'Make it clearer'
    );

    resetHarnessState();
    harnessState.sendQueue = [{}];
    results.regeneratedEmptyFailure = await captureError(() =>
        new LLMService().regenerateAssessmentQuestion(
            'true-false',
            'Course material',
            'Unit 5',
            '',
            { question: 'Old?', answer: 'true' },
            'Change it'
        )
    );

    resetHarnessState();
    harnessState.sendQueue = [new Promise(() => {})];
    results.regeneratedTimeoutFailure = await withImmediateTimeout(() =>
        captureError(() => new LLMService().regenerateAssessmentQuestion(
            'true-false',
            'Course material',
            'Unit 5',
            '',
            { question: 'Old?', answer: 'true' },
            'Change it'
        ))
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: 'prefix {"correct":true,"feedback":"Correct, Ada"} suffix' }];
    results.evaluationJson = await new LLMService().evaluateStudentAnswer('Q', 'A', 'A', 'short-answer', 'Ada');

    resetHarnessState();
    harnessState.sendQueue = [{ content: 'No JSON here but correct": true appears.' }];
    results.evaluationNoJson = await new LLMService().evaluateStudentAnswer('Q', 'A', 'A', 'short-answer');

    resetHarnessState();
    harnessState.sendQueue = [{ content: '{bad json}' }];
    results.evaluationInvalidJson = await new LLMService().evaluateStudentAnswer('Q', 'B', 'A', 'short-answer');

    resetHarnessState();
    harnessState.sendThrows = true;
    results.evaluationFailure = await captureError(() =>
        new LLMService().evaluateStudentAnswer('Q', 'B', 'A', 'short-answer')
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: '{"concernLevel":"medium","reason":"Needs support"}' }];
    results.mentalHealthValid = await new LLMService().analyzeMentalHealth(
        [{ role: 'user', content: 'I need help' }, { role: 'assistant', content: 'I am here' }],
        'detect'
    );

    resetHarnessState();
    harnessState.sendQueue = [{ content: '{"concernLevel":"","reason":""}' }];
    results.mentalHealthDefaults = await new LLMService().analyzeMentalHealth([{ role: 'user', content: 'ok' }], 'detect');

    resetHarnessState();
    harnessState.sendQueue = [{}];
    results.mentalHealthEmpty = await new LLMService().analyzeMentalHealth([{ role: 'user', content: 'ok' }], 'detect');

    resetHarnessState();
    harnessState.sendQueue = [{ content: 'no json' }];
    results.mentalHealthNoJson = await new LLMService().analyzeMentalHealth([{ role: 'user', content: 'ok' }], 'detect');

    resetHarnessState();
    harnessState.sendQueue = [{ content: '{bad json}' }];
    results.mentalHealthInvalidJson = await new LLMService().analyzeMentalHealth([{ role: 'user', content: 'ok' }], 'detect');

    resetHarnessState();
    harnessState.sendThrows = true;
    results.mentalHealthFailure = await new LLMService().analyzeMentalHealth([{ role: 'user', content: 'ok' }], 'detect');

    return results;
}

async function runPromptAndParseCase() {
    resetHarnessState();
    const service = new LLMService();
    const results = /** @type {Record<string, any>} */ ({});

    const customPrompts = {
        trueFalse: '{{questionType}} {{learningObjectives}} {{courseMaterial}} {{unitName}}',
        multipleChoice: '{{questionType}} {{learningObjectives}} {{courseMaterial}} {{unitName}}',
        shortAnswer: '{{questionType}} {{learningObjectives}} {{courseMaterial}} {{unitName}}',
    };
    results.customPrompts = [
        service.createQuestionGenerationPrompt('true-false', 'Material', 'Unit 1', 'LO', customPrompts),
        service.createQuestionGenerationPrompt('multiple-choice', 'Material', 'Unit 1', '', customPrompts),
        service.createQuestionGenerationPrompt('short-answer', 'Material', 'Unit 1', 'LO', customPrompts),
    ];
    results.customUnsupported = await captureError(() =>
        Promise.resolve(service.createQuestionGenerationPrompt('essay', 'Material', 'Unit 1', 'LO', customPrompts))
    );
    results.customTemplateFallback = service.createQuestionGenerationPrompt('true-false', 'Material', 'Unit 1', 'LO', {});
    results.defaultPrompts = [
        service.createQuestionGenerationPrompt('true-false', 'Material', 'Unit 1', 'LO'),
        service.createQuestionGenerationPrompt('multiple-choice', 'Material', 'Unit 1', 'LO'),
        service.createQuestionGenerationPrompt('short-answer', 'Material', 'Unit 1', 'LO'),
    ];
    results.defaultUnsupported = await captureError(() =>
        Promise.resolve(service.createQuestionGenerationPrompt('essay', 'Material', 'Unit 1'))
    );

    results.regenPrompts = [
        service.createQuestionRegenerationPrompt(
            'multiple-choice',
            'Material',
            'Unit 1',
            'LO',
            { question: 'Old?', options: { A: 'A1', B: 'B1', C: 'C1', D: 'D1' }, answer: 'A' },
            'Improve'
        ),
        service.createQuestionRegenerationPrompt('multiple-choice', 'Material', 'Unit 1', '', { options: {} }, 'Improve'),
        service.createQuestionRegenerationPrompt('true-false', 'Material', 'Unit 1', '', { question: 'Old?' }, 'Improve'),
        service.createQuestionRegenerationPrompt('short-answer', 'Material', 'Unit 1', '', { question: 'Old?' }, 'Improve'),
        service.createQuestionRegenerationPrompt('essay', 'Material', 'Unit 1', '', { question: 'Old?', answer: 'A' }, 'Improve'),
    ];

    results.schemas = [
        service.getJsonSchemaForQuestionType('true-false'),
        service.getJsonSchemaForQuestionType('multiple-choice'),
        service.getJsonSchemaForQuestionType('short-answer'),
        service.getJsonSchemaForQuestionType('essay'),
    ];

    results.parsed = {
        trueFalse: service.parseGeneratedQuestion(jsonQuestion('true-false', { type: 'different-type', correctAnswer: false }), 'true-false'),
        multipleChoice: service.parseGeneratedQuestion(jsonQuestion('multiple-choice'), 'multiple-choice'),
        shortAnswerWithPoints: service.parseGeneratedQuestion(jsonQuestion('short-answer'), 'short-answer'),
        shortAnswerWithoutPoints: service.parseGeneratedQuestion(jsonQuestion('short-answer', { keyPoints: undefined }), 'short-answer'),
        unknownType: service.parseGeneratedQuestion(
            JSON.stringify({ type: 'essay', question: 'Q?', explanation: 'E' }),
            'essay'
        ),
    };

    results.parseFallbacks = {
        noJsonTrueFalse: service.parseGeneratedQuestion('plain text', 'true-false'),
        invalidJsonMultipleChoice: service.parseGeneratedQuestion('{bad json}', 'multiple-choice'),
        missingRequiredShortAnswer: service.parseGeneratedQuestion(JSON.stringify({ type: 'short-answer' }), 'short-answer'),
        badTrueFalse: service.parseGeneratedQuestion(jsonQuestion('true-false', { correctAnswer: 'true' }), 'true-false'),
        missingMultipleChoiceFields: service.parseGeneratedQuestion(
            JSON.stringify({ type: 'multiple-choice', question: 'Q?', explanation: 'E' }),
            'multiple-choice'
        ),
        incompleteMultipleChoiceOptions: service.parseGeneratedQuestion(
            JSON.stringify({
                type: 'multiple-choice',
                question: 'Q?',
                options: { A: 'Only A' },
                correctAnswer: 'A',
                explanation: 'E',
            }),
            'multiple-choice'
        ),
        missingShortAnswerExpected: service.parseGeneratedQuestion(
            JSON.stringify({ type: 'short-answer', question: 'Q?', explanation: 'E' }),
            'short-answer'
        ),
    };

    return results;
}

async function runCase(name) {
    switch (name) {
        case 'settings-and-options':
            return runSettingsAndOptionsCase();
        case 'lifecycle':
            return runLifecycleCase();
        case 'assessment':
            return runAssessmentCase();
        case 'prompts-and-parsing':
            return runPromptAndParseCase();
        default:
            throw new Error(`Unknown LLM harness case: ${name}`);
    }
}

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/__ping', (_req, res) => res.json({ ok: true }));
app.get('/__ui', (_req, res) => {
    res.type('html').send(`<!doctype html>
<html>
<head><title>LLM service harness</title></head>
<body><main id="status">ready</main></body>
</html>`);
});

app.post('/__run', async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '');
        const data = await runCase(name);
        res.json({ ok: true, data });
    } catch (error) {
        res.status(500).json({
            ok: false,
            error: error && error.stack ? error.stack : String(error),
        });
    }
});

const port = Number(process.env.LLM_HARNESS_PORT);
const server = app.listen(port, () => {
    console.log(`[llm-service-harness] listening on ${port}`);
});

function shutdown() {
    try { v8.takeCoverage(); } catch { /* coverage disabled */ }
    try { server.close(); } catch { /* already closed */ }
    setTimeout(() => process.exit(0), 100).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
