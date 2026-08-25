const models = require('../../../src/services/llmModels');

describe('provider-aware LLM model catalog', () => {
    test('reuses exact built-in reasoning capabilities through the Proxy', () => {
        expect(models.knownReasoningEffortsForModel('qwen3.6-35b-a3b'))
            .toEqual(['none', 'low', 'medium', 'high']);
        expect(models.knownDefaultReasoningEffortForModel('qwen3.6-35b-a3b')).toBe('none');
        expect(models.knownReasoningEffortsForModel('unlisted-proxy-model')).toBeNull();
        expect(models.knownDefaultReasoningEffortForModel('unlisted-proxy-model')).toBeNull();
    });

    test('exposes the OpenAI catalog and preserves existing reasoning rules', () => {
        const catalog = models.catalogForProvider('openai', 'gpt-5-nano');
        expect(catalog.defaultModel).toBe('gpt-5-nano');
        expect(catalog.allowedModels).toContain('gpt-4.1-mini');
        expect(catalog.reasoningEffortsByModel['gpt-5-nano']).toEqual(['minimal', 'low', 'medium', 'high']);
        expect(catalog.reasoningEffortsByModel['gpt-5.6-luna'])
            .toEqual(['none', 'low', 'medium', 'high', 'xhigh', 'max']);
        expect(catalog.defaultReasoningEffortByModel).toMatchObject({
            'gpt-5-nano': 'minimal',
            'gpt-5.4-nano': 'low',
            'gpt-5.6-luna': 'low'
        });
        expect(models.normalizeReasoningEffort('openai', 'gpt-5.4-nano', 'minimal')).toBe('low');
        expect(models.supportsReasoning('openai', 'gpt-4.1-mini')).toBe(false);
    });

    test('exposes b3000 sandbox models and safe defaults', () => {
        const catalog = models.catalogForProvider('ubc-llm-sandbox', 'qwen3.6-35b-a3b');
        expect(catalog.allowedModels).toEqual(['qwen3.6-35b-a3b', 'gpt-oss-120b']);
        expect(catalog.defaultReasoningEffortByModel).toEqual({
            'qwen3.6-35b-a3b': 'none',
            'gpt-oss-120b': 'low'
        });
        expect(models.normalizeReasoningEffort('ubc-llm-sandbox', 'qwen3.6-35b-a3b')).toBe('none');
        expect(models.normalizeReasoningEffort('ubc-llm-sandbox', 'gpt-oss-120b', 'minimal')).toBe('low');
        expect(models.maxOutputTokensForModel('ubc-llm-sandbox', 'qwen3.6-35b-a3b')).toBe(4096);
        expect(models.maxOutputTokensForModel('ubc-llm-sandbox', 'gpt-oss-120b')).toBeNull();
    });

    test('keeps the sandbox restricted to its approved BiocBot chat models', () => {
        const catalog = models.catalogForProvider('ubc-llm-sandbox', 'future-model');
        expect(catalog.defaultModel).toBe('qwen3.6-35b-a3b');
        expect(catalog.allowedModels).toEqual(['qwen3.6-35b-a3b', 'gpt-oss-120b']);
        expect(catalog.allowedModels).not.toContain('future-model');
    });

    test('uses exact discovered proxy ids for both flat admin selectors and has no defaults', () => {
        const discovered = ['openai/gpt-5.6-luna:2026-08-01', 'vendor/embed.model-v2'];
        const catalog = models.adminCatalogForProvider('ubc-llm-proxy', discovered);

        expect(catalog.defaultModel).toBeNull();
        expect(catalog.defaultEmbeddingModel).toBeNull();
        expect(catalog.allowedModels).toEqual(discovered);
        expect(catalog.allowedEmbeddingModels).toEqual(discovered);
        expect(catalog.reasoningEffortsByModel[discovered[0]])
            .toEqual(['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max']);
    });

    test('limits Ollama selection to its configured local model', () => {
        expect(models.catalogForProvider('ollama', 'llama3.1')).toMatchObject({
            defaultModel: 'llama3.1',
            allowedModels: ['llama3.1']
        });
    });
});
