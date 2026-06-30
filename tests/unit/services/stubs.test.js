const { EmbeddingsStub, bagOfWordsEmbedding } = require('../../../src/services/embeddingsStub');
const { LLMStub, getLLMStub } = require('../../../src/services/llmStub');

describe('EmbeddingsStub', () => {
    test('creates deterministic normalized vectors with shared-token similarity', async () => {
        const stub = new EmbeddingsStub({ vectorSize: 16 });
        const [first] = await stub.embed('ATP ATP enzyme');
        const [same] = await stub.embed('ATP ATP enzyme');
        expect(first).toEqual(same);
        expect(first).toHaveLength(16);
        expect(Math.sqrt(first.reduce((sum, value) => sum + value ** 2, 0))).toBeCloseTo(1);
    });

    test('embeds arrays and gives empty text a stable non-zero vector', async () => {
        const stub = new EmbeddingsStub({ vectorSize: 4 });
        expect(await stub.embed(['ATP', 'DNA'])).toHaveLength(2);
        expect(bagOfWordsEmbedding('---', 4)).toEqual([1, 0, 0, 0]);
    });

    test('uses the production-compatible default dimension', () => {
        expect(new EmbeddingsStub().vectorSize).toBe(1536);
        expect(new EmbeddingsStub({ vectorSize: '8' }).vectorSize).toBe(8);
    });
});

describe('LLMStub', () => {
    test('serves queued, default, and normalized response content', async () => {
        const stub = new LLMStub();
        stub.enqueueContent(null);
        stub.enqueueMany(['second', { content: 'third' }, { answer: 4 }, null]);
        stub.setDefaultContent('fallback');
        await expect(stub.sendMessage('one')).resolves.toEqual({ content: '' });
        await expect(stub.sendMessage('two')).resolves.toEqual({ content: 'second' });
        await expect(stub.sendMessage('three')).resolves.toEqual({ content: 'third' });
        await expect(stub.sendMessage('four')).resolves.toEqual({ content: '{"answer":4}' });
        await expect(stub.sendMessage('five')).resolves.toEqual({ content: 'fallback' });
        expect(stub.callLog).toHaveLength(5);
    });

    test('rules match message and system prompt before the queue', async () => {
        const stub = new LLMStub();
        expect(() => stub.addRule({ content: 'x' })).toThrow('rule needs');
        stub.enqueueContent('queued');
        stub.addRule({ matchMessage: 'ATP', matchSystemPrompt: 'Tutor', content: 'rule reply' });
        await expect(stub.sendMessage('Explain ATP', { systemPrompt: 'Tutor mode' })).resolves.toEqual({ content: 'rule reply' });
        await expect(stub.sendMessage('Explain DNA', { systemPrompt: 'Tutor mode' })).resolves.toEqual({ content: 'queued' });
    });

    test('sendConversation selects the newest user message', async () => {
        const stub = new LLMStub();
        stub.addRule({ matchMessage: 'latest', content: 'matched' });
        const result = await stub.sendConversation([
            { role: 'user', content: 'old' },
            { role: 'assistant', content: 'reply' },
            { role: 'user', content: 'latest question' },
        ]);
        expect(result).toEqual({ content: 'matched' });
        expect(stub.callLog[0].kind).toBe('sendConversation');
    });

    test('conversation records messages and uses its latest user content', async () => {
        const stub = new LLMStub();
        stub.addRule({ matchMessage: 'question', content: 'answer' });
        const conversation = stub.createConversation();
        conversation.addMessage('system', 'system');
        conversation.addMessage('user', 'question');
        await expect(conversation.send({ temperature: 0 })).resolves.toEqual({ content: 'answer' });
        expect(conversation.messages).toHaveLength(2);
        expect(stub.callLog[0]).toMatchObject({ kind: 'conversation.send', options: { temperature: 0 } });
    });

    test('reset restores state and metadata methods mirror the toolkit', async () => {
        const stub = new LLMStub();
        stub.enqueueContent('x');
        stub.addRule({ matchMessage: 'x', content: 'y' });
        await stub.sendMessage('x');
        stub.reset();
        expect(stub).toMatchObject({ queue: [], rules: [], defaultContent: '{}', callLog: [] });
        expect(stub.getProviderName()).toBe('test-stub');
        await expect(stub.getAvailableModels()).resolves.toEqual(['test-stub-model']);
    });

    test('getLLMStub returns a singleton', () => {
        expect(getLLMStub()).toBe(getLLMStub());
    });
});
