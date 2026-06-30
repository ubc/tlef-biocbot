const { makeRouteApp, request } = require('../helpers/route-app');
const { getLLMStub } = require('../../../src/services/llmStub');
const router = require('../../../src/routes/testLlmStub');

const app = () => makeRouteApp(router);

beforeEach(() => getLLMStub().reset());

describe('test-only LLM stub routes', () => {
    test('enqueue accepts one or many responses and rejects empty requests', async () => {
        expect((await request(app()).post('/enqueue').send({})).status).toBe(400);
        let res = await request(app()).post('/enqueue').send({ content: 'one' });
        expect(res.body).toEqual({ success: true, queueLength: 1 });
        res = await request(app()).post('/enqueue').send({ responses: ['two', { content: 'three' }] });
        expect(res.body.queueLength).toBe(3);
    });

    test('default validates and changes fallback content', async () => {
        expect((await request(app()).post('/default').send({})).status).toBe(400);
        expect((await request(app()).post('/default').send({ content: 'fallback' })).status).toBe(200);
        await expect(getLLMStub().sendMessage('x')).resolves.toEqual({ content: 'fallback' });
    });

    test('rule validates matchers and registers a deterministic rule', async () => {
        expect((await request(app()).post('/rule').send({ matchMessage: 'x' })).status).toBe(400);
        expect((await request(app()).post('/rule').send({ content: 'reply' })).status).toBe(400);
        const res = await request(app()).post('/rule').send({ matchMessage: 'ATP', content: 'reply' });
        expect(res.body).toEqual({ success: true, ruleCount: 1 });
        await expect(getLLMStub().sendMessage('ATP')).resolves.toEqual({ content: 'reply' });
    });

    test('state reports counters and reset clears them', async () => {
        getLLMStub().enqueueContent('queued');
        await getLLMStub().sendMessage('call');
        let res = await request(app()).get('/state');
        expect(res.body).toMatchObject({ success: true, queueLength: 0, callCount: 1 });
        res = await request(app()).post('/reset');
        expect(res.body.success).toBe(true);
        expect(getLLMStub().callLog).toEqual([]);
    });
});
