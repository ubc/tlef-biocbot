// @ts-check
/**
 * Helpers for scripting the in-process LLM stub from Playwright specs.
 *
 * The stub is mounted at /api/test/llm-stub when the web server is started
 * with BIOCBOT_TEST_LLM_STUB=1 (see playwright.config.js webServer command
 * and src/services/llm.js).
 *
 * Usage:
 *   const { resetLlmStub, enqueueLlmResponses } = require('./helpers/llm-stub');
 *   await resetLlmStub(api);
 *   await enqueueLlmResponses(api, ['{"correct":true,"feedback":"ok"}']);
 *   // ...then hit the route that invokes the LLM
 */

async function resetLlmStub(api) {
    const res = await api.post('/api/test/llm-stub/reset', { failOnStatusCode: false });
    if (!res.ok()) {
        const body = await res.text();
        throw new Error(`LLM stub reset failed: ${res.status()} ${body}`);
    }
}

async function enqueueLlmResponses(api, responses) {
    const list = Array.isArray(responses) ? responses : [responses];
    const normalized = list.map((r) => {
        if (r == null) return { content: '' };
        if (typeof r === 'string') return { content: r };
        if (typeof r === 'object' && 'content' in r) return { content: String(r.content) };
        return { content: JSON.stringify(r) };
    });
    const res = await api.post('/api/test/llm-stub/enqueue', {
        data: { responses: normalized },
        failOnStatusCode: false,
    });
    if (!res.ok()) {
        const body = await res.text();
        throw new Error(`LLM stub enqueue failed: ${res.status()} ${body}`);
    }
}

async function setLlmStubDefault(api, content) {
    const res = await api.post('/api/test/llm-stub/default', {
        data: { content: String(content) },
        failOnStatusCode: false,
    });
    if (!res.ok()) {
        const body = await res.text();
        throw new Error(`LLM stub default set failed: ${res.status()} ${body}`);
    }
}

async function addLlmStubRule(api, rule) {
    const payload = {};
    if (rule.matchSystemPrompt !== undefined) payload.matchSystemPrompt = String(rule.matchSystemPrompt);
    if (rule.matchMessage !== undefined) payload.matchMessage = String(rule.matchMessage);
    payload.content = typeof rule.content === 'string' ? rule.content : JSON.stringify(rule.content);
    const res = await api.post('/api/test/llm-stub/rule', {
        data: payload,
        failOnStatusCode: false,
    });
    if (!res.ok()) {
        const body = await res.text();
        throw new Error(`LLM stub rule add failed: ${res.status()} ${body}`);
    }
}

async function getLlmStubState(api) {
    const res = await api.get('/api/test/llm-stub/state', { failOnStatusCode: false });
    if (!res.ok()) {
        const body = await res.text();
        throw new Error(`LLM stub state failed: ${res.status()} ${body}`);
    }
    return res.json();
}

module.exports = {
    resetLlmStub,
    enqueueLlmResponses,
    setLlmStubDefault,
    addLlmStubRule,
    getLlmStubState,
};
