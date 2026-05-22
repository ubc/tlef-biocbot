/**
 * Test-only routes for scripting the LLM stub from Playwright specs.
 *
 * Only mounted by src/server.js when BIOCBOT_TEST_LLM_STUB=1. These routes
 * are unauthenticated by design — they exist only in test runs to let the
 * e2e suite enqueue/reset scripted responses for the in-process LLM stub.
 */

const express = require('express');
const { getLLMStub } = require('../services/llmStub');

const router = express.Router();

router.post('/enqueue', (req, res) => {
    const stub = getLLMStub();
    const { content, responses } = req.body || {};
    if (Array.isArray(responses)) {
        stub.enqueueMany(responses);
    } else if (content !== undefined) {
        stub.enqueueContent(content);
    } else {
        return res.status(400).json({ success: false, message: 'Provide `content` or `responses`' });
    }
    return res.json({ success: true, queueLength: stub.queue.length });
});

router.post('/reset', (_req, res) => {
    const stub = getLLMStub();
    stub.reset();
    return res.json({ success: true });
});

router.post('/default', (req, res) => {
    const stub = getLLMStub();
    const { content } = req.body || {};
    if (content === undefined) {
        return res.status(400).json({ success: false, message: 'Provide `content`' });
    }
    stub.setDefaultContent(content);
    return res.json({ success: true });
});

router.post('/rule', (req, res) => {
    const stub = getLLMStub();
    const { matchSystemPrompt, matchMessage, content } = req.body || {};
    if (content === undefined) {
        return res.status(400).json({ success: false, message: 'Provide `content`' });
    }
    if (matchSystemPrompt === undefined && matchMessage === undefined) {
        return res.status(400).json({ success: false, message: 'Provide matchSystemPrompt or matchMessage' });
    }
    try {
        stub.addRule({ matchSystemPrompt, matchMessage, content });
    } catch (err) {
        return res.status(400).json({ success: false, message: err.message });
    }
    return res.json({ success: true, ruleCount: stub.rules.length });
});

router.get('/state', (_req, res) => {
    const stub = getLLMStub();
    return res.json({
        success: true,
        queueLength: stub.queue.length,
        defaultContent: stub.defaultContent,
        callCount: stub.callLog.length,
    });
});

module.exports = router;
