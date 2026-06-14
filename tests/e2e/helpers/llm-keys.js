// @ts-check

process.env.BIOCBOT_TEST_LLM_STUB = process.env.BIOCBOT_TEST_LLM_STUB || '1';

const { buildKeySubdocument } = require('../../../src/services/llmKeyStore');

function createValidLlmApiKey(scope = 'e2e') {
    return buildKeySubdocument(`sk-test-${scope}`, 'e2e-test');
}

module.exports = {
    createValidLlmApiKey,
};
