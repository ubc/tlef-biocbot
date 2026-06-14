const {
    LlmKeyError,
    structuredKeyError
} = require('../services/llmKeyStore');

function sendLlmKeyError(res, error) {
    if (!(error instanceof LlmKeyError) && !error?.code?.startsWith?.('LLM_KEY_')) {
        return false;
    }

    const status = error.status || 'missing';
    res.status(error.httpStatus || 403).json(structuredKeyError(status));
    return true;
}

async function resolveCourseAi(req, res, courseId) {
    try {
        const registry = req.app.locals.llmRegistry;
        if (!registry) {
            res.status(503).json({ success: false, message: 'LLM registry is not initialized' });
            return null;
        }
        return await registry.forCourse(req.app.locals.db, courseId);
    } catch (error) {
        if (sendLlmKeyError(res, error)) return null;
        throw error;
    }
}

async function resolveSuperchatAi(req, res, superchatId) {
    try {
        const registry = req.app.locals.llmRegistry;
        if (!registry) {
            res.status(503).json({ success: false, message: 'LLM registry is not initialized' });
            return null;
        }
        return await registry.forSuperchat(req.app.locals.db, superchatId);
    } catch (error) {
        if (sendLlmKeyError(res, error)) return null;
        throw error;
    }
}

async function resolveNotesAi(req, res) {
    try {
        const registry = req.app.locals.llmRegistry;
        if (!registry) {
            res.status(503).json({ success: false, message: 'LLM registry is not initialized' });
            return null;
        }
        return await registry.forNotes(req.app.locals.db);
    } catch (error) {
        if (sendLlmKeyError(res, error)) return null;
        throw error;
    }
}

module.exports = {
    resolveCourseAi,
    resolveNotesAi,
    resolveSuperchatAi,
    sendLlmKeyError
};
