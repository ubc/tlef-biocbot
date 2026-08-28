/**
 * Public load-balancer probes. Responses deliberately contain only a status.
 * Mount before body parsing, sessions and authentication.
 *
 * /live checks the process only. / and /ready check application readiness,
 * not the availability of every scoped LLM provider or external integration.
 */
const express = require('express');
const { QdrantClient } = require('@qdrant/js-client-rest');
const config = require('../services/config');
const { isChatEncryptionEnabled } = require('../services/chatEncryption');

const PROBE_TIMEOUT_MS = 2000;
const CACHE_TTL_MS = 5000;

// The driver/client timeouts cancel their I/O. This additional deadline keeps
// the HTTP response bounded even if an unexpected operation never settles.
function withTimeout(promise, timeoutMs) {
    let timer;
    const timeout = new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Health probe timed out')), timeoutMs);
    });
    return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * @param {Object} deps
 * @param {() => import('mongodb').Db | undefined} deps.getRawDb Driver Db,
 *   before the chat-encryption wrapper replaces app.locals.db.
 * @param {number} [deps.probeTimeoutMs] Dependency and response deadline.
 * @param {number} [deps.cacheTtlMs] Cache lifetime for both success and failure.
 */
function createHealthRouter({ getRawDb, probeTimeoutMs = PROBE_TIMEOUT_MS, cacheTtlMs = CACHE_TTL_MS }) {
    const router = express.Router();
    let qdrantClient;
    let cached;
    let inFlight;
    let lastFailures;

    function sendStatus(res, statusCode, status) {
        // Avoid Express's automatic ETag/304 handling: probes must receive a
        // fresh 200 or 503 even when a caller sends conditional headers.
        res.status(statusCode).type('json').end(JSON.stringify({ status }));
    }

    function sendReadiness(res, failures) {
        // Log only fixed check names on transitions, never upstream errors or
        // credentials. No internal details are serialized into the response.
        const failureKey = failures.join(', ');
        if (failureKey !== lastFailures) {
            if (failureKey) console.warn(`[health] Readiness checks failed: ${failureKey}`);
            else if (lastFailures) console.info('[health] Readiness recovered');
            lastFailures = failureKey;
        }
        sendStatus(res, failures.length ? 503 : 200, failures.length ? 'unhealthy' : 'healthy');
    }

    async function checkDependency(name, run) {
        try {
            await withTimeout(Promise.resolve().then(run), probeTimeoutMs);
            return null;
        } catch {
            return name;
        }
    }

    async function checkDependencies(rawDb) {
        const results = await Promise.all([
            checkDependency('mongodb', () => rawDb.admin().ping({ timeoutMS: probeTimeoutMs })),
            checkDependency('qdrant', async () => {
                if (!qdrantClient) {
                    const vectorConfig = config.getVectorDBConfig();
                    qdrantClient = new QdrantClient({
                        url: process.env.QDRANT_URL || `http://${vectorConfig.host}:${vectorConfig.port}`,
                        apiKey: process.env.QDRANT_API_KEY || undefined,
                        timeout: probeTimeoutMs,
                        checkCompatibility: false
                    });
                }
                // Read-only reachability: no embeddings, inference, collection
                // creation, or assumptions about provider-specific names.
                await qdrantClient.getCollections();
            })
        ]);
        return results.filter(Boolean);
    }

    function dependencyFailures(rawDb) {
        if (cached && Date.now() < cached.expiresAt) return Promise.resolve(cached.failures);
        if (!inFlight) {
            inFlight = checkDependencies(rawDb)
                .then(failures => {
                    cached = { failures, expiresAt: Date.now() + cacheTtlMs };
                    return failures;
                })
                .finally(() => { inFlight = null; });
        }
        return inFlight;
    }

    router.use((_req, res, next) => {
        // Internal probe caching is intentional; HTTP intermediaries must not
        // cache a success and keep routing traffic to an unavailable instance.
        res.set('Cache-Control', 'no-store');
        next();
    });

    router.get('/live', (_req, res) => {
        sendStatus(res, 200, 'ok');
    });

    router.get(['/', '/ready'], async (req, res) => {
        try {
            const { locals } = req.app;
            const failures = [];
            // Local gates are checked on every request, even with a cached
            // dependency result. Startup includes migrations and encryption.
            if (locals.startupComplete !== true) failures.push('startup');
            if (!locals.passport || !locals.authService) failures.push('auth');
            if (!locals.llmRegistry) failures.push('llmRegistry');
            const rawDb = getRawDb();
            if (!rawDb || !locals.db) failures.push('mongodb');
            if (isChatEncryptionEnabled() && (!locals.db || locals.db === rawDb)) {
                failures.push('encryption');
            }
            if (failures.length) return sendReadiness(res, failures);
            sendReadiness(res, await dependencyFailures(rawDb));
        } catch {
            sendReadiness(res, ['initialization']);
        }
    });

    return router;
}

module.exports = { createHealthRouter };
