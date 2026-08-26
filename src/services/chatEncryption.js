'use strict';

const { createEncryptedDb } = require('@ubc/genai-toolkit-encryption');
const { buildChatEncryptionConfig } = require('../config/chatEncryption');

const ENABLE_ENV = 'BIOCBOT_CHAT_ENCRYPTION_ENABLED';

/**
 * Require an explicit boolean-like value when the rollout flag is present.
 * A typo must not accidentally change whether chat payloads are encrypted.
 *
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @returns {boolean}
 */
function isChatEncryptionEnabled(env = process.env) {
    const raw = env[ENABLE_ENV];
    if (raw === undefined || raw === '') return false;

    const normalized = raw.trim().toLowerCase();
    if (normalized === 'true' || normalized === '1') return true;
    if (normalized === 'false' || normalized === '0') return false;

    throw new Error(`${ENABLE_ENV} must be true, false, 1, or 0`);
}

/**
 * Return the runtime database used by routes and services. When the feature is
 * disabled the original Db is returned unchanged. When enabled, toolkit
 * configuration and key validation happen before the wrapper is returned.
 *
 * @param {import('mongodb').Db} rawDb
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @returns {Promise<import('mongodb').Db | import('@ubc/genai-toolkit-encryption').ProtectedDb>}
 */
async function initializeChatEncryption(rawDb, env = process.env) {
    if (!isChatEncryptionEnabled(env)) {
        console.log('ℹ️ Student chat encryption is disabled');
        return rawDb;
    }

    const config = buildChatEncryptionConfig(env);
    const protectedDb = await createEncryptedDb(rawDb, config);
    console.log(
        `✅ Student chat encryption enabled (${config.readPolicy} reads, encrypted writes)`
    );
    return protectedDb;
}

module.exports = {
    ENABLE_ENV,
    initializeChatEncryption,
    isChatEncryptionEnabled
};
