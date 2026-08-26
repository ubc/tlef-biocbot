'use strict';

const {
    defineEncryptionConfig,
    EnvironmentKeyProvider
} = require('@ubc/genai-toolkit-encryption');

const CHAT_ENCRYPTION_NAMESPACE = 'tlef-biocbot';
const ACTIVE_CHAT_KEY_ID = 'student-chat-2026-01';

/**
 * Build BiocBot's application-owned encryption policy.
 *
 * The first rollout intentionally protects only the opaque chatData payload.
 * Operational fields stay plaintext so existing filters, sorts, retention,
 * pseudonymization, and dashboard queries keep their current semantics.
 *
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} env
 * @returns {import('@ubc/genai-toolkit-encryption').EncryptionConfig}
 */
function buildChatEncryptionConfig(env = process.env) {
    const readPolicy = /** @type {import('@ubc/genai-toolkit-encryption').ReadPolicy} */ (
        env.BIOCBOT_CHAT_ENCRYPTION_READ_POLICY || 'mixed'
    );
    const queryPolicy = /** @type {import('@ubc/genai-toolkit-encryption').QueryPolicy} */ (
        env.BIOCBOT_CHAT_ENCRYPTION_QUERY_POLICY || 'mixed'
    );

    return defineEncryptionConfig({
        namespace: CHAT_ENCRYPTION_NAMESPACE,
        keyProvider: new EnvironmentKeyProvider({
            activeEncryptionKey: {
                id: ACTIVE_CHAT_KEY_ID,
                env: 'BIOCBOT_CHAT_ENCRYPTION_KEY'
            },
            decryptionKeys: [],
            blindIndexKeys: [],
            env
        }),
        readPolicy,
        queryPolicy,
        writePolicy: 'encrypted',
        collections: {
            chat_sessions: {
                fields: {
                    chatData: { encrypt: true }
                }
            }
        },
        database: {
            uriEnv: 'MONGO_URI'
        }
    });
}

module.exports = {
    ACTIVE_CHAT_KEY_ID,
    CHAT_ENCRYPTION_NAMESPACE,
    buildChatEncryptionConfig
};
