'use strict';

const TOOLKIT_PACKAGE = '@ubc/genai-toolkit-encryption';

/** @type {any} */
let encryptionToolkit;

/**
 * The toolkit is published to GitHub Packages, so an install without a registry
 * token (CI, a fresh clone) cannot fetch it — hence it being an optional
 * dependency. Requiring it lazily keeps this module importable when it is
 * absent: the server still boots and the unit suite still runs, and only a
 * deployment that has actually turned chat encryption on needs it present.
 *
 * @returns {any} The toolkit, or null when it is not installed
 */
function loadEncryptionToolkit() {
    if (encryptionToolkit === undefined) {
        try {
            encryptionToolkit = require(TOOLKIT_PACKAGE);
        } catch (error) {
            if (error.code !== 'MODULE_NOT_FOUND') {
                throw error;
            }
            encryptionToolkit = null;
        }
    }
    return encryptionToolkit;
}

/**
 * Same as loadEncryptionToolkit, for the call sites that cannot continue
 * without it: encryption was asked for, so a missing toolkit is a hard error
 * rather than a silent fall back to plaintext writes.
 *
 * @returns {any}
 */
function requireEncryptionToolkit() {
    const toolkit = loadEncryptionToolkit();
    if (toolkit) return toolkit;

    const error = new Error(
        `Student chat encryption requires ${TOOLKIT_PACKAGE}, an optional dependency published to ` +
        'GitHub Packages. Install it with a registry token, or set ' +
        'BIOCBOT_CHAT_ENCRYPTION_ENABLED=false.'
    );
    error.code = 'CHAT_ENCRYPTION_TOOLKIT_MISSING';
    throw error;
}

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
    const { defineEncryptionConfig, EnvironmentKeyProvider } = requireEncryptionToolkit();

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
    TOOLKIT_PACKAGE,
    buildChatEncryptionConfig,
    loadEncryptionToolkit,
    requireEncryptionToolkit
};
