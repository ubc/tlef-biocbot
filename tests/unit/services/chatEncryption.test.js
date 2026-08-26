/// <reference types="node" />
/// <reference types="jest" />

'use strict';

const {
    initializeChatEncryption,
    isChatEncryptionEnabled
} = require('../../../src/services/chatEncryption');
const { loadEncryptionToolkit } = require('../../../src/config/chatEncryption');

// The toolkit is an optional dependency on GitHub Packages, so an install
// without a registry token (CI, a fresh clone) does not have it. The feature
// flag and pass-through behaviour still get covered there; only the cases that
// exercise real encryption need the package present.
const describeWithToolkit = loadEncryptionToolkit() ? describe : describe.skip;

const SYNTHETIC_KEY = Buffer.alloc(32, 7).toString('base64');

/** @returns {any} */
function fakeDb() {
    return {
        collection: jest.fn(() => ({}))
    };
}

/** @returns {any} */
function memoryDb() {
    /** @type {any} */
    let storedDocument = null;
    const collection = {
        collectionName: 'chat_sessions',
        dbName: 'synthetic-encryption-test',
        async replaceOne(/** @type {any} */ _filter, /** @type {any} */ replacement) {
            storedDocument = replacement;
            return { acknowledged: true, matchedCount: 0, modifiedCount: 0, upsertedCount: 1 };
        },
        async findOne() {
            return storedDocument;
        }
    };
    return {
        collection: jest.fn(() => collection),
        getStoredDocument: () => storedDocument
    };
}

describe('student chat encryption startup', () => {
    test('is disabled by default and returns the raw database', async () => {
        const db = fakeDb();

        expect(isChatEncryptionEnabled({})).toBe(false);
        await expect(initializeChatEncryption(db, {})).resolves.toBe(db);
    });

    test.each(['true', '1', ' TRUE '])('accepts enabled value %p', (value) => {
        expect(isChatEncryptionEnabled({
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: value
        })).toBe(true);
    });

    test.each(['false', '0', ' FALSE '])('accepts disabled value %p', (value) => {
        expect(isChatEncryptionEnabled({
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: value
        })).toBe(false);
    });

    test('rejects an ambiguous feature flag', () => {
        expect(() => isChatEncryptionEnabled({
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'yes'
        })).toThrow('BIOCBOT_CHAT_ENCRYPTION_ENABLED must be true, false, 1, or 0');
    });

});

describeWithToolkit('student chat encryption with the toolkit installed', () => {
    test('fails closed when enabled without a key', async () => {
        await expect(initializeChatEncryption(fakeDb(), {
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true'
        })).rejects.toMatchObject({ code: 'KEY_NOT_FOUND' });
    });

    test('wraps chat_sessions when enabled with a valid dedicated key', async () => {
        const protectedDb = /** @type {any} */ (await initializeChatEncryption(fakeDb(), {
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true',
            BIOCBOT_CHAT_ENCRYPTION_KEY: SYNTHETIC_KEY
        }));

        expect(protectedDb).not.toBeNull();
        expect(protectedDb.isProtected('chat_sessions')).toBe(true);
        expect(protectedDb.isProtected('courses')).toBe(false);
        expect(protectedDb.encryptionConfig.readPolicy).toBe('mixed');
        expect(protectedDb.encryptionConfig.writePolicy).toBe('encrypted');
    });

    test('stores an envelope while returning the original chat payload', async () => {
        const rawDb = memoryDb();
        const protectedDb = /** @type {any} */ (await initializeChatEncryption(rawDb, {
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true',
            BIOCBOT_CHAT_ENCRYPTION_KEY: SYNTHETIC_KEY
        }));
        const chats = protectedDb.collection('chat_sessions');
        const plaintext = {
            sessionId: 'synthetic-session',
            courseId: 'SYNTH-101',
            chatData: {
                messages: [{ type: 'user', content: 'synthetic question' }]
            }
        };

        await chats.replaceOne({ sessionId: plaintext.sessionId }, plaintext, { upsert: true });

        const stored = rawDb.getStoredDocument();
        expect(stored.sessionId).toBe('synthetic-session');
        expect(stored.chatData).toMatchObject({
            __ubc_enc: 1,
            alg: 'A256GCM',
            kid: 'student-chat-2026-01'
        });
        expect(stored.chatData.messages).toBeUndefined();
        expect(stored.chatData.iv.buffer).toHaveLength(12);
        expect(stored.chatData.tag.buffer).toHaveLength(16);

        const found = await chats.findOne({ sessionId: plaintext.sessionId });
        expect(found).toEqual(plaintext);
    });

    test('validates rollout policy values before returning a database', async () => {
        await expect(initializeChatEncryption(fakeDb(), {
            BIOCBOT_CHAT_ENCRYPTION_ENABLED: 'true',
            BIOCBOT_CHAT_ENCRYPTION_KEY: SYNTHETIC_KEY,
            BIOCBOT_CHAT_ENCRYPTION_READ_POLICY: 'lenient'
        })).rejects.toMatchObject({ code: 'CONFIGURATION_ERROR' });
    });
});
