#!/usr/bin/env node
'use strict';

require('dotenv').config({ quiet: true });

const { randomBytes } = require('node:crypto');
const { MongoClient } = require('mongodb');
const {
    buildChatEncryptionConfig,
    requireEncryptionToolkit,
    ENCRYPTED_CHAT_COLLECTIONS
} = require('../src/config/chatEncryption');

/**
 * The synthetic document each collection is probed with. Only `chatData` is
 * configured for encryption; the operational fields around it must survive as
 * plaintext so existing filters and sorts keep working.
 *
 * @param {string} collectionName
 */
function syntheticDocument(collectionName) {
    return {
        sessionId: `synthetic-canary-session-${collectionName}`,
        courseId: 'SYNTH-101',
        studentId: 'synthetic-student',
        instructorId: 'synthetic-instructor',
        superchatId: 'synthetic-superchat',
        isDeleted: false,
        savedAt: new Date().toISOString(),
        chatData: {
            messages: [
                { type: 'user', content: 'Synthetic student question' },
                { type: 'bot', content: 'Synthetic BiocBot answer' }
            ]
        }
    };
}

async function main() {
    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI is required for the synthetic encryption canary');
    }

    const { createEncryptedDb } = requireEncryptionToolkit();

    const databaseName = `biocbot-encryption-canary-${process.pid}-${Date.now()}`;
    const client = new MongoClient(process.env.MONGO_URI);
    let canaryDb;

    try {
        await client.connect();
        canaryDb = client.db(databaseName);

        const config = buildChatEncryptionConfig({
            ...process.env,
            BIOCBOT_CHAT_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
            BIOCBOT_CHAT_ENCRYPTION_READ_POLICY: 'mixed',
            BIOCBOT_CHAT_ENCRYPTION_QUERY_POLICY: 'mixed'
        });
        const protectedDb = await createEncryptedDb(canaryDb, config);

        // Every configured collection is probed, not just the first one. A
        // collection added to the policy but missed here would otherwise pass a
        // green canary while writing plaintext in production.
        const report = {
            database: databaseName,
            collections: {}
        };

        for (const collectionName of ENCRYPTED_CHAT_COLLECTIONS) {
            const protectedChats = protectedDb.collection(collectionName);
            const rawChats = canaryDb.collection(collectionName);
            const document = syntheticDocument(collectionName);

            await protectedChats.insertOne(document);
            const raw = await rawChats.findOne({ sessionId: document.sessionId });
            const roundTrip = await protectedChats.findOne({ sessionId: document.sessionId });
            const envelope = raw?.chatData;
            const collectionReport = {
                isProtected: protectedDb.isProtected(collectionName),
                operationalFieldsRemainQueryable:
                    raw?.sessionId === document.sessionId && raw?.courseId === document.courseId,
                storedChatData: {
                    isEnvelope: envelope?.__ubc_enc === 1,
                    version: envelope?.__ubc_enc,
                    algorithm: envelope?.alg,
                    keyId: envelope?.kid,
                    ivBytes: envelope?.iv?.buffer?.length,
                    tagBytes: envelope?.tag?.buffer?.length,
                    hasCiphertext: (envelope?.ct?.buffer?.length || 0) > 0,
                    plaintextMessagesPresent: Object.prototype.hasOwnProperty.call(
                        envelope || {},
                        'messages'
                    )
                },
                protectedReadMatches:
                    JSON.stringify(roundTrip?.chatData) === JSON.stringify(document.chatData)
            };
            report.collections[collectionName] = collectionReport;

            if (
                !collectionReport.isProtected ||
                !collectionReport.operationalFieldsRemainQueryable ||
                !collectionReport.storedChatData.isEnvelope ||
                collectionReport.storedChatData.plaintextMessagesPresent ||
                !collectionReport.protectedReadMatches
            ) {
                throw new Error(
                    `synthetic encryption canary did not meet its assertions for ${collectionName}`
                );
            }
        }

        console.log(JSON.stringify(report, null, 2));
    } finally {
        if (canaryDb) {
            await canaryDb.dropDatabase();
            console.log(`Removed synthetic canary database: ${databaseName}`);
        }
        await client.close();
    }
}

if (require.main === module) {
    main().catch((error) => {
        console.error(error.message);
        process.exitCode = 1;
    });
}
