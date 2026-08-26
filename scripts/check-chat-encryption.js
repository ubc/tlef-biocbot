#!/usr/bin/env node
'use strict';

require('dotenv').config({ quiet: true });

const { randomBytes } = require('node:crypto');
const { MongoClient } = require('mongodb');
const {
    buildChatEncryptionConfig,
    requireEncryptionToolkit
} = require('../src/config/chatEncryption');

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
        const protectedChats = protectedDb.collection('chat_sessions');
        const rawChats = canaryDb.collection('chat_sessions');
        const document = {
            sessionId: 'synthetic-canary-session',
            courseId: 'SYNTH-101',
            studentId: 'synthetic-student',
            savedAt: new Date().toISOString(),
            chatData: {
                messages: [
                    { type: 'user', content: 'Synthetic student question' },
                    { type: 'bot', content: 'Synthetic BiocBot answer' }
                ]
            }
        };

        await protectedChats.insertOne(document);
        const raw = await rawChats.findOne({ sessionId: document.sessionId });
        const roundTrip = await protectedChats.findOne({ sessionId: document.sessionId });
        const envelope = raw?.chatData;
        const report = {
            database: databaseName,
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

        if (
            !report.operationalFieldsRemainQueryable ||
            !report.storedChatData.isEnvelope ||
            report.storedChatData.plaintextMessagesPresent ||
            !report.protectedReadMatches
        ) {
            throw new Error('synthetic encryption canary did not meet its assertions');
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
