#!/usr/bin/env node

require('dotenv').config();

const { MongoClient } = require('mongodb');
const { grantSystemAdminByEmail } = require('../src/services/systemAdmin');
const { normalizeEmail } = require('../src/services/authorization');

async function main() {
    const email = normalizeEmail(process.argv[2]);
    const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;
    const dbName = process.env.DB_NAME || process.env.MONGO_DB_NAME;

    if (!email) {
        throw new Error('Usage: node scripts/grant-system-admin.js <email>');
    }

    if (!mongoUri) {
        throw new Error('MONGO_URI is required to grant system admin access.');
    }

    const client = new MongoClient(mongoUri);

    try {
        await client.connect();

        const db = dbName ? client.db(dbName) : client.db();
        const result = await grantSystemAdminByEmail(db, email, {
            grantedBy: 'bootstrap-script'
        });

        if (!result.success) {
            throw new Error(result.error || 'Failed to grant system admin access.');
        }

        console.log(`Granted system admin access to existing user ${email}.`);
    } finally {
        await client.close();
    }
}

main().catch(error => {
    console.error(error.message || error);
    process.exit(1);
});
