'use strict';

// The application already loads dotenv at startup. Loading it here as well
// makes this configuration usable directly by the toolkit's migration CLI.
require('dotenv').config({ quiet: true });

const { buildChatEncryptionConfig } = require('./chatEncryption');

module.exports = buildChatEncryptionConfig(process.env);
