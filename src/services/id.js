const crypto = require('crypto');

function createId(prefix) {
    if (typeof prefix !== 'string' || !/^[a-z][a-z0-9-]*$/i.test(prefix)) {
        throw new TypeError('ID prefix must be a non-empty alphanumeric label');
    }
    if (typeof crypto.randomUUID === 'function') {
        return `${prefix}_${crypto.randomUUID()}`;
    }
    return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
}

module.exports = { createId };
