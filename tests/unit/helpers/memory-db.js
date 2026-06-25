/**
 * In-memory MongoDB collection/db doubles for unit tests.
 *
 * This is a self-contained reimplementation of the MemoryCollection pattern used
 * by tests/e2e/helpers/src-route-model-harness.js — intentionally NOT imported
 * from there, because that harness boots a live Express server on require. Unit
 * tests need a side-effect-free fake.
 *
 * Supported query operators: $or, $and, $ne, $in, $nin, $exists, $size,
 * $gt/$gte/$lt/$lte, dotted field paths, and Mongo's "scalar matches an array by
 * membership" rule. Supported update operators: $set, $setOnInsert (on upsert),
 * $addToSet (with $each), $pull (scalar or sub-document match), $push (with $each).
 * Just enough for the model/service helpers under test — not a full Mongo.
 */

// Realm-local deep clone. We deliberately avoid structuredClone here: under
// jest-environment-node it produces Date objects from the host realm, so
// `instanceof Date` fails against the sandbox's Date. Rebuilding Dates with the
// local constructor keeps assertions like toBeInstanceOf(Date) honest.
function clone(value) {
    if (value === null || typeof value !== 'object') return value;
    if (value instanceof Date) return new Date(value.getTime());
    if (Array.isArray(value)) return value.map(clone);
    const out = {};
    for (const [key, val] of Object.entries(value)) out[key] = clone(val);
    return out;
}

function getPath(obj, path) {
    if (obj == null) return undefined;
    if (path.indexOf('.') === -1) return obj[path];
    return path.split('.').reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

function setPath(obj, path, value) {
    if (path.indexOf('.') === -1) {
        obj[path] = value;
        return;
    }
    const keys = path.split('.');
    const last = keys.pop();
    let cursor = obj;
    for (const key of keys) {
        if (cursor[key] == null || typeof cursor[key] !== 'object') cursor[key] = {};
        cursor = cursor[key];
    }
    cursor[last] = value;
}

function matchesOperators(docValue, cond) {
    return Object.entries(cond).every(([op, val]) => {
        switch (op) {
            case '$ne':
                return Array.isArray(docValue) ? !docValue.includes(val) : docValue !== val;
            case '$in':
                return Array.isArray(docValue)
                    ? docValue.some((v) => val.includes(v))
                    : val.includes(docValue);
            case '$nin':
                return !val.includes(docValue);
            case '$exists':
                return (docValue !== undefined) === val;
            case '$size':
                return Array.isArray(docValue) && docValue.length === val;
            case '$gt': return docValue > val;
            case '$gte': return docValue >= val;
            case '$lt': return docValue < val;
            case '$lte': return docValue <= val;
            default:
                return false;
        }
    });
}

function matchesField(docValue, cond) {
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
        return matchesOperators(docValue, cond);
    }
    // Mongo: a scalar query against an array field matches by membership.
    if (Array.isArray(docValue)) return docValue.includes(cond);
    return docValue === cond;
}

function matchesQuery(doc, query = {}) {
    return Object.entries(query).every(([key, cond]) => {
        if (key === '$or') return Array.isArray(cond) && cond.some((sub) => matchesQuery(doc, sub));
        if (key === '$and') return Array.isArray(cond) && cond.every((sub) => matchesQuery(doc, sub));
        return matchesField(getPath(doc, key), cond);
    });
}

function pullMatches(item, cond) {
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
        return Object.entries(cond).every(([k, v]) => item && item[k] === v);
    }
    return item === cond;
}

function applyUpdate(doc, update, { isInsert = false } = {}) {
    let modified = false;
    const sets = { ...(update.$set || {}), ...(isInsert ? update.$setOnInsert || {} : {}) };
    for (const [key, value] of Object.entries(sets)) {
        setPath(doc, key, value);
        modified = true;
    }
    for (const [key, value] of Object.entries(update.$addToSet || {})) {
        let arr = getPath(doc, key);
        if (!Array.isArray(arr)) { arr = []; setPath(doc, key, arr); }
        const values = value && value.$each ? value.$each : [value];
        for (const v of values) {
            if (!arr.includes(v)) { arr.push(v); modified = true; }
        }
    }
    for (const [key, cond] of Object.entries(update.$pull || {})) {
        const arr = getPath(doc, key);
        if (Array.isArray(arr)) {
            const kept = arr.filter((item) => !pullMatches(item, cond));
            if (kept.length !== arr.length) { setPath(doc, key, kept); modified = true; }
        }
    }
    for (const [key, value] of Object.entries(update.$push || {})) {
        let arr = getPath(doc, key);
        if (!Array.isArray(arr)) { arr = []; setPath(doc, key, arr); }
        const values = value && value.$each ? value.$each : [value];
        arr.push(...values);
        modified = true;
    }
    return modified;
}

function seedFromQuery(doc, query = {}) {
    for (const [key, value] of Object.entries(query)) {
        if (key.startsWith('$')) continue;
        if (value && typeof value === 'object' && !Array.isArray(value)) continue; // operator object
        setPath(doc, key, value);
    }
}

function compareValues(a, b) {
    // null/undefined sort last in ascending order.
    if (a == null && b == null) return 0;
    if (a == null) return 1;
    if (b == null) return -1;
    if (typeof a === 'string' && typeof b === 'string') return a.localeCompare(b);
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

function sortRows(rows, spec = {}) {
    const entries = Object.entries(spec);
    return rows.slice().sort((a, b) => {
        for (const [key, dir] of entries) {
            const cmp = compareValues(getPath(a, key), getPath(b, key));
            if (cmp !== 0) return dir < 0 ? -cmp : cmp;
        }
        return 0;
    });
}

class MemoryCollection {
    constructor(docs = []) {
        this.docs = docs.map(clone);
    }

    async findOne(query) {
        const found = this.docs.find((doc) => matchesQuery(doc, query || {}));
        return found ? clone(found) : null;
    }

    find(query) {
        let rows = this.docs.filter((doc) => matchesQuery(doc, query || {})).map(clone);
        const cursor = {
            project: () => cursor,
            projection: () => cursor,
            sort: (spec) => { rows = sortRows(rows, spec); return cursor; },
            limit: (n) => { rows = rows.slice(0, n); return cursor; },
            skip: (n) => { rows = rows.slice(n); return cursor; },
            toArray: async () => rows,
        };
        return cursor;
    }

    async insertOne(doc) {
        const stored = clone(doc);
        this.docs.push(stored);
        return { acknowledged: true, insertedId: stored._id || `mem-${this.docs.length}` };
    }

    async insertMany(docs = []) {
        for (const doc of docs) this.docs.push(clone(doc));
        return { acknowledged: true, insertedCount: docs.length };
    }

    async updateOne(query, update, options = {}) {
        const target = this.docs.find((doc) => matchesQuery(doc, query || {}));
        if (target) {
            const modified = applyUpdate(target, update);
            return { matchedCount: 1, modifiedCount: modified ? 1 : 0, upsertedCount: 0 };
        }
        if (options.upsert) {
            const fresh = {};
            seedFromQuery(fresh, query);
            applyUpdate(fresh, update, { isInsert: true });
            this.docs.push(fresh);
            return { matchedCount: 0, modifiedCount: 0, upsertedCount: 1, upsertedId: fresh._id || 'mem-upsert' };
        }
        return { matchedCount: 0, modifiedCount: 0, upsertedCount: 0 };
    }

    async updateMany(query, update) {
        const targets = this.docs.filter((doc) => matchesQuery(doc, query || {}));
        let modifiedCount = 0;
        for (const target of targets) {
            if (applyUpdate(target, update)) modifiedCount += 1;
        }
        return { matchedCount: targets.length, modifiedCount };
    }

    async deleteOne(query) {
        const index = this.docs.findIndex((doc) => matchesQuery(doc, query || {}));
        if (index === -1) return { deletedCount: 0 };
        this.docs.splice(index, 1);
        return { deletedCount: 1 };
    }

    async deleteMany(query = {}) {
        const before = this.docs.length;
        this.docs = this.docs.filter((doc) => !matchesQuery(doc, query));
        return { deletedCount: before - this.docs.length };
    }

    async countDocuments(query = {}) {
        return this.docs.filter((doc) => matchesQuery(doc, query)).length;
    }

    async createIndex() {
        return 'ok';
    }
}

/**
 * Build a fake db. Pass a map of collectionName -> array-of-docs (or
 * MemoryCollection) to seed; unknown collections are created empty on first use.
 */
function memoryDb(seed = {}) {
    const collections = {};
    for (const [name, value] of Object.entries(seed)) {
        collections[name] = value instanceof MemoryCollection ? value : new MemoryCollection(value);
    }
    return {
        collection(name) {
            if (!collections[name]) collections[name] = new MemoryCollection();
            return collections[name];
        },
        _collections: collections,
    };
}

module.exports = { MemoryCollection, memoryDb, matchesQuery };
