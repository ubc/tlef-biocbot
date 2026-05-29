/**
 * SuperChatNote Model
 * Platform-level shared instructor notes that feed into Super Chat retrieval.
 * These live independently of any single course (no courseId) and are stored
 * both in MongoDB (this model) and in a dedicated Qdrant collection (vectors).
 */

const COLLECTION_NAME = 'superchat_notes';
const CONTENT_SOFT_LIMIT = 5000;

function getCollection(db) {
    return db.collection(COLLECTION_NAME);
}

/**
 * Generate a unique note ID
 * @returns {string} Note ID in format "note_[timestamp]_[random]"
 */
function generateNoteId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 11);
    return `note_${timestamp}_${random}`;
}

/**
 * Derive a title from the first sentence of the content when none is provided.
 * @param {string} content
 * @returns {string}
 */
function autoGenerateTitle(content) {
    const clean = String(content || '').trim().replace(/\s+/g, ' ');
    if (!clean) return 'Untitled note';
    // First sentence (up to . ! ? or newline), capped at 80 chars.
    const match = clean.match(/^.*?[.!?](\s|$)/);
    const firstSentence = (match ? match[0] : clean).trim();
    const title = firstSentence.length > 80 ? `${firstSentence.slice(0, 77).trim()}...` : firstSentence;
    return title || 'Untitled note';
}

function normalizeTags(tags) {
    if (!Array.isArray(tags)) return [];
    return tags
        .map(tag => String(tag || '').trim())
        .filter(Boolean)
        .slice(0, 20);
}

/**
 * Ensure indexes exist for the collection. Safe to call repeatedly.
 * @param {Object} db
 */
async function ensureIndexes(db) {
    const collection = getCollection(db);
    await collection.createIndex({ noteId: 1 }, { unique: true });
    await collection.createIndex({ authorId: 1 });
    await collection.createIndex({ isDeleted: 1, createdAt: -1 });
}

/**
 * Create a new note document.
 * @param {Object} db
 * @param {Object} data - { authorId, authorName, title, content, tags, qdrantPointIds }
 * @returns {Promise<Object>} The created note document
 */
async function createNote(db, data) {
    const collection = getCollection(db);
    const now = new Date();
    const content = String(data.content || '').trim();

    const note = {
        noteId: generateNoteId(),
        authorId: data.authorId,
        authorName: data.authorName || 'Instructor',
        title: (data.title && String(data.title).trim()) || autoGenerateTitle(content),
        content,
        tags: normalizeTags(data.tags),
        qdrantPointIds: Array.isArray(data.qdrantPointIds) ? data.qdrantPointIds : [],
        usageCount: 0,
        isDeleted: false,
        createdAt: now,
        updatedAt: now,
        deletedAt: null
    };

    await collection.insertOne(note);
    return note;
}

/**
 * List all non-deleted notes, newest first.
 * @param {Object} db
 * @returns {Promise<Array>}
 */
async function listNotes(db) {
    const collection = getCollection(db);
    return collection
        .find({ $or: [{ isDeleted: { $exists: false } }, { isDeleted: false }] })
        .sort({ createdAt: -1 })
        .toArray();
}

/**
 * Get a single non-deleted note by ID.
 * @param {Object} db
 * @param {string} noteId
 * @returns {Promise<Object|null>}
 */
async function getNoteById(db, noteId) {
    const collection = getCollection(db);
    return collection.findOne({
        noteId,
        $or: [{ isDeleted: { $exists: false } }, { isDeleted: false }]
    });
}

/**
 * Update a note's editable fields and its Qdrant point references.
 * @param {Object} db
 * @param {string} noteId
 * @param {Object} updates - { title, content, tags, qdrantPointIds }
 * @returns {Promise<Object|null>} Updated note document
 */
async function updateNote(db, noteId, updates) {
    const collection = getCollection(db);
    const set = { updatedAt: new Date() };

    if (typeof updates.content === 'string') {
        set.content = updates.content.trim();
    }
    if (typeof updates.title === 'string') {
        set.title = updates.title.trim() || autoGenerateTitle(set.content || '');
    }
    if (updates.tags !== undefined) {
        set.tags = normalizeTags(updates.tags);
    }
    if (Array.isArray(updates.qdrantPointIds)) {
        set.qdrantPointIds = updates.qdrantPointIds;
    }

    await collection.updateOne({ noteId }, { $set: set });
    return getNoteById(db, noteId);
}

/**
 * Soft-delete a note (keeps the document, hides it from listings).
 * @param {Object} db
 * @param {string} noteId
 * @returns {Promise<void>}
 */
async function softDeleteNote(db, noteId) {
    const collection = getCollection(db);
    await collection.updateOne(
        { noteId },
        { $set: { isDeleted: true, deletedAt: new Date(), updatedAt: new Date() } }
    );
}

/**
 * Increment the usage counter for one or more notes (called on retrieval hits).
 * @param {Object} db
 * @param {Array<string>} noteIds
 * @returns {Promise<void>}
 */
async function incrementUsage(db, noteIds) {
    if (!Array.isArray(noteIds) || noteIds.length === 0) return;
    const collection = getCollection(db);
    const unique = [...new Set(noteIds.filter(Boolean))];
    if (unique.length === 0) return;
    await collection.updateMany(
        { noteId: { $in: unique } },
        { $inc: { usageCount: 1 } }
    );
}

module.exports = {
    COLLECTION_NAME,
    CONTENT_SOFT_LIMIT,
    generateNoteId,
    autoGenerateTitle,
    normalizeTags,
    ensureIndexes,
    createNote,
    listNotes,
    getNoteById,
    updateNote,
    softDeleteNote,
    incrementUsage
};
