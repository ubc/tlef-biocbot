/**
 * superChatNotesService
 * Orchestration layer for Super Chat Notes: coordinates the MongoDB model
 * (source of truth for note metadata) with the Qdrant vector store (search +
 * dedup). Keeps the two stores consistent on create / update / delete.
 */

const SuperChatNote = require('../models/SuperChatNote');
const NotesQdrantService = require('./notesQdrantService');

const DUP_THRESHOLD = NotesQdrantService.DEFAULT_DUP_THRESHOLD;

function notePayloadMeta(note) {
    return {
        authorId: note.authorId,
        authorName: note.authorName,
        title: note.title,
        tags: note.tags,
        createdAt: note.createdAt instanceof Date ? note.createdAt.toISOString() : note.createdAt
    };
}

/**
 * Create a note: persist metadata, embed + store vectors, then backfill the
 * Qdrant point IDs onto the Mongo doc.
 * @param {Object} db
 * @param {Object} data - { authorId, authorName, title, content, tags }
 * @returns {Promise<Object>} The created note
 */
async function createNote(db, data) {
    const note = await SuperChatNote.createNote(db, data);

    const qdrant = new NotesQdrantService();
    const pointIds = await qdrant.addNote(note.noteId, note.content, notePayloadMeta(note));

    if (pointIds.length) {
        await SuperChatNote.updateNote(db, note.noteId, { qdrantPointIds: pointIds });
        note.qdrantPointIds = pointIds;
    }
    return note;
}

/**
 * List all visible notes (newest first).
 */
async function listNotes(db) {
    return SuperChatNote.listNotes(db);
}

/**
 * Fetch a single visible note.
 */
async function getNoteById(db, noteId) {
    return SuperChatNote.getNoteById(db, noteId);
}

/**
 * Update a note (author-only). Re-embeds the content when it changes.
 * @returns {Promise<{ ok: boolean, status?: number, message?: string, note?: Object }>}
 */
async function updateNote(db, noteId, requesterId, updates) {
    const existing = await SuperChatNote.getNoteById(db, noteId);
    if (!existing) {
        return { ok: false, status: 404, message: 'Note not found' };
    }
    if (existing.authorId !== requesterId) {
        return { ok: false, status: 403, message: 'You can only edit your own notes' };
    }

    const contentChanged = typeof updates.content === 'string'
        && updates.content.trim() !== existing.content;

    // Persist metadata first so re-embed uses the latest title/tags.
    const updated = await SuperChatNote.updateNote(db, noteId, {
        title: updates.title,
        content: updates.content,
        tags: updates.tags
    });

    // Re-embed when the text changed; otherwise leave vectors untouched.
    if (contentChanged) {
        const qdrant = new NotesQdrantService();
        const pointIds = await qdrant.updateNote(noteId, updated.content, notePayloadMeta(updated));
        const finalNote = await SuperChatNote.updateNote(db, noteId, { qdrantPointIds: pointIds });
        return { ok: true, note: finalNote };
    }

    return { ok: true, note: updated };
}

/**
 * Soft-delete a note (author-only) and remove its vectors from Qdrant so it
 * stops influencing retrieval immediately.
 * @returns {Promise<{ ok: boolean, status?: number, message?: string }>}
 */
async function deleteNote(db, noteId, requesterId) {
    const existing = await SuperChatNote.getNoteById(db, noteId);
    if (!existing) {
        return { ok: false, status: 404, message: 'Note not found' };
    }
    if (existing.authorId !== requesterId) {
        return { ok: false, status: 403, message: 'You can only delete your own notes' };
    }

    await SuperChatNote.softDeleteNote(db, noteId);

    try {
        const qdrant = new NotesQdrantService();
        await qdrant.deleteNote(noteId);
    } catch (error) {
        console.error('Failed to remove note vectors from Qdrant:', error.message);
        // Mongo soft-delete already succeeded; surface success but log the drift.
    }

    return { ok: true };
}

/**
 * Probe for a similar existing note (for the soft duplicate warning).
 * @param {Object} db (unused but kept for signature symmetry)
 * @param {string} content
 * @param {string|null} excludeNoteId
 * @returns {Promise<Object|null>}
 */
async function checkSimilar(db, content, excludeNoteId = null) {
    const qdrant = new NotesQdrantService();
    return qdrant.findSimilarTo(content, { excludeNoteId, threshold: DUP_THRESHOLD });
}

/**
 * Increment usage counters for notes that were retrieved into an answer.
 */
async function incrementUsage(db, noteIds) {
    return SuperChatNote.incrementUsage(db, noteIds);
}

module.exports = {
    DUP_THRESHOLD,
    createNote,
    listNotes,
    getNoteById,
    updateNote,
    deleteNote,
    checkSimilar,
    incrementUsage
};
