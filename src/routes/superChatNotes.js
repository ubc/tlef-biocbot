const express = require('express');
const router = express.Router();
const notesService = require('../services/superChatNotesService');
const { CONTENT_SOFT_LIMIT } = require('../models/SuperChatNote');

// Hard ceiling above the soft UI limit, to reject obviously abusive payloads.
const CONTENT_HARD_LIMIT = CONTENT_SOFT_LIMIT * 2;

function getInstructor(req) {
    const userId = req.user && req.user.userId;
    const name = req.user && (req.user.displayName || req.user.username || req.user.email);
    return { userId, name: name || 'Instructor' };
}

function publicNote(note) {
    return {
        noteId: note.noteId,
        authorId: note.authorId,
        authorName: note.authorName,
        title: note.title,
        content: note.content,
        tags: note.tags || [],
        usageCount: note.usageCount || 0,
        createdAt: note.createdAt,
        updatedAt: note.updatedAt
    };
}

// List all visible notes
router.get('/', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });

        const { userId } = getInstructor(req);
        const notes = await notesService.listNotes(db);

        res.json({
            success: true,
            data: {
                notes: notes.map(note => ({
                    ...publicNote(note),
                    isOwn: note.authorId === userId
                }))
            }
        });
    } catch (error) {
        console.error('Error listing Super Chat notes:', error);
        res.status(500).json({ success: false, message: 'Failed to load notes' });
    }
});

// Probe for a similar existing note (soft duplicate warning)
router.post('/check-similar', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });

        const content = req.body && req.body.content;
        const excludeNoteId = (req.body && req.body.excludeNoteId) || null;
        if (!content || typeof content !== 'string' || !content.trim()) {
            return res.json({ success: true, similar: null });
        }

        const similar = await notesService.checkSimilar(db, content, excludeNoteId);
        res.json({ success: true, similar });
    } catch (error) {
        console.error('Error checking note similarity:', error);
        // Dedup is advisory — never block the author on a failure here.
        res.json({ success: true, similar: null });
    }
});

// Fetch a single note
router.get('/:id', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });

        const note = await notesService.getNoteById(db, req.params.id);
        if (!note) return res.status(404).json({ success: false, message: 'Note not found' });

        const { userId } = getInstructor(req);
        res.json({ success: true, note: { ...publicNote(note), isOwn: note.authorId === userId } });
    } catch (error) {
        console.error('Error fetching Super Chat note:', error);
        res.status(500).json({ success: false, message: 'Failed to load note' });
    }
});

// Create a note
router.post('/', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });

        const { userId, name } = getInstructor(req);
        if (!userId) return res.status(401).json({ success: false, message: 'Authentication required' });

        const { title, content, tags } = req.body || {};
        if (!content || typeof content !== 'string' || !content.trim()) {
            return res.status(400).json({ success: false, message: 'Note content is required' });
        }
        if (content.length > CONTENT_HARD_LIMIT) {
            return res.status(400).json({ success: false, message: `Note is too long (max ${CONTENT_HARD_LIMIT} characters)` });
        }

        const note = await notesService.createNote(db, {
            authorId: userId,
            authorName: name,
            title,
            content,
            tags
        });

        res.status(201).json({ success: true, note: { ...publicNote(note), isOwn: true } });
    } catch (error) {
        console.error('Error creating Super Chat note:', error);
        res.status(500).json({ success: false, message: 'Failed to create note' });
    }
});

// Update a note (author only)
router.put('/:id', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });

        const { userId } = getInstructor(req);
        if (!userId) return res.status(401).json({ success: false, message: 'Authentication required' });

        const { title, content, tags } = req.body || {};
        if (content !== undefined && (typeof content !== 'string' || !content.trim())) {
            return res.status(400).json({ success: false, message: 'Note content cannot be empty' });
        }
        if (typeof content === 'string' && content.length > CONTENT_HARD_LIMIT) {
            return res.status(400).json({ success: false, message: `Note is too long (max ${CONTENT_HARD_LIMIT} characters)` });
        }

        const result = await notesService.updateNote(db, req.params.id, userId, { title, content, tags });
        if (!result.ok) {
            return res.status(result.status || 400).json({ success: false, message: result.message });
        }

        res.json({ success: true, note: { ...publicNote(result.note), isOwn: true } });
    } catch (error) {
        console.error('Error updating Super Chat note:', error);
        res.status(500).json({ success: false, message: 'Failed to update note' });
    }
});

// Delete a note (author only)
router.delete('/:id', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });

        const { userId } = getInstructor(req);
        if (!userId) return res.status(401).json({ success: false, message: 'Authentication required' });

        const result = await notesService.deleteNote(db, req.params.id, userId);
        if (!result.ok) {
            return res.status(result.status || 400).json({ success: false, message: result.message });
        }

        res.json({ success: true, data: { noteId: req.params.id } });
    } catch (error) {
        console.error('Error deleting Super Chat note:', error);
        res.status(500).json({ success: false, message: 'Failed to delete note' });
    }
});

module.exports = router;
