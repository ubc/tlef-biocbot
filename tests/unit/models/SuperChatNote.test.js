/**
 * Unit tests for src/models/SuperChatNote.js — pure helpers + DB-backed CRUD
 * against the in-memory Mongo double. (incrementUsage exercises the $inc update
 * operator added to tests/unit/helpers/memory-db.js.)
 */
const { memoryDb } = require('../helpers/memory-db');
const SuperChatNote = require('../../../src/models/SuperChatNote');

const COLL = 'superchat_notes';

describe('SuperChatNote constants', () => {
    test('expose the collection name and content soft limit', () => {
        expect(SuperChatNote.COLLECTION_NAME).toBe('superchat_notes');
        expect(SuperChatNote.CONTENT_SOFT_LIMIT).toBe(5000);
    });
});

describe('SuperChatNote.generateNoteId', () => {
    test('matches the note_<timestamp>_<random> shape', () => {
        expect(SuperChatNote.generateNoteId()).toMatch(/^note_\d+_[a-z0-9]+$/);
    });
});

describe('SuperChatNote.autoGenerateTitle', () => {
    test('uses the first sentence, trimmed', () => {
        expect(SuperChatNote.autoGenerateTitle('Hello world. Second sentence.')).toBe('Hello world.');
        expect(SuperChatNote.autoGenerateTitle('Hi! There.')).toBe('Hi!');
    });

    test('collapses whitespace and uses the whole string when there is no sentence break', () => {
        expect(SuperChatNote.autoGenerateTitle('  No   punctuation here ')).toBe('No punctuation here');
    });

    // The doc comment says "up to . ! ? or newline", but a bare newline does NOT
    // terminate the sentence — it is collapsed to a space. Characterized, not fixed.
    test('a newline is collapsed to a space, not treated as a sentence end', () => {
        expect(SuperChatNote.autoGenerateTitle('Line one\nLine two')).toBe('Line one Line two');
    });

    test('falls back to "Untitled note" for empty/falsy content', () => {
        expect(SuperChatNote.autoGenerateTitle('')).toBe('Untitled note');
        expect(SuperChatNote.autoGenerateTitle('   ')).toBe('Untitled note');
        expect(SuperChatNote.autoGenerateTitle(null)).toBe('Untitled note');
    });

    test('caps a long first sentence at 80 chars with an ellipsis', () => {
        const title = SuperChatNote.autoGenerateTitle('A'.repeat(100) + '.');
        expect(title).toHaveLength(80);
        expect(title.endsWith('...')).toBe(true);
    });
});

describe('SuperChatNote.normalizeTags', () => {
    test('trims, drops empties, and stringifies entries', () => {
        expect(SuperChatNote.normalizeTags(['a', ' b ', '', null, 5])).toEqual(['a', 'b', '5']);
    });

    test('returns [] for non-array input', () => {
        expect(SuperChatNote.normalizeTags('a,b')).toEqual([]);
        expect(SuperChatNote.normalizeTags(undefined)).toEqual([]);
    });

    test('caps the list at 20 tags', () => {
        const many = Array.from({ length: 25 }, (_, i) => `t${i}`);
        expect(SuperChatNote.normalizeTags(many)).toHaveLength(20);
    });

    // String(0 || '') === '' so a numeric 0 tag is dropped. Characterized.
    test('drops a falsy 0 tag (String(0 || "") is empty)', () => {
        expect(SuperChatNote.normalizeTags([0, 'keep'])).toEqual(['keep']);
    });
});

describe('SuperChatNote.createNote', () => {
    test('fills defaults, auto-titles from content, and persists the note', async () => {
        const db = memoryDb({});
        const note = await SuperChatNote.createNote(db, { authorId: 'i1', content: '  Glycolysis basics. Details follow.  ' });

        expect(note).toMatchObject({
            authorId: 'i1',
            authorName: 'Instructor',
            title: 'Glycolysis basics.',
            content: 'Glycolysis basics. Details follow.',
            tags: [],
            qdrantPointIds: [],
            usageCount: 0,
            isDeleted: false,
            deletedAt: null,
        });
        expect(note.noteId).toMatch(/^note_\d+_/);
        expect(note.createdAt).toBeInstanceOf(Date);

        const stored = await db.collection(COLL).findOne({ noteId: note.noteId });
        expect(stored.content).toBe('Glycolysis basics. Details follow.');
    });

    test('prefers an explicit (trimmed) title and normalizes tags', async () => {
        const db = memoryDb({});
        const note = await SuperChatNote.createNote(db, {
            authorId: 'i1', authorName: 'Dr. X', title: '  Custom Title  ', content: 'x', tags: [' bio ', '', 'chem'],
        });
        expect(note.title).toBe('Custom Title');
        expect(note.authorName).toBe('Dr. X');
        expect(note.tags).toEqual(['bio', 'chem']);
    });
});

describe('SuperChatNote.listNotes', () => {
    test('returns non-deleted notes newest-first, including legacy docs with no isDeleted field', async () => {
        const db = memoryDb({
            [COLL]: [
                { noteId: 'a', createdAt: new Date('2026-01-01'), isDeleted: false },
                { noteId: 'b', createdAt: new Date('2026-03-01') }, // legacy: no isDeleted
                { noteId: 'c', createdAt: new Date('2026-02-01'), isDeleted: true }, // excluded
            ],
        });
        const notes = await SuperChatNote.listNotes(db);
        expect(notes.map(n => n.noteId)).toEqual(['b', 'a']);
    });
});

describe('SuperChatNote.getNoteById', () => {
    test('returns a non-deleted note, and null for a deleted or missing one', async () => {
        const db = memoryDb({
            [COLL]: [
                { noteId: 'a', isDeleted: false },
                { noteId: 'b', isDeleted: true },
            ],
        });
        expect(await SuperChatNote.getNoteById(db, 'a')).toMatchObject({ noteId: 'a' });
        expect(await SuperChatNote.getNoteById(db, 'b')).toBeNull();
        expect(await SuperChatNote.getNoteById(db, 'missing')).toBeNull();
    });
});

describe('SuperChatNote.updateNote', () => {
    test('updates provided fields, trims, and returns the fresh note', async () => {
        const db = memoryDb({ [COLL]: [{ noteId: 'a', title: 'Old', content: 'old', tags: [], isDeleted: false }] });
        const updated = await SuperChatNote.updateNote(db, 'a', { content: '  New body.  ', tags: ['x', ' y '] });

        expect(updated).toMatchObject({ noteId: 'a', content: 'New body.', tags: ['x', 'y'] });
        expect(updated.updatedAt).toBeInstanceOf(Date);
    });

    test('regenerates the title from content when the new title is blank', async () => {
        const db = memoryDb({ [COLL]: [{ noteId: 'a', title: 'Old', content: 'old', isDeleted: false }] });
        const updated = await SuperChatNote.updateNote(db, 'a', { content: 'Fresh subject. More.', title: '   ' });
        expect(updated.title).toBe('Fresh subject.');
    });
});

describe('SuperChatNote.softDeleteNote', () => {
    test('hides the note from getNoteById and listNotes', async () => {
        const db = memoryDb({ [COLL]: [{ noteId: 'a', isDeleted: false, createdAt: new Date() }] });
        await SuperChatNote.softDeleteNote(db, 'a');

        expect(await SuperChatNote.getNoteById(db, 'a')).toBeNull();
        expect(await SuperChatNote.listNotes(db)).toEqual([]);
        const raw = await db.collection(COLL).findOne({ noteId: 'a' });
        expect(raw.isDeleted).toBe(true);
        expect(raw.deletedAt).toBeInstanceOf(Date);
    });
});

describe('SuperChatNote.incrementUsage', () => {
    test('increments usageCount once per distinct id', async () => {
        const db = memoryDb({
            [COLL]: [
                { noteId: 'n1', usageCount: 0 },
                { noteId: 'n2', usageCount: 5 },
            ],
        });
        await SuperChatNote.incrementUsage(db, ['n1', 'n2', 'n1', null]);

        expect((await db.collection(COLL).findOne({ noteId: 'n1' })).usageCount).toBe(1);
        expect((await db.collection(COLL).findOne({ noteId: 'n2' })).usageCount).toBe(6);
    });

    test('is a no-op for an empty or non-array list', async () => {
        const db = memoryDb({ [COLL]: [{ noteId: 'n1', usageCount: 3 }] });
        await SuperChatNote.incrementUsage(db, []);
        await SuperChatNote.incrementUsage(db, null);
        expect((await db.collection(COLL).findOne({ noteId: 'n1' })).usageCount).toBe(3);
    });
});

describe('SuperChatNote.ensureIndexes', () => {
    test('runs without throwing against the in-memory double', async () => {
        const db = memoryDb({});
        await expect(SuperChatNote.ensureIndexes(db)).resolves.toBeUndefined();
    });
});
