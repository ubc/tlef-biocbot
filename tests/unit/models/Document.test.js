/**
 * Unit tests for src/models/Document.js against the in-memory Mongo double.
 */
const { memoryDb } = require('../helpers/memory-db');
const Document = require('../../../src/models/Document');

const COLL = 'documents';

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
    jest.restoreAllMocks();
});

describe('Document.mapContentTypeToDocumentType', () => {
    test('maps known upload content types to stored document types', () => {
        expect(Document.mapContentTypeToDocumentType('lecture-notes')).toBe('lecture_notes');
        expect(Document.mapContentTypeToDocumentType('practice-quiz')).toBe('practice_q_tutorials');
        expect(Document.mapContentTypeToDocumentType('additional')).toBe('additional');
        expect(Document.mapContentTypeToDocumentType('text')).toBe('text');
    });

    test('falls back to additional for unknown or missing content types', () => {
        expect(Document.mapContentTypeToDocumentType('slides')).toBe('additional');
        expect(Document.mapContentTypeToDocumentType(undefined)).toBe('additional');
    });
});

describe('Document.uploadDocument', () => {
    test('stores a new document with generated id, mapped type, timestamps, and uploaded status', async () => {
        const db = memoryDb({});
        const created = await Document.uploadDocument(db, {
            courseId: 'C1',
            lectureName: 'Unit 1',
            instructorId: 'i1',
            documentType: 'lecture-notes',
            contentType: 'file',
            filename: 'unit1.pdf',
            originalName: 'Unit 1.pdf',
            mimeType: 'application/pdf',
            size: 1234,
            status: 'parsing',
            metadata: { tags: ['bio'] },
        });

        expect(created).toMatchObject({
            courseId: 'C1',
            lectureName: 'Unit 1',
            instructorId: 'i1',
            documentType: 'lecture-notes',
            type: 'lecture_notes',
            status: 'uploaded',
            _id: 'mem-1',
            metadata: { tags: ['bio'] },
        });
        expect(created.documentId).toMatch(/^doc_[0-9a-f-]{36}$/i);
        expect(created.uploadDate).toBeInstanceOf(Date);
        expect(created.lastModified).toBeInstanceOf(Date);

        const stored = await db.collection(COLL).findOne({ documentId: created.documentId });
        expect(stored).toMatchObject({
            documentId: created.documentId,
            type: 'lecture_notes',
            status: 'uploaded',
        });
    });

    test('uses the fallback document type for unknown documentType values', async () => {
        const db = memoryDb({});
        const created = await Document.uploadDocument(db, {
            courseId: 'C1',
            lectureName: 'Unit 1',
            documentType: 'unknown-kind',
            contentType: 'text',
            content: 'plain text',
        });

        expect(created.type).toBe('additional');
        expect(created.content).toBe('plain text');
    });
});

describe('Document.getDocumentsForLecture', () => {
    test('returns only the requested course and lecture, newest first', async () => {
        const db = memoryDb({
            [COLL]: [
                { documentId: 'old', courseId: 'C1', lectureName: 'Unit 1', uploadDate: new Date('2026-01-01') },
                { documentId: 'new', courseId: 'C1', lectureName: 'Unit 1', uploadDate: new Date('2026-03-01') },
                { documentId: 'other-course', courseId: 'C2', lectureName: 'Unit 1', uploadDate: new Date('2026-04-01') },
                { documentId: 'other-lecture', courseId: 'C1', lectureName: 'Unit 2', uploadDate: new Date('2026-04-01') },
            ],
        });

        const docs = await Document.getDocumentsForLecture(db, 'C1', 'Unit 1');
        expect(docs.map(doc => doc.documentId)).toEqual(['new', 'old']);
    });
});

describe('Document.getDocumentById', () => {
    test('returns the matching document or null', async () => {
        const db = memoryDb({ [COLL]: [{ documentId: 'doc-1', filename: 'a.pdf' }] });

        expect(await Document.getDocumentById(db, 'doc-1')).toMatchObject({ filename: 'a.pdf' });
        expect(await Document.getDocumentById(db, 'missing')).toBeNull();
    });
});

describe('Document.updateDocumentContent', () => {
    test('sets extracted content, marks the document parsed, and reports success', async () => {
        const db = memoryDb({ [COLL]: [{ documentId: 'doc-1', content: '', status: 'uploaded' }] });

        const result = await Document.updateDocumentContent(db, 'doc-1', 'Extracted text');
        expect(result).toEqual({
            success: true,
            message: 'Document content updated successfully',
            modifiedCount: 1,
        });

        const updated = await Document.getDocumentById(db, 'doc-1');
        expect(updated).toMatchObject({ content: 'Extracted text', status: 'parsed' });
        expect(updated.lastModified).toBeInstanceOf(Date);
    });

    test('returns a not-found result when no document matches', async () => {
        const db = memoryDb({ [COLL]: [] });

        expect(await Document.updateDocumentContent(db, 'missing', 'text')).toEqual({
            success: false,
            error: 'Document not found',
        });
    });

    test('converts collection errors into a failure object', async () => {
        const db = {
            collection: () => ({
                updateOne: jest.fn(async () => {
                    throw new Error('write failed');
                }),
            }),
        };

        expect(await Document.updateDocumentContent(db, 'doc-1', 'text')).toEqual({
            success: false,
            error: 'write failed',
        });
    });
});

describe('Document.updateDocumentStatus', () => {
    test('sets status, lastModified, and caller-provided fields', async () => {
        const db = memoryDb({ [COLL]: [{ documentId: 'doc-1', status: 'uploaded' }] });

        const result = await Document.updateDocumentStatus(db, 'doc-1', 'error', { error: 'parse failed' });
        expect(result).toMatchObject({ matchedCount: 1, modifiedCount: 1 });

        const updated = await Document.getDocumentById(db, 'doc-1');
        expect(updated).toMatchObject({ status: 'error', error: 'parse failed' });
        expect(updated.lastModified).toBeInstanceOf(Date);
    });

    test('returns the raw update result for a missing document', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Document.updateDocumentStatus(db, 'missing', 'parsed')).resolves.toEqual({
            matchedCount: 0,
            modifiedCount: 0,
            upsertedCount: 0,
        });
    });
});

describe('Document.deleteDocument', () => {
    test('deletes the matching document and reports the deletion count', async () => {
        const db = memoryDb({ [COLL]: [{ documentId: 'doc-1' }, { documentId: 'doc-2' }] });

        expect(await Document.deleteDocument(db, 'doc-1')).toEqual({ deletedCount: 1 });
        expect(await Document.getDocumentById(db, 'doc-1')).toBeNull();
        expect(await Document.getDocumentById(db, 'doc-2')).toMatchObject({ documentId: 'doc-2' });
    });

    test('reports zero deletions for a missing document', async () => {
        const db = memoryDb({ [COLL]: [] });

        await expect(Document.deleteDocument(db, 'missing')).resolves.toEqual({ deletedCount: 0 });
    });
});

describe('Document.getDocumentStats', () => {
    test('returns the empty stats shape when the course has no documents', async () => {
        const db = memoryDb({ [COLL]: [{ courseId: 'C2', status: 'parsed', size: 100 }] });

        expect(await Document.getDocumentStats(db, 'C1')).toEqual({
            totalDocuments: 0,
            totalSize: 0,
            statusBreakdown: [],
        });
    });

    test('aggregates document count, size, and status breakdown for one course', async () => {
        const db = memoryDb({
            [COLL]: [
                { courseId: 'C1', status: 'uploaded', size: 100 },
                { courseId: 'C1', status: 'parsed', size: 200 },
                { courseId: 'C1', status: 'parsed', size: 50 },
                { courseId: 'C1', status: 'error', size: undefined },
                { courseId: 'C2', status: 'parsed', size: 999 },
            ],
        });

        const stats = await Document.getDocumentStats(db, 'C1');
        expect(stats).toMatchObject({
            _id: null,
            totalDocuments: 4,
            totalSize: 350,
        });
        expect(stats.statusBreakdown).toEqual(expect.arrayContaining([
            { status: 'uploaded', count: 1 },
            { status: 'parsed', count: 2 },
            { status: 'error', count: 1 },
        ]));
        expect(stats.statusBreakdown).toHaveLength(3);
    });
});
