const { memoryDb } = require('../helpers/memory-db');
const MessageFeedback = require('../../../src/models/MessageFeedback');

const COLL = MessageFeedback.COLLECTION_NAME;

describe('MessageFeedback model', () => {
    test('normalizes only supported ratings and null clears', () => {
        expect(MessageFeedback.normalizeRating('UP')).toBe('up');
        expect(MessageFeedback.normalizeRating(' down ')).toBe('down');
        expect(MessageFeedback.normalizeRating(null)).toBeNull();
        expect(MessageFeedback.normalizeRating('meh')).toBeUndefined();
    });

    test('creates a bounded message preview and stable hash', () => {
        const snapshot = MessageFeedback.buildMessageSnapshot(`  ${'A'.repeat(1200)}  `);
        expect(snapshot.messageContentPreview).toHaveLength(MessageFeedback.MESSAGE_PREVIEW_LIMIT);
        expect(snapshot.messageContentHash).toMatch(/^[a-f0-9]{64}$/);
        expect(MessageFeedback.buildMessageSnapshot('')).toEqual({
            messageContentPreview: '',
            messageContentHash: null
        });
    });

    test('upserts one current feedback record per student/conversation/message', async () => {
        const db = memoryDb({});
        const base = {
            courseId: 'C1',
            unitName: 'Unit 1',
            studentId: 's1',
            studentName: 'Student One',
            conversationId: 'session-1',
            messageId: 'msg-1',
            botMode: 'tutor',
            messageContent: 'Helpful answer'
        };

        const first = await MessageFeedback.upsertMessageFeedback(db, { ...base, rating: 'up' });
        expect(first).toMatchObject({ success: true, feedback: { rating: 'up', isActive: true } });

        const second = await MessageFeedback.upsertMessageFeedback(db, { ...base, rating: 'down' });
        expect(second).toMatchObject({ success: true, feedback: { rating: 'down', isActive: true } });

        const all = await db.collection(COLL).find({}).toArray();
        expect(all).toHaveLength(1);
        expect(all[0]).toMatchObject({
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            messageId: 'msg-1',
            rating: 'down'
        });
    });

    test('clearing feedback preserves the record but marks it inactive', async () => {
        const db = memoryDb({});
        const base = {
            courseId: 'C1',
            studentId: 's1',
            conversationId: 'session-1',
            messageId: 'msg-1'
        };

        await MessageFeedback.upsertMessageFeedback(db, { ...base, rating: 'up' });
        const cleared = await MessageFeedback.upsertMessageFeedback(db, { ...base, rating: null });

        expect(cleared.feedback).toMatchObject({ rating: null, isActive: false });
        expect(cleared.feedback.clearedAt).toBeInstanceOf(Date);
        expect(await MessageFeedback.listFeedbackForCourse(db, 'C1')).toEqual([]);

        const withCleared = await MessageFeedback.listFeedbackForCourse(db, 'C1', { includeCleared: true });
        expect(withCleared).toHaveLength(1);
        expect(withCleared[0].isActive).toBe(false);
    });

    test('lists active feedback and computes course stats including cleared records', async () => {
        const db = memoryDb({
            [COLL]: [
                { feedbackId: 'f1', courseId: 'C1', rating: 'up', isActive: true, updatedAt: new Date('2026-01-03') },
                { feedbackId: 'f2', courseId: 'C1', rating: 'down', isActive: true, updatedAt: new Date('2026-01-02') },
                { feedbackId: 'f3', courseId: 'C1', rating: null, isActive: false, updatedAt: new Date('2026-01-01') },
                { feedbackId: 'f4', courseId: 'C2', rating: 'up', isActive: true, updatedAt: new Date('2026-01-04') },
            ],
        });

        const active = await MessageFeedback.listFeedbackForCourse(db, 'C1');
        expect(active.map(item => item.feedbackId)).toEqual(['f1', 'f2']);
        await expect(MessageFeedback.getFeedbackStatsForCourse(db, 'C1')).resolves.toEqual({
            total: 3,
            up: 1,
            down: 1,
            cleared: 1
        });
    });

    test('exports feedback to CSV with escaped content', () => {
        const csv = MessageFeedback.feedbackToCsv([
            {
                feedbackId: 'f1',
                courseId: 'C1',
                unitName: 'Unit 1',
                conversationId: 'session-1',
                messageId: 'msg-1',
                studentId: 's1',
                studentName: 'Student, One',
                rating: 'up',
                isActive: true,
                botMode: 'tutor',
                messageContentPreview: 'Line "one"',
                messageContentHash: 'hash',
                createdAt: new Date('2026-01-01T00:00:00Z'),
                updatedAt: new Date('2026-01-02T00:00:00Z')
            }
        ]);

        expect(csv).toContain('feedbackId,courseId,unitName');
        expect(csv).toContain('"Student, One"');
        expect(csv).toContain('"Line ""one"""');
        expect(csv).toContain('2026-01-01T00:00:00.000Z');
    });

    test('ensureIndexes runs against the in-memory Mongo double', async () => {
        await expect(MessageFeedback.ensureIndexes(memoryDb({}))).resolves.toBeUndefined();
    });
});
