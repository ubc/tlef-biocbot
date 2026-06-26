/**
 * Message Feedback Model for MongoDB
 * Stores student thumbs-up / thumbs-down feedback on assistant chat messages.
 */

const crypto = require('crypto');

const COLLECTION_NAME = 'messageFeedback';
const VALID_RATINGS = new Set(['up', 'down']);
const MESSAGE_PREVIEW_LIMIT = 1000;

function getMessageFeedbackCollection(db) {
    return db.collection(COLLECTION_NAME);
}

function generateFeedbackId() {
    return `feedback_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
}

function normalizeText(value, limit = 255) {
    if (value === undefined || value === null) return '';
    return String(value).replace(/\s+/g, ' ').trim().slice(0, limit);
}

function normalizeRating(value) {
    if (value === null) return null;
    const normalized = normalizeText(value, 20).toLowerCase();
    return VALID_RATINGS.has(normalized) ? normalized : undefined;
}

function buildMessageSnapshot(messageContent) {
    const raw = typeof messageContent === 'string' ? messageContent : '';
    const normalized = raw.replace(/\s+/g, ' ').trim();

    if (!normalized) {
        return {
            messageContentPreview: '',
            messageContentHash: null
        };
    }

    return {
        messageContentPreview: normalized.slice(0, MESSAGE_PREVIEW_LIMIT),
        messageContentHash: crypto.createHash('sha256').update(normalized).digest('hex')
    };
}

function normalizeSourceAttribution(sourceAttribution) {
    if (!sourceAttribution || typeof sourceAttribution !== 'object' || Array.isArray(sourceAttribution)) {
        return null;
    }

    return {
        source: normalizeText(sourceAttribution.source, 80) || null,
        description: normalizeText(sourceAttribution.description, 500) || null,
        unitName: normalizeText(sourceAttribution.unitName, 120) || null,
        documentType: normalizeText(sourceAttribution.documentType, 80) || null
    };
}

function validateRequiredFeedbackFields(data) {
    const required = ['courseId', 'studentId', 'conversationId', 'messageId'];
    for (const field of required) {
        if (!normalizeText(data[field], 255)) {
            return `${field} is required`;
        }
    }
    return null;
}

function toPublicFeedback(feedback) {
    if (!feedback) return null;
    const { _id, ...publicFeedback } = feedback;
    return publicFeedback;
}

async function ensureIndexes(db) {
    const collection = getMessageFeedbackCollection(db);
    await collection.createIndex(
        { courseId: 1, studentId: 1, conversationId: 1, messageId: 1 },
        { unique: true, name: 'unique_student_message_feedback' }
    );
    await collection.createIndex(
        { courseId: 1, isActive: 1, updatedAt: -1 },
        { name: 'course_active_feedback_updated' }
    );
    await collection.createIndex(
        { studentId: 1, courseId: 1, updatedAt: -1 },
        { name: 'student_course_feedback_updated' }
    );
}

async function upsertMessageFeedback(db, data) {
    const requiredError = validateRequiredFeedbackFields(data || {});
    if (requiredError) {
        return { success: false, error: requiredError };
    }

    const rating = normalizeRating(data.rating);
    if (rating === undefined) {
        return { success: false, error: 'rating must be "up", "down", or null' };
    }

    const now = new Date();
    const isActive = rating !== null;
    const messageSnapshot = buildMessageSnapshot(data.messageContent);
    const filter = {
        courseId: normalizeText(data.courseId, 120),
        studentId: normalizeText(data.studentId, 120),
        conversationId: normalizeText(data.conversationId, 160),
        messageId: normalizeText(data.messageId, 160)
    };

    const update = {
        $setOnInsert: {
            feedbackId: generateFeedbackId(),
            ...filter,
            createdAt: now
        },
        $set: {
            rating,
            isActive,
            unitName: normalizeText(data.unitName, 160) || null,
            studentName: normalizeText(data.studentName, 160) || null,
            botMode: normalizeText(data.botMode, 60) || null,
            sourceAttribution: normalizeSourceAttribution(data.sourceAttribution),
            ...messageSnapshot,
            updatedAt: now
        }
    };

    if (isActive) {
        update.$unset = { clearedAt: '' };
    } else {
        update.$set.clearedAt = now;
    }

    const collection = getMessageFeedbackCollection(db);
    const feedback = await collection.findOneAndUpdate(
        filter,
        update,
        { upsert: true, returnDocument: 'after' }
    );

    return {
        success: true,
        feedback: toPublicFeedback(feedback)
    };
}

async function getFeedbackForMessage(db, data) {
    const requiredError = validateRequiredFeedbackFields(data || {});
    if (requiredError) return null;

    const collection = getMessageFeedbackCollection(db);
    return toPublicFeedback(await collection.findOne({
        courseId: normalizeText(data.courseId, 120),
        studentId: normalizeText(data.studentId, 120),
        conversationId: normalizeText(data.conversationId, 160),
        messageId: normalizeText(data.messageId, 160)
    }));
}

async function listFeedbackForCourse(db, courseId, options = {}) {
    const collection = getMessageFeedbackCollection(db);
    const filter = { courseId: normalizeText(courseId, 120) };

    if (!options.includeCleared) {
        filter.isActive = true;
    }
    if (options.rating) {
        const rating = normalizeRating(options.rating);
        if (rating) filter.rating = rating;
    }
    if (options.studentId) {
        filter.studentId = normalizeText(options.studentId, 120);
    }
    if (options.conversationId) {
        filter.conversationId = normalizeText(options.conversationId, 160);
    }

    const limit = Number.isInteger(options.limit) && options.limit > 0
        ? Math.min(options.limit, 1000)
        : 500;

    const feedback = await collection.find(filter)
        .sort({ updatedAt: -1 })
        .limit(limit)
        .toArray();

    return feedback.map(toPublicFeedback);
}

async function getFeedbackStatsForCourse(db, courseId) {
    const collection = getMessageFeedbackCollection(db);
    const feedback = await collection.find({ courseId: normalizeText(courseId, 120) }).toArray();

    return feedback.reduce((stats, item) => {
        stats.total += 1;
        if (item.isActive && item.rating === 'up') stats.up += 1;
        if (item.isActive && item.rating === 'down') stats.down += 1;
        if (!item.isActive) stats.cleared += 1;
        return stats;
    }, { total: 0, up: 0, down: 0, cleared: 0 });
}

function escapeCsvCell(value) {
    if (value === undefined || value === null) return '';
    const text = value instanceof Date ? value.toISOString() : String(value);
    if (/[",\n\r]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
}

function feedbackToCsv(feedback) {
    const headers = [
        'feedbackId',
        'courseId',
        'unitName',
        'conversationId',
        'messageId',
        'studentId',
        'studentName',
        'rating',
        'isActive',
        'botMode',
        'messageContentPreview',
        'messageContentHash',
        'createdAt',
        'updatedAt',
        'clearedAt'
    ];

    const rows = feedback.map(item => headers.map(header => escapeCsvCell(item[header])).join(','));
    return [headers.join(','), ...rows].join('\n');
}

module.exports = {
    COLLECTION_NAME,
    MESSAGE_PREVIEW_LIMIT,
    VALID_RATINGS,
    getMessageFeedbackCollection,
    generateFeedbackId,
    normalizeRating,
    buildMessageSnapshot,
    ensureIndexes,
    upsertMessageFeedback,
    getFeedbackForMessage,
    listFeedbackForCourse,
    getFeedbackStatsForCourse,
    feedbackToCsv,
    toPublicFeedback
};
