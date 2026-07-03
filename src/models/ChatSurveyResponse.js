/**
 * Chat Survey Response Model for MongoDB
 * Stores per-session student usefulness survey display/submission events.
 */

const crypto = require('crypto');
const { createId } = require('../services/id');

const COLLECTION_NAME = 'chatSurveyResponses';
const VALID_EVENT_TYPES = new Set(['shown', 'dismissed', 'submitted']);
const MIN_STAR_RATING = 1;
const MAX_STAR_RATING = 5;
const MAX_COMMENT_LENGTH = 2000;

function getChatSurveyResponseCollection(db) {
    return db.collection(COLLECTION_NAME);
}

function generateSurveyResponseId() {
    return createId('survey');
}

function normalizeText(value, limit = 255) {
    if (value === undefined || value === null) return '';
    return String(value).replace(/\s+/g, ' ').trim().slice(0, limit);
}

function normalizeComment(value) {
    if (value === undefined || value === null) return null;
    const normalized = String(value)
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .trim()
        .slice(0, MAX_COMMENT_LENGTH);
    return normalized || null;
}

function normalizeStarRating(value) {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < MIN_STAR_RATING || parsed > MAX_STAR_RATING) {
        return undefined;
    }
    return parsed;
}

function normalizeMessageCount(value) {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 0) return null;
    return Math.min(parsed, 1000);
}

function buildSettingsSnapshot(settings = {}) {
    const triggerMessageCount = Number(settings.triggerMessageCount);
    return {
        enabled: settings.enabled === true,
        triggerMessageCount: Number.isInteger(triggerMessageCount) ? triggerMessageCount : null,
        promptText: normalizeText(settings.promptText, 1000),
        introText: normalizeText(settings.introText, 2000),
        accuracyPrompt: normalizeText(settings.accuracyPrompt, 500),
        satisfactionPrompt: normalizeText(settings.satisfactionPrompt, 500),
        allowFreeText: settings.allowFreeText === true
    };
}

function buildSettingsFingerprint(settings = {}) {
    const snapshot = buildSettingsSnapshot(settings);
    return crypto
        .createHash('sha256')
        .update(JSON.stringify(snapshot))
        .digest('hex')
        .slice(0, 24);
}

function validateRequiredSurveyFields(data) {
    const required = ['courseId', 'studentId', 'conversationId'];
    for (const field of required) {
        if (!normalizeText(data[field], 255)) {
            return `${field} is required`;
        }
    }
    return null;
}

function toPublicSurveyResponse(response) {
    if (!response) return null;
    const { _id, ...publicResponse } = response;
    return publicResponse;
}

async function ensureIndexes(db) {
    const collection = getChatSurveyResponseCollection(db);
    await collection.createIndex(
        { courseId: 1, studentId: 1, conversationId: 1, settingsFingerprint: 1 },
        { unique: true, name: 'unique_student_chat_survey_response' }
    );
    await collection.createIndex(
        { courseId: 1, updatedAt: -1 },
        { name: 'course_chat_survey_updated' }
    );
    await collection.createIndex(
        { studentId: 1, courseId: 1, updatedAt: -1 },
        { name: 'student_course_chat_survey_updated' }
    );
}

async function upsertChatSurveyEvent(db, data = {}) {
    const requiredError = validateRequiredSurveyFields(data);
    if (requiredError) {
        return { success: false, error: requiredError };
    }

    const eventType = normalizeText(data.eventType, 30).toLowerCase();
    if (!VALID_EVENT_TYPES.has(eventType)) {
        return { success: false, error: 'eventType must be "shown", "dismissed", or "submitted"' };
    }

    const settingsSnapshot = buildSettingsSnapshot(data.settings || {});
    const settingsFingerprint = normalizeText(
        data.settingsFingerprint || buildSettingsFingerprint(settingsSnapshot),
        80
    );
    if (!settingsFingerprint) {
        return { success: false, error: 'settingsFingerprint is required' };
    }

    let ratingAccuracy = null;
    let ratingSatisfaction = null;
    if (eventType === 'submitted') {
        ratingAccuracy = normalizeStarRating(data.ratingAccuracy);
        ratingSatisfaction = normalizeStarRating(data.ratingSatisfaction);
        if (ratingAccuracy === undefined) {
            return { success: false, error: 'ratingAccuracy must be an integer from 1 to 5' };
        }
        if (ratingSatisfaction === undefined) {
            return { success: false, error: 'ratingSatisfaction must be an integer from 1 to 5' };
        }
    }

    const now = new Date();
    const filter = {
        courseId: normalizeText(data.courseId, 120),
        studentId: normalizeText(data.studentId, 120),
        conversationId: normalizeText(data.conversationId, 160),
        settingsFingerprint
    };

    const collection = getChatSurveyResponseCollection(db);
    const existing = await collection.findOne(filter);
    if (existing && existing.submittedAt && eventType !== 'submitted') {
        return {
            success: true,
            response: toPublicSurveyResponse(existing),
            ignored: true
        };
    }

    const update = {
        $setOnInsert: {
            responseId: generateSurveyResponseId(),
            ...filter,
            createdAt: now
        },
        $set: {
            studentName: normalizeText(data.studentName, 160) || null,
            unitName: normalizeText(data.unitName, 160) || null,
            botMode: normalizeText(data.botMode, 60) || null,
            messageCountAtPrompt: normalizeMessageCount(data.messageCountAtPrompt),
            promptText: settingsSnapshot.promptText || null,
            introText: settingsSnapshot.introText || null,
            accuracyPrompt: settingsSnapshot.accuracyPrompt || null,
            satisfactionPrompt: settingsSnapshot.satisfactionPrompt || null,
            triggerMessageCount: settingsSnapshot.triggerMessageCount,
            allowFreeText: settingsSnapshot.allowFreeText,
            settingsSnapshot,
            lastEvent: eventType,
            updatedAt: now
        }
    };

    if (eventType === 'shown') {
        update.$set.shownAt = existing?.shownAt || now;
        update.$set.lastShownAt = now;
    }

    if (eventType === 'dismissed') {
        update.$set.shownAt = existing?.shownAt || now;
        update.$set.dismissedAt = now;
    }

    if (eventType === 'submitted') {
        update.$set.shownAt = existing?.shownAt || now;
        update.$set.submittedAt = now;
        update.$set.ratingAccuracy = ratingAccuracy;
        update.$set.ratingSatisfaction = ratingSatisfaction;
        update.$set.comment = settingsSnapshot.allowFreeText ? normalizeComment(data.comment) : null;
        update.$unset = { dismissedAt: '' };
    }

    const response = await collection.findOneAndUpdate(
        filter,
        update,
        { upsert: true, returnDocument: 'after' }
    );

    return {
        success: true,
        response: toPublicSurveyResponse(response)
    };
}

async function getSurveyResponseForSession(db, data = {}) {
    const requiredError = validateRequiredSurveyFields(data);
    if (requiredError) return null;

    const settingsFingerprint = normalizeText(data.settingsFingerprint, 80);
    if (!settingsFingerprint) return null;

    const collection = getChatSurveyResponseCollection(db);
    return toPublicSurveyResponse(await collection.findOne({
        courseId: normalizeText(data.courseId, 120),
        studentId: normalizeText(data.studentId, 120),
        conversationId: normalizeText(data.conversationId, 160),
        settingsFingerprint
    }));
}

async function listSurveyResponsesForCourse(db, courseId, options = {}) {
    const collection = getChatSurveyResponseCollection(db);
    const filter = { courseId: normalizeText(courseId, 120) };

    if (options.studentId) {
        filter.studentId = normalizeText(options.studentId, 120);
    }
    if (options.conversationId) {
        filter.conversationId = normalizeText(options.conversationId, 160);
    }
    if (options.status === 'submitted') {
        filter.submittedAt = { $exists: true };
    } else if (options.status === 'dismissed') {
        filter.dismissedAt = { $exists: true };
        filter.submittedAt = { $exists: false };
    } else if (options.status === 'shown') {
        filter.shownAt = { $exists: true };
    }

    const limit = Number.isInteger(options.limit) && options.limit > 0
        ? Math.min(options.limit, 1000)
        : 500;

    const responses = await collection.find(filter)
        .sort({ updatedAt: -1 })
        .limit(limit)
        .toArray();

    return responses.map(toPublicSurveyResponse);
}

async function getSurveyStatsForCourse(db, courseId) {
    const collection = getChatSurveyResponseCollection(db);
    const responses = await collection.find({ courseId: normalizeText(courseId, 120) }).toArray();

    const average = (values) => values.length
        ? Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(2))
        : null;

    const accuracyRatings = responses
        .map(item => item.ratingAccuracy)
        .filter(rating => typeof rating === 'number');
    const satisfactionRatings = responses
        .map(item => item.ratingSatisfaction)
        .filter(rating => typeof rating === 'number');

    return {
        total: responses.length,
        shown: responses.filter(item => item.shownAt).length,
        dismissed: responses.filter(item => item.dismissedAt && !item.submittedAt).length,
        submitted: responses.filter(item => item.submittedAt).length,
        averageAccuracy: average(accuracyRatings),
        averageSatisfaction: average(satisfactionRatings)
    };
}

function escapeCsvCell(value) {
    if (value === undefined || value === null) return '';
    const text = value instanceof Date ? value.toISOString() : String(value);
    if (/[",\n\r]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
    }
    return text;
}

function surveyResponsesToCsv(responses) {
    const headers = [
        'responseId',
        'courseId',
        'unitName',
        'conversationId',
        'studentId',
        'studentName',
        'settingsFingerprint',
        'triggerMessageCount',
        'messageCountAtPrompt',
        'promptText',
        'introText',
        'accuracyPrompt',
        'satisfactionPrompt',
        'allowFreeText',
        'ratingAccuracy',
        'ratingSatisfaction',
        'comment',
        'lastEvent',
        'createdAt',
        'shownAt',
        'dismissedAt',
        'submittedAt',
        'updatedAt'
    ];

    const rows = responses.map(item => headers.map(header => escapeCsvCell(item[header])).join(','));
    return [headers.join(','), ...rows].join('\n');
}

module.exports = {
    COLLECTION_NAME,
    VALID_EVENT_TYPES,
    MIN_STAR_RATING,
    MAX_STAR_RATING,
    MAX_COMMENT_LENGTH,
    getChatSurveyResponseCollection,
    generateSurveyResponseId,
    normalizeStarRating,
    buildSettingsSnapshot,
    buildSettingsFingerprint,
    ensureIndexes,
    upsertChatSurveyEvent,
    getSurveyResponseForSession,
    listSurveyResponsesForCourse,
    getSurveyStatsForCourse,
    surveyResponsesToCsv,
    toPublicSurveyResponse
};
