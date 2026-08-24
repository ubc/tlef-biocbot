const crypto = require('crypto');
const previewSession = require('./previewSession');

const COLLECTION = 'student_pseudonyms';
const CODE_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const CODE_LENGTH = 4;
const SENSITIVE_EXPORT_KEYS = new Set([
    'studentId',
    'studentName',
    'username',
    'email',
    'puid',
    'academicStudentId'
]);

function normalizeCode(value) {
    return String(value ?? '').trim().toUpperCase();
}

function isValidCode(value) {
    return /^[A-Z0-9]{4}$/.test(normalizeCode(value));
}

function generateCode() {
    let code = '';
    for (let index = 0; index < CODE_LENGTH; index += 1) {
        code += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
    }
    return code;
}

async function ensureIndexes(db) {
    const collection = db.collection(COLLECTION);
    await Promise.all([
        collection.createIndex(
            { scopeType: 1, scopeId: 1, studentId: 1 },
            { unique: true, name: 'unique_pseudonym_student_per_scope' }
        ),
        collection.createIndex(
            { scopeType: 1, scopeId: 1, pseudonym: 1 },
            { unique: true, name: 'unique_pseudonym_code_per_scope' }
        )
    ]);
    return collection;
}

function parseCsv(text) {
    if (typeof text !== 'string' || !text.trim()) {
        throw new Error('CSV file is empty');
    }

    const rows = [];
    let row = [];
    let field = '';
    let quoted = false;

    for (let index = 0; index < text.length; index += 1) {
        const character = text[index];
        if (quoted) {
            if (character === '"' && text[index + 1] === '"') {
                field += '"';
                index += 1;
            } else if (character === '"') {
                quoted = false;
            } else {
                field += character;
            }
        } else if (character === '"') {
            quoted = true;
        } else if (character === ',') {
            row.push(field);
            field = '';
        } else if (character === '\n') {
            row.push(field.replace(/\r$/, ''));
            rows.push(row);
            row = [];
            field = '';
        } else {
            field += character;
        }
    }

    if (quoted) throw new Error('CSV contains an unterminated quoted value');
    if (field || row.length) {
        row.push(field.replace(/\r$/, ''));
        rows.push(row);
    }

    const nonEmptyRows = rows.filter(columns => columns.some(value => value.trim()));
    if (nonEmptyRows.length < 2) throw new Error('CSV must include a header and at least one student');

    const headers = nonEmptyRows[0].map((value, index) => {
        const cleaned = value.trim();
        return index === 0 ? cleaned.replace(/^\uFEFF/, '') : cleaned;
    });
    const studentIndex = headers.indexOf('Student');
    const studentIdIndex = headers.indexOf('Student_ID');
    if (studentIndex === -1 || studentIdIndex === -1) {
        throw new Error('CSV headers must include Student and Student_ID');
    }

    return nonEmptyRows.slice(1).map((columns, index) => ({
        line: index + 2,
        pseudonym: normalizeCode(columns[studentIndex]),
        studentId: String(columns[studentIdIndex] ?? '').trim()
    }));
}

async function getCourseStudentIds(db, courseId) {
    const course = await db.collection('courses').findOne({ courseId });
    if (!course) throw Object.assign(new Error('Course not found'), { statusCode: 404 });

    const [chatStudentIds, preferenceUsers] = await Promise.all([
        db.collection('chat_sessions').distinct('studentId', { courseId }),
        db.collection('users').find({ role: 'student', 'preferences.courseId': courseId })
            .project({ userId: 1, isPreview: 1 })
            .toArray()
    ]);

    const ids = new Set([
        ...Object.keys(course.studentEnrollment || {}),
        ...chatStudentIds,
        ...preferenceUsers.filter(user => !user.isPreview).map(user => user.userId)
    ]);

    return Array.from(ids)
        .filter(id => typeof id === 'string' && id && !previewSession.isPreviewUserId(id))
        .sort();
}

async function getSuperchatStudentIds(db, superchatId) {
    const superchat = await db.collection('superchats').findOne({ superchatId, isDeleted: { $ne: true } });
    if (!superchat) throw Object.assign(new Error('Superchat not found'), { statusCode: 404 });

    const ids = await db.collection('student_super_course_chat_sessions').distinct('studentId', {
        superchatId,
        isDeleted: { $ne: true }
    });
    return ids
        .filter(id => typeof id === 'string' && id && !previewSession.isPreviewUserId(id))
        .sort();
}

async function getAssociatedStudentIds(db, scopeType, scopeId) {
    if (scopeType === 'course') return getCourseStudentIds(db, scopeId);
    if (scopeType === 'superchat') return getSuperchatStudentIds(db, scopeId);
    throw Object.assign(new Error('Invalid pseudonym scope'), { statusCode: 400 });
}

async function getMappings(db, scopeType, scopeId) {
    return db.collection(COLLECTION)
        .find({ scopeType, scopeId })
        .sort({ pseudonym: 1 })
        .toArray();
}

async function getScopeStatus(db, scopeType, scopeId) {
    const [studentIds, mappings] = await Promise.all([
        getAssociatedStudentIds(db, scopeType, scopeId),
        getMappings(db, scopeType, scopeId)
    ]);
    const byStudentId = new Map(mappings.map(mapping => [mapping.studentId, mapping]));
    const missingStudentIds = studentIds.filter(studentId => !byStudentId.has(studentId));

    return {
        scopeType,
        scopeId,
        studentCount: studentIds.length,
        mappingCount: studentIds.length - missingStudentIds.length,
        complete: missingStudentIds.length === 0,
        missingStudentIds,
        mappings
    };
}

async function generateMissingMappings(db, scopeType, scopeId, actorId) {
    const collection = await ensureIndexes(db);
    const status = await getScopeStatus(db, scopeType, scopeId);
    const usedCodes = new Set(status.mappings.map(mapping => mapping.pseudonym));
    const now = new Date();
    const created = [];

    for (const studentId of status.missingStudentIds) {
        let pseudonym;
        do {
            pseudonym = generateCode();
        } while (usedCodes.has(pseudonym));

        const document = {
            scopeType,
            scopeId,
            studentId,
            pseudonym,
            source: 'generated',
            createdAt: now,
            createdBy: actorId,
            updatedAt: now
        };

        try {
            await collection.insertOne(document);
            usedCodes.add(pseudonym);
            created.push(document);
        } catch (error) {
            if (error && error.code === 11000) {
                // Another request may have filled this student or claimed this code.
                // Re-read the scope and continue without ever overwriting a mapping.
                const existing = await collection.findOne({ scopeType, scopeId, studentId });
                if (existing) continue;
                throw Object.assign(new Error('A code collision occurred; run generation again'), { statusCode: 409 });
            }
            throw error;
        }
    }

    return { createdCount: created.length, status: await getScopeStatus(db, scopeType, scopeId) };
}

async function importCourseCsv(db, courseId, csvText, actorId) {
    const rows = parseCsv(csvText);
    const collection = await ensureIndexes(db);
    const [associatedStudentIds, existingMappings] = await Promise.all([
        getCourseStudentIds(db, courseId),
        getMappings(db, 'course', courseId)
    ]);
    const associated = new Set(associatedStudentIds);
    const existingByStudent = new Map(existingMappings.map(row => [row.studentId, row]));
    const existingByCode = new Map(existingMappings.map(row => [row.pseudonym, row]));
    const seenStudents = new Map();
    const seenCodes = new Map();
    const errors = [];

    for (const row of rows) {
        if (!isValidCode(row.pseudonym)) {
            errors.push({ line: row.line, message: 'Student must be exactly four letters and/or digits' });
        }
        if (!row.studentId) {
            errors.push({ line: row.line, message: 'Student_ID is required' });
        } else if (!associated.has(row.studentId)) {
            errors.push({ line: row.line, message: `Student_ID ${row.studentId} is not associated with this course` });
        }
        if (seenStudents.has(row.studentId)) {
            errors.push({ line: row.line, message: `Student_ID duplicates line ${seenStudents.get(row.studentId)}` });
        } else {
            seenStudents.set(row.studentId, row.line);
        }
        if (seenCodes.has(row.pseudonym)) {
            errors.push({ line: row.line, message: `Student code duplicates line ${seenCodes.get(row.pseudonym)}` });
        } else {
            seenCodes.set(row.pseudonym, row.line);
        }
        if (existingByStudent.has(row.studentId)) {
            errors.push({ line: row.line, message: `Student_ID ${row.studentId} already has a mapping` });
        }
        if (existingByCode.has(row.pseudonym)) {
            errors.push({ line: row.line, message: `Student code ${row.pseudonym} is already assigned` });
        }
    }

    if (errors.length) {
        throw Object.assign(new Error('CSV validation failed; no mappings were imported'), {
            statusCode: 400,
            validationErrors: errors
        });
    }

    const now = new Date();
    const documents = rows.map(row => ({
        scopeType: 'course',
        scopeId: courseId,
        studentId: row.studentId,
        pseudonym: row.pseudonym,
        source: 'imported',
        createdAt: now,
        createdBy: actorId,
        updatedAt: now
    }));
    await collection.insertMany(documents, { ordered: true });
    return { importedCount: documents.length, status: await getScopeStatus(db, 'course', courseId) };
}

async function getMappingRows(db, scopeType, scopeId) {
    const status = await getScopeStatus(db, scopeType, scopeId);
    const userIds = status.mappings.map(mapping => mapping.studentId);
    const users = userIds.length
        ? await db.collection('users').find({ userId: { $in: userIds } })
            .project({ userId: 1, displayName: 1, username: 1, puid: 1 })
            .toArray()
        : [];
    const usersById = new Map(users.map(user => [user.userId, user]));

    return {
        ...status,
        mappings: status.mappings.map(mapping => {
            const user = usersById.get(mapping.studentId) || {};
            return {
                student: mapping.pseudonym,
                studentId: mapping.studentId,
                puid: user.puid || '',
                displayName: user.displayName || user.username || '',
                source: mapping.source
            };
        })
    };
}

function escapeCsv(value) {
    const text = String(value ?? '');
    return `"${text.replace(/"/g, '""')}"`;
}

function mappingRowsToCsv(rows) {
    return [
        'Student,Student_ID,PUID',
        ...rows.map(row => [row.student, row.studentId, row.puid].map(escapeCsv).join(','))
    ].join('\n');
}

function stripIdentifyingFields(value) {
    if (Array.isArray(value)) return value.map(stripIdentifyingFields);
    if (!value || typeof value !== 'object') return value;

    const clean = {};
    for (const [key, child] of Object.entries(value)) {
        if (key === '_id' || SENSITIVE_EXPORT_KEYS.has(key)) continue;
        clean[key] = stripIdentifyingFields(child);
    }
    return clean;
}

module.exports = {
    COLLECTION,
    generateCode,
    getAssociatedStudentIds,
    getMappingRows,
    getMappings,
    getScopeStatus,
    generateMissingMappings,
    importCourseCsv,
    isValidCode,
    mappingRowsToCsv,
    normalizeCode,
    parseCsv,
    stripIdentifyingFields
};
