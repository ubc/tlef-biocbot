const { createId } = require('./id');
const { getAcademicApiClient } = require('./academicApi');
const { normalizeEmail } = require('./authorization');

function normalizeText(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function normalizeAcademicPerson(person = {}) {
    const puid = normalizeText(person.puid || person.PUID || person.puidId);
    const studentId = normalizeText(person.ID || person.Student_ID || person.studentId || person.student_id);
    const email = normalizeEmail(person.email || person.workEmail || person.personalEmail || person.Email);
    const preferredName = normalizeText(
        person.preferredName ||
        person.displayName ||
        person.name ||
        person.Preferred_Name ||
        person.Legal_Name
    );

    return {
        puid,
        studentId,
        email,
        preferredName
    };
}

function generateUserId() {
    return createId('user');
}

async function findExistingStudent(usersCollection, student) {
    const query = [];
    if (student.puid) query.push({ puid: student.puid });
    if (student.email) query.push({ email: student.email });
    if (student.studentId) query.push({ academicStudentId: student.studentId });

    if (query.length === 0) {
        return null;
    }

    return usersCollection.findOne({ $or: query });
}

async function upsertAcademicStudent(db, student, courseId) {
    const usersCollection = db.collection('users');
    const now = new Date();
    const existing = await findExistingStudent(usersCollection, student);

    if (existing) {
        const setFields = {
            updatedAt: now
        };

        if (student.puid && !existing.puid) setFields.puid = student.puid;
        if (student.studentId && !existing.academicStudentId) setFields.academicStudentId = student.studentId;
        if (student.email && !existing.email) setFields.email = student.email;
        if (student.preferredName && (!existing.displayName || existing.displayName === existing.username)) {
            setFields.displayName = student.preferredName;
        }
        if (!existing.preferences || !existing.preferences.courseId) {
            setFields['preferences.courseId'] = courseId;
        }

        await usersCollection.updateOne(
            { userId: existing.userId },
            { $set: setFields }
        );

        return {
            ...existing,
            ...setFields,
            preferences: {
                ...(existing.preferences || {}),
                courseId: setFields['preferences.courseId'] || existing.preferences?.courseId || null
            },
            created: false
        };
    }

    const username = student.email || student.puid || student.studentId || generateUserId();
    const user = {
        userId: generateUserId(),
        username,
        email: student.email || null,
        passwordHash: null,
        role: 'student',
        displayName: student.preferredName || username,
        authProvider: 'saml',
        samlId: null,
        puid: student.puid || null,
        academicStudentId: student.studentId || null,
        isActive: true,
        lastLogin: null,
        createdAt: now,
        updatedAt: now,
        preferences: {
            theme: 'light',
            notifications: true,
            courseId
        },
        permissions: {
            systemAdmin: false
        },
        struggleState: {
            topics: []
        }
    };

    await usersCollection.insertOne(user);

    return {
        ...user,
        created: true
    };
}

function getManagedEnrollmentPuids(course = {}) {
    const enrollment = course.studentEnrollment || {};
    const managed = new Map();

    for (const [userId, record] of Object.entries(enrollment)) {
        if (!record || record.source !== 'academicSync') continue;
        const puid = normalizeText(record.puid || record.academicSync?.puid);
        if (puid) managed.set(puid, userId);
    }

    return managed;
}

async function syncCourseRoster(db, courseId, options = {}) {
    const coursesCollection = db.collection('courses');
    const course = await coursesCollection.findOne({ courseId });

    if (!course) {
        return { success: false, error: 'Course not found' };
    }

    const academicPeriod = options.academicPeriod || course.academicSync?.academicPeriod;
    const sectionIds = Array.isArray(options.sectionIds) && options.sectionIds.length > 0
        ? options.sectionIds
        : course.academicSync?.sectionIds;

    if (!academicPeriod || !Array.isArray(sectionIds) || sectionIds.length === 0) {
        return { success: false, error: 'Course is not linked to academic sections' };
    }

    const api = options.academicApi || getAcademicApiClient();
    const roster = await api.getStudentsFromSections(sectionIds, academicPeriod);
    const incoming = new Map();
    const skipped = [];

    for (const rawStudent of roster || []) {
        const student = normalizeAcademicPerson(rawStudent);
        if (!student.puid) {
            skipped.push({ reason: 'missing_puid', student });
            continue;
        }
        incoming.set(student.puid, student);
    }

    if ((roster || []).length > 0 && incoming.size === 0) {
        return {
            success: false,
            error: 'Roster contained students, but none included a PUID. No enrollment changes were made.',
            skipped: skipped.length
        };
    }

    const managedBefore = getManagedEnrollmentPuids(course);
    const now = new Date();
    const summary = {
        success: true,
        courseId,
        academicPeriod,
        sectionIds,
        incomingCount: incoming.size,
        added: 0,
        updated: 0,
        removed: 0,
        skipped: skipped.length
    };

    for (const [puid, student] of incoming.entries()) {
        const user = await upsertAcademicStudent(db, student, courseId);

        await coursesCollection.updateOne(
            { courseId },
            {
                $set: {
                    [`studentEnrollment.${user.userId}`]: {
                        enrolled: true,
                        source: 'academicSync',
                        puid,
                        studentId: student.studentId || null,
                        email: student.email || null,
                        displayName: student.preferredName || null,
                        syncedAt: now,
                        updatedAt: now
                    },
                    updatedAt: now
                }
            }
        );

        if (managedBefore.has(puid)) {
            summary.updated += 1;
        } else {
            summary.added += 1;
        }
    }

    for (const [puid, userId] of managedBefore.entries()) {
        if (incoming.has(puid)) continue;

        await coursesCollection.updateOne(
            { courseId },
            {
                $set: {
                    [`studentEnrollment.${userId}.enrolled`]: false,
                    [`studentEnrollment.${userId}.droppedAt`]: now,
                    [`studentEnrollment.${userId}.syncedAt`]: now,
                    [`studentEnrollment.${userId}.updatedAt`]: now,
                    updatedAt: now
                }
            }
        );
        summary.removed += 1;
    }

    await coursesCollection.updateOne(
        { courseId },
        {
            $set: {
                academicSync: {
                    ...(course.academicSync || {}),
                    academicPeriod,
                    sectionIds,
                    lastSyncAt: now,
                    lastSyncSummary: summary
                },
                updatedAt: now
            }
        }
    );

    return summary;
}

module.exports = {
    normalizeAcademicPerson,
    syncCourseRoster,
    upsertAcademicStudent
};
