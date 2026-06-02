// @ts-check
/**
 * Shared helpers for Super Course "bucket" (superchat) e2e specs.
 *
 * A superchat is an instructor/admin-curated grouping of courses students chat
 * across. Membership lives course-side (`course.superchatIds`), so seeding a
 * scenario means: (1) create the bucket(s), (2) put courses in them via
 * superchatIds, and (3) enroll the student so the enrollment-derived visibility
 * gate lets them see it.
 *
 * DB access reuses courses-test's withDb (relies on MONGO_URI via dotenv).
 */

require('dotenv').config();
const { withDb } = require('./courses-test');

const SUPERCHATS_COLLECTION = 'superchats';

/**
 * Insert (replacing any existing) a superchat bucket.
 * @param {Object} args
 * @param {string} args.superchatId
 * @param {string} [args.name]
 * @param {number|null} [args.yearLevel]
 * @param {boolean} [args.showToStudents]
 * @param {Object} [args.overrides] - extra chat settings (studentTopK, prompts, ...)
 */
async function seedSuperchat({
    superchatId,
    name = superchatId,
    yearLevel = null,
    showToStudents = true,
    overrides = {},
}) {
    const now = new Date();
    const doc = {
        superchatId,
        name,
        description: '',
        yearLevel,
        showToStudents,
        studentTopK: 5,
        instructorTopK: 5,
        includeInactiveCourses: false,
        instructorPrompt: 'E2E instructor super prompt',
        studentPrompt: 'E2E student super prompt',
        createdBy: null,
        createdAt: now,
        updatedAt: now,
        isDeleted: false,
        ...overrides,
    };

    await withDb(async (db) => {
        await db.collection(SUPERCHATS_COLLECTION).deleteMany({ superchatId });
        await db.collection(SUPERCHATS_COLLECTION).insertOne(doc);
    });

    return doc;
}

/** Delete buckets by id list. */
async function cleanupSuperchats(superchatIds) {
    if (!superchatIds || !superchatIds.length) return;
    await withDb((db) =>
        db.collection(SUPERCHATS_COLLECTION).deleteMany({ superchatId: { $in: superchatIds } })
    );
}

/** Replace the set of buckets a course belongs to. */
async function setCourseSuperchats(courseId, superchatIds) {
    await withDb((db) =>
        db.collection('courses').updateOne(
            { courseId },
            { $set: { superchatIds: Array.isArray(superchatIds) ? superchatIds : [], updatedAt: new Date() } }
        )
    );
}

/** Read a single bucket document. */
async function readSuperchat(superchatId) {
    return withDb((db) => db.collection(SUPERCHATS_COLLECTION).findOne({ superchatId }));
}

/** Remove super-course chat sessions by id list (test cleanup). */
async function cleanupSuperCourseSessions(sessionIds) {
    if (!sessionIds || !sessionIds.length) return;
    await withDb((db) =>
        db.collection('student_super_course_chat_sessions').deleteMany({ sessionId: { $in: sessionIds } })
    );
}

module.exports = {
    SUPERCHATS_COLLECTION,
    seedSuperchat,
    cleanupSuperchats,
    setCourseSuperchats,
    readSuperchat,
    cleanupSuperCourseSessions,
};
