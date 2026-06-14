// @ts-check
/**
 * Shared helpers for the student-side e2e suite.
 *
 * Builds on the quiz helper for DB access. Seeds a dedicated "student chat"
 * course plus a second course used for cross-course isolation tests. Both
 * courses enroll e2e_student. The "OTHER" course also enrolls a second
 * synthetic student so we can prove that one student cannot read, write,
 * or delete another student's chat history.
 */

const { withDb, getUserIdByUsername } = require('./quiz');
const { createValidLlmApiKey } = require('./llm-keys');

const STU_COURSE_ID = 'BIOC-E2E-STU';
const STU_COURSE_NAME = 'BIOC E2E Student Chat';

const STU_INACTIVE_COURSE_ID = 'BIOC-E2E-STU-INACTIVE';
const STU_INACTIVE_COURSE_NAME = 'BIOC E2E Student Chat (Inactive)';

const STU_OTHER_COURSE_ID = 'BIOC-E2E-STU-OTHER';
const STU_OTHER_COURSE_NAME = 'BIOC E2E Student Chat (Other Course)';

const STU_DELETED_COURSE_ID = 'BIOC-E2E-STU-DELETED';
const STU_DELETED_COURSE_NAME = 'BIOC E2E Student Chat (Deleted)';

// Synthetic "other student" — used only by tests that need to prove a
// real-but-different studentId is unreachable from the e2e_student account.
const OTHER_STUDENT_ID = 'user_e2e_other_student_fixed_id';

const APPROVED_TOPIC = 'Photosynthesis';

const STU_UNITS = [
    {
        name: 'Unit 1',
        displayName: 'Unit 1',
        isPublished: true,
    },
    {
        name: 'Unit 2',
        displayName: 'Unit 2',
        isPublished: false,
    },
];

async function getStudentId() {
    return getUserIdByUsername('e2e_student');
}

function buildCourseDoc({ courseId, courseName, instructorId, studentEnrollment, status = 'active', approvedStruggleTopics = [APPROVED_TOPIC] }) {
    const now = new Date();
    return {
        courseId,
        courseName,
        courseCode: `${courseId}-S`,
        instructorCourseCode: `${courseId}-I`,
        instructorId,
        instructors: [instructorId],
        tas: [],
        courseDescription: '',
        assessmentCriteria: '',
        courseMaterials: [],
        approvedStruggleTopics,
        courseStructure: { weeks: 2, lecturesPerWeek: 1, totalUnits: 2 },
        isOnboardingComplete: true,
        status,
        llmApiKey: createValidLlmApiKey(courseId),
        quizSettings: { enabled: true, testableUnits: 'all', allowLectureMaterialAccess: true },
        studentEnrollment,
        lectures: STU_UNITS.map((u) => ({
            name: u.name,
            displayName: u.displayName,
            isPublished: u.isPublished,
            learningObjectives: [],
            passThreshold: 0,
            createdAt: now,
            updatedAt: now,
            documents: [],
            assessmentQuestions: [],
        })),
        createdAt: now,
        updatedAt: now,
    };
}

/**
 * Reset all student-chat seed data. Idempotent.
 *
 * @param {Object} opts
 * @param {string} opts.instructorId
 * @param {Object} [opts.options]
 * @param {boolean} [opts.options.includeInactive=true]
 * @param {boolean} [opts.options.includeOther=true]
 * @param {boolean} [opts.options.includeDeleted=true]
 * @param {Array<string>} [opts.options.approvedTopics]
 */
async function resetStudentChatData({ instructorId, options = {} }) {
    const {
        includeInactive = true,
        includeOther = true,
        includeDeleted = true,
        approvedTopics = [APPROVED_TOPIC],
    } = options;

    const studentId = await getStudentId();

    await withDb(async (db) => {
        const ids = [
            STU_COURSE_ID,
            STU_INACTIVE_COURSE_ID,
            STU_OTHER_COURSE_ID,
            STU_DELETED_COURSE_ID,
        ];

        await db.collection('courses').deleteMany({ courseId: { $in: ids } });
        await db.collection('chat_sessions').deleteMany({ courseId: { $in: ids } });

        // Clear out the synthetic "other student" user doc and start fresh.
        // We use a fixed userId so chat_sessions for them are predictable.
        await db.collection('users').deleteMany({ userId: OTHER_STUDENT_ID });
        await db.collection('users').insertOne({
            userId: OTHER_STUDENT_ID,
            username: 'e2e_other_student_fixed',
            email: 'e2e-other-fixed@test.local',
            role: 'student',
            displayName: 'E2E Other Student (Fixed)',
            authProvider: 'local',
            createdAt: new Date(),
            updatedAt: new Date(),
        });

        // Reset the e2e_student struggle state — tests that exercise struggle
        // need a clean slate so they don't inherit prior runs.
        await db.collection('users').updateOne(
            { userId: studentId },
            { $unset: { struggleState: '' } }
        );

        const studentEnrollment = {
            [studentId]: { enrolled: true, enrolledAt: new Date() },
        };

        // Main course
        await db.collection('courses').insertOne(
            buildCourseDoc({
                courseId: STU_COURSE_ID,
                courseName: STU_COURSE_NAME,
                instructorId,
                studentEnrollment,
                approvedStruggleTopics: approvedTopics,
            })
        );

        if (includeInactive) {
            await db.collection('courses').insertOne(
                buildCourseDoc({
                    courseId: STU_INACTIVE_COURSE_ID,
                    courseName: STU_INACTIVE_COURSE_NAME,
                    instructorId,
                    studentEnrollment,
                    status: 'inactive',
                })
            );
        }

        if (includeOther) {
            // "Other" course — e2e_student AND the other synthetic student
            // are both enrolled here, so cross-student isolation tests can
            // act as either side.
            await db.collection('courses').insertOne(
                buildCourseDoc({
                    courseId: STU_OTHER_COURSE_ID,
                    courseName: STU_OTHER_COURSE_NAME,
                    instructorId,
                    studentEnrollment: {
                        ...studentEnrollment,
                        [OTHER_STUDENT_ID]: { enrolled: true, enrolledAt: new Date() },
                    },
                })
            );
        }

        if (includeDeleted) {
            await db.collection('courses').insertOne(
                buildCourseDoc({
                    courseId: STU_DELETED_COURSE_ID,
                    courseName: STU_DELETED_COURSE_NAME,
                    instructorId,
                    studentEnrollment,
                    status: 'deleted',
                })
            );
        }
    });
}

async function cleanupStudentChatData() {
    await withDb(async (db) => {
        const ids = [
            STU_COURSE_ID,
            STU_INACTIVE_COURSE_ID,
            STU_OTHER_COURSE_ID,
            STU_DELETED_COURSE_ID,
        ];
        await db.collection('courses').deleteMany({ courseId: { $in: ids } });
        await db.collection('chat_sessions').deleteMany({ courseId: { $in: ids } });
        await db.collection('users').deleteMany({ userId: OTHER_STUDENT_ID });
    });
}

/**
 * Insert a chat_session document directly. Lets us prove server-side filtering
 * without going through the full /api/chat/save flow when the test only cares
 * about read paths.
 *
 * @param {Object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.courseId
 * @param {string} opts.studentId
 * @param {string} opts.studentName
 * @param {string} [opts.title]
 * @param {Array<Object>} [opts.messages]
 */
async function seedChatSession({ sessionId, courseId, studentId, studentName, title = 'Seeded session', messages = [] }) {
    await withDb(async (db) => {
        await db.collection('chat_sessions').replaceOne(
            { sessionId },
            {
                sessionId,
                courseId,
                studentId,
                studentName,
                unitName: 'Unit 1',
                title,
                messageCount: messages.length,
                duration: '0s',
                savedAt: new Date().toISOString(),
                chatData: { messages },
                isDeleted: false,
                createdAt: new Date(),
            },
            { upsert: true }
        );
    });
}

async function setUserAgreement(userId, hasAgreed) {
    await withDb(async (db) => {
        if (hasAgreed === null) {
            await db.collection('userAgreements').deleteMany({ userId });
            return;
        }
        await db.collection('userAgreements').replaceOne(
            { userId, userType: 'student' },
            {
                userId,
                userType: 'student',
                hasAgreed,
                agreementVersion: '1.0',
                agreedAt: hasAgreed ? new Date() : null,
                updatedAt: new Date(),
                createdAt: new Date(),
            },
            { upsert: true }
        );
    });
}

module.exports = {
    STU_COURSE_ID,
    STU_COURSE_NAME,
    STU_INACTIVE_COURSE_ID,
    STU_OTHER_COURSE_ID,
    STU_DELETED_COURSE_ID,
    OTHER_STUDENT_ID,
    APPROVED_TOPIC,
    getStudentId,
    resetStudentChatData,
    cleanupStudentChatData,
    seedChatSession,
    setUserAgreement,
};
