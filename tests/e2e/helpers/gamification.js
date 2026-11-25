/**
 * Seed data for the gamification specs (tests/e2e/gamification.spec.js,
 * tests/a11y/gamification.a11y.spec.js): a course of their own with one
 * published unit, e2e_instructor teaching it, e2e_ta helping, and e2e_student
 * enrolled. Gamification starts off, as for any course.
 *
 * Both specs need a server running gamification (BIOCBOT_GAMIFICATION=1 and
 * the toolkit installed). serverRunsGamification() tells them, so they can
 * skip on a server without it, such as CI's today.
 */
const { withDb, getUserIdByUsername } = require('./quiz');
const { createValidLlmApiKey } = require('./llm-keys');

const GAMI_COURSE_ID = 'BIOC-E2E-GAMI';
const GAMI_UNIT = 'Unit 1';

async function serverRunsGamification(request) {
    const response = await request.get(`/api/gamification/courses/${GAMI_COURSE_ID}/enabled`);
    if (!response.ok()) return false;
    return (await response.json()).running === true;
}

async function clearGamificationData(db) {
    await db.collection('courses').deleteMany({ courseId: GAMI_COURSE_ID });
    await db.collection('chatSessionStarts').deleteMany({ courseId: GAMI_COURSE_ID });
    await db.collection('chat_sessions').deleteMany({ courseId: GAMI_COURSE_ID });
    for (const name of ['gamification_events', 'gamification_states', 'gamification_settings']) {
        await db.collection(name).deleteMany({ course: GAMI_COURSE_ID });
    }
    await db.collection('gamification_rules').deleteMany({ _id: GAMI_COURSE_ID });
}

async function resetGamificationCourse() {
    const [instructorId, studentId, taId] = await Promise.all([
        getUserIdByUsername('e2e_instructor'),
        getUserIdByUsername('e2e_student'),
        getUserIdByUsername('e2e_ta')
    ]);
    const now = new Date();
    await withDb(async db => {
        await clearGamificationData(db);
        await db.collection('courses').insertOne({
            courseId: GAMI_COURSE_ID,
            courseName: 'BIOC E2E Gamification',
            courseCode: `${GAMI_COURSE_ID}-S`,
            instructorCourseCode: `${GAMI_COURSE_ID}-I`,
            instructorId,
            instructors: [instructorId],
            tas: [taId],
            courseDescription: '',
            assessmentCriteria: '',
            courseMaterials: [],
            approvedStruggleTopics: [],
            courseStructure: { weeks: 1, lecturesPerWeek: 1, totalUnits: 1 },
            isOnboardingComplete: true,
            status: 'active',
            llmApiKey: createValidLlmApiKey(GAMI_COURSE_ID),
            quizSettings: { enabled: true, testableUnits: 'all', allowLectureMaterialAccess: true },
            studentEnrollment: { [studentId]: { enrolled: true, enrolledAt: now } },
            lectures: [{
                name: GAMI_UNIT,
                displayName: GAMI_UNIT,
                isPublished: true,
                learningObjectives: [],
                passThreshold: 0,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: []
            }],
            createdAt: now,
            updatedAt: now
        });
    });
    return { instructorId, studentId, taId };
}

async function cleanupGamificationCourse() {
    await withDb(clearGamificationData);
}

module.exports = {
    GAMI_COURSE_ID,
    GAMI_UNIT,
    serverRunsGamification,
    resetGamificationCourse,
    cleanupGamificationCourse
};
