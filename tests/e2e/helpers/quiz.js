// @ts-check
/**
 * Shared helpers for quiz e2e tests.
 *
 * Seeds a dedicated course (`BIOC-E2E-QUIZ`) with a known set of published
 * units, assessment questions, and (optionally) a stored document. Each spec's
 * beforeEach should call resetQuizCourse() so tests are independent.
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');
const { createValidLlmApiKey } = require('./llm-keys');

const QUIZ_COURSE_ID = 'BIOC-E2E-QUIZ';
const QUIZ_COURSE_NAME = 'BIOC E2E Quiz Test';

// Stable question IDs let API tests reference questions without having to
// re-fetch them after every seed.
const QUESTION_IDS = {
    mc: 'q_e2e_quiz_mc',
    tf: 'q_e2e_quiz_tf',
    sa: 'q_e2e_quiz_sa',
    unpublished: 'q_e2e_quiz_unpublished',
};

const DOC_ID = 'doc_e2e_quiz_material';

async function withDb(fn) {
    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI not set; cannot run quiz e2e tests.');
    }
    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    try {
        return await fn(client.db());
    } finally {
        await client.close();
    }
}

async function getUserIdByUsername(username) {
    return withDb(async (db) => {
        const u = await db.collection('users').findOne({ username });
        if (!u) throw new Error(`User ${username} not found in DB.`);
        return u.userId;
    });
}

async function getStudentId() {
    return getUserIdByUsername('e2e_student');
}

/**
 * Drop and recreate the quiz test course, its quiz attempts, and a sample
 * lecture document. Idempotent — safe to call from beforeEach.
 *
 * @param {Object} opts
 * @param {string} opts.instructorId
 * @param {Partial<{enabled: boolean, testableUnits: any, allowLectureMaterialAccess: boolean}>} [opts.quizSettings]
 */
async function resetQuizCourse({ instructorId, quizSettings = {} }) {
    const settings = {
        enabled: true,
        testableUnits: 'all',
        allowLectureMaterialAccess: true,
        allowSourceAttributionDownloads: false,
        ...quizSettings,
    };

    // The /api/quiz/* middleware (requireStudentEnrolled) requires students to
    // be enrolled in the course. Always enroll e2e_student so callers don't
    // have to thread a studentId through every test.
    const studentId = await getStudentId();
    const studentEnrollment = {
        [studentId]: { enrolled: true, enrolledAt: new Date() },
    };

    await withDb(async (db) => {
        await db.collection('courses').deleteMany({ courseId: QUIZ_COURSE_ID });
        await db.collection('quizAttempts').deleteMany({ courseId: QUIZ_COURSE_ID });
        await db.collection('documents').deleteMany({ courseId: QUIZ_COURSE_ID });

        const now = new Date();

        await db.collection('courses').insertOne({
            courseId: QUIZ_COURSE_ID,
            courseName: QUIZ_COURSE_NAME,
            courseCode: 'E2EQUIZS',
            instructorCourseCode: 'E2EQUIZI',
            instructorId,
            instructors: [instructorId],
            tas: [],
            courseDescription: '',
            assessmentCriteria: '',
            courseMaterials: [],
            approvedStruggleTopics: [],
            courseStructure: { weeks: 2, lecturesPerWeek: 1, totalUnits: 2 },
            isOnboardingComplete: true,
            status: 'active',
            llmApiKey: createValidLlmApiKey(QUIZ_COURSE_ID),
            quizSettings: settings,
            studentEnrollment,
            lectures: [
                {
                    name: 'Unit 1',
                    displayName: 'Unit 1',
                    isPublished: true,
                    learningObjectives: ['Understand biomolecules'],
                    passThreshold: 0,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        {
                            questionId: QUESTION_IDS.mc,
                            questionType: 'multiple-choice',
                            question: 'Which biomolecule is the primary energy currency of the cell?',
                            options: { A: 'DNA', B: 'ATP', C: 'Glucose', D: 'Glycogen' },
                            correctAnswer: 'B',
                            difficulty: 'easy',
                            tags: ['energy'],
                            points: 1,
                            isActive: true,
                        },
                        {
                            questionId: QUESTION_IDS.tf,
                            questionType: 'true-false',
                            question: 'Water is a polar molecule.',
                            correctAnswer: 'true',
                            difficulty: 'easy',
                            tags: ['water'],
                            points: 1,
                            isActive: true,
                        },
                        {
                            questionId: QUESTION_IDS.sa,
                            questionType: 'short-answer',
                            question: 'Name the bond formed between two amino acids during protein synthesis.',
                            correctAnswer: 'A peptide bond is formed via a condensation reaction between two amino acids.',
                            difficulty: 'medium',
                            tags: ['proteins'],
                            points: 2,
                            isActive: true,
                        },
                    ],
                },
                {
                    name: 'Unit 2',
                    displayName: 'Unit 2',
                    isPublished: false, // unpublished — its questions must never appear in /questions
                    learningObjectives: [],
                    passThreshold: 0,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        {
                            questionId: QUESTION_IDS.unpublished,
                            questionType: 'true-false',
                            question: 'This question must never be served to students.',
                            correctAnswer: 'true',
                            difficulty: 'easy',
                            tags: [],
                            points: 1,
                            isActive: true,
                        },
                    ],
                },
            ],
            createdAt: now,
            updatedAt: now,
        });

        await db.collection('documents').insertOne({
            documentId: DOC_ID,
            courseId: QUIZ_COURSE_ID,
            lectureName: 'Unit 1',
            instructorId,
            documentType: 'lecture-notes',
            type: 'lecture_notes',
            contentType: 'text',
            filename: 'unit1-notes.txt',
            originalName: 'Unit 1 Notes.txt',
            content: 'Biomolecule study material for Unit 1. ATP is the primary energy currency.',
            mimeType: 'text/plain',
            size: 80,
            status: 'parsed',
            uploadDate: now,
            lastModified: now,
            metadata: {},
        });
    });
}

async function cleanupQuizCourse() {
    await withDb(async (db) => {
        await db.collection('courses').deleteMany({ courseId: QUIZ_COURSE_ID });
        await db.collection('quizAttempts').deleteMany({ courseId: QUIZ_COURSE_ID });
        await db.collection('documents').deleteMany({ courseId: QUIZ_COURSE_ID });
    });
}

module.exports = {
    QUIZ_COURSE_ID,
    QUIZ_COURSE_NAME,
    QUESTION_IDS,
    DOC_ID,
    withDb,
    getUserIdByUsername,
    resetQuizCourse,
    cleanupQuizCourse,
};
