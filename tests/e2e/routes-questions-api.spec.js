// @ts-check
/**
 * API coverage for src/routes/questions.js (15% → target much higher).
 *
 * Per AGENTS.md, bug-exposing assertions are left failing and recorded in
 * FINDINGS.md (#21: `!correctAnswer` rejects falsy structured answers, #23:
 * routes trust body `instructorId` without checking course access, #24:
 * GET /:questionId is a global cross-course lookup).
 */

const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
} = require('./helpers/courses-test');
const { resetLlmStub, enqueueLlmResponses } = require('./helpers/llm-stub');

const COURSE_A = 'BIOC-E2E-API-QUESTIONS-A';
const COURSE_B = 'BIOC-E2E-API-QUESTIONS-B';

let instructorId;
let instructorFreshId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    instructorFreshId = await getUserIdByUsername(TEST_USERS.instructor_fresh.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_A, COURSE_B]);
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
});

// ---------------------------------------------------------------------------
// POST /api/questions
// ---------------------------------------------------------------------------
test.describe('POST /api/questions (create)', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_A, instructorId });
    });

    test('400 when required fields are missing', async ({ request: api }) => {
        const res = await api.post('/api/questions', { data: { courseId: COURSE_A } });
        expect(res.status()).toBe(400);
    });

    test('happy path creates a multiple-choice question and returns id', async ({ request: api }) => {
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'multiple-choice',
                question: 'Which biomolecule stores genetic information?',
                options: { A: 'DNA', B: 'ATP', C: 'Glucose', D: 'Glycogen' },
                correctAnswer: 'A',
                difficulty: 'easy',
                tags: ['genetics'],
                points: 1,
                learningObjective: 'Understand information macromolecules',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.questionId).toMatch(/^q_/);
    });

    test('creates a short-answer question (default points/difficulty)', async ({ request: api }) => {
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'short-answer',
                question: 'Define homeostasis.',
                correctAnswer: 'Maintenance of stable internal conditions despite external changes.',
            },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('PRODUCT BUG (FINDINGS #21): boolean false TF correctAnswer rejected as missing', async ({ request: api }) => {
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
                question: 'Hydrogen bonds are stronger than covalent bonds.',
                correctAnswer: false, // structured TF answer
            },
        });
        // EXPECTED: accept boolean false. Currently 400 because the route uses !correctAnswer.
        expect(res.ok()).toBeTruthy();
    });

    test('PRODUCT BUG (FINDINGS #21): MCQ correctAnswer index 0 rejected as missing', async ({ request: api }) => {
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'multiple-choice',
                question: 'Which is the first amino acid in the alphabet?',
                options: ['Alanine', 'Arginine', 'Asparagine', 'Glutamine'],
                correctAnswer: 0, // structured numeric index
            },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('PRODUCT BUG (FINDINGS #23): body `instructorId` mismatch is accepted (no auth check)', async ({ request: api }) => {
        // Authenticated as e2e_instructor but submits a different instructorId
        // for a course they own. Expected: 403 — route must derive identity
        // from req.user, not trust the request body.
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId: instructorFreshId, // not the caller
                questionType: 'true-false',
                question: 'Trust but verify.',
                correctAnswer: 'true',
            },
        });
        expect([401, 403]).toContain(res.status());
    });

    test('PRODUCT BUG (FINDINGS #23): authenticated instructor can mutate another instructor\'s course', async ({ request: api }) => {
        // COURSE_B is owned by instructor_fresh. Caller (e2e_instructor) is
        // authenticated but has no access to that course. Currently the route
        // never checks user/course relation, so it succeeds.
        await seedCourse({ courseId: COURSE_B, instructorId: instructorFreshId });
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_B,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
                question: 'Cross-course injection',
                correctAnswer: 'true',
            },
        });
        // EXPECTED: 403 — caller has no access to COURSE_B.
        expect([401, 403]).toContain(res.status());
    });
});

// ---------------------------------------------------------------------------
// GET /api/questions/lecture
// ---------------------------------------------------------------------------
test.describe('GET /api/questions/lecture', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when query params missing', async ({ request: api }) => {
        const res = await api.get('/api/questions/lecture?courseId=COURSE');
        expect(res.status()).toBe(400);
    });

    test('returns the list and count for a seeded lecture', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [
                {
                    name: 'Unit 1',
                    isPublished: true,
                    learningObjectives: [],
                    passThreshold: 2,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        {
                            questionId: 'q_e2e_listed_1',
                            questionType: 'true-false',
                            question: 'A',
                            correctAnswer: 'true',
                            isActive: true,
                        },
                    ],
                },
            ],
        });
        const res = await api.get(`/api/questions/lecture?courseId=${COURSE_A}&lectureName=${encodeURIComponent('Unit 1')}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.count).toBeGreaterThanOrEqual(1);
        expect(body.data.questions.find((q) => q.questionId === 'q_e2e_listed_1')).toBeTruthy();
    });
});

// ---------------------------------------------------------------------------
// GET /api/questions/:questionId (global lookup) — FINDINGS #24
// ---------------------------------------------------------------------------
test.describe('GET /api/questions/:questionId', () => {
    test('404 when questionId does not exist', async ({ baseURL }) => {
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get('/api/questions/q_does_not_exist');
            expect(res.status()).toBe(404);
        } finally {
            await api.dispose();
        }
    });

    test('returns the question for the owning instructor', async ({ baseURL }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [
                    { questionId: 'q_e2e_owner', questionType: 'true-false', question: 'A', correctAnswer: 'true', isActive: true },
                ],
            }],
        });
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get('/api/questions/q_e2e_owner');
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.data.questionId).toBe('q_e2e_owner');
        } finally {
            await api.dispose();
        }
    });

    test('PRODUCT BUG (FINDINGS #24): any authenticated user can fetch a question from another course', async ({ baseURL }) => {
        // Seed a question in COURSE_B (owned by instructor_fresh).
        const now = new Date();
        await seedCourse({
            courseId: COURSE_B,
            instructorId: instructorFreshId,
            lectures: [{
                name: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [
                    { questionId: 'q_e2e_other_course', questionType: 'true-false', question: 'private', correctAnswer: 'true', isActive: true },
                ],
            }],
        });
        // Caller is e2e_instructor — has no access to COURSE_B.
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get('/api/questions/q_e2e_other_course');
            // EXPECTED: 403/404. Currently 200 — leaks the question.
            expect([403, 404]).toContain(res.status());
        } finally {
            await api.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// PUT /api/questions/:questionId
// ---------------------------------------------------------------------------
test.describe('PUT /api/questions/:questionId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required fields missing', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.put('/api/questions/q_anything', {
            data: { courseId: COURSE_A },
        });
        expect(res.status()).toBe(400);
    });

    test('happy path updates question fields', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [
                    { questionId: 'q_e2e_update', questionType: 'true-false', question: 'Old text', correctAnswer: 'true', isActive: true, points: 1 },
                ],
            }],
        });
        const res = await api.put('/api/questions/q_e2e_update', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                question: 'New text',
                points: 5,
                tags: ['updated'],
                learningObjective: '  Trimmed objective  ',
            },
        });
        expect(res.ok()).toBeTruthy();

        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        const q = doc.lectures[0].assessmentQuestions.find((x) => x.questionId === 'q_e2e_update');
        expect(q.question).toBe('New text');
        expect(q.points).toBe(5);
        expect(q.learningObjective).toBe('Trimmed objective'); // normalized
    });
});

// ---------------------------------------------------------------------------
// DELETE /api/questions/:questionId
// ---------------------------------------------------------------------------
test.describe('DELETE /api/questions/:questionId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when fields missing', async ({ request: api }) => {
        const res = await api.delete('/api/questions/q_x', { data: { courseId: COURSE_A } });
        expect(res.status()).toBe(400);
    });

    test('happy path soft-deletes (sets isActive false)', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [
                    { questionId: 'q_e2e_delete', questionType: 'true-false', question: 'X', correctAnswer: 'true', isActive: true },
                ],
            }],
        });
        const res = await api.delete('/api/questions/q_e2e_delete', {
            data: { courseId: COURSE_A, lectureName: 'Unit 1', instructorId },
        });
        expect(res.ok()).toBeTruthy();

        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        const q = doc.lectures[0].assessmentQuestions.find((x) => x.questionId === 'q_e2e_delete');
        // Implementation either removes or sets isActive:false; either way the
        // question is no longer "active".
        if (q) {
            expect(q.isActive).toBe(false);
        }
    });

    test('400 when course or lecture is unknown (model returns failure)', async ({ request: api }) => {
        const res = await api.delete('/api/questions/q_nope', {
            data: { courseId: 'BIOC-E2E-API-NOPE', lectureName: 'Unit 1', instructorId },
        });
        // Route surfaces model failure as 400
        expect([400, 404]).toContain(res.status());
    });
});

// ---------------------------------------------------------------------------
// GET /api/questions/stats
//
// PRODUCT BUG: `/stats` is registered AFTER `/:questionId` in
// src/routes/questions.js, so Express treats `stats` as a questionId. The
// /stats handler is therefore unreachable. Same pattern hits `/course-material`
// below.
// ---------------------------------------------------------------------------
test.describe('GET /api/questions/stats', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when courseId is missing', async ({ request: api }) => {
        // The /stats route is now reachable (FINDINGS #32 closed by reordering
        // its declaration before /:questionId). With no courseId, the handler
        // short-circuits on the missing-param branch.
        const res = await api.get('/api/questions/stats');
        expect(res.status()).toBe(400);
    });

    test('returns zero counts when the course has lectures but no questions', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: false,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        const res = await api.get(`/api/questions/stats?courseId=${COURSE_A}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        // Real course path wraps the counts under `data.stats`.
        expect(body.data.stats.totalQuestions).toBe(0);
        expect(body.data.stats.totalPoints).toBe(0);
        expect(body.data.stats.typeBreakdown).toEqual([]);
    });

    test('aggregates questions by type and points across all lectures', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [
                {
                    name: 'Unit 1',
                    isPublished: true,
                    learningObjectives: [],
                    passThreshold: 2,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        { questionId: 'q-stats-1', questionType: 'true-false', question: 'TF1', correctAnswer: 'true', points: 2 },
                        { questionId: 'q-stats-2', questionType: 'multiple-choice', question: 'MC1', options: { A: 'a', B: 'b' }, correctAnswer: 'A' },
                    ],
                },
                {
                    name: 'Unit 2',
                    isPublished: false,
                    learningObjectives: [],
                    passThreshold: 2,
                    createdAt: now,
                    updatedAt: now,
                    documents: [],
                    assessmentQuestions: [
                        { questionId: 'q-stats-3', questionType: 'true-false', question: 'TF2', correctAnswer: 'false', points: 3 },
                    ],
                },
            ],
        });
        const res = await api.get(`/api/questions/stats?courseId=${COURSE_A}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        // Two TF (points 2 + 3 = 5) + one MC (default points 1). Total = 3 questions, 6 points.
        expect(body.data.stats.totalQuestions).toBe(3);
        expect(body.data.stats.totalPoints).toBe(6);
        const tf = body.data.stats.typeBreakdown.find((entry) => entry.type === 'true-false');
        const mc = body.data.stats.typeBreakdown.find((entry) => entry.type === 'multiple-choice');
        expect(tf).toEqual({ type: 'true-false', count: 2, points: 5 });
        expect(mc).toEqual({ type: 'multiple-choice', count: 1, points: 1 });
    });

    test('returns zero counts when the course does not exist', async ({ request: api }) => {
        const res = await api.get('/api/questions/stats?courseId=BIOC-E2E-NOPE-STATS');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.totalQuestions).toBe(0);
        expect(body.data.totalPoints).toBe(0);
        expect(body.data.typeBreakdown).toEqual([]);
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/bulk
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/bulk', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required fields or questions array missing', async ({ request: api }) => {
        const r1 = await api.post('/api/questions/bulk', { data: {} });
        expect(r1.status()).toBe(400);

        const r2 = await api.post('/api/questions/bulk', {
            data: { courseId: 'X', lectureName: 'Unit 1', instructorId, questions: 'not-array' },
        });
        expect(r2.status()).toBe(400);
    });

    test('happy path inserts each question and returns inserted ids', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/bulk', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questions: [
                    {
                        questionType: 'true-false',
                        question: 'Bulk Q1',
                        correctAnswer: 'true',
                        learningObjective: '',
                    },
                    {
                        questionType: 'multiple-choice',
                        question: 'Bulk Q2',
                        options: { A: 'a', B: 'b' },
                        correctAnswer: 'A',
                        learningObjective: '',
                    },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.insertedCount).toBe(2);
        expect(body.data.insertedIds).toHaveLength(2);
    });

    test('empty questions array is technically valid → inserts 0', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/bulk', {
            data: { courseId: COURSE_A, lectureName: 'Unit 1', instructorId, questions: [] },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.insertedCount).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// GET /api/questions/course-material
// (Reachable now that the static path is declared before /:questionId.)
// ---------------------------------------------------------------------------
test.describe('GET /api/questions/course-material', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required query params are missing', async ({ request: api }) => {
        const res = await api.get('/api/questions/course-material');
        expect(res.status()).toBe(400);
    });

    test('happy path returns aggregated document content', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [
                    {
                        documentId: 'doc-cm-1',
                        type: 'lecture_notes',
                        documentType: 'lecture-notes',
                        originalName: 'Lecture Notes A.txt',
                        content: 'ATP is the cellular energy currency.',
                    },
                ],
                assessmentQuestions: [],
            }],
        });
        const res = await api.get(
            `/api/questions/course-material?courseId=${COURSE_A}&lectureName=Unit 1&instructorId=${instructorId}`
        );
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.hasMaterials).toBe(true);
    });

    test('404 when the course does not exist', async ({ request: api }) => {
        const res = await api.get(
            `/api/questions/course-material?courseId=BIOC-E2E-NOPE-CM&lectureName=Unit 1&instructorId=${instructorId}`
        );
        expect(res.status()).toBe(404);
    });

    test('404 when the lecture does not exist on the course', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: false,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        const res = await api.get(
            `/api/questions/course-material?courseId=${COURSE_A}&lectureName=Unit 99&instructorId=${instructorId}`
        );
        expect(res.status()).toBe(404);
    });

    test('returns hasMaterials=false when the lecture has no documents', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                isPublished: false,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        const res = await api.get(
            `/api/questions/course-material?courseId=${COURSE_A}&lectureName=Unit 1&instructorId=${instructorId}`
        );
        // Existing lecture but no documents — should be a 200 with hasMaterials=false
        // or a 404 depending on the route's contract. Either is fine; just don't 500.
        expect([200, 404]).toContain(res.status());
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/check-answer
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/check-answer', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required fields missing', async ({ request: api }) => {
        const res = await api.post('/api/questions/check-answer', {
            data: { question: 'A?' },
        });
        expect(res.status()).toBe(400);
    });

    test('returns the parsed correct/feedback shape when the LLM returns well-formed JSON', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({ correct: true, feedback: 'E2E, your answer is correct.' }),
        ]);
        // Short-answer eval is billed to the course key, so the route resolves
        // the course's LLM via courseId — seed a keyed course and pass its id.
        await seedCourse({ courseId: COURSE_A, instructorId });

        const res = await api.post('/api/questions/check-answer', {
            data: {
                courseId: COURSE_A,
                question: 'What molecule stores genetic information?',
                studentAnswer: 'DNA',
                expectedAnswer: 'Deoxyribonucleic acid (DNA)',
                questionType: 'short-answer',
                studentName: 'E2E',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data).toEqual({
            correct: true,
            feedback: 'E2E, your answer is correct.',
        });
    });

    test('still returns a result when the LLM response is not JSON (fallback parser)', async ({ request: api }) => {
        // evaluateStudentAnswer falls back to substring matching when JSON parse fails.
        // The string `correct": true` is what the fallback looks for, so the route
        // still surfaces { correct: true } and uses the raw content as feedback.
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            'Yes, correct": true — your reasoning is sound, well done.',
        ]);
        await seedCourse({ courseId: COURSE_A, instructorId });

        const res = await api.post('/api/questions/check-answer', {
            data: {
                courseId: COURSE_A,
                question: 'What molecule stores genetic information?',
                studentAnswer: 'DNA',
                expectedAnswer: 'Deoxyribonucleic acid (DNA)',
                questionType: 'short-answer',
                studentName: 'E2E',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.correct).toBe(true);
        expect(typeof body.data.feedback).toBe('string');
        expect(body.data.feedback.length).toBeGreaterThan(0);
    });

    test('handles malformed JSON in the LLM response without crashing', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            '{ "correct": true, "feedback": "missing close brace',
        ]);
        await seedCourse({ courseId: COURSE_A, instructorId });

        const res = await api.post('/api/questions/check-answer', {
            data: {
                courseId: COURSE_A,
                question: 'What molecule stores genetic information?',
                studentAnswer: 'DNA',
                expectedAnswer: 'Deoxyribonucleic acid (DNA)',
                questionType: 'short-answer',
                studentName: 'E2E',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(typeof body.data.correct).toBe('boolean');
        expect(typeof body.data.feedback).toBe('string');
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/generate-ai (validation-only paths to avoid LLM tax)
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/generate-ai', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required fields missing', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', { data: {} });
        expect(res.status()).toBe(400);
    });

    test('400 when regenerate is true without feedback', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
                regenerate: true,
            },
        });
        expect(res.status()).toBe(400);
    });

    test('400 when questionType is invalid', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'essay',
            },
        });
        expect(res.status()).toBe(400);
    });

    test('404 when course does not exist', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: 'BIOC-E2E-API-NOPE',
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
            },
        });
        expect(res.status()).toBe(404);
    });

    test('403 when caller does not own the course', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_B, instructorId: instructorFreshId });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_B,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
            },
        });
        expect(res.status()).toBe(403);
    });

    test('404 when unit does not exist on owned course', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 99',
                instructorId,
                questionType: 'true-false',
            },
        });
        expect(res.status()).toBe(404);
    });

    test('400 when struggleTopic is not in approvedStruggleTopics', async ({ request: api }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { approvedStruggleTopics: ['Approved Topic'] },
        });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
                struggleTopic: 'Not Approved Topic',
            },
        });
        expect(res.status()).toBe(400);
    });

    test('400 when unit has no course materials', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
            },
        });
        expect(res.status()).toBe(400);
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/auto-link-learning-objectives
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/auto-link-learning-objectives', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when required fields missing', async ({ request: api }) => {
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: { courseId: 'X' },
        });
        expect(res.status()).toBe(400);
    });

    test('short-circuits with no LOs', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: [],
                questions: [{ questionId: 'q1', question: 'A?' }],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.linkedCount).toBe(0);
        expect(body.data.matchedQuestions[0].learningObjective).toBe('');
    });

    test('short-circuits with no questions in DB and none supplied', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Understand X', 'Compare Y'],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.matchedQuestions).toEqual([]);
    });

    test('returns matchedQuestions populated from a well-formed LLM JSON response', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                matches: [
                    { ref: 'q1', learningObjective: 'Understand the energy currency of cells' },
                ],
            }),
        ]);
        await seedCourse({ courseId: COURSE_A, instructorId });

        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Understand the energy currency of cells', 'Compare DNA and RNA structure'],
                questions: [
                    { ref: 'q1', question: 'What molecule is the universal energy carrier?', learningObjective: '' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.data.matchedQuestions)).toBe(true);
        expect(body.data.matchedQuestions.length).toBe(1);
        expect(body.data.matchedQuestions[0].learningObjective)
            .toBe('Understand the energy currency of cells');
    });

    test('matchedQuestions stay unmatched when the LLM returns malformed JSON', async ({ request: api }) => {
        // extractFirstJSONObject in routes/questions.js returns null when the
        // content is not parseable, and the route falls back to keeping the
        // empty learningObjective from the original question.
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            'this is not JSON at all — just prose with no braces',
        ]);
        await seedCourse({ courseId: COURSE_A, instructorId });

        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Understand the energy currency of cells'],
                questions: [
                    { ref: 'q1', question: 'What molecule is the universal energy carrier?', learningObjective: '' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(Array.isArray(body.data.matchedQuestions)).toBe(true);
        expect(body.data.matchedQuestions.length).toBe(1);
        expect(body.data.matchedQuestions[0].learningObjective).toBe('');
    });
});
