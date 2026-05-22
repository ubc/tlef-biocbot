// @ts-check
/**
 * Quiz API tests — covers the /api/quiz/* routes directly via Playwright's
 * request fixture. UI rendering is exercised by student-quiz.spec.js; this
 * suite is for shape, status codes, persistence, and the LLM-backed paths.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    QUIZ_COURSE_ID,
    QUESTION_IDS,
    DOC_ID,
    withDb,
    getUserIdByUsername,
    resetQuizCourse,
    cleanupQuizCourse,
} = require('./helpers/quiz');
const { resetLlmStub, enqueueLlmResponses } = require('./helpers/llm-stub');

let instructorId;
let studentId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
});

test.afterAll(async () => {
    await cleanupQuizCourse();
});

// ----------------------------------------------------------------------------
// /api/quiz/status
// ----------------------------------------------------------------------------
test.describe('GET /api/quiz/status', () => {
    test.use({ storageState: storageStatePath('student') });

    test('returns enabled:true when quiz is enabled', async ({ request: api }) => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });

        const res = await api.get(`/api/quiz/status?courseId=${QUIZ_COURSE_ID}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toMatchObject({ success: true, enabled: true });
    });

    test('returns enabled:false when quiz is disabled', async ({ request: api }) => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: false } });

        const res = await api.get(`/api/quiz/status?courseId=${QUIZ_COURSE_ID}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body).toMatchObject({ success: true, enabled: false });
    });

    test('returns 400 when courseId is missing', async ({ request: api }) => {
        const res = await api.get('/api/quiz/status');
        expect(res.status()).toBe(400);
    });
});

// ----------------------------------------------------------------------------
// /api/quiz/questions
// ----------------------------------------------------------------------------
test.describe('GET /api/quiz/questions', () => {
    test.use({ storageState: storageStatePath('student') });

    test('returns 403 when quiz is disabled', async ({ request: api }) => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: false } });

        const res = await api.get(`/api/quiz/questions?courseId=${QUIZ_COURSE_ID}`);
        expect(res.status()).toBe(403);
    });

    test('returns questions for published units only and never leaks correctAnswer', async ({ request: api }) => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });

        const res = await api.get(`/api/quiz/questions?courseId=${QUIZ_COURSE_ID}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();

        expect(body.success).toBe(true);
        expect(body.allowLectureMaterialAccess).toBe(true);

        // Three published questions (Unit 1) — Unit 2 is unpublished
        expect(body.questions).toHaveLength(3);
        const ids = body.questions.map((q) => q.questionId).sort();
        expect(ids).toEqual([QUESTION_IDS.mc, QUESTION_IDS.sa, QUESTION_IDS.tf].sort());

        // No published question is from Unit 2
        for (const q of body.questions) {
            expect(q.lectureName).toBe('Unit 1');
            // The correctAnswer must never be exposed to the client
            expect(q).not.toHaveProperty('correctAnswer');
        }

        // The unpublished unit's question id must NOT appear
        expect(ids).not.toContain(QUESTION_IDS.unpublished);

        // Units list reflects published, testable units only
        expect(body.units.map((u) => u.name)).toEqual(['Unit 1']);
    });

    test('honors testableUnits filter when restricted', async ({ request: api }) => {
        // Seed with two published units, then restrict testableUnits to ['Unit 1']
        await resetQuizCourse({
            instructorId,
            quizSettings: { enabled: true, testableUnits: ['Unit 1'] },
        });
        // Make Unit 2 published too, so the testableUnits filter has work to do
        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: QUIZ_COURSE_ID, 'lectures.name': 'Unit 2' },
                { $set: { 'lectures.$.isPublished': true } }
            )
        );

        const res = await api.get(`/api/quiz/questions?courseId=${QUIZ_COURSE_ID}`);
        const body = await res.json();
        expect(body.success).toBe(true);
        // Only Unit 1 questions — Unit 2 is published but not testable
        expect(body.questions.every((q) => q.lectureName === 'Unit 1')).toBe(true);
        expect(body.units.map((u) => u.name)).toEqual(['Unit 1']);
    });

    test('returns empty list when no units are published', async ({ request: api }) => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });
        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: QUIZ_COURSE_ID },
                { $set: { 'lectures.$[].isPublished': false } }
            )
        );

        const res = await api.get(`/api/quiz/questions?courseId=${QUIZ_COURSE_ID}`);
        const body = await res.json();
        expect(body).toMatchObject({ success: true, questions: [], units: [] });
    });
});

// ----------------------------------------------------------------------------
// /api/quiz/check-answer
// ----------------------------------------------------------------------------
test.describe('POST /api/quiz/check-answer', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });
    });

    test('marks a correct MC answer as correct', async ({ request: api }) => {
        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.mc,
                lectureName: 'Unit 1',
                studentAnswer: 'B', // correct
            },
        });
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.correct).toBe(true);
        expect(body.data.feedback).toMatch(/correct/i);
    });

    test('marks an incorrect MC answer as wrong and reveals the correct answer', async ({ request: api }) => {
        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.mc,
                lectureName: 'Unit 1',
                studentAnswer: 'A', // wrong
            },
        });
        const body = await res.json();
        expect(body.data.correct).toBe(false);
        expect(body.data.correctAnswer).toBe('B');
    });

    test('marks a correct TF answer as correct', async ({ request: api }) => {
        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.tf,
                lectureName: 'Unit 1',
                studentAnswer: 'true',
            },
        });
        const body = await res.json();
        expect(body.data.correct).toBe(true);
    });

    test('marks an incorrect TF answer as wrong', async ({ request: api }) => {
        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.tf,
                lectureName: 'Unit 1',
                studentAnswer: 'false',
            },
        });
        const body = await res.json();
        expect(body.data.correct).toBe(false);
    });

    test('returns 404 for an unknown questionId', async ({ request: api }) => {
        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: 'q_does_not_exist',
                lectureName: 'Unit 1',
                studentAnswer: 'B',
            },
        });
        expect(res.status()).toBe(404);
    });

    test('returns 400 when required fields are missing', async ({ request: api }) => {
        const res = await api.post('/api/quiz/check-answer', {
            data: { courseId: QUIZ_COURSE_ID, questionId: QUESTION_IDS.mc },
        });
        expect(res.status()).toBe(400);
    });

    // --- LLM-backed short-answer evaluation ---
    // Previously these called the real LLM service; now they script the
    // in-process stub so the suite runs offline. Each case enqueues a
    // specific LLM response to drive a known branch of evaluateStudentAnswer.
    test.describe('short-answer (stubbed LLM)', () => {
        test('grades a short answer as correct when the LLM returns well-formed JSON', async ({ request: api }) => {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, [
                JSON.stringify({ correct: true, feedback: 'E2E Student, your answer captures the key idea.' }),
            ]);

            const res = await api.post('/api/quiz/check-answer', {
                data: {
                    courseId: QUIZ_COURSE_ID,
                    questionId: QUESTION_IDS.sa,
                    lectureName: 'Unit 1',
                    studentAnswer:
                        'A peptide bond, formed by a condensation reaction between the carboxyl and amino groups of adjacent amino acids.',
                    studentName: 'E2E Student',
                },
            });
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.success).toBe(true);
            expect(body.data).toEqual({
                correct: true,
                feedback: 'E2E Student, your answer captures the key idea.',
            });
        });

        test('grades a short answer as incorrect when the LLM returns well-formed JSON', async ({ request: api }) => {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, [
                JSON.stringify({ correct: false, feedback: 'E2E Student, that does not match the expected concept.' }),
            ]);

            const res = await api.post('/api/quiz/check-answer', {
                data: {
                    courseId: QUIZ_COURSE_ID,
                    questionId: QUESTION_IDS.sa,
                    lectureName: 'Unit 1',
                    studentAnswer: 'Banana phone purple seventeen',
                    studentName: 'E2E Student',
                },
            });
            const body = await res.json();
            expect(body.success).toBe(true);
            expect(body.data.correct).toBe(false);
            expect(body.data.feedback).toContain('does not match');
        });

        test('still returns a shape when the LLM response is not JSON (fallback)', async ({ request: api }) => {
            // evaluateStudentAnswer falls back to a substring scan when JSON
            // parsing fails. Verify that path produces a usable response.
            await resetLlmStub(api);
            await enqueueLlmResponses(api, [
                'E2E Student, you nailed it: correct": true — keep going.',
            ]);

            const res = await api.post('/api/quiz/check-answer', {
                data: {
                    courseId: QUIZ_COURSE_ID,
                    questionId: QUESTION_IDS.sa,
                    lectureName: 'Unit 1',
                    studentAnswer: 'whatever',
                    studentName: 'E2E Student',
                },
            });
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.success).toBe(true);
            expect(typeof body.data.correct).toBe('boolean');
            expect(typeof body.data.feedback).toBe('string');
            expect(body.data.feedback.length).toBeGreaterThan(0);
        });

        test('does not crash on malformed JSON in the LLM response', async ({ request: api }) => {
            await resetLlmStub(api);
            await enqueueLlmResponses(api, [
                '{ "correct": true, "feedback": "missing brace',
            ]);

            const res = await api.post('/api/quiz/check-answer', {
                data: {
                    courseId: QUIZ_COURSE_ID,
                    questionId: QUESTION_IDS.sa,
                    lectureName: 'Unit 1',
                    studentAnswer: 'whatever',
                    studentName: 'E2E Student',
                },
            });
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.success).toBe(true);
            expect(typeof body.data.correct).toBe('boolean');
            expect(typeof body.data.feedback).toBe('string');
        });
    });
});

// ----------------------------------------------------------------------------
// /api/quiz/attempt and /api/quiz/history
// ----------------------------------------------------------------------------
test.describe('POST /api/quiz/attempt + GET /api/quiz/history', () => {
    test.describe('authenticated as student', () => {
        test.use({ storageState: storageStatePath('student') });

        test.beforeEach(async () => {
            await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });
        });

        test('records an attempt and surfaces it in history stats', async ({ request: api }) => {
            // Two attempts: one correct, one wrong
            const a1 = await api.post('/api/quiz/attempt', {
                data: {
                    courseId: QUIZ_COURSE_ID,
                    questionId: QUESTION_IDS.mc,
                    lectureName: 'Unit 1',
                    questionType: 'multiple-choice',
                    studentAnswer: 'B',
                    correct: true,
                    feedback: 'Correct! Well done.',
                },
            });
            expect(a1.ok()).toBeTruthy();
            const a1Body = await a1.json();
            expect(a1Body.success).toBe(true);
            expect(a1Body.attemptId).toMatch(/^qa_/);

            const a2 = await api.post('/api/quiz/attempt', {
                data: {
                    courseId: QUIZ_COURSE_ID,
                    questionId: QUESTION_IDS.tf,
                    lectureName: 'Unit 1',
                    questionType: 'true-false',
                    studentAnswer: 'false',
                    correct: false,
                    feedback: 'Incorrect. The correct answer is true.',
                },
            });
            expect(a2.ok()).toBeTruthy();

            // DB truth — both attempts persisted with the right studentId
            const stored = await withDb((db) =>
                db.collection('quizAttempts').find({ courseId: QUIZ_COURSE_ID }).toArray()
            );
            expect(stored).toHaveLength(2);
            expect(stored.every((a) => a.studentId === studentId)).toBe(true);

            // Stats
            const histRes = await api.get(`/api/quiz/history?courseId=${QUIZ_COURSE_ID}`);
            const hist = await histRes.json();
            expect(hist.success).toBe(true);
            expect(hist.stats.totalAttempts).toBe(2);
            expect(hist.stats.correctCount).toBe(1);
            expect(hist.stats.accuracy).toBe(50);
            expect(hist.stats.unitBreakdown['Unit 1']).toEqual({ total: 2, correct: 1 });
        });

        test('returns 400 when required fields are missing', async ({ request: api }) => {
            const res = await api.post('/api/quiz/attempt', {
                data: { courseId: QUIZ_COURSE_ID, questionId: QUESTION_IDS.mc },
            });
            expect(res.status()).toBe(400);
        });
    });

    test.describe('unauthenticated', () => {
        // Override storage state to an empty (logged-out) context.
        // The requireAuth middleware redirects API calls to /login when the
        // path (post mount) doesn't start with /api/ — so we accept either a
        // 401 JSON response or a 302 redirect as proof the request was
        // rejected. Either way it must NOT reach the route handler.
        test('rejects unauthenticated requests to /attempt and /history', async ({ baseURL }) => {
            const api = await request.newContext({ baseURL });
            try {
                const attemptRes = await api.post('/api/quiz/attempt', {
                    maxRedirects: 0,
                    failOnStatusCode: false,
                    data: {
                        courseId: QUIZ_COURSE_ID,
                        questionId: QUESTION_IDS.mc,
                        lectureName: 'Unit 1',
                        questionType: 'multiple-choice',
                        studentAnswer: 'B',
                        correct: true,
                    },
                });
                expect([302, 401]).toContain(attemptRes.status());

                const histRes = await api.get(
                    `/api/quiz/history?courseId=${QUIZ_COURSE_ID}`,
                    { maxRedirects: 0, failOnStatusCode: false }
                );
                expect([302, 401]).toContain(histRes.status());

                // And no attempt was persisted
                const persisted = await withDb((db) =>
                    db.collection('quizAttempts').countDocuments({ courseId: QUIZ_COURSE_ID })
                );
                expect(persisted).toBe(0);
            } finally {
                await api.dispose();
            }
        });
    });
});

// ----------------------------------------------------------------------------
// /api/quiz/materials and download
// ----------------------------------------------------------------------------
test.describe('Quiz materials', () => {
    test.use({ storageState: storageStatePath('student') });

    test('GET /materials returns 403 when allowLectureMaterialAccess is false', async ({ request: api }) => {
        await resetQuizCourse({
            instructorId,
            quizSettings: { enabled: true, allowLectureMaterialAccess: false },
        });

        const res = await api.get(
            `/api/quiz/materials?courseId=${QUIZ_COURSE_ID}&lectureName=Unit 1`
        );
        expect(res.status()).toBe(403);
    });

    test('GET /materials returns the seeded document when access is allowed', async ({ request: api }) => {
        await resetQuizCourse({
            instructorId,
            quizSettings: { enabled: true, allowLectureMaterialAccess: true },
        });

        const res = await api.get(
            `/api/quiz/materials?courseId=${QUIZ_COURSE_ID}&lectureName=${encodeURIComponent('Unit 1')}`
        );
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.materials).toHaveLength(1);
        expect(body.materials[0]).toMatchObject({
            documentId: DOC_ID,
            originalName: 'Unit 1 Notes.txt',
            mimeType: 'text/plain',
        });
    });

    test('GET /materials/:id/download returns the file content with attachment headers', async ({ request: api }) => {
        await resetQuizCourse({
            instructorId,
            quizSettings: { enabled: true, allowLectureMaterialAccess: true },
        });

        const res = await api.get(
            `/api/quiz/materials/${DOC_ID}/download?courseId=${QUIZ_COURSE_ID}`
        );
        expect(res.ok()).toBeTruthy();
        const disposition = res.headers()['content-disposition'] || '';
        expect(disposition.toLowerCase()).toContain('attachment');
        expect(disposition).toContain('Unit 1 Notes.txt');

        const text = await res.text();
        expect(text).toContain('ATP is the primary energy currency');
    });

    test('GET /materials/:id/download returns 403 when access is disabled', async ({ request: api }) => {
        await resetQuizCourse({
            instructorId,
            quizSettings: { enabled: true, allowLectureMaterialAccess: false },
        });

        const res = await api.get(
            `/api/quiz/materials/${DOC_ID}/download?courseId=${QUIZ_COURSE_ID}`
        );
        expect(res.status()).toBe(403);
    });
});

// ----------------------------------------------------------------------------
// /api/quiz/chat — profanity, safety, and the real-LLM happy path
// ----------------------------------------------------------------------------
test.describe('POST /api/quiz/chat', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });
    });

    test('returns 400 when required fields are missing', async ({ request: api }) => {
        const res = await api.post('/api/quiz/chat', {
            data: { courseId: QUIZ_COURSE_ID, lectureName: 'Unit 1' },
        });
        expect(res.status()).toBe(400);
    });

    test('profanity is intercepted with a system response, no LLM call needed', async ({ request: api }) => {
        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Which biomolecule is the primary energy currency of the cell?',
                questionType: 'multiple-choice',
                studentAnswer: 'A',
                message: 'this question is shit, explain it',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.source).toBe('system');
        expect(body.message).toMatch(/appropriate/i);
    });

    test('mental-health safety keyword returns the Wellness Centre message', async ({ request: api }) => {
        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Which biomolecule is the primary energy currency of the cell?',
                questionType: 'multiple-choice',
                studentAnswer: 'A',
                message: 'I want to kill myself, I cannot do this anymore.',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.source).toBe('system');
        expect(body.message).toMatch(/wellness/i);
    });

    test('benign question reaches the LLM and returns a quiz-help response', async ({ request: api }) => {
        const llmReply = 'Think about which biomolecule cells use to power active transport. That is your hint.';
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [llmReply]);

        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Which biomolecule is the primary energy currency of the cell?',
                questionType: 'multiple-choice',
                correctAnswer: 'B',
                studentAnswer: 'A',
                message: 'Can you give me a hint about how to think about energy in cells?',
                conversationHistory: [],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.source).toBe('quiz-help');
        expect(body.message).toBe(llmReply);
    });

    test('quiz-chat returns the raw LLM text even when it is not JSON-shaped', async ({ request: api }) => {
        // /api/quiz/chat is plain-text in/out, so non-JSON content is the
        // normal case. This documents that the route passes the LLM string
        // through verbatim without any JSON parsing.
        const llmReply = 'Plain prose with no braces or JSON anywhere.';
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [llmReply]);

        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Which biomolecule is the primary energy currency of the cell?',
                questionType: 'multiple-choice',
                correctAnswer: 'B',
                studentAnswer: 'A',
                message: 'Give me one sentence of help.',
                conversationHistory: [],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.source).toBe('quiz-help');
        expect(body.message).toBe(llmReply);
    });

    test('quiz-chat falls back to a default message when the LLM returns empty content', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, ['']);

        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Which biomolecule is the primary energy currency of the cell?',
                questionType: 'multiple-choice',
                correctAnswer: 'B',
                studentAnswer: 'A',
                message: 'Help me out.',
                conversationHistory: [],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.source).toBe('quiz-help');
        expect(typeof body.message).toBe('string');
        expect(body.message.length).toBeGreaterThan(0);
    });
});

// ----------------------------------------------------------------------------
// Additional focused coverage + product-bug exposures
// ----------------------------------------------------------------------------
// Targets the branches that the suites above leave uncovered in
// src/routes/quiz.js — primarily the filename / mime / download branches, the
// soft-delete filter in /questions, the conversation/prompts paths in /chat,
// and three product bugs in /check-answer and /attempt.
test.describe('Quiz API — focused coverage + product bugs', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await resetQuizCourse({ instructorId, quizSettings: { enabled: true } });
    });

    // ------------------------------------------------------------------------
    // /questions soft-delete filter
    // ------------------------------------------------------------------------
    test('GET /questions skips soft-deleted (isActive:false) questions', async ({ request: api }) => {
        await withDb(async (db) => {
            const course = await db.collection('courses').findOne({ courseId: QUIZ_COURSE_ID });
            const lectures = course.lectures.map((lec) => {
                if (lec.name !== 'Unit 1') return lec;
                return {
                    ...lec,
                    assessmentQuestions: lec.assessmentQuestions.map((q) =>
                        q.questionId === QUESTION_IDS.mc ? { ...q, isActive: false } : q
                    ),
                };
            });
            await db.collection('courses').updateOne(
                { courseId: QUIZ_COURSE_ID },
                { $set: { lectures } }
            );
        });

        const res = await api.get(`/api/quiz/questions?courseId=${QUIZ_COURSE_ID}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        const ids = body.questions.map((q) => q.questionId);
        expect(ids).not.toContain(QUESTION_IDS.mc);
        expect(ids).toContain(QUESTION_IDS.tf);
        expect(ids).toContain(QUESTION_IDS.sa);
    });

    // ------------------------------------------------------------------------
    // /materials missing-field branches
    // ------------------------------------------------------------------------
    test('GET /materials returns 400 when courseId or lectureName is missing', async ({ request: api }) => {
        const r1 = await api.get('/api/quiz/materials?lectureName=Unit%201');
        expect(r1.status()).toBe(400);

        const r2 = await api.get(`/api/quiz/materials?courseId=${QUIZ_COURSE_ID}`);
        expect(r2.status()).toBe(400);
    });

    // ------------------------------------------------------------------------
    // /materials/:id/download — auxiliary branches
    // ------------------------------------------------------------------------
    test('GET /materials/:id/download returns 400 when courseId is missing', async ({ request: api }) => {
        const res = await api.get(`/api/quiz/materials/${DOC_ID}/download`);
        expect(res.status()).toBe(400);
    });

    test('GET /materials/:id/download returns 404 when documentId does not exist', async ({ request: api }) => {
        const res = await api.get(`/api/quiz/materials/doc_does_not_exist/download?courseId=${QUIZ_COURSE_ID}`);
        expect(res.status()).toBe(404);
    });

    test('GET /materials/:id/download returns 404 when the document belongs to a different course', async ({ request: api }) => {
        const otherDocId = 'doc_e2e_quiz_other_course';
        await withDb((db) => db.collection('documents').insertOne({
            documentId: otherDocId,
            courseId: `${QUIZ_COURSE_ID}-OTHER`,
            lectureName: 'Unit 1',
            documentType: 'lecture-notes',
            contentType: 'text',
            content: 'should never be served',
            mimeType: 'text/plain',
            filename: 'other.txt',
            originalName: 'other.txt',
            size: 20,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
        }));
        try {
            const res = await api.get(`/api/quiz/materials/${otherDocId}/download?courseId=${QUIZ_COURSE_ID}`);
            expect(res.status()).toBe(404);
        } finally {
            await withDb((db) => db.collection('documents').deleteOne({ documentId: otherDocId }));
        }
    });

    test('GET /materials/:id/download serves binary file content with the stored MIME type', async ({ request: api }) => {
        const binDocId = 'doc_e2e_quiz_binary';
        // %PDF-1.4 header bytes so the response body has identifiable content.
        const payload = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34, 0x0A, 0x00, 0x01, 0x02]);
        await withDb((db) => db.collection('documents').insertOne({
            documentId: binDocId,
            courseId: QUIZ_COURSE_ID,
            lectureName: 'Unit 1',
            documentType: 'lecture-notes',
            contentType: 'file',
            fileData: payload,
            mimeType: 'application/pdf',
            filename: 'lecture.pdf',
            originalName: 'Lecture Slides.pdf',
            size: payload.length,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
        }));
        try {
            const res = await api.get(`/api/quiz/materials/${binDocId}/download?courseId=${QUIZ_COURSE_ID}`);
            expect(res.ok()).toBeTruthy();
            expect(res.headers()['content-type']).toContain('application/pdf');

            const body = await res.body();
            expect(body.length).toBe(payload.length);
            expect(Buffer.compare(body, payload)).toBe(0);

            const disposition = res.headers()['content-disposition'] || '';
            expect(disposition.toLowerCase()).toContain('attachment');
            expect(disposition).toContain('Lecture Slides.pdf');
        } finally {
            await withDb((db) => db.collection('documents').deleteOne({ documentId: binDocId }));
        }
    });

    test('GET /materials/:id/download returns 500 when contentType=file but fileData is corrupt', async ({ request: api }) => {
        const badDocId = 'doc_e2e_quiz_bad_filedata';
        // Truthy but neither a Buffer nor anything with a `.buffer` — forces the
        // `payload === null` branch and the 500 response.
        await withDb((db) => db.collection('documents').insertOne({
            documentId: badDocId,
            courseId: QUIZ_COURSE_ID,
            lectureName: 'Unit 1',
            documentType: 'lecture-notes',
            contentType: 'file',
            fileData: { not: 'a buffer' },
            mimeType: 'application/octet-stream',
            filename: 'corrupt.bin',
            originalName: 'corrupt.bin',
            size: 0,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
        }));
        try {
            const res = await api.get(`/api/quiz/materials/${badDocId}/download?courseId=${QUIZ_COURSE_ID}`);
            expect(res.status()).toBe(500);
        } finally {
            await withDb((db) => db.collection('documents').deleteOne({ documentId: badDocId }));
        }
    });

    test('GET /materials/:id/download URL-encodes non-ASCII filenames with an ASCII fallback', async ({ request: api }) => {
        const uniDocId = 'doc_e2e_quiz_unicode_name';
        const unicodeName = 'Café Résumé.txt';
        await withDb((db) => db.collection('documents').insertOne({
            documentId: uniDocId,
            courseId: QUIZ_COURSE_ID,
            lectureName: 'Unit 1',
            documentType: 'lecture-notes',
            contentType: 'text',
            content: 'unicode body',
            mimeType: 'text/plain',
            filename: 'notes.txt',
            originalName: unicodeName,
            size: 12,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
        }));
        try {
            const res = await api.get(`/api/quiz/materials/${uniDocId}/download?courseId=${QUIZ_COURSE_ID}`);
            expect(res.ok()).toBeTruthy();
            const disposition = res.headers()['content-disposition'] || '';
            expect(disposition.toLowerCase()).toContain('attachment');
            // ASCII fallback strips non-ASCII; the RFC 5987 filename* preserves UTF-8.
            expect(disposition).toMatch(/filename="C[^"]+\.txt"/);
            expect(disposition).not.toContain('Café');
            expect(disposition).toContain("filename*=UTF-8''");
            expect(disposition).toContain(encodeURIComponent(unicodeName));
        } finally {
            await withDb((db) => db.collection('documents').deleteOne({ documentId: uniDocId }));
        }
    });

    test('GET /materials/:id/download infers the filename extension from each known MIME type', async ({ request: api }) => {
        const mimeCases = [
            { suffix: 'pdf',     mime: 'application/pdf',                                                             ext: '.pdf'  },
            { suffix: 'md',      mime: 'text/markdown',                                                                ext: '.md'   },
            { suffix: 'doc',     mime: 'application/msword',                                                          ext: '.doc'  },
            { suffix: 'docx',    mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',     ext: '.docx' },
            { suffix: 'rtf',     mime: 'application/rtf',                                                              ext: '.rtf'  },
            { suffix: 'txt',     mime: 'text/plain',                                                                   ext: '.txt'  },
            { suffix: 'unknown', mime: 'application/x-unrecognised',                                                   ext: ''      },
        ];
        const docs = mimeCases.map((c) => ({
            documentId: `doc_mime_${c.suffix}`,
            courseId: QUIZ_COURSE_ID,
            lectureName: 'Unit 1',
            documentType: 'lecture-notes',
            contentType: 'text',
            content: `content-${c.suffix}`,
            mimeType: c.mime,
            // originalName has NO extension → forces the MIME inference path.
            originalName: `Lecture Notes ${c.suffix}`,
            filename: '',
            size: 1,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
        }));
        try {
            await withDb((db) => db.collection('documents').insertMany(docs));
            for (const c of mimeCases) {
                const res = await api.get(`/api/quiz/materials/doc_mime_${c.suffix}/download?courseId=${QUIZ_COURSE_ID}`);
                expect(res.ok()).toBeTruthy();
                const disposition = res.headers()['content-disposition'] || '';
                expect(disposition).toContain(`Lecture Notes ${c.suffix}${c.ext}`);
            }
        } finally {
            await withDb((db) => db.collection('documents').deleteMany({
                documentId: { $in: docs.map((d) => d.documentId) },
            }));
        }
    });

    test('GET /materials/:id/download takes the extension from filename when originalName has none', async ({ request: api }) => {
        const docId = 'doc_e2e_quiz_filename_ext';
        await withDb((db) => db.collection('documents').insertOne({
            documentId: docId,
            courseId: QUIZ_COURSE_ID,
            lectureName: 'Unit 1',
            documentType: 'lecture-notes',
            contentType: 'text',
            content: 'fallback ext from filename',
            mimeType: 'application/x-anything',
            filename: 'stored.md',
            // originalName has NO extension — should fall back to filename's `.md`.
            originalName: 'Pretty Display Name',
            size: 12,
            status: 'parsed',
            uploadDate: new Date(),
            lastModified: new Date(),
        }));
        try {
            const res = await api.get(`/api/quiz/materials/${docId}/download?courseId=${QUIZ_COURSE_ID}`);
            expect(res.ok()).toBeTruthy();
            const disposition = res.headers()['content-disposition'] || '';
            // The route should reach for `filename` because it carries a real
            // extension and `originalName` does not.
            expect(disposition).toContain('stored.md');
        } finally {
            await withDb((db) => db.collection('documents').deleteOne({ documentId: docId }));
        }
    });

    // ------------------------------------------------------------------------
    // /chat — uncovered branches (course.prompts override, conversation
    // history loop, short-answer correctAnswer lookup)
    // ------------------------------------------------------------------------
    test('POST /chat uses course-specific prompts and iterates the conversation history block', async ({ request: api }) => {
        await withDb((db) => db.collection('courses').updateOne(
            { courseId: QUIZ_COURSE_ID },
            { $set: { prompts: {
                base: 'You are a focused quiz tutor for biology.',
                quizHelp: 'Be concise and never reveal the literal correct answer.',
            } } }
        ));
        const llmReply = 'Phosphorylation drives ATP because it stores energy in the third phosphate bond.';
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [llmReply]);

        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Which biomolecule is the primary energy currency of the cell?',
                questionType: 'multiple-choice',
                correctAnswer: 'B',
                studentAnswer: 'A',
                message: 'Why is the cell\'s energy carrier the one that gets phosphorylated and dephosphorylated?',
                conversationHistory: [
                    { role: 'user',      content: 'I was confused earlier.' },
                    { role: 'assistant', content: 'No worries — what part?' },
                    { role: 'user',      content: 'Why ATP and not glucose directly.' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.source).toBe('quiz-help');
        expect(body.message).toBe(llmReply);
    });

    test('POST /chat looks up short-answer correctAnswer from the DB when the client sends the AI placeholder', async ({ request: api }) => {
        const llmReply = 'A peptide bond joins amino acids during translation.';
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [llmReply]);
        const res = await api.post('/api/quiz/chat', {
            data: {
                courseId: QUIZ_COURSE_ID,
                lectureName: 'Unit 1',
                questionText: 'Name the bond formed between two amino acids during protein synthesis.',
                questionType: 'short-answer',
                correctAnswer: '[evaluated by AI - see feedback]',
                studentAnswer: 'no idea',
                message: 'Can you remind me what kind of bond connects amino acids?',
                conversationHistory: [],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.source).toBe('quiz-help');
    });

    // ========================================================================
    // PRODUCT BUGS — these tests are intentionally left failing per AGENTS.md.
    // ========================================================================

    test('PRODUCT BUG: /check-answer reveals answers even when the quiz is disabled', async ({ request: api }) => {
        // Disable the quiz. /questions correctly returns 403 in that state,
        // but /check-answer has no enabled-check, so a student can still call
        // it and harvest correctAnswer values for every seeded question.
        await resetQuizCourse({ instructorId, quizSettings: { enabled: false } });

        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.mc,
                lectureName: 'Unit 1',
                studentAnswer: 'A',
            },
        });
        // Expected behavior: server should refuse since the quiz is disabled.
        expect(res.status()).toBe(403);
    });

    test('PRODUCT BUG: /check-answer reveals answers for questions in unpublished units', async ({ request: api }) => {
        // Unit 2 is unpublished in the seed and houses QUESTION_IDS.unpublished.
        // /questions correctly hides it, but /check-answer fetches by raw
        // lectureName+questionId without consulting isPublished, so it leaks
        // the verdict (and correctAnswer for MC/TF) for hidden questions.
        const res = await api.post('/api/quiz/check-answer', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.unpublished,
                lectureName: 'Unit 2',
                studentAnswer: 'true',
            },
        });
        // Expected behavior: 403/404 — content from unpublished units should
        // never be reachable by a student.
        expect([403, 404]).toContain(res.status());
        if (res.ok()) {
            const body = await res.json();
            expect(body.data).not.toHaveProperty('correctAnswer');
        }
    });

    test('PRODUCT BUG: /attempt trusts a student-supplied `correct` flag without cross-checking', async ({ request: api }) => {
        // The student deliberately submits a known-wrong MC answer ('A' when
        // the correct answer is 'B') but lies in the body with `correct: true`.
        // The route stores whatever the client sends, so a student can inflate
        // their accuracy stats arbitrarily. The server should at minimum reject
        // an attempt whose `correct` flag contradicts the canonical answer.
        const cheat = await api.post('/api/quiz/attempt', {
            data: {
                courseId: QUIZ_COURSE_ID,
                questionId: QUESTION_IDS.mc,
                lectureName: 'Unit 1',
                questionType: 'multiple-choice',
                studentAnswer: 'A',
                correct: true,
                feedback: 'fabricated',
            },
        });
        expect([400, 403, 409, 422]).toContain(cheat.status());

        // And history should not credit the fabricated attempt.
        const histRes = await api.get(`/api/quiz/history?courseId=${QUIZ_COURSE_ID}`);
        const hist = await histRes.json();
        expect(hist.stats.correctCount).toBe(0);
    });
});
