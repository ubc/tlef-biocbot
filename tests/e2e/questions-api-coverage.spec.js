// @ts-check
/**
 * Coverage for src/routes/questions.js — targets paths the existing
 * routes-questions-api.spec.js does not reach:
 *   - model-failure 400s (lecture not found, course not found) on POST/PUT/DELETE
 *   - bulk insert with auto-linking (LLM stubbed)
 *   - auto-link-learning-objectives DB-write path (no body.questions)
 *   - auto-link-learning-objectives preserveExisting short-circuit
 *   - generate-ai full success path with materials (LLM stubbed)
 *   - generate-ai regenerate happy path with feedback (LLM stubbed)
 *   - generate-ai content-truncation path (>6000 chars combined content)
 *   - generate-ai approved-struggle-topic happy path
 *   - extractFirstJSONObject fallback paths (exercised via auto-link)
 *
 * Per AGENTS.md these are browser-level (HTTP) tests. The web server runs
 * with BIOCBOT_TEST_LLM_STUB=1; each LLM call is scripted via the
 * /api/test/llm-stub helpers so the suite is hermetic and fast.
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

const COURSE_A = 'BIOC-E2E-QCOV-A';
const COURSE_B = 'BIOC-E2E-QCOV-B';

let instructorId;
let instructorFreshId;

async function seedDocumentForUnit({ courseId, lectureName, documentId, content, originalName, documentType = 'lecture-notes' }) {
    const now = new Date();
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({ documentId });
        await db.collection('documents').insertOne({
            documentId,
            courseId,
            lectureName,
            originalName: originalName || 'Material.txt',
            content,
            documentType,
            status: 'parsed',
            createdAt: now,
            updatedAt: now,
        });
        await db.collection('courses').updateOne(
            { courseId, 'lectures.name': lectureName },
            {
                $push: {
                    'lectures.$.documents': {
                        documentId,
                        documentType,
                        originalName: originalName || 'Material.txt',
                        type: documentType === 'lecture-notes' ? 'lecture_notes' : 'practice_q_tutorials',
                        content,
                    },
                },
            }
        );
    });
}

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    instructorFreshId = await getUserIdByUsername(TEST_USERS.instructor_fresh.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({ courseId: { $in: [COURSE_A, COURSE_B] } });
    });
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_A, COURSE_B]);
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
});

// ---------------------------------------------------------------------------
// POST /api/questions — model failure path (lecture not found → 400)
// Covers L222-227 (result.success === false branch).
// ---------------------------------------------------------------------------
test.describe('POST /api/questions model-failure paths', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when lecture is unknown (model returns failure)', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 999',
                instructorId,
                questionType: 'true-false',
                question: 'Q?',
                correctAnswer: 'true',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(String(body.message)).toContain('Lecture not found');
    });

    test('400 when course is unknown', async ({ request: api }) => {
        const res = await api.post('/api/questions', {
            data: {
                courseId: 'BIOC-E2E-NEVER-EXISTED',
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
                question: 'Q?',
                correctAnswer: 'true',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(String(body.message)).toContain('Course not found');
    });
});

// ---------------------------------------------------------------------------
// PUT /api/questions/:questionId — model failure path (course not found)
// Covers L553-558.
// ---------------------------------------------------------------------------
test.describe('PUT /api/questions/:questionId model-failure path', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when courseId is unknown', async ({ request: api }) => {
        const res = await api.put('/api/questions/q_anything', {
            data: {
                courseId: 'BIOC-E2E-NEVER',
                lectureName: 'Unit 1',
                instructorId,
                question: 'updated',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('updates with rich metadata, options, tags, points (sanitizeQuestionPayload coverage)', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [
                    { questionId: 'q_e2e_qcov_put_1', questionType: 'multiple-choice', question: 'old', correctAnswer: 'A', isActive: true },
                ],
            }],
        });
        const res = await api.put('/api/questions/q_e2e_qcov_put_1', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'multiple-choice',
                question: 'new',
                options: { A: 'a', B: 'b', C: 'c', D: 'd' },
                correctAnswer: 'B',
                explanation: 'Because…',
                difficulty: 'hard',
                tags: ['tag1', 'tag2'],
                points: 7,
                metadata: { reviewStatus: 'approved' },
                learningObjective: 'Trim me  ',
            },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) => db.collection('courses').findOne({ courseId: COURSE_A }));
        const q = doc.lectures[0].assessmentQuestions.find((x) => x.questionId === 'q_e2e_qcov_put_1');
        expect(q.question).toBe('new');
        expect(q.options.B).toBe('b');
        expect(q.points).toBe(7);
        expect(q.tags).toEqual(['tag1', 'tag2']);
        expect(q.difficulty).toBe('hard');
        expect(q.learningObjective).toBe('Trim me');
    });
});

// ---------------------------------------------------------------------------
// DELETE /api/questions/:questionId — model failure
// Covers L615-620 / L633-639 catch (we trigger the failure branch only).
// ---------------------------------------------------------------------------
test.describe('DELETE /api/questions/:questionId model-failure path', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when course or lecture is unknown', async ({ request: api }) => {
        const res = await api.delete('/api/questions/q_x', {
            data: { courseId: 'BIOC-E2E-NEVER', lectureName: 'Unit 1', instructorId },
            failOnStatusCode: false,
        });
        expect([400, 404]).toContain(res.status());
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/bulk — auto-link branch covers L766-781 (LLM call)
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/bulk auto-link branch', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('runs auto-link when unit has LOs and one question is missing a learningObjective', async ({ request: api }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: {
                lectures: [{
                    name: 'Unit 1',
                    displayName: 'Unit 1',
                    isPublished: true,
                    learningObjectives: ['Understand DNA structure', 'Compare DNA and RNA'],
                    passThreshold: 2,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                    documents: [],
                    assessmentQuestions: [],
                }],
            },
        });
        // linkQuestionsToLearningObjectives sends one prompt covering both
        // questions; refs default to "question-1"/"question-2" because the
        // bulk payload omits ref/questionId.
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                matches: [
                    { ref: 'question-1', learningObjective: 'Understand DNA structure' },
                    { ref: 'question-2', learningObjective: 'Compare DNA and RNA' },
                ],
            }),
        ]);
        const res = await api.post('/api/questions/bulk', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questions: [
                    { questionType: 'short-answer', question: 'What molecule stores genes?', correctAnswer: 'DNA', learningObjective: '' },
                    { questionType: 'short-answer', question: 'Name a difference between DNA and RNA.', correctAnswer: 'sugar', learningObjective: '' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.insertedCount).toBeGreaterThanOrEqual(1);
        expect(typeof body.data.autoLinkedCount).toBe('number');
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/auto-link-learning-objectives — DB-write branch
// Covers L396-435 (no body.questions, server fetches from DB, then updates).
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/auto-link-learning-objectives DB-write path', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('updates questions in DB when body.questions is omitted', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: true,
                learningObjectives: ['Understand DNA structure', 'Compare DNA and RNA'],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [
                    { questionId: 'q_db_link_1', questionType: 'short-answer', question: 'What stores genes?', correctAnswer: 'DNA', isActive: true, learningObjective: '' },
                    { questionId: 'q_db_link_2', questionType: 'short-answer', question: 'What is the sugar in RNA?', correctAnswer: 'ribose', isActive: true, learningObjective: '' },
                ],
            }],
        });
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                matches: [
                    { ref: 'q_db_link_1', learningObjective: 'Understand DNA structure' },
                    { ref: 'q_db_link_2', learningObjective: 'Compare DNA and RNA' },
                ],
            }),
        ]);
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Understand DNA structure', 'Compare DNA and RNA'],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(typeof body.data.updatedCount).toBe('number');
        expect(typeof body.data.linkedCount).toBe('number');
        expect(Array.isArray(body.data.matchedQuestions)).toBe(true);
    });

    test('preserveExisting short-circuits when every question already has a learningObjective', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Objective A', 'Objective B'],
                questions: [
                    { ref: 'q1', question: 'Q1', learningObjective: 'Objective A' },
                    { ref: 'q2', question: 'Q2', learningObjective: 'Objective B' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        // All questions already linked → linkedCount=2, no LLM call
        expect(body.data.linkedCount).toBe(2);
    });
});

// ---------------------------------------------------------------------------
// GET /api/questions/:questionId — fallthrough 404 (questionId we never seeded)
// Covers L494-499 fallback only if the global findOne returns a course with
// matching nested array but the inner find misses (a defensive branch).
// We just exercise the simple 404 path.
// ---------------------------------------------------------------------------
test.describe('GET /api/questions/:questionId additional 404', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('404 when no course matches the questionId', async ({ request: api }) => {
        const res = await api.get('/api/questions/q_no_match_in_any_course', { failOnStatusCode: false });
        expect(res.status()).toBe(404);
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/generate-ai — full success path with materials.
// Exercises ~200 lines of content prep, LO formatting, LLM call, response.
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/generate-ai full success', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('happy path produces an assessment question with the LLM', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'DNA Basics',
                isPublished: true,
                learningObjectives: ['Understand the role of DNA in cells'],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-gen-ai-1',
            content: 'DNA (deoxyribonucleic acid) is the molecule that stores genetic information in cells. ' +
                     'It consists of two strands forming a double helix. The four nucleotide bases are adenine, ' +
                     'thymine, cytosine, and guanine. RNA is similar but single-stranded and uses uracil instead of thymine. ' +
                     'DNA replication produces two identical copies prior to cell division.',
            originalName: 'Lecture Notes A.txt',
            documentType: 'lecture-notes',
        });
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                type: 'multiple-choice',
                question: 'Which molecule stores genetic information in cells?',
                options: { A: 'RNA', B: 'DNA', C: 'Protein', D: 'Lipid' },
                correctAnswer: 'B',
                explanation: 'DNA is the genetic material; RNA is transcribed from it.',
            }),
        ]);
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'multiple-choice',
                learningObjectives: ['Understand the role of DNA in cells'],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.question).toBe('Which molecule stores genetic information in cells?');
        expect(body.data.answer).toBe('B');
        expect(body.data.options).toMatchObject({ A: 'RNA', B: 'DNA', C: 'Protein', D: 'Lipid' });
        expect(body.data.aiGenerated).toBe(true);
    });

    test('regenerate=true with feedback exercises the regeneration branch', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Cell Energy',
                isPublished: true,
                learningObjectives: ['Identify the cellular energy currency'],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-gen-ai-regen',
            content: 'ATP (adenosine triphosphate) is the primary energy currency of cells. ' +
                     'When ATP is hydrolyzed to ADP and inorganic phosphate, energy is released to drive cellular work.',
            originalName: 'Lecture Notes Energy.txt',
            documentType: 'lecture-notes',
        });
        // Regenerate path with LOs makes TWO LLM calls: regenerate + relink.
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                type: 'true-false',
                question: 'ATP is the primary energy currency of cells.',
                correctAnswer: true,
                explanation: 'ATP releases energy on hydrolysis to ADP + Pi.',
            }),
            JSON.stringify({
                matches: [
                    { ref: 'regenerated-question', learningObjective: 'Identify the cellular energy currency' },
                ],
            }),
        ]);
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
                learningObjectives: ['Identify the cellular energy currency'],
                regenerate: true,
                feedback: 'Make it easier and shorter.',
                previousQuestion: { question: 'old', answer: 'true' },
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.wasRegenerated).toBe(true);
        expect(body.data.answer).toBe('true');
        expect(body.data.selectedLearningObjective).toBe('Identify the cellular energy currency');
    });

    test('approved struggleTopic exercises the topic-focus branch', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { approvedStruggleTopics: ['DNA replication'] },
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-gen-ai-struggle',
            content: 'DNA replication is semiconservative and uses DNA polymerase. ' +
                     'Each daughter strand contains one original and one new strand.',
            originalName: 'Lecture Notes Replication.txt',
            documentType: 'lecture-notes',
        });
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                type: 'short-answer',
                question: 'Describe how DNA replication produces two identical strands.',
                expectedAnswer: 'Semiconservative replication uses each strand as a template via DNA polymerase.',
                keyPoints: ['semiconservative', 'DNA polymerase', 'template strand'],
                explanation: 'Each daughter has one original strand and one newly synthesised strand.',
            }),
        ]);
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'short-answer',
                struggleTopic: 'DNA replication',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.struggleTopic).toBe('DNA replication');
        expect(body.data.answer).toBe('Semiconservative replication uses each strand as a template via DNA polymerase.');
    });

    test('combined content > 6000 chars triggers the truncation/prioritization branch', async ({ request: api }) => {
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        // 7000-char "Lecture Notes" doc + 2000-char additional material.
        const big = 'Lecture Notes content. '.repeat(350); // ~7700 chars
        const extra = 'Additional Material content. '.repeat(80); // ~2400 chars
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-gen-big-1',
            content: big,
            originalName: 'Lecture Notes Big.txt',
            documentType: 'lecture-notes',
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-gen-big-2',
            content: extra,
            originalName: 'Additional Material.txt',
            documentType: 'other',
        });
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({
                type: 'true-false',
                question: 'The provided lecture notes were truncated before being sent to the LLM.',
                correctAnswer: true,
                explanation: 'When combined content exceeds 6000 chars, the route trims sections.',
            }),
        ]);
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.answer).toBe('true');
    });

    // -------------------------------------------------------------------------
    // Malformed-response branches for /generate-ai
    // -------------------------------------------------------------------------
    test('generate-ai returns a fallback question when the LLM JSON is malformed', async ({ request: api }) => {
        // parseGeneratedQuestion catches the parse error and returns a fallback
        // structure instead of throwing, so the route surfaces 200 with the
        // canned "Error parsing generated question" placeholder.
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-malformed-1',
            content: 'Cells are the basic unit of life. They contain organelles such as the nucleus.',
            originalName: 'Lecture Notes Malformed.txt',
            documentType: 'lecture-notes',
        });
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            'no JSON at all — just prose from the model',
        ]);
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.question).toContain('Error parsing');
    });

    test('generate-ai returns 500 when the LLM responds with empty content', async ({ request: api }) => {
        // generateAssessmentQuestion throws 'No response content received'
        // when llm.sendMessage returns an empty content string, which the
        // route catches and maps to a 500 error response.
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: true,
                learningObjectives: [],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-empty-1',
            content: 'Some lecture content.',
            originalName: 'Lecture Notes Empty.txt',
            documentType: 'lecture-notes',
        });
        await resetLlmStub(api);
        await enqueueLlmResponses(api, ['']);
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'short-answer',
            },
        });
        expect(res.status()).toBe(500);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(String(body.error || '')).toContain('No response content');
    });
});

// uncovered: 503 "Database connection not available" / "LLM service not available" — require app.locals mock.
// uncovered: outer catch (500) handlers in questions.js — defensive throws not reachable via HTTP.
// uncovered: /stats and /course-material handlers — shadowed by /:questionId (route-ordering bug, see routes-questions-api.spec.js).
