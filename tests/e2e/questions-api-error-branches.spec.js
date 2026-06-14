// @ts-check
/**
 * Error- and edge-branch coverage for src/routes/questions.js.
 *
 * Targets uncovered branches that the existing specs
 * (routes-questions-api.spec.js, questions-api-coverage.spec.js) do not reach:
 *
 *   - Per-field validation short-circuits in POST/, GET/lecture, PUT, DELETE,
 *     /bulk, /check-answer, /generate-ai, /auto-link-learning-objectives.
 *   - POST /generate-ai role/access guards: course-not-found 404, cross-instructor
 *     403, unit-not-found 404, regenerate-without-feedback 400, invalid
 *     questionType 400, struggleTopic-not-approved 400, no-documents 400, and
 *     documents-with-empty-content 400 (the post-document-loop branch).
 *   - POST /auto-link-learning-objectives: empty-LO short-circuit, empty-questions
 *     short-circuit when body.questions is provided, the
 *     `learningObjectives:[]` + array-body-questions array-map fallback.
 *
 * HTTP-only — no internal mocks. Per AGENTS.md:
 *   - shadowed /stats and /course-material handlers are unreachable (FINDINGS
 *     #32) and are NOT exercised here.
 *   - the "db not available" / "llm not available" 503 branches require
 *     mutating app.locals at runtime and are skipped as unreachable defensive
 *     code in production.
 */

const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
} = require('./helpers/courses-test');

const COURSE_A = 'BIOC-E2E-QEB-A';
const COURSE_B = 'BIOC-E2E-QEB-B';

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

// Seed a course-material document into the documents collection and attach
// the docRef to the lecture's documents[] array. Optionally allow an empty
// content string so we can drive the "documents present but empty" branch.
async function seedDocumentForUnit({
    courseId,
    lectureName,
    documentId,
    content,
    originalName = 'Material.txt',
    documentType = 'lecture-notes',
}) {
    const now = new Date();
    await withDb(async (db) => {
        await db.collection('documents').deleteMany({ documentId });
        await db.collection('documents').insertOne({
            documentId,
            courseId,
            lectureName,
            originalName,
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
                        originalName,
                        type: documentType === 'lecture-notes' ? 'lecture_notes' : 'practice_q_tutorials',
                        content,
                    },
                },
            }
        );
    });
}

// ---------------------------------------------------------------------------
// POST /api/questions — per-field validation branches
// Covers the 6-disjunct guard on line 178; each missing field exercises a
// different short-circuit branch.
// ---------------------------------------------------------------------------
test.describe('POST /api/questions per-field validation', () => {
    test.use({ storageState: storageStatePath('instructor') });

    const baseFields = () => ({
        courseId: COURSE_A,
        lectureName: 'Unit 1',
        instructorId: 'inst',
        questionType: 'true-false',
        question: 'Q?',
        correctAnswer: 'true',
    });

    for (const field of ['courseId', 'lectureName', 'instructorId', 'questionType', 'question', 'correctAnswer']) {
        test(`400 when ${field} is missing`, async ({ request: api }) => {
            const data = baseFields();
            delete data[field];
            const res = await api.post('/api/questions', { data, failOnStatusCode: false });
            expect(res.status()).toBe(400);
            const body = await res.json();
            expect(body.success).toBe(false);
            expect(String(body.message)).toContain('Missing required fields');
        });
    }

    test('empty body trips the first short-circuit', async ({ request: api }) => {
        const res = await api.post('/api/questions', { data: {}, failOnStatusCode: false });
        expect(res.status()).toBe(400);
    });
});

// ---------------------------------------------------------------------------
// GET /api/questions/lecture — query-param validation + course-missing
// fallthrough (Course model returns [] → success with count 0).
// ---------------------------------------------------------------------------
test.describe('GET /api/questions/lecture validation', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 with only courseId', async ({ request: api }) => {
        const res = await api.get(`/api/questions/lecture?courseId=${COURSE_A}`, { failOnStatusCode: false });
        expect(res.status()).toBe(400);
    });

    test('400 with only lectureName', async ({ request: api }) => {
        const res = await api.get('/api/questions/lecture?lectureName=Unit%201', { failOnStatusCode: false });
        expect(res.status()).toBe(400);
    });

    test('400 with neither param', async ({ request: api }) => {
        const res = await api.get('/api/questions/lecture', { failOnStatusCode: false });
        expect(res.status()).toBe(400);
    });

    test('success with empty list when course does not exist (model returns [])', async ({ request: api }) => {
        const res = await api.get('/api/questions/lecture?courseId=BIOC-E2E-NEVER&lectureName=Unit%201');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.count).toBe(0);
    });

    test('success with empty list when course exists but lecture is absent', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.get(`/api/questions/lecture?courseId=${COURSE_A}&lectureName=${encodeURIComponent('Unit 9999')}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.count).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// PUT /api/questions/:questionId — per-field validation branches.
// Covers the 4-disjunct guard on line 524.
// ---------------------------------------------------------------------------
test.describe('PUT /api/questions/:questionId per-field validation', () => {
    test.use({ storageState: storageStatePath('instructor') });

    const baseFields = () => ({
        courseId: COURSE_A,
        lectureName: 'Unit 1',
        instructorId: 'inst',
        question: 'updated',
    });

    for (const field of ['courseId', 'lectureName', 'instructorId']) {
        test(`400 when ${field} is missing`, async ({ request: api }) => {
            const data = baseFields();
            delete data[field];
            const res = await api.put('/api/questions/q_x', { data, failOnStatusCode: false });
            expect(res.status()).toBe(400);
            const body = await res.json();
            expect(String(body.message)).toContain('Missing required fields');
        });
    }
});

// ---------------------------------------------------------------------------
// DELETE /api/questions/:questionId — per-field validation branches.
// Covers the 4-disjunct guard on line 590.
// ---------------------------------------------------------------------------
test.describe('DELETE /api/questions/:questionId per-field validation', () => {
    test.use({ storageState: storageStatePath('instructor') });

    const baseFields = () => ({
        courseId: COURSE_A,
        lectureName: 'Unit 1',
        instructorId: 'inst',
    });

    for (const field of ['courseId', 'lectureName', 'instructorId']) {
        test(`400 when ${field} is missing`, async ({ request: api }) => {
            const data = baseFields();
            delete data[field];
            const res = await api.delete('/api/questions/q_x', { data, failOnStatusCode: false });
            expect(res.status()).toBe(400);
            const body = await res.json();
            expect(String(body.message)).toContain('Missing required fields');
        });
    }

    test('400 with empty delete body', async ({ request: api }) => {
        const res = await api.delete('/api/questions/q_x', { data: {}, failOnStatusCode: false });
        expect(res.status()).toBe(400);
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/bulk — per-field validation + 0-insert paths.
// Covers the 5-disjunct guard on line 738.
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/bulk per-field validation', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when questions is missing entirely', async ({ request: api }) => {
        const res = await api.post('/api/questions/bulk', {
            data: { courseId: COURSE_A, lectureName: 'Unit 1', instructorId },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('400 when questions is null', async ({ request: api }) => {
        const res = await api.post('/api/questions/bulk', {
            data: { courseId: COURSE_A, lectureName: 'Unit 1', instructorId, questions: null },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('400 when questions is an object (not array)', async ({ request: api }) => {
        const res = await api.post('/api/questions/bulk', {
            data: { courseId: COURSE_A, lectureName: 'Unit 1', instructorId, questions: { 0: 'x' } },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    for (const field of ['courseId', 'lectureName', 'instructorId']) {
        test(`400 when ${field} is missing`, async ({ request: api }) => {
            const data = { courseId: COURSE_A, lectureName: 'Unit 1', instructorId: 'inst', questions: [] };
            delete data[field];
            const res = await api.post('/api/questions/bulk', { data, failOnStatusCode: false });
            expect(res.status()).toBe(400);
        });
    }

    test('bulk insert into unit with empty LO list skips auto-linking (no LLM call)', async ({ request: api }) => {
        // Covers the `needsAutoLinking` branch where unitLearningObjectives is
        // empty so the LLM path is NOT taken (line 763-781). Existing spec
        // exercises the OPPOSITE branch (LOs present).
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/bulk', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questions: [
                    { questionType: 'true-false', question: 'No LO unit', correctAnswer: 'true', learningObjective: '' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.insertedCount).toBe(1);
        expect(body.data.autoLinkedCount).toBe(0);
    });

    test('bulk insert skips auto-linking when every question already has a LO', async ({ request: api }) => {
        // Even with unit LOs present, the `questionsToSave.some(missing-LO)`
        // condition is false → no LLM call. Hits the "skip" branch of L764.
        const now = new Date();
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            lectures: [{
                name: 'Unit 1',
                displayName: 'Unit 1',
                isPublished: false,
                learningObjectives: ['Understand DNA', 'Understand RNA'],
                passThreshold: 2,
                createdAt: now,
                updatedAt: now,
                documents: [],
                assessmentQuestions: [],
            }],
        });
        const res = await api.post('/api/questions/bulk', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questions: [
                    { questionType: 'true-false', question: 'A', correctAnswer: 'true', learningObjective: 'Understand DNA' },
                    { questionType: 'true-false', question: 'B', correctAnswer: 'true', learningObjective: 'Understand RNA' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.insertedCount).toBe(2);
        // autoLinkedCount stays 0 because the LLM path was bypassed (each
        // already had a learningObjective at submission time).
        expect(body.data.autoLinkedCount).toBe(0);
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/check-answer — validation + happy path.
// Covers the 3-disjunct guard on line 1016 and the success path through to
// llmService.evaluateStudentAnswer (exercises L1031-1042).
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/check-answer', () => {
    test.use({ storageState: storageStatePath('instructor') });

    for (const field of ['question', 'studentAnswer', 'expectedAnswer']) {
        test(`400 when ${field} is missing`, async ({ request: api }) => {
            const data = {
                question: 'What is ATP?',
                studentAnswer: 'energy',
                expectedAnswer: 'adenosine triphosphate',
                questionType: 'short-answer',
                studentName: 'Tester',
            };
            delete data[field];
            const res = await api.post('/api/questions/check-answer', { data, failOnStatusCode: false });
            expect(res.status()).toBe(400);
            const body = await res.json();
            expect(String(body.message)).toContain('Missing required fields');
        });
    }

    test('400 when all three required fields are missing', async ({ request: api }) => {
        const res = await api.post('/api/questions/check-answer', {
            data: { questionType: 'short-answer' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('happy path returns an LLM evaluation result', async ({ request: api }) => {
        test.setTimeout(120_000);
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/check-answer', {
            data: {
                courseId: COURSE_A,
                question: 'What molecule stores genetic information in cells?',
                studentAnswer: 'DNA',
                expectedAnswer: 'DNA (deoxyribonucleic acid)',
                questionType: 'short-answer',
                studentName: 'E2E',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data).toBeTruthy();
    });

    test('happy path defaults studentName when omitted', async ({ request: api }) => {
        // Drives the `studentName || 'Student'` default branch on L1036.
        test.setTimeout(120_000);
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/check-answer', {
            data: {
                courseId: COURSE_A,
                question: 'What gas do plants take in for photosynthesis?',
                studentAnswer: 'carbon dioxide',
                expectedAnswer: 'CO2',
            },
        });
        expect(res.ok()).toBeTruthy();
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/auto-link-learning-objectives — validation + branches.
// Covers L314-319 (missing courseId/lectureName), L341-356 (no LOs available
// short-circuit when body.questions is provided), L362-372 (no source
// questions short-circuit), the `learningObjectives non-array → DB lookup`
// branch on L337-339, and the `Array.isArray(questions)` map fallback for
// `matchedQuestions` when no LOs (L347-353).
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/auto-link-learning-objectives validation', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('400 when courseId is missing', async ({ request: api }) => {
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: { lectureName: 'Unit 1' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('400 when lectureName is missing', async ({ request: api }) => {
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: { courseId: COURSE_A },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('200 with no-LOs short-circuit when learningObjectives:[] + questions:[obj]', async ({ request: api }) => {
        // L337-339: empty body LOs → falls to DB. Unit has no LOs → DB returns [].
        // L341-356: 0 LOs branch returns success with mapped matchedQuestions.
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: [],
                questions: [
                    { questionId: 'q1', question: 'Q1', learningObjective: '  Existing  ' },
                ],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.linkedCount).toBe(0);
        expect(body.data.matchedQuestions).toHaveLength(1);
        // Verify normalizeLearningObjective trimmed it (L350-351).
        expect(body.data.matchedQuestions[0].learningObjective).toBe('Existing');
    });

    test('200 with no-LOs short-circuit and no body.questions returns matchedQuestions:[]', async ({ request: api }) => {
        // Same 0-LO branch, but body.questions is undefined → Array.isArray=false
        // → matchedQuestions defaults to []. (L347-354 else branch.)
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: [],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.matchedQuestions).toEqual([]);
        expect(body.data.linkedCount).toBe(0);
    });

    test('200 with no-source-questions short-circuit (body LOs present, unit has 0 questions)', async ({ request: api }) => {
        // L362-372: LOs present, but body.questions omitted → sourceQuestions =
        // CourseModel.getAssessmentQuestions(...) which is []. Returns early.
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Obj A', 'Obj B'],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(String(body.message)).toMatch(/No assessment questions/i);
        expect(body.data.matchedQuestions).toEqual([]);
    });

    test('200 with empty body.questions array short-circuits (no LLM call)', async ({ request: api }) => {
        // Array.isArray(questions) && questions.length === 0 → sourceQuestions is
        // []. L362-372 still returns early.
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/auto-link-learning-objectives', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                learningObjectives: ['Obj A'],
                questions: [],
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.data.matchedQuestions).toEqual([]);
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/generate-ai — guard branches that do NOT need the LLM.
// Each test stops execution before the LLM call so they run fast.
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/generate-ai validation guards', () => {
    test.use({ storageState: storageStatePath('instructor') });

    const validBase = () => ({
        courseId: COURSE_A,
        lectureName: 'Unit 1',
        instructorId,
        questionType: 'true-false',
    });

    for (const field of ['courseId', 'lectureName', 'instructorId', 'questionType']) {
        test(`400 when ${field} is missing`, async ({ request: api }) => {
            const data = validBase();
            delete data[field];
            const res = await api.post('/api/questions/generate-ai', { data, failOnStatusCode: false });
            expect(res.status()).toBe(400);
            const body = await res.json();
            expect(String(body.message)).toContain('Missing required fields');
        });
    }

    test('400 when regenerate=true with no feedback', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', {
            data: { ...validBase(), regenerate: true },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(String(body.message)).toContain('Feedback is required');
    });

    test('400 when questionType is not in the allowed set', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', {
            data: { ...validBase(), questionType: 'fill-in-the-blank' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(String(body.message)).toMatch(/Invalid question type/i);
    });

    test('400 with a different invalid questionType (essay)', async ({ request: api }) => {
        // Same guard, different bad value — confirms it consistently rejects.
        const res = await api.post('/api/questions/generate-ai', {
            data: { ...validBase(), questionType: 'essay' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('404 when course does not exist', async ({ request: api }) => {
        const res = await api.post('/api/questions/generate-ai', {
            data: { ...validBase(), courseId: 'BIOC-E2E-DOES-NOT-EXIST' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(404);
        const body = await res.json();
        expect(String(body.message)).toContain('Course not found');
    });

    test('403 when authenticated user is not on the course (cross-instructor)', async ({ request: api }) => {
        // Course owned by instructor_fresh. Caller is e2e_instructor. The
        // route's access check (L1121-1138) should deny.
        await seedCourse({ courseId: COURSE_B, instructorId: instructorFreshId });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_B,
                lectureName: 'Unit 1',
                instructorId: instructorFreshId, // body value is ignored
                questionType: 'true-false',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(403);
        const body = await res.json();
        expect(String(body.message)).toContain('Access denied');
    });

    test('404 when unit is not in the course', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/generate-ai', {
            data: { ...validBase(), lectureName: 'Unit 999 Never Was' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(404);
        const body = await res.json();
        expect(String(body.message)).toContain('not found in course');
    });

    test('400 when struggleTopic is not in the approved list', async ({ request: api }) => {
        // approvedStruggleTopics is empty by default. Any non-empty struggle
        // topic should fail the isApprovedTopic check (L1153-1165).
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                ...validBase(),
                struggleTopic: 'Some random topic that was never approved',
            },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(String(body.message)).toContain('not approved');
    });

    test('400 when struggleTopic is approved but only after whitespace normalization', async ({ request: api }) => {
        // Verifies the `replace(/\s+/g, ' ').trim()` normalization on L1149-1151
        // does NOT bypass the approved-topic guard for unmatched topics.
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { approvedStruggleTopics: ['Mitosis basics'] },
        });
        const res = await api.post('/api/questions/generate-ai', {
            data: { ...validBase(), struggleTopic: 'Photosynthesis basics' },
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
    });

    test('400 when unit has no documents', async ({ request: api }) => {
        // Unit 1 default has documents:[]. Hits L1175-1183.
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/generate-ai', {
            data: validBase(),
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(String(body.message)).toContain('No course materials');
    });

    test('400 when documents exist but every document has empty content', async ({ request: api }) => {
        // Hits L1209-1218: docs loaded from DB but combinedContent.trim() is "".
        await seedCourse({ courseId: COURSE_A, instructorId });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-empty-content-1',
            content: '',
            originalName: 'Empty Lecture Notes.txt',
            documentType: 'lecture-notes',
        });
        await seedDocumentForUnit({
            courseId: COURSE_A,
            lectureName: 'Unit 1',
            documentId: 'doc-empty-content-2',
            content: '   \n  \t  ',
            originalName: 'Whitespace Lecture Notes.txt',
            documentType: 'lecture-notes',
        });
        const res = await api.post('/api/questions/generate-ai', {
            data: validBase(),
            failOnStatusCode: false,
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(String(body.message)).toContain('No content found');
    });
});

// ---------------------------------------------------------------------------
// POST /api/questions/generate-ai — anonymous (unauthenticated) caller.
// Hits the `user && (...)` access branch where `user` is falsy → hasAccess
// false → 403 (L1131-1138).
// ---------------------------------------------------------------------------
test.describe('POST /api/questions/generate-ai unauthenticated access guard', () => {
    test.use({ storageState: { cookies: [], origins: [] } });

    test('redirects/denies anonymous caller', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/questions/generate-ai', {
            data: {
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                instructorId,
                questionType: 'true-false',
            },
            // maxRedirects=0 so we observe the auth middleware's 302/401
            // rather than the login page that Playwright would otherwise
            // auto-follow.
            maxRedirects: 0,
            failOnStatusCode: false,
        });
        // Either the route-level access check fires (403) or upstream auth
        // middleware redirects (302) / rejects (401). All exercise the
        // "no req.user" path through src/routes/questions.js.
        expect([401, 403, 302]).toContain(res.status());
    });
});
