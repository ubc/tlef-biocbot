// @ts-check
/**
 * API coverage for src/routes/chat.js (~65% → target higher).
 *
 * Focuses on:
 *   - Source-attribution document downloads (auth, gating, text/binary, broken
 *     fileData, cross-course leak).
 *   - The lightweight management endpoints (/status, /test, /models, /save).
 *   - Practice question + check-practice-answer (both with MCQ and short-answer
 *     paths).
 *   - POST /api/chat validation branches (no message, missing course/unit,
 *     unpublished unit, profanity short-circuit).
 *
 * The full RAG path is exercised by chat-rag-documents.spec.js.
 */

const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const {
    withDb,
    getUserIdByUsername,
    seedCourse,
    cleanupCourses,
    cleanupCoursesForUser,
    setStudentEnrollment,
} = require('./helpers/courses-test');
const { resetLlmStub, enqueueLlmResponses } = require('./helpers/llm-stub');

const COURSE_A = 'BIOC-E2E-API-CHAT-A';
const COURSE_B = 'BIOC-E2E-API-CHAT-B';

let instructorId;
let instructorFreshId;
let studentId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    instructorFreshId = await getUserIdByUsername(TEST_USERS.instructor_fresh.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
    await withDb((db) =>
        db.collection('documents').deleteMany({ courseId: { $in: [COURSE_A, COURSE_B] } })
    );
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_A, COURSE_B]);
    await cleanupCoursesForUser(instructorId);
    await cleanupCoursesForUser(instructorFreshId);
});

// ---------------------------------------------------------------------------
// GET /api/chat/source-documents/:documentId/download
// ---------------------------------------------------------------------------
test.describe('GET /api/chat/source-documents/:documentId/download', () => {
    test('400 when documentId or courseId missing', async ({ baseURL }) => {
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('student'),
        });
        try {
            const res = await api.get('/api/chat/source-documents/whatever/download');
            // The middleware needs a courseId for enrollment check; without
            // courseId the request lands at the route which returns 400.
            // (If middleware blocks first with 403, that's also acceptable.)
            expect([400, 403]).toContain(res.status());
        } finally {
            await api.dispose();
        }
    });

    test('404 when course does not exist', async ({ baseURL }) => {
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get('/api/chat/source-documents/x/download?courseId=BIOC-E2E-API-NOPE');
            expect(res.status()).toBe(404);
        } finally {
            await api.dispose();
        }
    });

    test('403 when source-attribution downloads are disabled', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: false } },
        });
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/x/download?courseId=${COURSE_A}`);
            expect(res.status()).toBe(403);
        } finally {
            await api.dispose();
        }
    });

    test('404 when document does not exist (downloads enabled)', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/doc-missing/download?courseId=${COURSE_A}`);
            expect(res.status()).toBe(404);
        } finally {
            await api.dispose();
        }
    });

    test('404 when document exists but belongs to another course', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const now = new Date();
        await withDb((db) =>
            db.collection('documents').insertOne({
                documentId: 'doc-foreign-source',
                courseId: 'BIOC-E2E-API-CHAT-OTHER',
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                contentType: 'text',
                content: 'foreign',
                filename: 'f.txt',
                originalName: 'f.txt',
                mimeType: 'text/plain',
                size: 7,
                status: 'parsed',
                uploadDate: now,
                lastModified: now,
            })
        );
        try {
            const api = await request.newContext({
                baseURL,
                storageState: storageStatePath('instructor'),
            });
            try {
                const res = await api.get(`/api/chat/source-documents/doc-foreign-source/download?courseId=${COURSE_A}`);
                expect(res.status()).toBe(404);
            } finally {
                await api.dispose();
            }
        } finally {
            await withDb((db) =>
                db.collection('documents').deleteOne({ documentId: 'doc-foreign-source' })
            );
        }
    });

    test('serves text source content with attachment headers', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const now = new Date();
        await withDb((db) =>
            db.collection('documents').insertOne({
                documentId: 'doc-src-text',
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                contentType: 'text',
                content: 'Source-attribution text body.',
                filename: 'source.txt',
                originalName: 'Source.txt',
                mimeType: 'text/plain',
                size: 28,
                status: 'parsed',
                uploadDate: now,
                lastModified: now,
            })
        );
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/doc-src-text/download?courseId=${COURSE_A}`);
            expect(res.ok()).toBeTruthy();
            const text = await res.text();
            expect(text).toContain('Source-attribution text body.');
            expect((res.headers()['content-disposition'] || '').toLowerCase()).toContain('attachment');
        } finally {
            await api.dispose();
        }
    });

    test('serves binary source data with the stored mime type', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const now = new Date();
        const payload = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34]);
        await withDb((db) =>
            db.collection('documents').insertOne({
                documentId: 'doc-src-bin',
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                contentType: 'file',
                fileData: payload,
                filename: 'lecture.pdf',
                originalName: 'Lecture.pdf',
                mimeType: 'application/pdf',
                size: payload.length,
                status: 'parsed',
                uploadDate: now,
                lastModified: now,
            })
        );
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/doc-src-bin/download?courseId=${COURSE_A}`);
            expect(res.ok()).toBeTruthy();
            expect(res.headers()['content-type']).toContain('application/pdf');
            const body = await res.body();
            expect(Buffer.compare(body, payload)).toBe(0);
        } finally {
            await api.dispose();
        }
    });

    test('serves GridFS-backed source files (e.g. PPTX) as the original binary', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const gridfs = require('../../src/services/gridfs');
        const PPTX_MIME = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
        // Stand-in for real PPTX bytes; only fidelity of the round-trip matters.
        const payload = Buffer.from('PK fake pptx archive bytes for download test', 'utf8');
        const now = new Date();
        const fileId = await withDb(async (db) => {
            const id = await gridfs.uploadBuffer(db, payload, 'Chromatin.pptx', { contentType: PPTX_MIME });
            await db.collection('documents').insertOne({
                documentId: 'doc-src-gridfs',
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                contentType: 'file',
                fileId: id,
                content: 'extracted slide text that must NOT be served as the download',
                filename: 'Chromatin.pptx',
                originalName: 'Chromatin.pptx',
                mimeType: PPTX_MIME,
                size: payload.length,
                status: 'parsed',
                uploadDate: now,
                lastModified: now,
            });
            return id;
        });
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/doc-src-gridfs/download?courseId=${COURSE_A}`);
            expect(res.ok()).toBeTruthy();
            expect(res.headers()['content-type']).toContain('presentationml');
            expect((res.headers()['content-disposition'] || '')).toContain('Chromatin.pptx');
            const body = await res.body();
            expect(Buffer.compare(body, payload)).toBe(0);
        } finally {
            await api.dispose();
            await withDb(async (db) => {
                await db.collection('documents').deleteOne({ documentId: 'doc-src-gridfs' });
                await gridfs.deleteFile(db, fileId);
            });
        }
    });

    test('500 when contentType=file but fileData is unusable', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const now = new Date();
        await withDb((db) =>
            db.collection('documents').insertOne({
                documentId: 'doc-src-broken',
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                contentType: 'file',
                fileData: { not: 'a buffer' },
                filename: 'broken.bin',
                originalName: 'broken.bin',
                mimeType: 'application/octet-stream',
                size: 0,
                status: 'parsed',
                uploadDate: now,
                lastModified: now,
            })
        );
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/doc-src-broken/download?courseId=${COURSE_A}`);
            expect(res.status()).toBe(500);
        } finally {
            await api.dispose();
        }
    });

    test('403 for student who is not enrolled (downloads enabled)', async ({ baseURL }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { quizSettings: { allowSourceAttributionDownloads: true } },
        });
        const now = new Date();
        await withDb((db) =>
            db.collection('documents').insertOne({
                documentId: 'doc-src-text-2',
                courseId: COURSE_A,
                lectureName: 'Unit 1',
                documentType: 'lecture-notes',
                contentType: 'text',
                content: 'private',
                filename: 's.txt',
                originalName: 's.txt',
                mimeType: 'text/plain',
                size: 7,
                status: 'parsed',
                uploadDate: now,
                lastModified: now,
            })
        );
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('student'),
        });
        try {
            const res = await api.get(`/api/chat/source-documents/doc-src-text-2/download?courseId=${COURSE_A}`);
            expect(res.status()).toBe(403);
        } finally {
            await api.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// GET /api/chat/status, /api/chat/models  +  POST /api/chat/test
// ---------------------------------------------------------------------------
test.describe('chat service introspection', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('GET /status returns the current llm status', async ({ request: api }) => {
        const res = await api.get('/api/chat/status');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data).toBeTruthy();
    });

    test('GET /models returns the available models', async ({ request: api }) => {
        const res = await api.get('/api/chat/models');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.success).toBe(true);
        expect(body.data.provider).toBeTruthy();
        expect(Array.isArray(body.data.models)).toBe(true);
    });

    test('POST /test exercises the LLM round-trip', async ({ request: api }) => {
        test.setTimeout(60_000);
        const res = await api.post('/api/chat/test', { data: {} });
        // Either 200 (connected) or 503 (test failed). Both are valid branches.
        expect([200, 503]).toContain(res.status());
        const body = await res.json();
        expect(body.provider).toBeTruthy();
    });
});

// ---------------------------------------------------------------------------
// POST /api/chat/save
// ---------------------------------------------------------------------------
test.describe('POST /api/chat/save', () => {
    test.use({ storageState: storageStatePath('student') });

    test('400 when required fields missing', async ({ request: api }) => {
        const res = await api.post('/api/chat/save', { data: { sessionId: 's' } });
        expect(res.status()).toBe(400);
    });

    test('happy path inserts/upserts the chat session', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        await setStudentEnrollment(COURSE_A, studentId, true);
        const res = await api.post('/api/chat/save', {
            data: {
                sessionId: 'sess-e2e-1',
                courseId: COURSE_A,
                studentId,
                studentName: 'E2E Student',
                unitName: 'Unit 1',
                title: 'My Session',
                messageCount: 4,
                duration: '3m',
                chatData: { metadata: { currentMode: 'tutor' }, messages: [] },
            },
        });
        expect(res.ok()).toBeTruthy();

        const stored = await withDb((db) =>
            db.collection('chat_sessions').findOne({ sessionId: 'sess-e2e-1' })
        );
        try {
            expect(stored.courseId).toBe(COURSE_A);
            expect(stored.studentId).toBe(studentId);
        } finally {
            await withDb((db) =>
                db.collection('chat_sessions').deleteOne({ sessionId: 'sess-e2e-1' })
            );
        }
    });
});

// ---------------------------------------------------------------------------
// POST /api/chat/practice-question + /check-practice-answer
// ---------------------------------------------------------------------------
test.describe('practice question lifecycle', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
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
                    { questionId: 'q-pr-1', questionType: 'multiple-choice', question: 'Energy currency?', options: { A: 'DNA', B: 'ATP' }, correctAnswer: 'B', isActive: true },
                    { questionId: 'q-pr-2', questionType: 'true-false', question: 'Water is polar.', correctAnswer: 'true', isActive: true },
                ],
            }],
        });
        await setStudentEnrollment(COURSE_A, studentId, true);
    });

    test('400 when courseId or unitName missing', async ({ request: api }) => {
        const res = await api.post('/api/chat/practice-question', {
            data: { courseId: COURSE_A },
        });
        expect(res.status()).toBe(400);
    });

    test('returns noQuestions when unit has no assessment questions', async ({ request: api }) => {
        // Re-seed with no questions
        await seedCourse({ courseId: COURSE_A, instructorId });
        await setStudentEnrollment(COURSE_A, studentId, true);
        const res = await api.post('/api/chat/practice-question', {
            data: { courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.noQuestions).toBe(true);
    });

    test('happy path: short-answer practice question is generated and scored from well-formed LLM JSON', async ({ request: api }) => {
        await resetLlmStub(api);
        // First call: generate the practice question. Second call:
        // evaluateStudentAnswer for the short-answer branch.
        await enqueueLlmResponses(api, [
            JSON.stringify({
                questionType: 'short-answer',
                question: 'Describe how cells transport glucose across the membrane.',
                correctAnswer: 'Via GLUT transporters using facilitated diffusion.',
                explanation: 'GLUT family proteins move glucose down its gradient.',
            }),
            JSON.stringify({
                correct: false,
                feedback: 'E2E Student, that does not address the GLUT transporters.',
            }),
        ]);

        const gen = await api.post('/api/chat/practice-question', {
            data: { courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(gen.ok()).toBeTruthy();
        const genBody = await gen.json();
        expect(genBody.data.practiceId).toBeTruthy();
        // Server must not leak the correct answer back to the client.
        expect(genBody.data.correctAnswer).toBeUndefined();

        const chk = await api.post('/api/chat/check-practice-answer', {
            data: {
                practiceId: genBody.data.practiceId,
                studentAnswer: 'nonsense answer that is definitely wrong',
                studentName: 'E2E Student',
            },
        });
        expect(chk.ok()).toBeTruthy();
        const chkBody = await chk.json();
        expect(chkBody.success).toBe(true);
        expect(chkBody.data.correct).toBe(false);
        expect(chkBody.data.feedback).toContain('GLUT transporters');
    });

    test('practice-question returns 500 when LLM response is not JSON', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            'sorry, I cannot generate that right now — no JSON at all',
        ]);

        const res = await api.post('/api/chat/practice-question', {
            data: { courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(res.status()).toBe(500);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(body.message).toMatch(/practice question/i);
    });

    test('practice-question returns 500 when LLM JSON is missing required fields', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            JSON.stringify({ questionType: 'short-answer', question: 'Missing correctAnswer field' }),
        ]);

        const res = await api.post('/api/chat/practice-question', {
            data: { courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(res.status()).toBe(500);
        const body = await res.json();
        expect(body.success).toBe(false);
        expect(body.message).toMatch(/incomplete|practice question/i);
    });

    test('practice-question returns 500 when LLM JSON is malformed', async ({ request: api }) => {
        await resetLlmStub(api);
        await enqueueLlmResponses(api, [
            '{ "questionType": "short-answer", "question": "broken',
        ]);

        const res = await api.post('/api/chat/practice-question', {
            data: { courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(res.status()).toBe(500);
        const body = await res.json();
        expect(body.success).toBe(false);
    });

    test('check-practice-answer 400 when fields missing', async ({ request: api }) => {
        const res = await api.post('/api/chat/check-practice-answer', {
            data: { practiceId: 'pq_anything' },
        });
        expect(res.status()).toBe(400);
    });

    test('check-practice-answer 404 when practiceId is unknown', async ({ request: api }) => {
        const res = await api.post('/api/chat/check-practice-answer', {
            data: { practiceId: 'pq_never_generated', studentAnswer: 'foo' },
        });
        expect(res.status()).toBe(404);
    });
});

// ---------------------------------------------------------------------------
// POST /api/chat — validation paths
// ---------------------------------------------------------------------------
test.describe('POST /api/chat (validation)', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        await setStudentEnrollment(COURSE_A, studentId, true);
    });

    test('400 when message missing', async ({ request: api }) => {
        const res = await api.post('/api/chat', {
            data: { courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(res.status()).toBe(400);
    });

    test('400 when courseId or unitName missing', async ({ request: api }) => {
        const res = await api.post('/api/chat', {
            data: { message: 'hello' },
        });
        expect(res.status()).toBe(400);
    });

    test('404 when course does not exist', async ({ request: api }) => {
        const res = await api.post('/api/chat', {
            data: { message: 'hello', courseId: 'BIOC-E2E-API-NOPE', unitName: 'Unit 1' },
        });
        // requireActiveCourseForNonInstructors middleware returns next() when
        // course not found, so the chat handler receives it and returns 404.
        // requireStudentEnrolled may also reject with 404. Either is fine.
        expect([404]).toContain(res.status());
    });

    test('400 when selected unit is not published', async ({ request: api }) => {
        // Seeded course has lectures Unit 1 / Unit 2 with isPublished:false.
        const res = await api.post('/api/chat', {
            data: { message: 'hello', courseId: COURSE_A, unitName: 'Unit 1' },
        });
        expect(res.status()).toBe(400);
    });

    test('profanity short-circuits with system warning (no LLM call)', async ({ request: api }) => {
        // Has to pass the unit-publish check, so publish Unit 1.
        await withDb((db) =>
            db.collection('courses').updateOne(
                { courseId: COURSE_A, 'lectures.name': 'Unit 1' },
                { $set: { 'lectures.$.isPublished': true } }
            )
        );
        const res = await api.post('/api/chat', {
            data: {
                message: 'this question is shit, explain it',
                courseId: COURSE_A,
                unitName: 'Unit 1',
            },
        });
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.model).toBe('system');
        expect(body.message).toMatch(/language/i);
        expect(body.debug.profanityFiltered).toBe(true);
    });
});
