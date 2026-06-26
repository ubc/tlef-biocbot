// @ts-check
/**
 * API coverage for src/routes/settings.js (~59% → target higher).
 *
 * Hits prompts, quiz, anonymize-students, mental-health-prompt, llm-tag, and
 * the public /can-delete-all flag. System-admin-gated endpoints (/global,
 * /llm, /system-admins, /mental-health-prompt) are exercised at the 403 layer
 * since we don't seed a SYSTEM_ADMIN_EMAILS user.
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

const COURSE_A = 'BIOC-E2E-API-SETTINGS-A';

let instructorId;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
});

test.beforeEach(async () => {
    await cleanupCoursesForUser(instructorId);
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_A]);
    await cleanupCoursesForUser(instructorId);
});

// ---------------------------------------------------------------------------
// /can-delete-all
// ---------------------------------------------------------------------------
test.describe('GET /api/settings/can-delete-all', () => {
    test('returns canDeleteAll:false for a non-system-admin instructor', async ({ baseURL }) => {
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get('/api/settings/can-delete-all');
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.canDeleteAll).toBe(false);
            expect(body.isSystemAdmin).toBe(false);
        } finally {
            await api.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// /prompts (course-level)
// ---------------------------------------------------------------------------
test.describe('prompts (course-level)', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('GET /prompts returns defaults when no courseId is provided', async ({ request: api }) => {
        const res = await api.get('/api/settings/prompts');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.isCourseSpecific).toBe(false);
        expect(typeof body.prompts.base).toBe('string');
    });

    test('GET /prompts returns course-specific prompts when present', async ({ request: api }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: {
                prompts: {
                    base: 'COURSE_BASE',
                    protege: 'COURSE_PROTEGE',
                    tutor: 'COURSE_TUTOR',
                    explain: 'COURSE_EXPLAIN',
                    directive: 'COURSE_DIRECTIVE',
                    quizHelp: 'COURSE_QUIZ_HELP',
                    chatSummary: 'COURSE_CHAT_SUMMARY',
                    studentIdleTimeout: 180,
                },
            },
        });
        const res = await api.get(`/api/settings/prompts?courseId=${COURSE_A}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.isCourseSpecific).toBe(true);
        expect(body.prompts.base).toBe('COURSE_BASE');
        expect(body.prompts.chatSummary).toBe('COURSE_CHAT_SUMMARY');
        expect(body.prompts.studentIdleTimeout).toBe(180);
    });

    test('POST /prompts 400 when courseId missing', async ({ request: api }) => {
        const res = await api.post('/api/settings/prompts', {
            data: { base: 'a', protege: 'b', tutor: 'c', explain: 'd', directive: 'e' },
        });
        expect(res.status()).toBe(400);
    });

    test('POST /prompts 400 when prompt fields are not strings', async ({ request: api }) => {
        const res = await api.post('/api/settings/prompts', {
            data: { courseId: COURSE_A, base: 1, protege: 'b', tutor: 'c', explain: 'd', directive: 'e' },
        });
        expect(res.status()).toBe(400);
    });

    test('POST /prompts 400 with "Invalid prompt format" when course exists but prompt is non-string', async ({ request: api }) => {
        // Seed the course so the route reaches the type-validation branch
        // instead of short-circuiting on the access check's "Course not found".
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/prompts', {
            data: { courseId: COURSE_A, base: 1, protege: 'b', tutor: 'c', explain: 'd', directive: 'e' },
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(body.message).toMatch(/Invalid prompt format/i);
    });

    test('POST /prompts 400 when chatSummary is not a string', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/prompts', {
            data: {
                courseId: COURSE_A,
                base: 'a', protege: 'b', tutor: 'c', explain: 'd', directive: 'e',
                chatSummary: 123,
            },
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(body.message).toMatch(/Invalid prompt format/i);
    });

    test('POST /prompts 400 when studentIdleTimeout out of range', async ({ request: api }) => {
        const res = await api.post('/api/settings/prompts', {
            data: {
                courseId: COURSE_A,
                base: 'a', protege: 'b', tutor: 'c', explain: 'd', directive: 'e',
                studentIdleTimeout: 10, // below 30s floor
            },
        });
        expect(res.status()).toBe(400);
    });

    test('POST /prompts 400 with "Invalid idle timeout value" when course exists but timeout is too low', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/prompts', {
            data: {
                courseId: COURSE_A,
                base: 'a', protege: 'b', tutor: 'c', explain: 'd', directive: 'e',
                studentIdleTimeout: 10,
            },
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(body.message).toMatch(/Invalid idle timeout value/i);
    });

    test('POST /prompts 400 when studentIdleTimeout is above the 1200s ceiling', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/prompts', {
            data: {
                courseId: COURSE_A,
                base: 'a', protege: 'b', tutor: 'c', explain: 'd', directive: 'e',
                studentIdleTimeout: 9999,
            },
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(body.message).toMatch(/Invalid idle timeout value/i);
    });

    test('POST /prompts 400 when studentIdleTimeout is not a number', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/prompts', {
            data: {
                courseId: COURSE_A,
                base: 'a', protege: 'b', tutor: 'c', explain: 'd', directive: 'e',
                studentIdleTimeout: 'definitely not a number',
            },
        });
        expect(res.status()).toBe(400);
        const body = await res.json();
        expect(body.message).toMatch(/Invalid idle timeout value/i);
    });

    test('POST /prompts happy path persists course-specific prompts', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/prompts', {
            data: {
                courseId: COURSE_A,
                base: 'B', protege: 'P', tutor: 'T', explain: 'E', directive: 'D',
                quizHelp: 'Q',
                chatSummary: 'SUMMARY_PROMPT',
                additiveRetrieval: true,
                additionalMaterialSecondarySearch: true,
                studentIdleTimeout: 300,
            },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc.prompts.base).toBe('B');
        expect(doc.prompts.chatSummary).toBe('SUMMARY_PROMPT');
        expect(doc.isAdditiveRetrieval).toBe(true);
        expect(doc.additionalMaterialSecondarySearch).toBe(true);
        expect(doc.prompts.studentIdleTimeout).toBe(300);
    });

    test('GET /prompts defaults additionalMaterialSecondarySearch to false when unset', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.get(`/api/settings/prompts?courseId=${COURSE_A}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(body.prompts.additionalMaterialSecondarySearch).toBe(false);
    });

    test('POST /prompts/reset 400 when courseId missing', async ({ request: api }) => {
        const res = await api.post('/api/settings/prompts/reset', { data: {} });
        expect(res.status()).toBe(400);
    });

    test('POST /prompts/reset wipes course prompts', async ({ request: api }) => {
        await seedCourse({
            courseId: COURSE_A,
            instructorId,
            overrides: { prompts: { base: 'old' }, additionalMaterialSecondarySearch: true },
        });
        const res = await api.post('/api/settings/prompts/reset', {
            data: { courseId: COURSE_A },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc.prompts).toBeUndefined();
        expect(doc.isAdditiveRetrieval).toBe(true);
        expect(doc.additionalMaterialSecondarySearch).toBe(false);
    });
});

// ---------------------------------------------------------------------------
// /global, /llm, /question-prompts, /mental-health-prompt — admin-gated
// We exercise the 403 path for non-system-admins.
// ---------------------------------------------------------------------------
test.describe('system-admin-gated endpoints', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('GET /global 403 for non-admin', async ({ request: api }) => {
        const res = await api.get('/api/settings/global');
        expect(res.status()).toBe(403);
    });

    test('POST /global 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/global', {
            data: { allowLocalLogin: false },
        });
        expect(res.status()).toBe(403);
    });

    test('GET /llm 403 for non-admin', async ({ request: api }) => {
        const res = await api.get('/api/settings/llm');
        expect(res.status()).toBe(403);
    });

    test('POST /llm 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/llm', {
            data: { model: 'gpt-4.1-mini' },
        });
        expect(res.status()).toBe(403);
    });

    test('GET /system-admins 403 for non-admin', async ({ request: api }) => {
        const res = await api.get('/api/settings/system-admins');
        expect(res.status()).toBe(403);
    });

    test('POST /system-admins 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/system-admins', {
            data: { email: 'someone@example.com' },
        });
        expect(res.status()).toBe(403);
    });

    test('POST /system-admins/revoke 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/system-admins/revoke', {
            data: { email: 'someone@example.com' },
        });
        expect(res.status()).toBe(403);
    });

    test('GET /question-prompts 403 for non-admin', async ({ request: api }) => {
        const res = await api.get('/api/settings/question-prompts');
        expect(res.status()).toBe(403);
    });

    test('POST /question-prompts 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/question-prompts', {
            data: { courseId: COURSE_A, systemPrompt: 'a', trueFalse: 'b', multipleChoice: 'c', shortAnswer: 'd' },
        });
        expect(res.status()).toBe(403);
    });

    test('POST /question-prompts/reset 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/question-prompts/reset', {
            data: { courseId: COURSE_A },
        });
        expect(res.status()).toBe(403);
    });

    test('GET /mental-health-prompt 403 for non-admin', async ({ request: api }) => {
        const res = await api.get('/api/settings/mental-health-prompt');
        expect(res.status()).toBe(403);
    });

    test('POST /mental-health-prompt 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/mental-health-prompt', {
            data: { courseId: COURSE_A, prompt: 'x' },
        });
        expect(res.status()).toBe(403);
    });

    test('POST /mental-health-prompt/reset 403 for non-admin', async ({ request: api }) => {
        const res = await api.post('/api/settings/mental-health-prompt/reset', {
            data: { courseId: COURSE_A },
        });
        expect(res.status()).toBe(403);
    });
});

// ---------------------------------------------------------------------------
// /llm-tag (public)
// ---------------------------------------------------------------------------
test.describe('GET /api/settings/llm-tag', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('returns numeric llm/reasoning indices', async ({ request: api }) => {
        const res = await api.get('/api/settings/llm-tag');
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(typeof body.llmIndex).toBe('number');
        expect(typeof body.reasoningIndex).toBe('number');
    });

    test('reflects custom settings in DB', async ({ request: api }) => {
        await withDb((db) =>
            db.collection('settings').updateOne(
                { _id: 'llm' },
                { $set: { model: 'gpt-5-nano', reasoningEffort: 'high' } },
                { upsert: true }
            )
        );
        try {
            const res = await api.get('/api/settings/llm-tag');
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.llmIndex).toBe(2); // gpt-5-nano
            expect(body.reasoningIndex).toBe(4); // high
        } finally {
            await withDb((db) =>
                db.collection('settings').deleteOne({ _id: 'llm' })
            );
        }
    });
});

// ---------------------------------------------------------------------------
// /quiz
// ---------------------------------------------------------------------------
test.describe('GET/POST /api/settings/quiz', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('GET 400 when courseId missing', async ({ request: api }) => {
        const res = await api.get('/api/settings/quiz');
        expect(res.status()).toBe(400);
    });

    test('GET returns default quiz settings shape', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.get(`/api/settings/quiz?courseId=${COURSE_A}`);
        expect(res.ok()).toBeTruthy();
        const body = await res.json();
        expect(typeof body.settings.enabled).toBe('boolean');
    });

    test('POST 400 when courseId missing', async ({ request: api }) => {
        const res = await api.post('/api/settings/quiz', {
            data: { enabled: true },
        });
        expect(res.status()).toBe(400);
    });

    test('POST persists settings', async ({ request: api }) => {
        await seedCourse({ courseId: COURSE_A, instructorId });
        const res = await api.post('/api/settings/quiz', {
            data: {
                courseId: COURSE_A,
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
                allowSourceAttributionDownloads: false,
            },
        });
        expect(res.ok()).toBeTruthy();
        const doc = await withDb((db) =>
            db.collection('courses').findOne({ courseId: COURSE_A })
        );
        expect(doc.quizSettings.enabled).toBe(true);
    });
});

// ---------------------------------------------------------------------------
// /anonymize-students
// ---------------------------------------------------------------------------
test.describe('anonymize-students', () => {
    test.describe('as instructor', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('GET 400 when courseId missing', async ({ request: api }) => {
            const res = await api.get('/api/settings/anonymize-students');
            expect(res.status()).toBe(400);
        });

        test('GET returns enabled flag for a course', async ({ request: api }) => {
            await seedCourse({ courseId: COURSE_A, instructorId });
            const res = await api.get(`/api/settings/anonymize-students?courseId=${COURSE_A}`);
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(typeof body.enabled).toBe('boolean');
        });

        test('POST 400 when courseId missing', async ({ request: api }) => {
            const res = await api.post('/api/settings/anonymize-students', {
                data: { enabled: true },
            });
            expect(res.status()).toBe(400);
        });

        test('POST persists the flag', async ({ request: api }) => {
            await seedCourse({ courseId: COURSE_A, instructorId });
            const res = await api.post('/api/settings/anonymize-students', {
                data: { courseId: COURSE_A, enabled: true },
            });
            expect(res.ok()).toBeTruthy();
            const doc = await withDb((db) =>
                db.collection('courses').findOne({ courseId: COURSE_A })
            );
            expect(doc.anonymizeStudents[instructorId].enabled).toBe(true);
        });
    });
});
