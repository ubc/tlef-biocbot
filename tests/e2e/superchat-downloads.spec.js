// @ts-check
/**
 * Superchat (bucket) chat-session downloads — issue #363.
 *
 * Bucket transcripts live in student_super_course_chat_sessions keyed by
 * superchatId + studentId (they do NOT belong to any single course), so the
 * download scope is the bucket. Access matches the per-course chat downloads:
 * system admins only (requireDownloadAdmin), NOT the wider instructor-or-admin
 * gate used for bucket CRUD.
 *
 * Covers the /api/superchats/:id/chat-sessions endpoints and the scope picker
 * on the instructor downloads page.
 */

const fs = require('fs/promises');
const { test, expect } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const { getUserIdByUsername, seedCourse, cleanupCourses } = require('./helpers/courses-test');
const { setSystemAdmin } = require('./helpers/downloads');
const {
    seedSuperchat,
    cleanupSuperchats,
    seedSuperCourseSession,
    cleanupSuperCourseSessions,
} = require('./helpers/superchats-test');

const BUCKET_ID = 'e2e-scdl-bucket';
const BUCKET_NAME = 'BIOC E2E SCDL Bucket';
const OTHER_BUCKET_ID = 'e2e-scdl-other-bucket';
const COURSE_ID = 'BIOC-E2E-SCDL-COURSE';
const COURSE_NAME = 'BIOC E2E SCDL Course';

const STUDENT_A_ID = 'user_e2e_scdl_student_a';
const STUDENT_A_NAME = 'Avery Super';
const STUDENT_B_ID = 'user_e2e_scdl_student_b';
const STUDENT_B_NAME = 'Blake Bucket';

const SESSION_A1_ID = 'e2e_scdl_session_a1';
const SESSION_A2_ID = 'e2e_scdl_session_a2';
const SESSION_A_DELETED_ID = 'e2e_scdl_session_a_deleted';
const SESSION_B1_ID = 'e2e_scdl_session_b1';
const SESSION_OTHER_BUCKET_ID = 'e2e_scdl_session_other_bucket';

const ALL_SESSION_IDS = [
    SESSION_A1_ID,
    SESSION_A2_ID,
    SESSION_A_DELETED_ID,
    SESSION_B1_ID,
    SESSION_OTHER_BUCKET_ID,
];

let instructorId;

async function seedDownloadScenario() {
    await seedSuperchat({ superchatId: BUCKET_ID, name: BUCKET_NAME, showToStudents: true });
    await seedSuperchat({ superchatId: OTHER_BUCKET_ID, name: 'BIOC E2E SCDL Other', showToStudents: true });

    // 9 seconds between first user message and last bot reply -> duration "9s"
    await seedSuperCourseSession({
        sessionId: SESSION_A1_ID,
        superchatId: BUCKET_ID,
        studentId: STUDENT_A_ID,
        studentName: STUDENT_A_NAME,
        title: 'Avery Bucket Chat One',
        savedAt: '2026-02-01T10:00:00.000Z',
        messages: [
            { type: 'user', content: 'What is ATP?', timestamp: '2026-02-01T10:00:00.000Z' },
            { type: 'bot', content: '<p>ATP is the energy currency.</p>', timestamp: '2026-02-01T10:00:09.000Z' },
        ],
    });
    await seedSuperCourseSession({
        sessionId: SESSION_A2_ID,
        superchatId: BUCKET_ID,
        studentId: STUDENT_A_ID,
        studentName: STUDENT_A_NAME,
        title: 'Avery Bucket Chat Two',
        savedAt: '2026-02-02T10:00:00.000Z',
        messages: [
            { type: 'user', content: 'Explain glycolysis.', timestamp: '2026-02-02T10:00:00.000Z' },
            { type: 'bot', content: 'Glycolysis splits glucose.', timestamp: '2026-02-02T10:00:05.000Z' },
        ],
    });
    // Student-deleted session must never appear in admin downloads
    await seedSuperCourseSession({
        sessionId: SESSION_A_DELETED_ID,
        superchatId: BUCKET_ID,
        studentId: STUDENT_A_ID,
        studentName: STUDENT_A_NAME,
        title: 'Avery Deleted Chat',
        savedAt: '2026-02-03T10:00:00.000Z',
        messages: [
            { type: 'user', content: 'Deleted question.', timestamp: '2026-02-03T10:00:00.000Z' },
        ],
        isDeleted: true,
    });
    await seedSuperCourseSession({
        sessionId: SESSION_B1_ID,
        superchatId: BUCKET_ID,
        studentId: STUDENT_B_ID,
        studentName: STUDENT_B_NAME,
        title: 'Blake Bucket Chat',
        savedAt: '2026-02-04T10:00:00.000Z',
        messages: [
            { type: 'user', content: 'What is the Krebs cycle?', timestamp: '2026-02-04T10:00:00.000Z' },
            { type: 'bot', content: 'A series of reactions in mitochondria.', timestamp: '2026-02-04T10:00:03.000Z' },
        ],
    });
    // Session in a different bucket must not leak into this bucket's export
    await seedSuperCourseSession({
        sessionId: SESSION_OTHER_BUCKET_ID,
        superchatId: OTHER_BUCKET_ID,
        studentId: STUDENT_A_ID,
        studentName: STUDENT_A_NAME,
        title: 'Other Bucket Chat',
        savedAt: '2026-02-05T10:00:00.000Z',
        messages: [
            { type: 'user', content: 'Other bucket content.', timestamp: '2026-02-05T10:00:00.000Z' },
        ],
    });
}

async function cleanupDownloadScenario() {
    await cleanupSuperCourseSessions(ALL_SESSION_IDS);
    await cleanupSuperchats([BUCKET_ID, OTHER_BUCKET_ID]);
}

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
});

test.describe('Superchat downloads API (system admin)', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test.beforeEach(async () => {
        await seedDownloadScenario();
        await setSystemAdmin(instructorId, true);
    });

    test.afterEach(async () => {
        await cleanupDownloadScenario();
        await setSystemAdmin(instructorId, false);
    });

    test('lists students grouped with session metadata, excluding deleted and other-bucket sessions', async ({ request: api }) => {
        const resp = await api.get(`/api/superchats/${BUCKET_ID}/chat-sessions`);
        expect(resp.status()).toBe(200);
        const { data } = await resp.json();

        expect(data.superchatId).toBe(BUCKET_ID);
        expect(data.superchatName).toBe(BUCKET_NAME);
        expect(data.totalStudents).toBe(2);
        expect(data.totalSessions).toBe(3);

        // Newest activity first: Blake (Feb 4) before Avery (Feb 2)
        expect(data.students.map((s) => s.studentId)).toEqual([STUDENT_B_ID, STUDENT_A_ID]);

        const avery = data.students.find((s) => s.studentId === STUDENT_A_ID);
        expect(avery.studentName).toBe(STUDENT_A_NAME);
        expect(avery.totalSessions).toBe(2);
        const sessionIds = avery.sessions.map((s) => s.sessionId);
        expect(sessionIds).toContain(SESSION_A1_ID);
        expect(sessionIds).toContain(SESSION_A2_ID);
        expect(sessionIds).not.toContain(SESSION_A_DELETED_ID);
        expect(sessionIds).not.toContain(SESSION_OTHER_BUCKET_ID);

        // Duration computed from message timestamps, metadata only (no transcripts)
        const a1 = avery.sessions.find((s) => s.sessionId === SESSION_A1_ID);
        expect(a1.duration).toBe('9s');
        expect(a1.messageCount).toBe(2);
        expect(a1.studentId).toBe(STUDENT_A_ID);
        expect(a1.chatData).toBeUndefined();
    });

    test('returns a single session with full chat data', async ({ request: api }) => {
        const resp = await api.get(`/api/superchats/${BUCKET_ID}/chat-sessions/${STUDENT_A_ID}/${SESSION_A1_ID}`);
        expect(resp.status()).toBe(200);
        const { data } = await resp.json();

        expect(data.sessionId).toBe(SESSION_A1_ID);
        expect(data.superchatName).toBe(BUCKET_NAME);
        expect(data.duration).toBe('9s');
        expect(data.chatData.messages).toHaveLength(2);
        expect(data.chatData.messages[0].content).toBe('What is ATP?');
    });

    test('single-session fetch 404s for deleted sessions and unknown buckets', async ({ request: api }) => {
        const deleted = await api.get(
            `/api/superchats/${BUCKET_ID}/chat-sessions/${STUDENT_A_ID}/${SESSION_A_DELETED_ID}`,
            { failOnStatusCode: false }
        );
        expect(deleted.status()).toBe(404);

        const unknownBucket = await api.get(
            `/api/superchats/does-not-exist/chat-sessions`,
            { failOnStatusCode: false }
        );
        expect(unknownBucket.status()).toBe(404);
    });

    test('bulk export returns full transcripts for the whole bucket or a single student', async ({ request: api }) => {
        const full = await api.get(`/api/superchats/${BUCKET_ID}/chat-sessions/export`);
        expect(full.status()).toBe(200);
        const fullData = (await full.json()).data;

        expect(fullData.superchatName).toBe(BUCKET_NAME);
        expect(fullData.totalStudents).toBe(2);
        expect(fullData.totalSessions).toBe(3);
        const averyFull = fullData.students.find((s) => s.studentId === STUDENT_A_ID);
        expect(averyFull.sessions).toHaveLength(2);
        expect(averyFull.sessions.every((s) => Array.isArray(s.chatData.messages))).toBe(true);

        const filtered = await api.get(
            `/api/superchats/${BUCKET_ID}/chat-sessions/export?studentId=${STUDENT_A_ID}`
        );
        expect(filtered.status()).toBe(200);
        const filteredData = (await filtered.json()).data;
        expect(filteredData.totalStudents).toBe(1);
        expect(filteredData.totalSessions).toBe(2);
        expect(filteredData.students[0].studentId).toBe(STUDENT_A_ID);
    });

    test('a non-admin instructor gets 403 on every download endpoint', async ({ request: api }) => {
        await setSystemAdmin(instructorId, false);

        const endpoints = [
            `/api/superchats/${BUCKET_ID}/chat-sessions`,
            `/api/superchats/${BUCKET_ID}/chat-sessions/export`,
            `/api/superchats/${BUCKET_ID}/chat-sessions/${STUDENT_A_ID}/${SESSION_A1_ID}`,
        ];
        for (const endpoint of endpoints) {
            const resp = await api.get(endpoint, { failOnStatusCode: false });
            expect(resp.status()).toBe(403);
        }
    });
});

test.describe('Superchat downloads API (student)', () => {
    test.use({ storageState: storageStatePath('student') });

    test.beforeEach(async () => {
        await seedDownloadScenario();
    });

    test.afterEach(async () => {
        await cleanupDownloadScenario();
    });

    test('students are rejected from superchat download endpoints', async ({ request: api }) => {
        const resp = await api.get(`/api/superchats/${BUCKET_ID}/chat-sessions`, { failOnStatusCode: false });
        expect(resp.status()).toBe(403);
    });
});

test.describe('Downloads page superchat scope (system admin UI)', () => {
    test.use({ storageState: storageStatePath('instructor'), acceptDownloads: true });

    test.beforeEach(async () => {
        await seedCourse({ courseId: COURSE_ID, instructorId, courseName: COURSE_NAME });
        await seedDownloadScenario();
        await setSystemAdmin(instructorId, true);
    });

    test.afterEach(async () => {
        await cleanupDownloadScenario();
        await cleanupCourses([COURSE_ID]);
        await setSystemAdmin(instructorId, false);
    });

    async function readDownloadedJson(download) {
        const downloadPath = await download.path();
        expect(downloadPath).toBeTruthy();
        return JSON.parse(await fs.readFile(downloadPath, 'utf8'));
    }

    test('admin can switch to a bucket, browse sessions, and download transcripts', async ({ page }) => {
        await page.goto(`/instructor/downloads?courseId=${COURSE_ID}`);
        await expect(page.locator('#course-title')).toHaveText(
            `${COURSE_NAME} - Download Chats`,
            { timeout: 15_000 }
        );

        // Bucket options exist, so the scope picker is shown
        const selector = page.locator('#scope-selector');
        await expect(selector).toBeVisible({ timeout: 15_000 });
        await selector.selectOption(`superchat:${BUCKET_ID}`);

        // Scope labels flip to the bucket
        await expect(page.locator('#course-title')).toHaveText(`${BUCKET_NAME} - Download Chats`);
        await expect(page.locator('#scope-subtitle')).toHaveText('Superchat Student Chat Downloads');
        await expect(page.locator('#download-all-label')).toHaveText('Download All Superchat Data');
        await expect(page.locator('#total-students')).toHaveText('2');

        // Open a student's sessions and download one as JSON
        const card = page.locator('.student-card', { hasText: STUDENT_A_NAME });
        await expect(card).toBeVisible();
        await card.getByRole('button', { name: 'View Sessions' }).click();

        const modal = page.locator('#student-modal');
        await expect(modal).toBeVisible({ timeout: 10_000 });
        await expect(modal.locator('#student-course')).toHaveText(BUCKET_NAME);
        await expect(modal.locator('.session-item')).toHaveCount(2);

        const sessionItem = modal.locator('.session-item-wrapper', { hasText: 'Avery Bucket Chat One' });
        await sessionItem.locator('.download-dropdown-toggle').click();
        const [download] = await Promise.all([
            page.waitForEvent('download'),
            sessionItem.getByRole('button', { name: 'Download JSON' }).click(),
        ]);
        const sessionJson = await readDownloadedJson(download);
        expect(sessionJson.messages).toHaveLength(2);
        expect(sessionJson.messages[0].content).toBe('What is ATP?');

        await modal.locator('.modal-close').click();

        // Whole-bucket export via the single round-trip endpoint
        await page.locator('#download-course-btn').click();
        const [bucketDownload] = await Promise.all([
            page.waitForEvent('download'),
            page.locator('#download-menu-course-all').getByRole('button', { name: 'Download JSON' }).click(),
        ]);
        const bucketJson = await readDownloadedJson(bucketDownload);
        expect(bucketJson.superchatName).toBe(BUCKET_NAME);
        expect(bucketJson.totalStudents).toBe(2);
        expect(bucketJson.students).toHaveLength(2);

        // Switching back restores the course scope
        await selector.selectOption('course');
        await expect(page.locator('#course-title')).toHaveText(`${COURSE_NAME} - Download Chats`);
        await expect(page.locator('#scope-subtitle')).toHaveText('Student Chat Downloads');
    });
});
