// @ts-check
/**
 * API coverage for src/routes/auth.js (~44% → target ~75%+) plus the
 * underlying src/services/authService.js (~30%) and src/config/passport.js
 * (~44%). The dead `/ubcshib` block and the SAML strategy paths require
 * external IdPs and are out of scope.
 */

const crypto = require('crypto');
const { test, expect, request } = require('./fixtures/monocart');
const { TEST_USERS, storageStatePath } = require('./helpers/users');
const { withDb, getUserIdByUsername } = require('./helpers/courses-test');

let instructorId;
let studentId;

// Unique throwaway user we register/delete inside the spec
const NEW_USERNAME = `e2e_api_auth_${crypto.randomBytes(4).toString('hex')}`;
const NEW_PASSWORD = `E2e!${crypto.randomBytes(16).toString('hex')}`;

test.beforeAll(async () => {
    instructorId = await getUserIdByUsername(TEST_USERS.instructor.username);
    studentId = await getUserIdByUsername(TEST_USERS.student.username);
});

test.afterAll(async () => {
    // Clean any users created during this spec
    await withDb((db) =>
        db.collection('users').deleteMany({ username: { $regex: /^e2e_api_auth_/ } })
    );
});

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
test.describe('POST /api/auth/login', () => {
    test('400 when username or password missing', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/login', { data: {} });
            expect(res.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('401 when password is wrong', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/login', {
                data: { username: TEST_USERS.instructor.username, password: 'definitely-wrong' },
            });
            expect(res.status()).toBe(401);
        } finally {
            await api.dispose();
        }
    });

    test('401 when user does not exist', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/login', {
                data: { username: 'no-such-user-ever', password: 'x' },
            });
            expect(res.status()).toBe(401);
        } finally {
            await api.dispose();
        }
    });

    test('403 when allowLocalLogin is disabled globally', async ({ baseURL }) => {
        await withDb((db) =>
            db.collection('settings').updateOne(
                { _id: 'global' },
                { $set: { allowLocalLogin: false } },
                { upsert: true }
            )
        );
        try {
            const api = await request.newContext({ baseURL });
            try {
                const res = await api.post('/api/auth/login', {
                    data: { username: 'whatever', password: 'x' },
                });
                expect(res.status()).toBe(403);
            } finally {
                await api.dispose();
            }
        } finally {
            await withDb((db) =>
                db.collection('settings').updateOne(
                    { _id: 'global' },
                    { $set: { allowLocalLogin: true } }
                )
            );
        }
    });
});

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
test.describe('POST /api/auth/register', () => {
    test('400 when required fields missing', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/register', { data: { username: 'x' } });
            expect(res.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('400 when role is invalid', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/register', {
                data: { username: 'x', password: 'p', role: 'admin' },
            });
            expect(res.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('200 happy path creates a new user', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/register', {
                data: {
                    username: NEW_USERNAME,
                    password: NEW_PASSWORD,
                    email: `${NEW_USERNAME}@test.local`,
                    role: 'student',
                    displayName: 'E2E API Auth User',
                },
            });
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.user.username).toBe(NEW_USERNAME);
        } finally {
            await api.dispose();
        }
    });

    test('400 when re-registering an existing username', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.post('/api/auth/register', {
                data: {
                    username: NEW_USERNAME,
                    password: NEW_PASSWORD,
                    role: 'student',
                },
            });
            expect(res.status()).toBe(400);
        } finally {
            await api.dispose();
        }
    });

    test('403 when allowLocalLogin is disabled globally', async ({ baseURL }) => {
        await withDb((db) =>
            db.collection('settings').updateOne(
                { _id: 'global' },
                { $set: { allowLocalLogin: false } },
                { upsert: true }
            )
        );
        try {
            const api = await request.newContext({ baseURL });
            try {
                const res = await api.post('/api/auth/register', {
                    data: { username: 'x', password: 'p', role: 'student' },
                });
                expect(res.status()).toBe(403);
            } finally {
                await api.dispose();
            }
        } finally {
            await withDb((db) =>
                db.collection('settings').updateOne(
                    { _id: 'global' },
                    { $set: { allowLocalLogin: true } }
                )
            );
        }
    });
});

// ---------------------------------------------------------------------------
// /me and /logout
// ---------------------------------------------------------------------------
test.describe('GET /api/auth/me + POST /api/auth/logout', () => {
    test('401 when not authenticated', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.get('/api/auth/me');
            expect(res.status()).toBe(401);
        } finally {
            await api.dispose();
        }
    });

    test('returns the user when authenticated', async ({ baseURL }) => {
        const api = await request.newContext({
            baseURL,
            storageState: storageStatePath('instructor'),
        });
        try {
            const res = await api.get('/api/auth/me');
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.user.userId).toBe(instructorId);
            expect(body.user.role).toBe('instructor');
        } finally {
            await api.dispose();
        }
    });

    test('logout destroys the session (next /me returns 401)', async ({ baseURL }) => {
        // Fresh context so we can destroy without polluting the shared storage.
        const creds = JSON.parse(
            require('fs').readFileSync(
                require('path').join(__dirname, '..', '..', 'playwright', '.auth', '.credentials.json'),
                'utf8'
            )
        );
        const api = await request.newContext({ baseURL });
        try {
            const login = await api.post('/api/auth/login', {
                data: { username: TEST_USERS.student.username, password: creds.student },
            });
            expect(login.ok()).toBeTruthy();

            const meOk = await api.get('/api/auth/me');
            expect(meOk.ok()).toBeTruthy();

            const logout = await api.post('/api/auth/logout');
            expect(logout.ok()).toBeTruthy();

            const meAfter = await api.get('/api/auth/me');
            expect(meAfter.status()).toBe(401);
        } finally {
            await api.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// PUT /api/auth/preferences  +  POST /api/auth/set-course
// ---------------------------------------------------------------------------
test.describe('preferences + set-course', () => {
    test.use({ storageState: storageStatePath('instructor') });

    test('PUT /preferences 400 when preferences not an object', async ({ request: api }) => {
        const res = await api.put('/api/auth/preferences', { data: { preferences: 'oops' } });
        expect(res.status()).toBe(400);
    });

    test('PUT /preferences updates the user', async ({ request: api }) => {
        const res = await api.put('/api/auth/preferences', {
            data: { preferences: { theme: 'dark', courseId: 'BIOC-E2E-API-NONE' } },
        });
        expect(res.ok()).toBeTruthy();
    });

    test('POST /set-course 400 when courseId missing', async ({ request: api }) => {
        const res = await api.post('/api/auth/set-course', { data: {} });
        expect(res.status()).toBe(400);
    });

    test('POST /set-course happy path stores the course', async ({ request: api }) => {
        const res = await api.post('/api/auth/set-course', {
            data: { courseId: 'BIOC-E2E-API-NONE' },
        });
        expect(res.ok()).toBeTruthy();
    });

});

// ---------------------------------------------------------------------------
// /tas, /users/:userId, DELETE /tas/:taId
// ---------------------------------------------------------------------------
test.describe('user-management endpoints', () => {
    test.describe('as instructor', () => {
        test.use({ storageState: storageStatePath('instructor') });

        test('GET /tas returns the TA users', async ({ request: api }) => {
            const res = await api.get('/api/auth/tas');
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(Array.isArray(body.data)).toBe(true);
        });

        test('PRODUCT BUG: GET /users/:userId throws because findOne(...).project() is not a function (mongo v6)', async ({ request: api }) => {
            // src/routes/auth.js:610-620 does `collection.findOne(...).project(...)`.
            // In mongodb driver 6.x, findOne returns a Document, not a Cursor,
            // so .project is undefined and every call to this endpoint throws.
            // EXPECTED: 200 with user data. Currently always 500.
            const res = await api.get(`/api/auth/users/${studentId}`);
            expect(res.ok()).toBeTruthy();
        });

        test('PRODUCT BUG: GET /users/:userId crashes even for missing users (same root cause)', async ({ request: api }) => {
            // EXPECTED: 404. Currently 500 from the same findOne(...).project() bug.
            const res = await api.get('/api/auth/users/no-such-user');
            expect(res.status()).toBe(404);
        });
    });

    test.describe('as student', () => {
        test.use({ storageState: storageStatePath('student') });

        test('GET /tas 403 for non-instructor', async ({ request: api }) => {
            const res = await api.get('/api/auth/tas');
            expect(res.status()).toBe(403);
        });

        test('GET /users/:userId 403 for non-instructor', async ({ request: api }) => {
            const res = await api.get(`/api/auth/users/${instructorId}`);
            expect(res.status()).toBe(403);
        });
    });

    test('GET /tas 401 when unauthenticated', async ({ baseURL }) => {
        const anon = await request.newContext({ baseURL });
        try {
            const res = await anon.get('/api/auth/tas');
            expect(res.status()).toBe(401);
        } finally {
            await anon.dispose();
        }
    });
});

// ---------------------------------------------------------------------------
// POST /api/auth/promote-to-ta + DELETE /api/auth/tas/:taId
// ---------------------------------------------------------------------------
test.describe('promote-to-ta + DELETE /tas/:taId', () => {
    test.use({ storageState: storageStatePath('instructor') });

    let promotedUserId;

    test.beforeAll(async () => {
        // Register a throwaway student to promote
        const baseURL = `http://localhost:${process.env.TLEF_BIOCBOT_PORT || 8085}`;
        const api = await request.newContext({ baseURL });
        try {
            const username = `e2e_api_auth_promote_${crypto.randomBytes(4).toString('hex')}`;
            const res = await api.post('/api/auth/register', {
                data: {
                    username,
                    password: `E2e!${crypto.randomBytes(8).toString('hex')}`,
                    email: `${username}@test.local`,
                    role: 'student',
                    displayName: 'E2E Promote',
                },
            });
            const body = await res.json();
            promotedUserId = body.user.userId;
        } finally {
            await api.dispose();
        }
    });

    test('400 when userId missing', async ({ request: api }) => {
        const res = await api.post('/api/auth/promote-to-ta', { data: {} });
        expect(res.status()).toBe(400);
    });

    test('404 when user does not exist', async ({ request: api }) => {
        const res = await api.post('/api/auth/promote-to-ta', {
            data: { userId: 'no-such-user' },
        });
        expect(res.status()).toBe(404);
    });

    test('happy path promotes a student to TA and assigns invitedCourses', async ({ request: api }) => {
        // promote-to-ta now verifies the instructor owns the course before
        // attaching it to the new TA's invitedCourses, so the course must
        // exist with this instructor as owner for the happy-path assertion.
        await withDb((db) =>
            db.collection('courses').insertOne({
                courseId: 'BIOC-E2E-API-AUTH-X',
                courseName: 'Auth Promote Target',
                instructorId,
                instructors: [instructorId],
                status: 'active',
                lectures: [],
            })
        );
        try {
            const res = await api.post('/api/auth/promote-to-ta', {
                data: { userId: promotedUserId, courseId: 'BIOC-E2E-API-AUTH-X' },
            });
            expect(res.ok()).toBeTruthy();
            const doc = await withDb((db) =>
                db.collection('users').findOne({ userId: promotedUserId })
            );
            expect(doc.role).toBe('ta');
            expect(doc.invitedCourses).toContain('BIOC-E2E-API-AUTH-X');
        } finally {
            await withDb((db) =>
                db.collection('courses').deleteOne({ courseId: 'BIOC-E2E-API-AUTH-X' })
            );
        }
    });

    test('DELETE /tas/:taId demotes a TA back to student and pulls them from courses', async ({ request: api }) => {
        // Seed a course with the TA assigned, then call delete.
        await withDb((db) =>
            db.collection('courses').insertOne({
                courseId: 'BIOC-E2E-API-AUTH-DEMOTE',
                courseName: 'Demote Demo',
                instructorId,
                instructors: [instructorId],
                tas: [promotedUserId],
                status: 'active',
                lectures: [],
            })
        );
        try {
            const res = await api.delete(`/api/auth/tas/${promotedUserId}`);
            expect(res.ok()).toBeTruthy();
            const doc = await withDb((db) =>
                db.collection('users').findOne({ userId: promotedUserId })
            );
            expect(doc.role).toBe('student');
            const course = await withDb((db) =>
                db.collection('courses').findOne({ courseId: 'BIOC-E2E-API-AUTH-DEMOTE' })
            );
            expect(course.tas).not.toContain(promotedUserId);
        } finally {
            await withDb((db) =>
                db.collection('courses').deleteOne({ courseId: 'BIOC-E2E-API-AUTH-DEMOTE' })
            );
            await withDb((db) =>
                db.collection('users').deleteOne({ userId: promotedUserId })
            );
        }
    });
});

// ---------------------------------------------------------------------------
// GET /api/auth/methods
// ---------------------------------------------------------------------------
test.describe('GET /api/auth/methods', () => {
    test('returns the configured auth method flags', async ({ baseURL }) => {
        const api = await request.newContext({ baseURL });
        try {
            const res = await api.get('/api/auth/methods');
            expect(res.ok()).toBeTruthy();
            const body = await res.json();
            expect(body.success).toBe(true);
            expect(typeof body.methods.local).toBe('boolean');
            expect(typeof body.methods.allowLocalLogin).toBe('boolean');
        } finally {
            await api.dispose();
        }
    });

    test('reflects allowLocalLogin=false from settings', async ({ baseURL }) => {
        await withDb((db) =>
            db.collection('settings').updateOne(
                { _id: 'global' },
                { $set: { allowLocalLogin: false } },
                { upsert: true }
            )
        );
        try {
            const api = await request.newContext({ baseURL });
            try {
                const res = await api.get('/api/auth/methods');
                expect(res.ok()).toBeTruthy();
                const body = await res.json();
                expect(body.methods.allowLocalLogin).toBe(false);
                expect(body.methods.local).toBe(false);
            } finally {
                await api.dispose();
            }
        } finally {
            await withDb((db) =>
                db.collection('settings').updateOne(
                    { _id: 'global' },
                    { $set: { allowLocalLogin: true } }
                )
            );
        }
    });
});
