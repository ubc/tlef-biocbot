// @ts-check
/**
 * Compact harness for defensive src route/model branches that the live server
 * cannot reach without swapping app.locals, Passport callbacks, or DB methods.
 */

const moduleRequire = eval('require');
const express = require('express');
const passport = moduleRequire('passport');
const AuthService = moduleRequire('../../../src/services/authService');
const User = moduleRequire('../../../src/models/User');
const UserAgreement = moduleRequire('../../../src/models/UserAgreement');
const CourseModel = moduleRequire('../../../src/models/Course');
const QdrantService = moduleRequire('../../../src/services/qdrantService');
const createAuthMiddleware = moduleRequire('../../../src/middleware/auth');

const app = express();
app.use(express.json());

const ORIGINAL = {
    passportAuthenticate: passport.authenticate,
    User: { ...User },
    Course: { ...CourseModel },
    Qdrant: {
        initialize: QdrantService.prototype.initialize,
        getCollectionStats: QdrantService.prototype.getCollectionStats,
        processAndStoreDocument: QdrantService.prototype.processAndStoreDocument,
        searchDocuments: QdrantService.prototype.searchDocuments,
        searchDocumentsByCourse: QdrantService.prototype.searchDocumentsByCourse,
        deleteDocumentChunks: QdrantService.prototype.deleteDocumentChunks,
        deleteCollection: QdrantService.prototype.deleteCollection,
    },
    AuthServiceGetUserById: AuthService.prototype.getUserById,
};

function restoreOriginals() {
    Object.assign(User, ORIGINAL.User);
    Object.assign(CourseModel, ORIGINAL.Course);
    QdrantService.prototype.initialize = ORIGINAL.Qdrant.initialize;
    QdrantService.prototype.getCollectionStats = ORIGINAL.Qdrant.getCollectionStats;
    QdrantService.prototype.processAndStoreDocument = ORIGINAL.Qdrant.processAndStoreDocument;
    QdrantService.prototype.searchDocuments = ORIGINAL.Qdrant.searchDocuments;
    QdrantService.prototype.searchDocumentsByCourse = ORIGINAL.Qdrant.searchDocumentsByCourse;
    QdrantService.prototype.deleteDocumentChunks = ORIGINAL.Qdrant.deleteDocumentChunks;
    QdrantService.prototype.deleteCollection = ORIGINAL.Qdrant.deleteCollection;
    AuthService.prototype.getUserById = ORIGINAL.AuthServiceGetUserById;
}

class MemoryCollection {
    constructor(docs = []) {
        this.docs = docs;
    }

    async findOne(query) {
        return this.docs.find(doc => matchesQuery(doc, query || {})) || null;
    }

    async insertOne(doc) {
        this.docs.push({ ...doc });
        return { insertedId: `inserted-${this.docs.length}` };
    }

    async updateOne(query, update) {
        const doc = await this.findOne(query);
        if (!doc) return { modifiedCount: 0, upsertedCount: 0 };
        Object.assign(doc, update.$set || {});
        return { modifiedCount: 1, upsertedCount: 0 };
    }

    async replaceOne(query, replacement, options = {}) {
        const index = this.docs.findIndex(doc => matchesQuery(doc, query || {}));
        if (index >= 0) {
            this.docs[index] = { ...replacement };
            return { matchedCount: 1, modifiedCount: 1, upsertedCount: 0 };
        }
        if (options.upsert) {
            this.docs.push({ ...replacement });
            return { matchedCount: 0, modifiedCount: 0, upsertedCount: 1 };
        }
        return { matchedCount: 0, modifiedCount: 0, upsertedCount: 0 };
    }

    async countDocuments() {
        return this.docs.length;
    }

    find(query) {
        const rows = this.docs.filter(doc => matchesQuery(doc, query || {}));
        const cursor = {
            project: () => cursor,
            sort: () => cursor,
            toArray: async () => rows,
        };
        return cursor;
    }

    aggregate(pipeline) {
        const match = pipeline && pipeline[0] && pipeline[0].$match ? pipeline[0].$match : {};
        const rows = this.docs.filter(doc => Object.entries(match).every(([k, v]) => doc[k] === v));
        const agreedUsers = rows.filter(doc => doc.hasAgreed).length;
        return {
            toArray: async () => rows.length === 0 ? [] : [{
                totalUsers: rows.length,
                agreedUsers,
                pendingUsers: rows.length - agreedUsers,
            }],
        };
    }
}

function matchesQuery(doc, query = {}) {
    return Object.entries(query).every(([key, value]) => {
        if (key === '$or') {
            return Array.isArray(value) && value.some(part => matchesQuery(doc, part));
        }

        const docValue = doc[key];
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            if (Object.prototype.hasOwnProperty.call(value, '$ne') && docValue === value.$ne) {
                return false;
            }
            if (Object.prototype.hasOwnProperty.call(value, '$exists')) {
                const exists = Object.prototype.hasOwnProperty.call(doc, key);
                if (exists !== value.$exists) return false;
            }
            return Object.entries(value)
                .filter(([operator]) => operator !== '$ne' && operator !== '$exists')
                .every(([, expected]) => docValue === expected);
        }

        return docValue === value;
    });
}

function memoryDb(collections = {}) {
    return {
        collection(name) {
            if (!collections[name]) collections[name] = new MemoryCollection();
            return collections[name];
        },
        listCollections() {
            return { toArray: async () => Object.keys(collections).map(name => ({ name })) };
        },
        async dropCollection(name) {
            delete collections[name];
        },
    };
}

const baseUser = {
    userId: 'harness-user',
    username: 'harness',
    email: 'harness@example.test',
    role: 'student',
    displayName: 'Harness User',
    authProvider: 'basic',
    preferences: {},
    permissions: { systemAdmin: false },
    isActive: true,
};

/** @type {any} */
const state = {
    mode: '',
    user: null,
    session: null,
    db: memoryDb(),
    authService: new AuthService(memoryDb()),
    passportForLocals: null,
    llm: {
        sendMessage: async () => ({ content: '{"matches":[{"ref":"q1","learningObjective":"Objective A"}]}' }),
        analyzeMentalHealth: async () => ({ concernLevel: 'no concern', reason: '' }),
        evaluateStudentAnswer: async () => ({ correct: true, feedback: 'stub' }),
        generateAssessmentQuestion: async () => ({ question: 'Generated?', answer: 'true', options: {} }),
        regenerateAssessmentQuestion: async () => ({ question: 'Regenerated?', answer: 'true', options: {} }),
    },
    lastQdrantSearch: null,
    lastLlmRequest: null,
};

function fakeSession(session) {
    return {
        ...(session || {}),
        destroy(cb) {
            state.session = null;
            if (cb) cb();
        },
    };
}

function applyRequestState(req, _res, next) {
    req.user = state.user;
    req.session = fakeSession(state.session);
    req.login = (_user, cb) => cb(state.mode === 'auth-login-session-error' ? new Error('harness login failure') : null);
    req.logout = (cb) => cb(state.mode === 'auth-logout-passport-error' ? new Error('harness logout failure') : null);
    req.app.locals.db = state.db;
    req.app.locals.authService = state.authService;
    req.app.locals.passport = state.passportForLocals;
    req.app.locals.llm = state.llm;
    next();
}

function configurePassport(mode) {
    // Passport is wrapped once before route modules are required. The returned
    // middleware consults state.mode at request time, including for SAML routes
    // whose middleware is constructed during module load.
    void mode;
}

function configureQdrant(mode) {
    if (mode === 'qdrant-init-throws') {
        QdrantService.prototype.initialize = async function () {
            this.client = null;
            throw new Error('harness init failure');
        };
        return;
    }

    QdrantService.prototype.initialize = async function () {
        this.client = {
            scroll: async () => ({
                points: [
                    { payload: { documentId: 'valid-doc' } },
                    { payload: { documentId: 'orphan-doc' } },
                    { payload: {} },
                ],
                next_page_offset: null,
            }),
        };
    };

    QdrantService.prototype.getCollectionStats = async () => {
        if (mode === 'qdrant-stats-throws') throw new Error('harness stats failure');
        return { vectorsCount: 3 };
    };
    QdrantService.prototype.processAndStoreDocument = async () => {
        if (mode === 'qdrant-process-throws') throw new Error('harness process failure');
        if (mode === 'qdrant-process-fails') return { success: false, error: 'store failed' };
        return { success: true, message: 'stored', chunksProcessed: 1, chunksStored: 1 };
    };
    QdrantService.prototype.searchDocuments = async (query, filters, limit) => {
        if (mode === 'qdrant-search-throws') throw new Error('harness search failure');
        state.lastQdrantSearch = { query, filters, limit };
        const courseId = Array.isArray(filters && filters.courseId) ? filters.courseId[0] : filters && filters.courseId;
        return [{
            id: 'chunk-1',
            score: 0.91,
            courseId,
            lectureName: 'Unit 1',
            documentId: 'doc-1',
            fileName: 'doc.txt',
            documentType: 'lecture-notes',
            type: 'lecture_notes',
            chunkText: 'Harness chunk text',
            chunkIndex: 0,
            timestamp: new Date().toISOString(),
        }];
    };
    // Super Course retrieval now fans out one filtered search per course and
    // merges with a per-course floor. Mirror searchDocuments' recording shape
    // (filters.courseId stays the full course array) so the existing assertions
    // hold, and return a per-course map with one chunk each.
    QdrantService.prototype.searchDocumentsByCourse = async (query, courseIds, perCourseLimit) => {
        if (mode === 'qdrant-search-throws') throw new Error('harness search failure');
        const ids = Array.isArray(courseIds) ? courseIds : [];
        state.lastQdrantSearch = { query, filters: { courseId: ids }, limit: perCourseLimit };
        const map = new Map();
        for (const courseId of ids) {
            map.set(courseId, [{
                id: `chunk-${courseId}`,
                score: 0.91,
                courseId,
                lectureName: 'Unit 1',
                documentId: 'doc-1',
                fileName: 'doc.txt',
                documentType: 'lecture-notes',
                type: 'lecture_notes',
                chunkText: 'Harness chunk text',
                chunkIndex: 0,
                timestamp: new Date().toISOString(),
            }]);
        }
        return map;
    };
    QdrantService.prototype.deleteDocumentChunks = async () => {
        if (mode === 'qdrant-delete-throws') throw new Error('harness delete failure');
        if (mode === 'qdrant-delete-fails') return { success: false, error: 'delete failed' };
        return { success: true, message: 'deleted', deletedCount: 2 };
    };
    QdrantService.prototype.deleteCollection = async () => {
        if (mode === 'qdrant-collection-throws') throw new Error('harness collection failure');
        if (mode === 'qdrant-collection-fails' || mode === 'qdrant-delete-all-qdrant-fails') {
            return { success: false, error: 'collection failed' };
        }
        return { success: true, message: 'collection deleted', deletedCount: 4 };
    };
}

function applyMode(mode) {
    restoreOriginals();
    state.mode = mode || '';
    state.user = null;
    state.session = null;
    state.db = memoryDb({
        users: new MemoryCollection([{ ...baseUser }]),
        documents: new MemoryCollection([{ _id: 'valid-doc', documentId: 'valid-doc', courseId: 'BIOC-H' }]),
    });
    state.authService = new AuthService(state.db);
    state.passportForLocals = null;
    state.llm = {
        sendMessage: async () => ({ content: '{"matches":[{"ref":"q1","learningObjective":"Objective A"}]}' }),
        analyzeMentalHealth: async () => ({ concernLevel: 'no concern', reason: '' }),
        evaluateStudentAnswer: async () => ({ correct: true, feedback: 'stub' }),
        generateAssessmentQuestion: async () => ({ question: 'Generated?', answer: 'true', options: {} }),
        regenerateAssessmentQuestion: async () => ({ question: 'Regenerated?', answer: 'true', options: {} }),
    };
    state.lastQdrantSearch = null;
    state.lastLlmRequest = null;

    configurePassport(state.mode);
    configureQdrant(state.mode);

    if (state.mode === 'middleware-session-user') state.session = { userId: 'harness-user' };
    if (state.mode === 'middleware-missing-user') state.session = { userId: 'missing-user' };
    if (state.mode === 'middleware-throw-user') {
        state.session = { userId: 'harness-user' };
        AuthService.prototype.getUserById = async () => { throw new Error('harness auth throw'); };
    }
    if (state.mode === 'middleware-wrong-role') state.user = { ...baseUser, role: 'student' };
    if (state.mode === 'middleware-admin-denied') state.user = { ...baseUser, role: 'instructor', permissions: { systemAdmin: false } };
    if (state.mode === 'middleware-admin-ok') state.user = { ...baseUser, role: 'instructor', permissions: { systemAdmin: true } };
    if (state.mode === 'middleware-ta-no-course') state.user = { ...baseUser, role: 'ta', preferences: {} };
    if (state.mode === 'middleware-ta-throws') {
        state.user = { ...baseUser, role: 'ta', preferences: { courseId: 'BIOC-H' } };
        CourseModel.checkTAPermission = async () => { throw new Error('harness ta permission failure'); };
    }
    if (state.mode === 'middleware-course-instructor-no-context') state.user = { ...baseUser, role: 'instructor', preferences: {} };
    if (state.mode === 'auth-no-service') {
        state.user = { ...baseUser, role: 'instructor' };
        state.session = { userId: 'harness-user', userRole: 'instructor' };
        state.authService = null;
    }
    if (state.mode === 'auth-cwl-helper-success') {
        state.user = { ...baseUser, authProvider: 'saml' };
        state.session = { userId: 'harness-user' };
        state.passportForLocals = { ubcShibHelpers: { logout: (_req, cb) => cb(null, 'https://idp.example/logout') } };
    }
    if (state.mode === 'auth-cwl-helper-error') {
        state.user = { ...baseUser, authProvider: 'saml' };
        state.session = { userId: 'harness-user' };
        state.passportForLocals = { ubcShibHelpers: { logout: (_req, cb) => cb(new Error('helper failed')) } };
    }
    if (state.mode === 'questions-no-db') {
        // /api/questions auth-checks `req.user` before the db-missing 503,
        // so the harness must supply an instructor user for that branch to be
        // reachable. The userId matches the body `instructorId: 'inst'` the
        // spec sends, so the same-instructor check passes.
        state.user = { ...baseUser, userId: 'inst', role: 'instructor' };
        state.db = null;
    }
    if (state.mode === 'questions-no-llm') {
        state.user = { ...baseUser, userId: 'inst', role: 'instructor' };
        state.llm = null;
    }
    if (state.mode === 'questions-course-throws') {
        state.user = { ...baseUser, userId: 'inst', role: 'instructor' };
        // The new course-access pre-check would otherwise turn this into a
        // 403 before we ever hit the dependency-throw branch under test.
        CourseModel.userHasCourseAccess = async () => true;
        // GET /api/questions/lecture early-returns 200 when the course isn't
        // present; seed BIOC-H so we reach the throwing model call.
        state.db = memoryDb({
            users: new MemoryCollection([{ ...baseUser }]),
            documents: new MemoryCollection([{ _id: 'valid-doc', documentId: 'valid-doc', courseId: 'BIOC-H' }]),
            courses: new MemoryCollection([{ _id: 'BIOC-H', courseId: 'BIOC-H', instructorId: 'inst', instructors: ['inst'] }]),
        });
        CourseModel.updateAssessmentQuestions = async () => { throw new Error('harness question failure'); };
        CourseModel.getAssessmentQuestions = async () => { throw new Error('harness question fetch failure'); };
    }
    if (state.mode === 'questions-llm-throws') {
        state.user = { ...baseUser, userId: 'inst', role: 'instructor' };
        CourseModel.userHasCourseAccess = async () => true;
        state.llm = { evaluateStudentAnswer: async () => { throw new Error('harness eval failure'); } };
    }
    if (state.mode === 'qdrant-admin' || state.mode === 'qdrant-delete-all-qdrant-fails' || state.mode === 'qdrant-collection-fails') {
        state.user = { ...baseUser, role: 'instructor', permissions: { systemAdmin: true } };
    }
    if (state.mode === 'qdrant-delete-all-no-db') {
        state.user = { ...baseUser, role: 'instructor', permissions: { systemAdmin: true } };
        state.db = null;
    }
    if (state.mode === 'qdrant-cleanup-no-db') {
        // requireDirectQdrantAccess returns 401 if no user, before the
        // db-missing 503 branch is reachable.
        state.user = { ...baseUser, userId: 'inst', role: 'instructor' };
        CourseModel.userHasCourseAccess = async () => true;
        state.db = null;
    }
    // The remaining qdrant-* modes hit routes guarded by
    // requireDirectQdrantAccess. Without a user they'd return 401 long before
    // reaching the service-failure / collection-failure branches under test.
    if (
        state.mode === 'qdrant-process-fails'
        || state.mode === 'qdrant-process-throws'
        || state.mode === 'qdrant-search-throws'
        || state.mode === 'qdrant-delete-throws'
        || state.mode === 'qdrant-delete-fails'
        || state.mode === 'qdrant-collection-throws'
        || state.mode === 'qdrant-stats-throws'
    ) {
        state.user = { ...baseUser, userId: 'inst', role: 'instructor' };
        CourseModel.userHasCourseAccess = async () => true;
    }
    if (state.mode === 'chat-rag-topk') {
        state.user = { ...baseUser, userId: 'student-harness', role: 'student' };
        state.db = memoryDb({
            users: new MemoryCollection([{ ...baseUser }]),
            courses: new MemoryCollection([{
                courseId: 'BIOC-H',
                courseName: 'Harness Course',
                instructorId: 'inst',
                instructors: ['inst'],
                approvedStruggleTopics: [],
                ragSettings: { student: { topK: 5 } },
                lectures: [{ name: 'Unit 1', isPublished: true }],
            }]),
            mentalHealthFlags: new MemoryCollection([]),
        });
        state.llm = {
            sendMessage: async () => ({ content: 'Harness chat response', model: 'harness-llm', usage: { tokens: 1 } }),
            analyzeMentalHealth: async () => ({ concernLevel: 'no concern', reason: '' }),
        };
    }
    if (state.mode === 'instructor-super-chat' || state.mode === 'instructor-super-chat-inactive') {
        state.user = { ...baseUser, userId: 'inst', role: 'instructor', permissions: { systemAdmin: true } };
        state.db = memoryDb({
            users: new MemoryCollection([{ ...baseUser, userId: 'inst', role: 'instructor' }]),
            settings: new MemoryCollection([{
                _id: 'superCourseChat',
                instructorTopK: 6,
                studentTopK: 8,
                includeInactiveCourses: state.mode === 'instructor-super-chat-inactive',
                showStudentSuperCourse: false,
                instructorPrompt: 'Harness instructor super prompt',
                studentPrompt: 'Harness student super prompt',
            }]),
            // Membership is now course-side via superchatIds. The instructor super
            // chat (no superchatId) pools every course that's in >=1 bucket.
            // BIOC-C is opted out -> omit superchatIds so the $exists matcher drops it.
            courses: new MemoryCollection([
                { courseId: 'BIOC-A', courseName: 'Biochemistry A', status: 'active', superchatIds: ['harness-bucket'] },
                { courseId: 'BIOC-B', courseName: 'Biochemistry B', status: 'inactive', superchatIds: ['harness-bucket'] },
                { courseId: 'BIOC-C', courseName: 'Biochemistry C', status: 'active' },
                { courseId: 'BIOC-D', courseName: 'Biochemistry D', status: 'deleted', superchatIds: ['harness-bucket'] },
            ]),
        });
        state.llm = {
            sendMessage: async (prompt, options) => {
                state.lastLlmRequest = { prompt, options };
                return { content: 'Harness instructor super answer', model: 'harness-llm', usage: { tokens: 1 } };
            },
            analyzeMentalHealth: async () => ({ concernLevel: 'no concern', reason: '' }),
        };
    }
}

applyMode('');

passport.authenticate = function (strategy, cbOrOptions) {
    if (state.mode === 'shib-login-throws' && strategy === 'ubcshib') {
        throw new Error('harness shib unavailable');
    }

    return (req, res, next) => {
        if (strategy === 'local' && typeof cbOrOptions === 'function') {
            if (state.mode === 'auth-login-passport-error') {
                cbOrOptions(new Error('harness passport failure'));
                return;
            }
            cbOrOptions(null, { ...baseUser, role: 'student' }, null);
            return;
        }

        if ((strategy === 'ubcshib' || strategy === 'saml') && state.mode.startsWith('shib-post-')) {
            const role = state.mode.replace('shib-post-', '');
            req.user = { ...baseUser, userId: `shib-${role}`, role };
            req.session = fakeSession({});
            next();
            return;
        }

        if (typeof ORIGINAL.passportAuthenticate === 'function') {
            return ORIGINAL.passportAuthenticate.call(passport, strategy, cbOrOptions)(req, res, next);
        }
        next();
    };
};

app.get('/__ping', (_req, res) => res.json({ ok: true }));
app.get('/__last-qdrant-search', (_req, res) => res.json(state.lastQdrantSearch || {}));
app.get('/__last-llm-request', (_req, res) => res.json(state.lastLlmRequest || {}));
app.post('/__configure', (req, res) => {
    applyMode(req.body.mode || '');
    res.json({ ok: true });
});

app.post('/__auth-service/:name', async (req, res) => {
    try {
        const service = new AuthService(req.body && req.body.throwingDb ? {
            collection: () => ({ findOne: async () => { throw new Error('db boom'); } }),
        } : state.db);
        const name = req.params.name;
        if (name === 'login-missing') return res.json(await service.loginUser('', ''));
        if (name === 'login-db-throw') return res.json(await service.loginUser('x', 'p'));
        if (name === 'set-course-missing-user') return res.json(await service.setCurrentCourseId('missing', 'BIOC-H'));
        if (name === 'session-and-role-helpers') {
            return res.json({
                nullSession: service.createSessionUser(null),
                hasNoRole: service.hasRole(null, 'student'),
                student: service.isStudent(baseUser),
                instructor: service.isInstructor({ ...baseUser, role: 'instructor' }),
                admin: service.isSystemAdmin({ ...baseUser, permissions: { systemAdmin: true } }),
                noCourse: service.getCurrentCourseId(null),
                course: service.getCurrentCourseId({ preferences: { courseId: 'BIOC-H' } }),
            });
        }
        if (name === 'initialize-default-users') {
            const initService = new AuthService(memoryDb({ users: new MemoryCollection([]) }));
            let calls = 0;
            initService.registerUser = async () => ({ success: true, userId: ++calls === 1 ? 'instructor-id' : 'student-id' });
            return res.json(await initService.initializeDefaultUsers());
        }
        if (name === 'initialize-instructor-fails') {
            const initService = new AuthService(memoryDb({ users: new MemoryCollection([]) }));
            initService.registerUser = async () => ({ success: false, error: 'no instructor' });
            return res.json(await initService.initializeDefaultUsers());
        }
        if (name === 'initialize-student-fails') {
            const initService = new AuthService(memoryDb({ users: new MemoryCollection([]) }));
            let calls = 0;
            initService.registerUser = async () => (++calls === 1 ? { success: true, userId: 'instructor-id' } : { success: false, error: 'no student' });
            return res.json(await initService.initializeDefaultUsers());
        }
        res.status(404).json({ error: 'unknown auth service case' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/__user-agreement/:name', async (req, res) => {
    try {
        const name = req.params.name;
        if (name === 'db-required') {
            await UserAgreement.getUserAgreement(null, 'u', 'student');
        }
        if (name === 'defaults-and-stats') {
            const db = memoryDb({ userAgreements: new MemoryCollection([]) });
            const created = await UserAgreement.createOrUpdateUserAgreement(db, 'u1', 'student', {});
            const agreed = await UserAgreement.hasUserAgreed(db, 'u1', 'student', '1.0');
            const emptyStats = await UserAgreement.getAgreementStats(memoryDb({ userAgreements: new MemoryCollection([]) }));
            const stats = await UserAgreement.getAgreementStats(memoryDb({
                userAgreements: new MemoryCollection([
                    { userId: 'u1', userType: 'student', hasAgreed: true },
                    { userId: 'u2', userType: 'student', hasAgreed: false },
                ]),
            }), 'student');
            return res.json({ created, agreed, emptyStats, stats });
        }
        res.status(404).json({ error: 'unknown agreement case' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/__user-model/:name', async (req, res) => {
    try {
        const name = req.params.name;
        const users = new MemoryCollection([{
            ...baseUser,
            userId: 'saml-existing',
            username: 'old@example.test',
            email: 'old@example.test',
            role: name === 'saml-preserve-ta' ? 'ta' : 'student',
            authProvider: 'saml',
            puid: name === 'get-by-puid' || name === 'saml-existing-update' || name === 'saml-preserve-ta' ? 'puid-1' : null,
            samlId: null,
        }]);
        const db = memoryDb({ users });
        if (name === 'get-by-puid') {
            return res.json({
                missing: await User.getUserByPuid(db, ''),
                found: await User.getUserByPuid(db, 'puid-1'),
            });
        }
        if (name === 'saml-missing-identifier') return res.json(await User.createOrGetSAMLUser(db, { email: '' }));
        if (name === 'saml-create-defaults') return res.json(await User.createOrGetSAMLUser(db, { samlId: 'new-saml', email: 'new@example.test' }));
        if (name === 'saml-existing-update') {
            return res.json(await User.createOrGetSAMLUser(db, {
                puid: 'puid-1',
                samlId: 'new-saml-id',
                email: 'updated@example.test',
                username: 'updated',
                displayName: 'Updated User',
                role: 'instructor',
            }));
        }
        if (name === 'saml-preserve-ta') {
            return res.json(await User.createOrGetSAMLUser(db, {
                puid: 'puid-1',
                email: 'ta@example.test',
                role: 'student',
            }));
        }
        if (name === 'update-and-deactivate-failures') {
            return res.json({
                preferences: await User.updateUserPreferences(db, 'missing', { theme: 'dark' }),
                deactivateMissing: await User.deactivateUser(db, 'missing'),
                deactivateFound: await User.deactivateUser(db, 'saml-existing'),
            });
        }
        res.status(404).json({ error: 'unknown user model case' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const authMiddleware = createAuthMiddleware(state.db);

app.all('/api/middleware/require-auth', applyRequestState, authMiddleware.requireAuth, (_req, res) => res.json({ ok: true }));
app.all('/api/middleware/require-instructor', applyRequestState, authMiddleware.requireRole('instructor'), (_req, res) => res.json({ ok: true }));
app.all('/api/middleware/require-instructor-or-ta', applyRequestState, authMiddleware.requireInstructorOrTA, (_req, res) => res.json({ ok: true }));
app.all('/api/middleware/require-system-admin', applyRequestState, authMiddleware.requireSystemAdmin, (_req, res) => res.json({ ok: true }));
app.all('/api/middleware/redirect-if-authenticated', applyRequestState, authMiddleware.redirectIfAuthenticated, (_req, res) => res.json({ ok: true }));
app.all('/api/middleware/require-course-context', applyRequestState, authMiddleware.requireCourseContext, (req, res) => res.json({ ok: true, courseId: req.courseId || null }));
app.all('/api/middleware/ta-permission', applyRequestState, authMiddleware.requireTAPermission('courses'), (_req, res) => res.json({ ok: true }));

app.use('/api/auth', applyRequestState, moduleRequire('../../../src/routes/auth'));
app.use('/', applyRequestState, moduleRequire('../../../src/routes/shibboleth'));
app.use('/api/questions', applyRequestState, moduleRequire('../../../src/routes/questions'));
app.use('/api/qdrant', applyRequestState, moduleRequire('../../../src/routes/qdrant'));
app.use('/api/chat', applyRequestState, moduleRequire('../../../src/routes/chat'));
app.use('/api/instructor/chat', applyRequestState, moduleRequire('../../../src/routes/instructorChat'));

const port = Number(process.env.SRC_HARNESS_PORT || 0);
const server = app.listen(port, '127.0.0.1', () => {
    const address = server.address();
    console.log(`[src-route-model-harness] listening on ${typeof address === 'object' && address ? address.port : port}`);
});

process.on('SIGTERM', () => {
    server.close(() => process.exit(0));
});
