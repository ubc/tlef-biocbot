// @ts-check
/**
 * Minimal Express harness for src/routes/quiz.js error-path coverage.
 *
 * The production server always wires up app.locals.db + app.locals.llm and
 * always mounts auth middleware before /api/quiz, which makes the route file's
 * "missing-dependency" 503s, its top-level try/catch blocks, and the
 * "unauthenticated" branches unreachable from the live e2e server. This
 * harness mounts the real router with controllable dependencies and stubbable
 * model methods so each spec test can dial in the exact failure it wants.
 *
 * The harness is spawned as a child of the Playwright test runner with the
 * same NODE_V8_COVERAGE directory as the main webServer, so its branch
 * coverage gets merged into the monocart report by the existing global
 * teardown.
 */

const express = require('express');
const v8 = require('v8');

const CourseModel = require('../../../src/models/Course');
const QuizAttempt = require('../../../src/models/QuizAttempt');
const DocumentModel = require('../../../src/models/Document');
const QdrantService = require('../../../src/services/qdrantService');

const quizRoutes = require('../../../src/routes/quiz');

// Snapshot pristine method bindings so `/__reset` can restore them after a
// test that monkey-patches a model or a prototype method.
const ORIGINAL = {
    Course: { ...CourseModel },
    QuizAttempt: { ...QuizAttempt },
    Document: { ...DocumentModel },
    QdrantInitialize: QdrantService.prototype.initialize,
    QdrantSearchDocuments: QdrantService.prototype.searchDocuments,
};

function restoreOriginals() {
    Object.assign(CourseModel, ORIGINAL.Course);
    Object.assign(QuizAttempt, ORIGINAL.QuizAttempt);
    Object.assign(DocumentModel, ORIGINAL.Document);
    QdrantService.prototype.initialize = ORIGINAL.QdrantInitialize;
    QdrantService.prototype.searchDocuments = ORIGINAL.QdrantSearchDocuments;
}

function freshState() {
    return {
        db: {
            // Permissive default so non-error paths can pass through. The
            // tests that want a specific failure swap this out via applyMode.
            collection: () => ({ findOne: async () => null }),
        },
        llm: {
            evaluateStudentAnswer: async () => ({ correct: false, feedback: 'stub' }),
            sendMessage: async () => ({ content: 'stub llm reply' }),
        },
        user: { userId: 'harness-student' },
    };
}

let state = freshState();

function applyMode(mode) {
    restoreOriginals();
    state = freshState();

    switch (mode) {
        case '':
        case 'reset':
            return;
        case 'no-db':
            state.db = null;
            return;
        case 'no-llm':
            state.llm = null;
            return;
        case 'no-auth':
            state.user = null;
            return;
        case 'throw-getQuizSettings':
            CourseModel.getQuizSettings = async () => {
                throw new Error('harness: getQuizSettings');
            };
            return;
        case 'throw-getAssessmentQuestions':
            // /check-answer now goes through the visibility gate before reaching
            // getAssessmentQuestions, so we have to stub the gate as enabled.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            CourseModel.getPublishedLectures = async () => ['U'];
            CourseModel.getAssessmentQuestions = async () => {
                throw new Error('harness: getAssessmentQuestions');
            };
            return;
        case 'throw-saveAttempt':
            // /attempt now runs the same visibility gate as /check-answer and
            // cross-checks the submitted `correct` flag against the stored
            // answer, so the stubbed question must match the test's request:
            // questionId 'q', lectureName 'U', MCQ correctAnswer 'A' (matching
            // studentAnswer 'A' so the gate accepts the attempt).
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            CourseModel.getPublishedLectures = async () => ['U'];
            CourseModel.getAssessmentQuestions = async () => [{
                questionId: 'q',
                questionType: 'multiple-choice',
                question: 'stub',
                correctAnswer: 'A',
                isActive: true,
            }];
            QuizAttempt.saveAttempt = async () => {
                throw new Error('harness: saveAttempt');
            };
            return;
        case 'throw-getAttemptStats':
            QuizAttempt.getAttemptStats = async () => {
                throw new Error('harness: getAttemptStats');
            };
            return;
        case 'throw-getDocumentsForLecture':
            // Allow access first so we reach the throw site.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            DocumentModel.getDocumentsForLecture = async () => {
                throw new Error('harness: getDocumentsForLecture');
            };
            return;
        case 'throw-getDocumentById':
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            DocumentModel.getDocumentById = async () => {
                throw new Error('harness: getDocumentById');
            };
            return;
        case 'check-answer-sa-no-llm':
            // /check-answer's visibility gate runs before the LLM branch, so the
            // course must look quiz-enabled and the lecture must be published &
            // testable for the route to even reach the SA LLM call.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            CourseModel.getPublishedLectures = async () => ['U'];
            CourseModel.getAssessmentQuestions = async () => [{
                questionId: 'q-test-sa',
                questionType: 'short-answer',
                question: 'Stub short-answer',
                correctAnswer: 'Stub correct answer',
                isActive: true,
            }];
            state.llm = null;
            return;
        case 'chat-throw-courses-findOne':
            state.db = {
                collection: () => ({
                    findOne: async () => {
                        throw new Error('harness: courses.findOne');
                    },
                }),
            };
            return;
        case 'chat-llm-empty-response':
            // No `.content` on the response → routes through the fallback branch.
            state.llm = /** @type {any} */ ({
                sendMessage: async () => ({}),
            });
            return;
        case 'chat-qdrant-returns-results':
            // Skip the real LLM-config-driven Qdrant init and feed canned hits
            // so the "searchResults && length > 0" branch + the .map() arrow
            // function in /chat are exercised.
            QdrantService.prototype.initialize = async function () { /* no-op */ };
            QdrantService.prototype.searchDocuments = async function () {
                return [
                    { lectureName: 'Unit 1', fileName: 'notes.pdf',          chunkText: 'ATP is the cell\'s energy currency.' },
                    { lectureName: 'Unit 1', fileName: 'lecture-slides.pdf', chunkText: 'Energy carriers include ATP and GTP.' },
                ];
            };
            return;
        case 'questions-missing-optional-fields':
            // Exercise the `q.options || {}` / `q.difficulty || 'medium'` /
            // `q.tags || []` / `q.points || 1` defaults in /questions plus
            // the `lecture?.displayName || name` fallback in the units map.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            CourseModel.getPublishedLectures = async () => ['Unit X'];
            CourseModel.getCourseWithOnboarding = async () => ({
                courseId: 'BIOC-1',
                lectures: [{ name: 'Unit X' /* no displayName */ }],
            });
            CourseModel.getAssessmentQuestions = async () => [{
                questionId: 'q-minimal',
                questionType: 'multiple-choice',
                question: 'Bare-bones question — no options/difficulty/tags/points.',
                // intentionally no `options`, `difficulty`, `tags`, `points`
                isActive: true,
            }];
            return;
        case 'check-answer-sa-default-studentname':
            // SA question + stubbed LLM that records the studentName it was
            // called with → exercises the `studentName || 'Student'` default.
            CourseModel.getAssessmentQuestions = async () => [{
                questionId: 'q-test-sa',
                questionType: 'short-answer',
                question: 'Stub Q',
                correctAnswer: 'Stub correct answer',
            }];
            state.llm = {
                evaluateStudentAnswer: async (_q, _sa, _ca, _qt, studentName) => ({
                    correct: false,
                    feedback: `studentName=${studentName}`,
                }),
                sendMessage: async () => ({ content: '' }),
            };
            return;
        case 'download-no-name-no-filename':
            // Exercises resolveDownloadFilename's `|| fallbackName` branch
            // (both originalName and filename empty) and the trailing
            // `safeName || \`${fallbackName}.txt\`` fallback.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            DocumentModel.getDocumentById = async () => ({
                documentId: 'doc-anon',
                courseId: 'BIOC-1',
                contentType: 'text',
                content: 'anonymous content',
                // no originalName, no filename, no mimeType
            });
            return;
        case 'download-text-no-mimetype':
            // Text branch with no mimeType → exercises the
            // `${document.mimeType || 'text/plain'}; charset=utf-8` fallback.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            DocumentModel.getDocumentById = async () => ({
                documentId: 'doc-text-no-mime',
                courseId: 'BIOC-1',
                contentType: 'text',
                content: '', // empty string → typeof check passes
                originalName: 'notes.txt',
                // no mimeType
            });
            return;
        case 'download-file-no-mimetype':
            // File branch with no mimeType → exercises the
            // `document.mimeType || 'application/octet-stream'` fallback.
            CourseModel.getQuizSettings = async () => ({
                enabled: true,
                testableUnits: 'all',
                allowLectureMaterialAccess: true,
            });
            DocumentModel.getDocumentById = async () => ({
                documentId: 'doc-file-no-mime',
                courseId: 'BIOC-1',
                contentType: 'file',
                fileData: Buffer.from([0x01, 0x02, 0x03]),
                originalName: 'binary.dat',
                // no mimeType
            });
            return;
        case 'chat-prompts-partial-base':
            // course.prompts present but `.base` is falsy → the
            // `if (course.prompts.base)` branch's "not-taken" path is hit.
            state.db = {
                collection: () => ({
                    findOne: async () => ({
                        courseId: 'BIOC-1',
                        prompts: { quizHelp: 'override quiz help only' /* no base */ },
                    }),
                }),
            };
            return;
        case 'chat-prompts-partial-quizhelp':
            // course.prompts present but `.quizHelp` is falsy → exercises the
            // not-taken path of the quizHelp override branch.
            state.db = {
                collection: () => ({
                    findOne: async () => ({
                        courseId: 'BIOC-1',
                        prompts: { base: 'override base only' /* no quizHelp */ },
                    }),
                }),
            };
            return;
        case 'chat-correctanswer-lookup-fields-missing':
            // Drive every fallback in the short-answer correctAnswer DB lookup
            // (course with no lectures match / lecture with no assessmentQuestions /
            // assessmentQuestion not matching by question text).
            state.db = {
                collection: () => ({
                    findOne: async () => ({
                        courseId: 'BIOC-1',
                        lectures: [
                            { name: 'OtherUnit', assessmentQuestions: [{ question: 'no match' }] },
                            { name: 'TargetUnit' /* no assessmentQuestions */ },
                        ],
                    }),
                }),
            };
            return;
        default:
            return;
    }
}

const app = express();
app.use(express.json());

app.get('/__ping', (_req, res) => res.json({ ok: true }));

app.post('/__configure', (req, res) => {
    const mode = String((req.body && req.body.mode) || '');
    applyMode(mode);
    res.json({ ok: true, mode });
});

app.post('/__reset', (_req, res) => {
    applyMode('');
    res.json({ ok: true });
});

// Per-request injection of the active state into app.locals + req.user. The
// router reads from req.app.locals.db and req.app.locals.llm; this middleware
// is what makes those reads return our test-controlled values.
app.use((req, _res, next) => {
    if (state.db === null) {
        delete req.app.locals.db;
    } else {
        req.app.locals.db = state.db;
    }
    if (state.llm === null) {
        delete req.app.locals.llm;
    } else {
        req.app.locals.llm = state.llm;
    }
    req.user = state.user;
    next();
});

app.use('/api/quiz', quizRoutes);

const port = Number(process.env.QUIZ_HARNESS_PORT);
const server = app.listen(port, () => {
    console.log(`[quiz-harness] listening on ${port}`);
});

// Explicit coverage flush before exit. v8.takeCoverage() writes a JSON file
// into NODE_V8_COVERAGE on demand; the existing global-teardown picks it up.
// We intentionally avoid the v8-coverage-hook here because that hook would
// overwrite server-info.json and steer the teardown signal away from the
// main webServer.
function shutdown() {
    try { v8.takeCoverage(); } catch { /* coverage disabled */ }
    try { server.close(); } catch { /* already closed */ }
    setTimeout(() => process.exit(0), 100).unref();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
