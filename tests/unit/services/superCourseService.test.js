// Decouple from the heavy Qdrant/embeddings stack (and the config singleton it
// pulls in) so requiring superCourseService stays side-effect-free. None of the
// functions under test touch these.
jest.mock('../../../src/services/qdrantService', () =>
    jest.fn().mockImplementation(() => ({
        client: null,
        initialize: jest.fn().mockResolvedValue(undefined),
        searchDocumentsByCourse: jest.fn().mockResolvedValue(new Map()),
    }))
);
jest.mock('../../../src/services/notesQdrantService', () =>
    jest.fn().mockImplementation(() => ({
        initialize: jest.fn().mockResolvedValue(undefined),
        searchNotes: jest.fn().mockResolvedValue([]),
    }))
);
jest.mock('../../../src/models/SuperChatNote', () => ({
    incrementUsage: jest.fn().mockResolvedValue(undefined),
}));

const superCourse = require('../../../src/services/superCourseService');
const prompts = require('../../../src/services/prompts');
const QdrantService = require('../../../src/services/qdrantService');
const NotesQdrantService = require('../../../src/services/notesQdrantService');
const SuperChatNote = require('../../../src/models/SuperChatNote');
const { memoryDb } = require('../helpers/memory-db');

const DEFAULTS = prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS;

describe('superCourseService.resolveSuperCourseChatSettings', () => {
    test('an empty settings doc yields the documented defaults', () => {
        const s = superCourse.resolveSuperCourseChatSettings({});
        expect(s).toMatchObject({
            studentTopK: DEFAULTS.studentTopK,
            instructorTopK: DEFAULTS.instructorTopK,
            includeInactiveCourses: false,
            showStudentSuperCourse: false,
            includeNotesInRetrieval: true,
            noteRetrievalRatio: 0.25,
            noteMinScore: 0.25,
            instructorPrompt: DEFAULTS.instructorPrompt,
            studentPrompt: DEFAULTS.studentPrompt,
        });
    });

    test('topK values are validated, out-of-range falls back', () => {
        expect(superCourse.resolveSuperCourseChatSettings({ studentTopK: 5 }).studentTopK).toBe(5);
        expect(superCourse.resolveSuperCourseChatSettings({ studentTopK: 0 }).studentTopK).toBe(DEFAULTS.studentTopK);
        expect(superCourse.resolveSuperCourseChatSettings({ studentTopK: 99 }).studentTopK).toBe(DEFAULTS.studentTopK);
        expect(superCourse.resolveSuperCourseChatSettings({ instructorTopK: 12 }).instructorTopK).toBe(12);
    });

    test('boolean flags require a strict true', () => {
        expect(superCourse.resolveSuperCourseChatSettings({ includeInactiveCourses: true }).includeInactiveCourses).toBe(true);
        expect(superCourse.resolveSuperCourseChatSettings({ includeInactiveCourses: 'yes' }).includeInactiveCourses).toBe(false);
        expect(superCourse.resolveSuperCourseChatSettings({ showStudentSuperCourse: true }).showStudentSuperCourse).toBe(true);
    });

    test('includeNotesInRetrieval is on unless explicitly false', () => {
        expect(superCourse.resolveSuperCourseChatSettings({}).includeNotesInRetrieval).toBe(true);
        expect(superCourse.resolveSuperCourseChatSettings({ includeNotesInRetrieval: true }).includeNotesInRetrieval).toBe(true);
        expect(superCourse.resolveSuperCourseChatSettings({ includeNotesInRetrieval: false }).includeNotesInRetrieval).toBe(false);
    });

    test('note ratio/min-score validate to [0,1] and allow 0', () => {
        expect(superCourse.resolveSuperCourseChatSettings({ noteRetrievalRatio: 0.5 }).noteRetrievalRatio).toBe(0.5);
        expect(superCourse.resolveSuperCourseChatSettings({ noteRetrievalRatio: 0 }).noteRetrievalRatio).toBe(0);
        expect(superCourse.resolveSuperCourseChatSettings({ noteRetrievalRatio: 1.5 }).noteRetrievalRatio).toBe(0.25);
        expect(superCourse.resolveSuperCourseChatSettings({ noteMinScore: -1 }).noteMinScore).toBe(0.25);
        expect(superCourse.resolveSuperCourseChatSettings({ noteMinScore: 'x' }).noteMinScore).toBe(0.25);
    });

    test('prompts use a non-blank override or fall back to the default', () => {
        expect(superCourse.resolveSuperCourseChatSettings({ instructorPrompt: 'Custom IP' }).instructorPrompt).toBe('Custom IP');
        expect(superCourse.resolveSuperCourseChatSettings({ instructorPrompt: '   ' }).instructorPrompt).toBe(DEFAULTS.instructorPrompt);
        expect(superCourse.resolveSuperCourseChatSettings({ studentPrompt: 42 }).studentPrompt).toBe(DEFAULTS.studentPrompt);
    });

    test('level modifiers keep known keys, coerce non-strings, and drop extras', () => {
        const resolved = superCourse.resolveSuperCourseChatSettings({
            studentLevelModifiers: { intro: 'My intro', graduate: 123, bogus: 'drop me' },
        });
        expect(resolved.studentLevelModifiers.intro).toBe('My intro');
        expect(resolved.studentLevelModifiers.graduate).toBe(DEFAULTS.studentLevelModifiers.graduate);
        expect(resolved.studentLevelModifiers.undergraduate).toBe(DEFAULTS.studentLevelModifiers.undergraduate);
        expect(Object.keys(resolved.studentLevelModifiers)).toEqual(prompts.STUDENT_LEVEL_KEYS);
    });

    test('supports the no-argument defaults and valid student prompt/modifier overrides', () => {
        expect(superCourse.resolveSuperCourseChatSettings()).toMatchObject({
            studentPrompt: DEFAULTS.studentPrompt,
        });
        const resolved = superCourse.resolveSuperCourseChatSettings({
            studentPrompt: 'Custom student prompt',
            instructorLevelModifiers: { overview: 'Be terse' },
        });
        expect(resolved.studentPrompt).toBe('Custom student prompt');
        expect(resolved.instructorLevelModifiers.overview).toBe('Be terse');
    });
});

describe('superCourseService.buildSuperCoursePoolQuery', () => {
    test('a specific bucket filters by id and excludes inactive courses by default', () => {
        const query = superCourse.buildSuperCoursePoolQuery('bucket-1');
        expect(query.superchatIds).toBe('bucket-1');
        expect(query.status).toEqual({ $ne: 'deleted' });
        expect(query.$or).toEqual([
            { status: { $exists: false } },
            { status: null },
            { status: 'active' },
        ]);
    });

    test('no bucket id means "any bucket"; includeInactive drops the active-only $or', () => {
        const query = superCourse.buildSuperCoursePoolQuery(null, true);
        expect(query.superchatIds).toEqual({ $exists: true, $ne: [] });
        expect(query.$or).toBeUndefined();
    });
});

describe('superCourseService.mergeBalancedCourseResults', () => {
    test('returns [] when the map is empty', () => {
        expect(superCourse.mergeBalancedCourseResults(new Map(), 4)).toEqual([]);
    });

    test('front-loads one chunk per course before filling the rest by score', () => {
        const map = new Map([
            ['A', [{ id: 'a1', score: 0.9 }, { id: 'a2', score: 0.5 }]],
            ['B', [{ id: 'b1', score: 0.8 }, { id: 'b2', score: 0.4 }]],
        ]);
        // target 2, two courses -> floor 1: each course's top chunk is guaranteed.
        const merged = superCourse.mergeBalancedCourseResults(map, 2);
        expect(merged.map((m) => m.id)).toEqual(['a1', 'b1']);
    });

    test('dedupes shared ids and skips empty course lists', () => {
        const map = new Map([
            ['A', [{ id: 'shared', score: 0.9 }, { id: 'a2', score: 0.3 }]],
            ['B', [{ id: 'shared', score: 0.7 }]],
            ['C', []],
        ]);
        const merged = superCourse.mergeBalancedCourseResults(map, 5);
        const ids = merged.map((m) => m.id);
        expect(ids).toContain('shared');
        expect(ids).toContain('a2');
        expect(new Set(ids).size).toBe(ids.length); // no duplicates
    });

    test('uses zero for missing scores and enforces the target after guarantees', () => {
        const map = new Map([
            ['A', [{ id: 'a1' }, { id: 'a2', score: 0.2 }]],
            ['B', [{ id: 'b1', score: 0.4 }, { id: 'b2' }]],
        ]);
        expect(superCourse.mergeBalancedCourseResults(map, 3).map(item => item.id))
            .toEqual(['a1', 'b1', 'a2']);
    });

    test('handles missing scores on either side of the remainder comparator', () => {
        const map = new Map([
            ['A', [{ id: 'a1', score: 1 }, { id: 'a2' }, { id: 'a3', score: 0.2 }]],
            ['B', [{ id: 'b1', score: 1 }, { id: 'b2', score: 0.3 }, { id: 'b3' }]],
        ]);
        expect(superCourse.mergeBalancedCourseResults(map, 5).map(item => item.id))
            .toEqual(['a1', 'b1', 'a2', 'b2', 'a3']);

        const missingScoreFirst = new Map([
            ['A', [{ id: 'ga', score: 1 }, { id: 'missing' }]],
            ['B', [{ id: 'gb', score: 1 }, { id: 'scored', score: 0.5 }]],
        ]);
        expect(superCourse.mergeBalancedCourseResults(missingScoreFirst, 3).map(item => item.id))
            .toEqual(['ga', 'gb', 'scored']);
    });
});

describe('superCourseService.searchSuperCourse', () => {
    const poolDb = () => memoryDb({
        courses: [
            { courseId: 'C1', courseName: 'One', status: 'active', superchatIds: ['b1'] },
            { courseId: 'C2', courseName: 'Two', status: 'active', superchatIds: ['b1'] },
        ],
    });

    beforeEach(() => {
        jest.clearAllMocks();
        QdrantService.mockImplementation(() => ({
            client: null,
            initialize: jest.fn().mockResolvedValue(undefined),
            searchDocumentsByCourse: jest.fn().mockResolvedValue(new Map()),
        }));
        NotesQdrantService.mockImplementation(() => ({
            initialize: jest.fn().mockResolvedValue(undefined),
            searchNotes: jest.fn().mockResolvedValue([]),
        }));
        SuperChatNote.incrementUsage.mockResolvedValue(undefined);
    });

    test('initializes lecture retrieval, balances courses, and tags results', async () => {
        const instance = {
            client: null,
            initialize: jest.fn().mockResolvedValue(undefined),
            searchDocumentsByCourse: jest.fn().mockResolvedValue(new Map([
                ['C1', [{ id: 'a', score: 0.9, courseId: 'C1' }]],
                ['C2', [{ id: 'b', score: 0.8, courseId: 'C2' }]],
            ])),
        };
        QdrantService.mockImplementationOnce(() => instance);

        const found = await superCourse.searchSuperCourse(poolDb(), 'ATP', 2, { superchatId: 'b1' });

        expect(instance.initialize).toHaveBeenCalledTimes(1);
        expect(instance.searchDocumentsByCourse).toHaveBeenCalledWith('ATP', ['C1', 'C2'], 2);
        expect(found.results.map(result => result.sourceType)).toEqual(['lecture', 'lecture']);
    });

    test('supports default search options with an empty retrieval pool', async () => {
        await expect(superCourse.searchSuperCourse(memoryDb({}), 'ATP', 3))
            .resolves.toEqual({ pool: [], results: [] });
    });

    test('uses an injected initialized Qdrant service and defaults an invalid limit to eight', async () => {
        const qdrant = {
            client: {},
            initialize: jest.fn(),
            searchDocumentsByCourse: jest.fn().mockResolvedValue(new Map()),
        };
        await superCourse.searchSuperCourse(poolDb(), 'ATP', 0, { superchatId: 'b1', qdrant });
        expect(qdrant.initialize).not.toHaveBeenCalled();
        expect(qdrant.searchDocumentsByCourse).toHaveBeenCalledWith('ATP', ['C1', 'C2'], 8);
    });

    test('allocates note slots, initializes from injected Qdrant, and donates unused slots to lectures', async () => {
        const qdrant = {
            client: {},
            searchDocumentsByCourse: jest.fn().mockResolvedValue(new Map([
                ['C1', [1, 2, 3, 4].map(n => ({ id: `l${n}`, score: 1 - n / 10, courseId: 'C1' }))],
            ])),
        };
        const notes = {
            initialize: jest.fn().mockResolvedValue(undefined),
            searchNotes: jest.fn().mockResolvedValue([{ id: 'n1', noteId: 'note-1', sourceType: 'note', score: 0.9 }]),
        };
        NotesQdrantService.mockImplementationOnce(() => notes);

        const found = await superCourse.searchSuperCourse(poolDb(), 'ATP', 4, {
            superchatId: 'b1', includeNotes: true, noteRatio: 0.5, noteMinScore: 0.4, qdrant,
        });

        expect(notes.initialize).toHaveBeenCalledWith(qdrant);
        expect(notes.searchNotes).toHaveBeenCalledWith('ATP', 2, { minScore: 0.4 });
        expect(found.results.filter(result => result.sourceType === 'lecture')).toHaveLength(3);
        expect(found.results.at(-1)).toMatchObject({ sourceType: 'note', noteId: 'note-1' });
        expect(SuperChatNote.incrementUsage).toHaveBeenCalledWith(expect.anything(), ['note-1']);
    });

    test('caps over-returned notes and always preserves a lecture slot', async () => {
        const qdrant = {
            client: {},
            searchDocumentsByCourse: jest.fn().mockResolvedValue(new Map([
                ['C1', [{ id: 'lecture', score: 1, courseId: 'C1' }]],
            ])),
        };
        const notes = {
            initialize: jest.fn(),
            searchNotes: jest.fn().mockResolvedValue([
                { noteId: 'n1', sourceType: 'note' },
                { noteId: 'n2', sourceType: 'note' },
                { noteId: 'n3', sourceType: 'note' },
            ]),
        };
        NotesQdrantService.mockImplementationOnce(() => notes);

        const found = await superCourse.searchSuperCourse(poolDb(), 'ATP', 2, {
            superchatId: 'b1', includeNotes: true, noteRatio: 1, qdrant,
        });
        expect(found.results).toHaveLength(2);
        expect(found.results[0].sourceType).toBe('lecture');
        expect(found.results[1].noteId).toBe('n1');
    });

    test('treats malformed notes as empty and does not count notes without IDs', async () => {
        const notes = { initialize: jest.fn(), searchNotes: jest.fn().mockResolvedValue(null) };
        NotesQdrantService.mockImplementationOnce(() => notes);
        await expect(superCourse.searchSuperCourse(memoryDb({}), 'ATP', 4, {
            includeNotes: true, noteRatio: 1,
        })).resolves.toMatchObject({ pool: [], results: [] });

        notes.searchNotes.mockResolvedValueOnce([{ sourceType: 'note', chunkText: 'anonymous' }]);
        NotesQdrantService.mockImplementationOnce(() => notes);
        await superCourse.searchSuperCourse(memoryDb({}), 'ATP', 4, { includeNotes: true, noteRatio: 1 });
        expect(SuperChatNote.incrementUsage).not.toHaveBeenCalled();
    });

    test('degrades gracefully on ordinary note errors but propagates LlmKeyError', async () => {
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        const notes = { initialize: jest.fn(), searchNotes: jest.fn().mockRejectedValue(new Error('notes down')) };
        NotesQdrantService.mockImplementationOnce(() => notes);
        await expect(superCourse.searchSuperCourse(memoryDb({}), 'ATP', 4, {
            includeNotes: true, noteRatio: 0.5,
        })).resolves.toMatchObject({ results: [] });
        expect(errorSpy).toHaveBeenCalledWith('Super Course note retrieval failed:', 'notes down');

        const keyError = Object.assign(new Error('missing key'), { name: 'LlmKeyError' });
        notes.searchNotes.mockRejectedValueOnce(keyError);
        NotesQdrantService.mockImplementationOnce(() => notes);
        await expect(superCourse.searchSuperCourse(memoryDb({}), 'ATP', 4, {
            includeNotes: true, noteRatio: 0.5,
        })).rejects.toBe(keyError);
        errorSpy.mockRestore();
    });

    test('logs a rejected fire-and-forget usage update without failing retrieval', async () => {
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        const notes = {
            initialize: jest.fn(),
            searchNotes: jest.fn().mockResolvedValue([{ noteId: 'n1', sourceType: 'note' }]),
        };
        NotesQdrantService.mockImplementationOnce(() => notes);
        SuperChatNote.incrementUsage.mockRejectedValueOnce(new Error('write failed'));

        const found = await superCourse.searchSuperCourse(memoryDb({}), 'ATP', 4, {
            includeNotes: true, noteRatio: 1,
        });
        await Promise.resolve();
        expect(found.results).toHaveLength(1);
        expect(errorSpy).toHaveBeenCalledWith('Failed to increment note usage:', 'write failed');
        errorSpy.mockRestore();
    });
});

describe('superCourseService context/summary builders', () => {
    const pool = [
        { courseId: 'C1', courseName: 'Course One' },
        { courseId: 'C2', courseCode: 'CC2' },
    ];

    test('buildSuperCourseContext renders lecture and note sources', () => {
        const context = superCourse.buildSuperCourseContext([
            { sourceType: 'lecture', courseId: 'C1', lectureName: 'Unit 2', fileName: 'f.pdf', chunkText: 'LEC' },
            { sourceType: 'note', authorName: 'Dr X', chunkText: 'NOTE' },
        ], pool);
        expect(context).toContain('From Course One / Unit 2 (f.pdf):\nLEC');
        expect(context).toContain('From an instructor note by Dr X');
        expect(context).toContain('NOTE');
        expect(context).toContain('\n\n---\n\n');
    });

    test('buildSuperCourseContext formats valid note dates and uses safe source fallbacks', () => {
        expect(superCourse.buildSuperCourseContext()).toBe('');
        const context = superCourse.buildSuperCourseContext([
            { sourceType: 'note', createdAt: '2026-06-15T12:00:00Z', chunkText: '' },
            { sourceType: 'note', createdAt: 'not-a-date' },
            { sourceType: 'lecture' },
        ]);
        expect(context).toContain('From an instructor note by an instructor (2026-06-15)');
        expect(context).toContain('From an instructor note by an instructor:\n');
        expect(context).toContain('From Unknown course / Unknown unit (Unknown source):');
    });

    test('buildSuperCoursePoolSummary lists courses or a no-courses message', () => {
        expect(superCourse.buildSuperCoursePoolSummary()).toMatch(/No courses are currently included/);
        expect(superCourse.buildSuperCoursePoolSummary(pool)).toBe('Course One (C1); CC2 (C2)');
        expect(superCourse.buildSuperCoursePoolSummary([{ courseId: 'C3' }])).toBe('C3 (C3)');
    });

    test('buildSuperCourseCitations tags lecture vs note citations', () => {
        const citations = superCourse.buildSuperCourseCitations([
            { sourceType: 'lecture', courseId: 'C1', lectureName: 'Unit 2', fileName: 'f.pdf', documentId: 'd1', score: 0.9 },
            { sourceType: 'note', noteId: 'n1', authorName: 'Dr X', score: 0.7 },
        ], pool);
        expect(citations[0]).toMatchObject({ sourceType: 'lecture', courseName: 'Course One', lectureName: 'Unit 2' });
        expect(citations[1]).toMatchObject({ sourceType: 'note', noteId: 'n1' });
        expect(citations[1].label).toContain('Note by Dr X');
    });

    test('buildSuperCourseCitations exposes stable null/default fields for sparse inputs', () => {
        expect(superCourse.buildSuperCourseCitations()).toEqual([]);
        const citations = superCourse.buildSuperCourseCitations([
            { sourceType: 'note', createdAt: '2026-06-15T12:00:00Z' },
            { sourceType: 'lecture' },
            { sourceType: 'lecture', courseId: 'raw-id', documentType: 'pdf' },
        ]);
        expect(citations[0]).toMatchObject({
            noteId: null, authorName: null, title: null, label: 'Note by instructor, 2026-06-15',
        });
        expect(citations[1]).toMatchObject({
            courseId: null, courseName: null, lectureName: null, fileName: null, documentId: null,
        });
        expect(citations[2].courseName).toBe('raw-id');
    });

    test('buildSuperCourseSourceAttribution distinguishes empty vs retrieved results', () => {
        const empty = superCourse.buildSuperCourseSourceAttribution([], pool);
        expect(empty.source).toBe('general-biochemistry');
        expect(empty.documents).toEqual([]);
        expect(empty.poolCourses).toHaveLength(2);

        const withResults = superCourse.buildSuperCourseSourceAttribution([
            { sourceType: 'lecture', courseId: 'C1', lectureName: 'Unit 2', documentId: 'd1', fileName: 'f.pdf', score: 0.9 },
            { sourceType: 'lecture', courseId: 'C1', lectureName: 'Unit 2', documentId: 'd1', fileName: 'f.pdf', score: 0.8 }, // dup documentId
        ], pool);
        expect(withResults.source).toBe('super-course');
        expect(withResults.documents).toHaveLength(1); // deduped by documentId
        expect(withResults.description).toContain('From:');
    });

    test('buildSuperCourseSourceAttribution includes and deduplicates instructor notes', () => {
        const attributed = superCourse.buildSuperCourseSourceAttribution([
            { sourceType: 'note', id: 'raw-1', authorName: 'Dr X', title: 'Review', createdAt: '2026-06-15T12:00:00Z', score: 0.8 },
            { sourceType: 'note', id: 'raw-1', authorName: 'Duplicate' },
            { sourceType: 'note', noteId: 'n2', score: 0.4 },
        ]);
        expect(attributed.documents).toHaveLength(2);
        expect(attributed.documents[0]).toMatchObject({
            sourceType: 'note', courseName: 'Note by Dr X', unitName: '2026-06-15',
            noteId: null, fileName: 'Review', documentType: 'note',
        });
        expect(attributed.documents[1]).toMatchObject({
            courseName: 'Note by instructor', unitName: 'Instructor note', noteId: 'n2', fileName: null,
        });
        expect(attributed.description).toContain('Note by Dr X / 2026-06-15');
    });

    test('buildSuperCourseSourceAttribution supports defaults and sparse lecture fallbacks', () => {
        expect(superCourse.buildSuperCourseSourceAttribution()).toMatchObject({
            source: 'general-biochemistry',
            description: 'No courses are currently included in the Super Course source pool',
        });
        const attributed = superCourse.buildSuperCourseSourceAttribution([
            { sourceType: 'lecture', courseId: 'raw', lectureName: 'U', fileName: 'f', type: 'slides' },
            { sourceType: 'lecture' },
            { sourceType: 'lecture' },
        ]);
        expect(attributed.documents).toHaveLength(2);
        expect(attributed.documents[0]).toMatchObject({
            courseName: 'raw', documentId: null, documentType: 'slides',
        });
        expect(attributed.documents[1]).toMatchObject({
            courseId: null, courseName: null, unitName: null, documentId: null,
            fileName: null, documentType: null,
        });
        expect(attributed.description).toContain('Course');

        const poolFallback = superCourse.buildSuperCourseSourceAttribution(
            [{ sourceType: 'lecture', courseId: 'C9' }],
            [{ courseId: 'C9' }]
        );
        expect(poolFallback.poolCourses[0].courseName).toBe('C9');
    });
});

describe('superCourseService.getEnrolledCourseIds', () => {
    function seededDb() {
        return memoryDb({
            courses: [
                { courseId: 'C1', status: 'active', studentEnrollment: { S1: { enrolled: true } } },
                { courseId: 'C2', status: 'active', studentEnrollment: { S1: { enrolled: false } } },     // banned
                { courseId: 'C3', status: 'deleted', studentEnrollment: { S1: { enrolled: true } } },     // deleted
                { courseId: 'C4', status: 'active', studentEnrollment: { S2: { enrolled: true } } },      // other student
                { courseId: 'C6', studentEnrollment: { S1: { enrolled: true } } },                       // no status -> active
            ],
        });
    }

    test('returns [] for a missing db or student id', async () => {
        await expect(superCourse.getEnrolledCourseIds(null, 'S1')).resolves.toEqual([]);
        await expect(superCourse.getEnrolledCourseIds(seededDb(), '')).resolves.toEqual([]);
    });

    test('returns only the actively-enrolled, non-deleted courses for the student', async () => {
        const ids = await superCourse.getEnrolledCourseIds(seededDb(), 'S1');
        expect(ids.sort()).toEqual(['C1', 'C6']);
    });
});

describe('superCourseService.getStudentAccessibleSuperchatIds', () => {
    function seededDb() {
        return memoryDb({
            courses: [
                { courseId: 'C1', status: 'active', studentEnrollment: { S1: { enrolled: true } }, superchatIds: ['b1', 'b2'] },
                { courseId: 'C6', studentEnrollment: { S1: { enrolled: true } }, superchatIds: ['b2', 'b3', ' b3 '] },
                { courseId: 'C2', status: 'active', studentEnrollment: { S1: { enrolled: false } }, superchatIds: ['bX'] }, // banned
            ],
        });
    }

    test('unions superchatIds across enrolled courses, deduped and trimmed', async () => {
        const ids = await superCourse.getStudentAccessibleSuperchatIds(seededDb(), 'S1');
        expect([...ids].sort()).toEqual(['b1', 'b2', 'b3']);
    });

    test('returns an empty set when the student has no enrolled courses', async () => {
        const ids = await superCourse.getStudentAccessibleSuperchatIds(seededDb(), 'NOBODY');
        expect(ids.size).toBe(0);
    });
});

describe('superCourseService.getSuperCourseRetrievalPool', () => {
    function seededDb() {
        return memoryDb({
            courses: [
                { courseId: 'C1', courseName: 'Alpha', status: 'active', superchatIds: ['b1'], approvedStruggleTopics: ['Glycolysis', 'glycolysis', 'Krebs'] },
                { courseId: 'C2', courseName: 'Beta', status: 'inactive', superchatIds: ['b1'], approvedStruggleTopics: [] },
                { courseId: 'C3', courseName: 'Gamma', status: 'deleted', superchatIds: ['b1'] },
                { courseId: 'C4', courseName: 'Delta', superchatIds: ['b2'] },
            ],
        });
    }

    test('a bucket pool excludes inactive/deleted/other-bucket courses by default', async () => {
        const pool = await superCourse.getSuperCourseRetrievalPool(seededDb(), { superchatId: 'b1' });
        expect(pool.map((c) => c.courseId)).toEqual(['C1']);
    });

    test('includeInactiveCourses keeps inactive (but never deleted) courses, sorted by name', async () => {
        const pool = await superCourse.getSuperCourseRetrievalPool(seededDb(), { superchatId: 'b1', includeInactiveCourses: true });
        expect(pool.map((c) => c.courseId)).toEqual(['C1', 'C2']); // Alpha, Beta
    });

    test('getSuperCourseApprovedTopics normalizes topics and drops topic-less courses', async () => {
        const topics = await superCourse.getSuperCourseApprovedTopics(seededDb(), { superchatId: 'b1', includeInactiveCourses: true });
        expect(topics).toEqual([
            { courseId: 'C1', courseName: 'Alpha', approvedTopics: ['Glycolysis', 'Krebs'] },
        ]);
    });

    test('pool/topic helpers support default options and course-name fallbacks', async () => {
        const db = memoryDb({ courses: [
            { courseId: 'C1', courseCode: 'CODE', status: 'active', superchatIds: ['b1'], approvedStruggleTopics: ['A'] },
            { courseId: 'C2', status: 'active', superchatIds: ['b1'], approvedStruggleTopics: ['B'] },
            { courseId: 'C3', status: 'active', superchatIds: ['b1'] },
            { courseId: '', status: 'active', superchatIds: ['b1'] },
        ] });
        await expect(superCourse.getSuperCourseRetrievalPool(db)).resolves.toHaveLength(3);
        await expect(superCourse.getSuperCourseApprovedTopics(db)).resolves.toEqual([
            { courseId: 'C1', courseName: 'CODE', approvedTopics: ['A'] },
            { courseId: 'C2', courseName: 'C2', approvedTopics: ['B'] },
        ]);
    });
});

describe('superCourseService settings/bucket resolution', () => {
    test('getSuperCourseChatSettings resolves the stored settings doc', async () => {
        const db = memoryDb({ settings: [{ _id: 'superCourseChat', studentTopK: 5 }] });
        const settings = await superCourse.getSuperCourseChatSettings(db);
        expect(settings.studentTopK).toBe(5);
        expect(settings.instructorTopK).toBe(DEFAULTS.instructorTopK); // untouched -> default
    });

    test('getSuperCourseChatSettings uses defaults when the settings doc is absent', async () => {
        await expect(superCourse.getSuperCourseChatSettings(memoryDb({})))
            .resolves.toMatchObject({ studentTopK: DEFAULTS.studentTopK });
    });

    test('getInstructorSuperCourseChat reports key availability and never shows students', async () => {
        const db = memoryDb({
            settings: [{ _id: 'superCourseChat', llmApiKey: { status: 'valid', last4: '1234' }, studentTopK: 6 }],
        });
        const chat = await superCourse.getInstructorSuperCourseChat(db);
        expect(chat).toMatchObject({ superchatId: null, name: 'Instructor Super Course', showToStudents: false, aiAvailable: true });
        expect(chat.llmKey.status).toBe('valid');
        expect(chat.settings.studentTopK).toBe(6);
    });

    test('getInstructorSuperCourseChat with no settings doc is unavailable with defaults', async () => {
        const chat = await superCourse.getInstructorSuperCourseChat(memoryDb({}));
        expect(chat.aiAvailable).toBe(false);
        expect(chat.settings.studentTopK).toBe(DEFAULTS.studentTopK);
    });

    test('getSuperchat resolves a bucket and returns null for missing/deleted', async () => {
        const db = memoryDb({
            superchats: [
                { superchatId: 'b1', name: 'Year 2', description: 'desc', yearLevel: 2, showToStudents: true, llmApiKey: { status: 'valid' }, studentTopK: 5, isDeleted: false },
                { superchatId: 'b9', name: 'Gone', isDeleted: true },
            ],
        });
        const bucket = await superCourse.getSuperchat(db, 'b1');
        expect(bucket).toMatchObject({ superchatId: 'b1', name: 'Year 2', yearLevel: 2, showToStudents: true, aiAvailable: true });
        expect(bucket.settings.studentTopK).toBe(5);

        await expect(superCourse.getSuperchat(db, 'missing')).resolves.toBeNull();
        await expect(superCourse.getSuperchat(db, 'b9')).resolves.toBeNull(); // soft-deleted
    });

    test('getSuperchat normalizes missing optional metadata', async () => {
        const db = memoryDb({ superchats: [{ superchatId: 'b1', name: 'Sparse', isDeleted: false }] });
        await expect(superCourse.getSuperchat(db, 'b1')).resolves.toMatchObject({
            description: '', yearLevel: null, showToStudents: false, aiAvailable: false,
        });
    });

    test('listSuperchats can filter to student-visible buckets', async () => {
        const db = memoryDb({
            superchats: [
                { superchatId: 'b1', name: 'A', yearLevel: 1, showToStudents: true, isDeleted: false },
                { superchatId: 'b2', name: 'B', yearLevel: 2, showToStudents: false, isDeleted: false },
                { superchatId: 'b3', name: 'C', yearLevel: 3, isDeleted: true },
            ],
        });
        const all = await superCourse.listSuperchats(db);
        expect(all.map((b) => b.superchatId)).toEqual(['b1', 'b2']); // deleted excluded, year-ordered

        const visible = await superCourse.listSuperchats(db, { studentVisibleOnly: true });
        expect(visible.map((b) => b.superchatId)).toEqual(['b1']);
    });

    test('listSuperchats normalizes missing summary metadata', async () => {
        const db = memoryDb({ superchats: [{ superchatId: 'b1', name: 'Sparse', isDeleted: false }] });
        await expect(superCourse.listSuperchats(db)).resolves.toEqual([
            expect.objectContaining({ description: '', yearLevel: null, showToStudents: false, aiAvailable: false }),
        ]);
    });
});
