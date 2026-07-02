/**
 * Unit tests for the PURE (synchronous, no-DB) exported helpers of
 * src/models/Course.js. DB-backed helpers live in Course.db.test.js.
 *
 * Only exported functions are tested (per unit_tests.md: test real exports,
 * don't add internal helpers to module.exports just to reach them). Internal
 * helpers like normalizeTopicLabel / getTopicLabel / normalizeCode are exercised
 * indirectly through the exported functions that call them.
 */
const Course = require('../../../src/models/Course');

describe('Course constants', () => {
    test('expose the documented year-level and RAG bounds', () => {
        expect(Course.MIN_YEAR_LEVEL).toBe(1);
        expect(Course.MAX_YEAR_LEVEL).toBe(5);
        expect(Course.DEFAULT_STUDENT_RAG_TOP_K).toBe(3);
        expect(Course.MIN_RAG_TOP_K).toBe(1);
        expect(Course.MAX_RAG_TOP_K).toBe(20);
    });
});

describe('Course.normalizeYearLevel', () => {
    test('accepts integers within 1..5 inclusive', () => {
        expect(Course.normalizeYearLevel(1)).toBe(1);
        expect(Course.normalizeYearLevel(5)).toBe(5);
        expect(Course.normalizeYearLevel(3)).toBe(3);
    });

    test('coerces numeric strings via Number()', () => {
        expect(Course.normalizeYearLevel('4')).toBe(4);
    });

    test('returns null outside the range or for non-integers', () => {
        expect(Course.normalizeYearLevel(0)).toBeNull();
        expect(Course.normalizeYearLevel(6)).toBeNull();
        expect(Course.normalizeYearLevel(2.5)).toBeNull();
        expect(Course.normalizeYearLevel('abc')).toBeNull();
        expect(Course.normalizeYearLevel(null)).toBeNull();
        expect(Course.normalizeYearLevel(undefined)).toBeNull();
        expect(Course.normalizeYearLevel('')).toBeNull();
    });

    // Characterizes Number() coercion: true -> 1 (in range). Not "fixed" here.
    test('coerces boolean true to 1 (Number(true) === 1)', () => {
        expect(Course.normalizeYearLevel(true)).toBe(1);
    });
});

describe('Course.parseYearLevelFromName', () => {
    test('uses the leading digit of a standard 3-digit course number', () => {
        expect(Course.parseYearLevelFromName('BIOC 401')).toBe(4);
        expect(Course.parseYearLevelFromName('CHEM 121')).toBe(1);
    });

    test('maps 500-level numbers to Graduate (5)', () => {
        expect(Course.parseYearLevelFromName('BIOC 530')).toBe(5);
        expect(Course.parseYearLevelFromName('BIOC 999')).toBe(5);
    });

    test('uses the leading digit of a 4-digit code', () => {
        expect(Course.parseYearLevelFromName('MATH 1010')).toBe(1);
    });

    test('returns null when there is no usable number', () => {
        expect(Course.parseYearLevelFromName('Intro to Biology')).toBeNull();
        expect(Course.parseYearLevelFromName('Course 0')).toBeNull(); // first digit 0 -> null
    });

    test('returns null for non-string input', () => {
        expect(Course.parseYearLevelFromName(401)).toBeNull();
        expect(Course.parseYearLevelFromName(null)).toBeNull();
    });

    // A bare single digit falls through to the `(\d+)` fallback, so its own value
    // is the "first digit": "7" -> min(7,5) = 5. Characterized, not fixed.
    test('clamps a single-digit fallback to MAX_YEAR_LEVEL', () => {
        expect(Course.parseYearLevelFromName('Level 7')).toBe(5);
    });
});

describe('Course.normalizeTopicList', () => {
    test('trims, collapses whitespace, and dedupes case-insensitively (first wins)', () => {
        expect(Course.normalizeTopicList(['Glycolysis', 'glycolysis ', '  Krebs   Cycle '])).toEqual([
            'Glycolysis',
            'Krebs Cycle',
        ]);
    });

    test('reads labels off topic objects via their .topic field', () => {
        expect(Course.normalizeTopicList([{ topic: 'ATP' }, 'atp'])).toEqual(['ATP']);
    });

    test('drops empty, whitespace-only, and non-string/non-object entries', () => {
        expect(Course.normalizeTopicList(['', '   ', null, 123, 'Real'])).toEqual(['Real']);
    });

    test('returns [] for non-array input', () => {
        expect(Course.normalizeTopicList('Glycolysis')).toEqual([]);
        expect(Course.normalizeTopicList(undefined)).toEqual([]);
    });
});

describe('Course.normalizeTopicObjectList', () => {
    test('wraps a bare string into a normalized topic object with manual defaults', () => {
        const [topic] = Course.normalizeTopicObjectList(['Glycolysis']);
        expect(topic).toMatchObject({ topic: 'Glycolysis', unitId: null, source: 'manual' });
        expect(topic.createdAt).toBeInstanceOf(Date);
    });

    test('applies provided defaults to bare-string topics', () => {
        const [topic] = Course.normalizeTopicObjectList(['ATP'], { source: 'scraped', unitId: '  U1  ' });
        expect(topic).toMatchObject({ topic: 'ATP', unitId: 'U1', source: 'scraped' });
    });

    test('reads metadata straight off an object topic and trims unitId', () => {
        const [topic] = Course.normalizeTopicObjectList([{ topic: 'Krebs', source: 'scraped', unitId: ' U2 ' }]);
        expect(topic).toMatchObject({ topic: 'Krebs', unitId: 'U2', source: 'scraped' });
    });

    test('falls back to manual for an unrecognized source value', () => {
        const [topic] = Course.normalizeTopicObjectList([{ topic: 'X', source: 'bogus' }]);
        expect(topic.source).toBe('manual');
    });

    test('preserves metadata from existingTopics matched by case-insensitive label', () => {
        const existing = [{ topic: 'atp', unitId: 'U9', source: 'scraped' }];
        const [topic] = Course.normalizeTopicObjectList(['ATP'], {}, existing);
        expect(topic).toMatchObject({ topic: 'ATP', unitId: 'U9', source: 'scraped' });
    });

    test('dedupes case-insensitively keeping the first label', () => {
        const result = Course.normalizeTopicObjectList([{ topic: 'ATP' }, 'atp', 'Atp']);
        expect(result).toHaveLength(1);
        expect(result[0].topic).toBe('ATP');
    });

    test('returns [] for non-array input', () => {
        expect(Course.normalizeTopicObjectList('nope')).toEqual([]);
    });

    test('drops malformed topic objects in both new and existing lists', () => {
        expect(Course.normalizeTopicObjectList([
            { topic: 123 },
            { topic: '   ' },
            { topic: 'Valid', unitId: '   ' },
        ], {}, [{ topic: null }, { bogus: true }])).toEqual([
            expect.objectContaining({ topic: 'Valid', unitId: null }),
        ]);
    });
});

describe('Course.normalizeRagTopK', () => {
    test('accepts integers within 1..20', () => {
        expect(Course.normalizeRagTopK(1)).toBe(1);
        expect(Course.normalizeRagTopK(20)).toBe(20);
        expect(Course.normalizeRagTopK('7')).toBe(7);
    });

    test('falls back to the default (3) for out-of-range / non-integer / missing', () => {
        expect(Course.normalizeRagTopK(0)).toBe(3);
        expect(Course.normalizeRagTopK(21)).toBe(3);
        expect(Course.normalizeRagTopK(2.5)).toBe(3);
        expect(Course.normalizeRagTopK(undefined)).toBe(3);
    });

    test('honors a custom fallback (used by updateRagSettings to detect invalid input)', () => {
        expect(Course.normalizeRagTopK(0, null)).toBeNull();
        expect(Course.normalizeRagTopK(99, null)).toBeNull();
    });
});

describe('Course.resolveRagSettings', () => {
    test('defaults student topK to 3 when unset', () => {
        expect(Course.resolveRagSettings({})).toEqual({ student: { topK: 3 } });
        expect(Course.resolveRagSettings()).toEqual({ student: { topK: 3 } });
    });

    test('passes a valid stored topK through', () => {
        expect(Course.resolveRagSettings({ ragSettings: { student: { topK: 8 } } })).toEqual({
            student: { topK: 8 },
        });
    });

    test('clamps an invalid stored topK back to the default', () => {
        expect(Course.resolveRagSettings({ ragSettings: { student: { topK: 99 } } })).toEqual({
            student: { topK: 3 },
        });
    });
});

describe('Course.getAllowInSuperCourse', () => {
    test('is true only for a strict boolean true', () => {
        expect(Course.getAllowInSuperCourse({ allowInSuperCourse: true })).toBe(true);
    });

    test('is false for truthy-but-not-true, missing, or no document', () => {
        expect(Course.getAllowInSuperCourse({ allowInSuperCourse: 'true' })).toBe(false);
        expect(Course.getAllowInSuperCourse({ allowInSuperCourse: 1 })).toBe(false);
        expect(Course.getAllowInSuperCourse({})).toBe(false);
        expect(Course.getAllowInSuperCourse()).toBe(false);
    });
});

describe('Course.normalizeSuperchatIds', () => {
    test('trims, dedupes, and preserves first-seen order', () => {
        expect(Course.normalizeSuperchatIds(['a', ' a ', 'b', 'a'])).toEqual(['a', 'b']);
    });

    test('drops empty strings and non-string entries', () => {
        expect(Course.normalizeSuperchatIds([1, null, 'x', '  ', { id: 'y' }])).toEqual(['x']);
    });

    test('returns [] for non-array input', () => {
        expect(Course.normalizeSuperchatIds('nope')).toEqual([]);
        expect(Course.normalizeSuperchatIds(undefined)).toEqual([]);
    });
});

describe('Course.getCourseSuperchatIds', () => {
    test('reads and normalizes the superchatIds field', () => {
        expect(Course.getCourseSuperchatIds({ superchatIds: ['a', 'a', 'b'] })).toEqual(['a', 'b']);
    });

    test('returns [] when the field is absent or the doc is empty', () => {
        expect(Course.getCourseSuperchatIds({})).toEqual([]);
        expect(Course.getCourseSuperchatIds()).toEqual([]);
    });
});
