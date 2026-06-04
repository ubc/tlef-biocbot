// @ts-check
/**
 * Unit coverage for mergeBalancedCourseResults in src/services/superCourseService.js.
 *
 * This is the per-course retrieval floor that fixes the Super Course bug where a
 * pool course with denser/more-similar chunks (e.g. BIOC 202) won every top-K
 * slot, silently shutting other opted-in courses (e.g. BIOC 302) out of every
 * answer. The function is pure, so it's tested directly without Qdrant.
 */

const { test, expect } = require('./fixtures/monocart');
const { mergeBalancedCourseResults } = require('../../src/services/superCourseService');

// Build a course's ranked hit list: ids prefixed by course, descending scores.
function courseHits(prefix, count, topScore) {
    return Array.from({ length: count }, (_, i) => ({
        id: `${prefix}-${i}`,
        score: topScore - i * 0.01,
        courseId: prefix,
    }));
}

function courseIdsOf(results) {
    return results.map(r => r.courseId);
}

test('every course is represented even when one course dominates on score', () => {
    // BIOC 202 has uniformly higher scores than BIOC 302; a plain global top-8
    // would return all 202. The floor must still seat 302.
    const byCourse = new Map([
        ['BIOC-202', courseHits('BIOC-202', 10, 0.9)],
        ['BIOC-302', courseHits('BIOC-302', 10, 0.4)],
    ]);

    const merged = mergeBalancedCourseResults(byCourse, 8);

    expect(merged).toHaveLength(8);
    const counts = courseIdsOf(merged).reduce((acc, id) => {
        acc[id] = (acc[id] || 0) + 1;
        return acc;
    }, /** @type {Record<string, number>} */ ({}));
    // floor = ⌊8 / 2⌋ = 4 guaranteed each; remainder fills by score (more 202).
    expect(counts['BIOC-302']).toBeGreaterThanOrEqual(4);
    expect(counts['BIOC-202']).toBeGreaterThanOrEqual(4);
    // No duplicate ids.
    expect(new Set(merged.map(r => r.id)).size).toBe(8);
});

test('the front of the list is balanced so downstream slicing keeps representation', () => {
    const byCourse = new Map([
        ['A', courseHits('A', 10, 0.9)],
        ['B', courseHits('B', 10, 0.4)],
    ]);

    const merged = mergeBalancedCourseResults(byCourse, 8);

    // First two entries are each course's #1 chunk (round-robin by rank), so a
    // caller slicing to a smaller budget still sees both courses.
    expect(courseIdsOf(merged.slice(0, 2)).sort()).toEqual(['A', 'B']);
});

test('a course that returned nothing does not waste its floor', () => {
    // Only one course has hits; floor is computed over courses that returned
    // results, so the lone course fills the whole budget.
    const byCourse = new Map([
        ['A', courseHits('A', 10, 0.9)],
        ['B', []],
    ]);

    const merged = mergeBalancedCourseResults(byCourse, 8);

    expect(merged).toHaveLength(8);
    expect(new Set(courseIdsOf(merged))).toEqual(new Set(['A']));
});

test('a thin course contributes all it has and the rest backfills from the dense course', () => {
    const byCourse = new Map([
        ['A', courseHits('A', 10, 0.9)],
        ['B', courseHits('B', 2, 0.5)], // only 2 chunks available
    ]);

    const merged = mergeBalancedCourseResults(byCourse, 8);

    expect(merged).toHaveLength(8);
    const counts = courseIdsOf(merged).reduce((acc, id) => {
        acc[id] = (acc[id] || 0) + 1;
        return acc;
    }, /** @type {Record<string, number>} */ ({}));
    expect(counts['B']).toBe(2); // both of B's chunks seated
    expect(counts['A']).toBe(6); // A backfills the remainder
});

test('empty pool returns an empty list', () => {
    expect(mergeBalancedCourseResults(new Map(), 8)).toEqual([]);
    expect(mergeBalancedCourseResults(new Map([['A', []]]), 8)).toEqual([]);
});

test('single course behaves like a plain top-K by score', () => {
    const byCourse = new Map([['A', courseHits('A', 10, 0.9)]]);
    const merged = mergeBalancedCourseResults(byCourse, 5);
    expect(merged.map(r => r.id)).toEqual(['A-0', 'A-1', 'A-2', 'A-3', 'A-4']);
});
