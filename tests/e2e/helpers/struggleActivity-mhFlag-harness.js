// @ts-nocheck
/**
 * Coverage harness for residual branches in:
 *   - src/models/StruggleActivity.js  (createActivityEntry; default-options
 *     branches in get* helpers; weekly aggregation Sunday-snap branch)
 *   - src/models/MentalHealthFlag.js  (createMentalHealthFlag, updateFlagStatus
 *     "no rows changed" branch, getMentalHealthFlagStats with multiple statuses)
 *
 * These functions are exercised in production but a handful of optional-field
 * and "default value" branches aren't hit by the live routes; this harness
 * covers them with a fake Mongo collection.
 */

const assert = require('assert/strict');
const path = require('path');
const v8 = require('v8');

const StruggleActivity = require(path.resolve(__dirname, '../../../src/models/StruggleActivity'));
const MentalHealthFlag = require(path.resolve(__dirname, '../../../src/models/MentalHealthFlag'));

class FakeCollection {
    constructor() {
        this.docs = [];
        this.aggregateResults = [];
        this.updateResult = { matchedCount: 1, modifiedCount: 1 };
    }
    async insertOne(doc) {
        this.docs.push(doc);
        return { acknowledged: true, insertedId: 'id-' + this.docs.length };
    }
    find(query) {
        this.lastFind = query;
        const matches = this.docs.filter((d) => {
            for (const [k, v] of Object.entries(query)) {
                if (d[k] !== v) return false;
            }
            return true;
        });
        return {
            sort: (s) => {
                this.lastSort = s;
                return {
                    limit: (n) => ({
                        toArray: async () => matches.slice(0, n),
                    }),
                    toArray: async () => matches,
                };
            },
        };
    }
    async updateOne(filter, update) {
        this.lastUpdate = { filter, update };
        return this.updateResult;
    }
    aggregate(pipeline) {
        this.lastPipeline = pipeline;
        return {
            toArray: async () => this.aggregateResults,
        };
    }
}

function makeDb(byName) {
    return {
        collection(name) {
            const coll = byName[name];
            if (!coll) throw new Error('Unexpected collection name: ' + name);
            return coll;
        },
    };
}

async function run() {
    // ---- StruggleActivity.createActivityEntry: default timestamp branch (data.timestamp undefined) ----
    {
        const coll = new FakeCollection();
        const result = await StruggleActivity.createActivityEntry(
            makeDb({ struggleActivity: coll }),
            { userId: 'u1', studentName: 'Alice', courseId: 'C1', topic: '  Krebs Cycle  ', state: 'Active' }
        );
        assert.equal(result.acknowledged, true);
        assert.equal(coll.docs[0].topic, 'krebs cycle');
        assert.ok(coll.docs[0].timestamp instanceof Date);
    }

    // ---- StruggleActivity.createActivityEntry: explicit timestamp ----
    {
        const coll = new FakeCollection();
        const ts = new Date('2026-04-01T00:00:00Z');
        await StruggleActivity.createActivityEntry(
            makeDb({ struggleActivity: coll }),
            { userId: 'u1', studentName: 'Alice', courseId: 'C1', topic: 'X', state: 'Inactive', timestamp: ts }
        );
        assert.equal(coll.docs[0].timestamp, ts);
    }

    // ---- StruggleActivity.getActivityByCourse: default limit + no state filter ----
    {
        const coll = new FakeCollection();
        coll.docs = [{ courseId: 'C', state: 'Active' }, { courseId: 'C', state: 'Inactive' }];
        const out = await StruggleActivity.getActivityByCourse(makeDb({ struggleActivity: coll }), 'C');
        assert.equal(out.length, 2);
        assert.deepEqual(coll.lastFind, { courseId: 'C' });
    }

    // ---- StruggleActivity.getActivityByCourse: explicit state filter + limit ----
    {
        const coll = new FakeCollection();
        coll.docs = [{ courseId: 'C', state: 'Active' }];
        const out = await StruggleActivity.getActivityByCourse(makeDb({ struggleActivity: coll }), 'C', { state: 'Active', limit: 5 });
        assert.equal(out.length, 1);
        assert.equal(coll.lastFind.state, 'Active');
    }

    // ---- StruggleActivity.getActivityByStudent: default limit branch ----
    {
        const coll = new FakeCollection();
        coll.docs = [{ userId: 'u', timestamp: new Date() }];
        const out = await StruggleActivity.getActivityByStudent(makeDb({ struggleActivity: coll }), 'u');
        assert.equal(out.length, 1);
    }

    // ---- StruggleActivity.getWeeklyActiveTopics: default weeks branch ----
    {
        const coll = new FakeCollection();
        coll.aggregateResults = [{ weekStart: new Date('2026-04-06'), topics: [], totalCount: 0 }];
        const out = await StruggleActivity.getWeeklyActiveTopics(makeDb({ struggleActivity: coll }), 'C');
        assert.equal(out.length, 1);
        assert.ok(coll.lastPipeline);
        // course-scoped: $match includes courseId, no source filter
        assert.equal(coll.lastPipeline[0].$match.courseId, 'C');
        assert.equal(coll.lastPipeline[0].$match.source, undefined);
    }

    // ---- StruggleActivity.createActivityEntry: source defaults to 'course' ----
    {
        const coll = new FakeCollection();
        await StruggleActivity.createActivityEntry(
            makeDb({ struggleActivity: coll }),
            { userId: 'u1', studentName: 'A', courseId: 'C1', topic: 'X', state: 'Active' }
        );
        assert.equal(coll.docs[0].source, 'course');
    }

    // ---- StruggleActivity.createActivityEntry: explicit superCourse source ----
    {
        const coll = new FakeCollection();
        await StruggleActivity.createActivityEntry(
            makeDb({ struggleActivity: coll }),
            { userId: 'u1', studentName: 'A', courseId: 'C1', topic: 'X', state: 'Active', source: 'superCourse' }
        );
        assert.equal(coll.docs[0].source, 'superCourse');
    }

    // ---- StruggleActivity.createActivityEntry: unknown source coerced to 'course' ----
    {
        const coll = new FakeCollection();
        await StruggleActivity.createActivityEntry(
            makeDb({ struggleActivity: coll }),
            { userId: 'u1', studentName: 'A', courseId: 'C1', topic: 'X', state: 'Active', source: 'bogus' }
        );
        assert.equal(coll.docs[0].source, 'course');
    }

    // ---- StruggleActivity.getActivityByCourse: source filter applied ----
    {
        const coll = new FakeCollection();
        coll.docs = [
            { courseId: 'C', state: 'Active', source: 'superCourse' },
            { courseId: 'C', state: 'Active', source: 'course' }
        ];
        const out = await StruggleActivity.getActivityByCourse(
            makeDb({ struggleActivity: coll }), 'C', { source: 'superCourse' }
        );
        assert.equal(out.length, 1);
        assert.equal(coll.lastFind.source, 'superCourse');
    }

    // ---- StruggleActivity.getSuperCourseActivity: default (all courses, source superCourse) ----
    {
        const coll = new FakeCollection();
        coll.docs = [
            { courseId: 'C1', source: 'superCourse', state: 'Active' },
            { courseId: 'C2', source: 'superCourse', state: 'Active' },
            { courseId: 'C1', source: 'course', state: 'Active' }
        ];
        const out = await StruggleActivity.getSuperCourseActivity(makeDb({ struggleActivity: coll }));
        assert.equal(out.length, 2); // only superCourse rows, across courses
        assert.deepEqual(coll.lastFind, { source: 'superCourse' });
    }

    // ---- StruggleActivity.getSuperCourseActivity: with state filter + limit ----
    {
        const coll = new FakeCollection();
        coll.docs = [{ source: 'superCourse', state: 'Active' }];
        const out = await StruggleActivity.getSuperCourseActivity(
            makeDb({ struggleActivity: coll }), { state: 'Active', limit: 10 }
        );
        assert.equal(out.length, 1);
        assert.equal(coll.lastFind.state, 'Active');
    }

    // ---- StruggleActivity.getWeeklyActiveTopics: null courseId + source → global Super Chat ----
    {
        const coll = new FakeCollection();
        coll.aggregateResults = [];
        await StruggleActivity.getWeeklyActiveTopics(
            makeDb({ struggleActivity: coll }), null, { source: 'superCourse' }
        );
        const match = coll.lastPipeline[0].$match;
        assert.equal(match.courseId, undefined); // not course-scoped
        assert.equal(match.source, 'superCourse');
    }

    // ---- MentalHealthFlag.createMentalHealthFlag: minimal fields use defaults ----
    {
        const coll = new FakeCollection();
        const r = await MentalHealthFlag.createMentalHealthFlag(
            makeDb({ mentalHealthFlags: coll }),
            { studentId: 's1', courseId: 'C1', message: 'help', concernLevel: 'low concern' }
        );
        assert.equal(r.success, true);
        assert.match(r.flagId, /^mhf_/);
        assert.equal(coll.docs[0].studentName, 'Unknown Student');
        assert.equal(coll.docs[0].unitName, 'Unknown Unit');
        assert.deepEqual(coll.docs[0].conversationContext, []);
        assert.equal(coll.docs[0].llmReason, '');
        assert.equal(coll.docs[0].status, 'pending');
    }

    // ---- MentalHealthFlag.createMentalHealthFlag: full fields ----
    {
        const coll = new FakeCollection();
        await MentalHealthFlag.createMentalHealthFlag(
            makeDb({ mentalHealthFlags: coll }),
            {
                studentId: 's1',
                studentName: 'Bob',
                courseId: 'C1',
                unitName: 'Unit 2',
                message: 'I feel hopeless',
                conversationContext: [{ role: 'user', content: 'hi' }],
                concernLevel: 'high concern',
                llmReason: 'self-harm phrasing',
            }
        );
        assert.equal(coll.docs[0].studentName, 'Bob');
        assert.equal(coll.docs[0].unitName, 'Unit 2');
        assert.equal(coll.docs[0].llmReason, 'self-harm phrasing');
    }

    // ---- MentalHealthFlag.updateFlagStatus: 'escalated' sets escalatedBy/At ----
    {
        const coll = new FakeCollection();
        const r = await MentalHealthFlag.updateFlagStatus(
            makeDb({ mentalHealthFlags: coll }),
            'mhf_x',
            'escalated',
            'inst1'
        );
        assert.equal(r.success, true);
        assert.equal(coll.lastUpdate.update.$set.escalatedBy, 'inst1');
        assert.ok(coll.lastUpdate.update.$set.escalatedAt instanceof Date);
    }

    // ---- MentalHealthFlag.updateFlagStatus: 'resolved' sets resolvedBy/At ----
    {
        const coll = new FakeCollection();
        const r = await MentalHealthFlag.updateFlagStatus(
            makeDb({ mentalHealthFlags: coll }),
            'mhf_y',
            'resolved',
            'admin1'
        );
        assert.equal(r.success, true);
        assert.equal(coll.lastUpdate.update.$set.resolvedBy, 'admin1');
    }

    // ---- MentalHealthFlag.updateFlagStatus: 'disregarded' sets resolvedBy/At ----
    {
        const coll = new FakeCollection();
        await MentalHealthFlag.updateFlagStatus(
            makeDb({ mentalHealthFlags: coll }),
            'mhf_z',
            'disregarded',
            'admin1'
        );
        assert.equal(coll.lastUpdate.update.$set.resolvedBy, 'admin1');
    }

    // ---- MentalHealthFlag.updateFlagStatus: 'dismissed' (neither escalation nor resolution branch) ----
    {
        const coll = new FakeCollection();
        await MentalHealthFlag.updateFlagStatus(
            makeDb({ mentalHealthFlags: coll }),
            'mhf_d',
            'dismissed',
            'inst1'
        );
        assert.equal(coll.lastUpdate.update.$set.escalatedBy, undefined);
        assert.equal(coll.lastUpdate.update.$set.resolvedBy, undefined);
    }

    // ---- MentalHealthFlag.updateFlagStatus: no rows modified → returns success:false ----
    {
        const coll = new FakeCollection();
        coll.updateResult = { matchedCount: 0, modifiedCount: 0 };
        const r = await MentalHealthFlag.updateFlagStatus(
            makeDb({ mentalHealthFlags: coll }),
            'missing',
            'dismissed',
            'inst1'
        );
        assert.equal(r.success, false);
    }

    // ---- MentalHealthFlag.getMentalHealthFlagsForCourse: with and without status filter ----
    {
        const coll = new FakeCollection();
        coll.docs = [{ courseId: 'C', status: 'pending', createdAt: new Date('2026-01-01') }];
        // No status — filter doesn't include `status`
        let out = await MentalHealthFlag.getMentalHealthFlagsForCourse(makeDb({ mentalHealthFlags: coll }), 'C');
        assert.equal(out.length, 1);
        assert.equal(coll.lastFind.status, undefined);

        // status='all' — also excluded from filter
        out = await MentalHealthFlag.getMentalHealthFlagsForCourse(makeDb({ mentalHealthFlags: coll }), 'C', 'all');
        assert.equal(out.length, 1);

        // explicit status — included
        out = await MentalHealthFlag.getMentalHealthFlagsForCourse(makeDb({ mentalHealthFlags: coll }), 'C', 'pending');
        assert.equal(coll.lastFind.status, 'pending');
    }

    // ---- MentalHealthFlag.getMentalHealthFlagStats: aggregates multiple statuses ----
    {
        const coll = new FakeCollection();
        coll.aggregateResults = [
            { _id: 'pending', count: 3 },
            { _id: 'escalated', count: 2 },
            { _id: 'resolved', count: 1 },
        ];
        const stats = await MentalHealthFlag.getMentalHealthFlagStats(makeDb({ mentalHealthFlags: coll }), 'C');
        assert.equal(stats.total, 6);
        assert.equal(stats.pending, 3);
        assert.equal(stats.escalated, 2);
        assert.equal(stats.resolved, 1);
        assert.equal(stats.dismissed, 0);
    }

    // ---- MentalHealthFlag.getMentalHealthFlagStats: empty ----
    {
        const coll = new FakeCollection();
        coll.aggregateResults = [];
        const stats = await MentalHealthFlag.getMentalHealthFlagStats(makeDb({ mentalHealthFlags: coll }), 'C');
        assert.equal(stats.total, 0);
    }
}

run()
    .then(() => {
        try { v8.takeCoverage(); } catch { /* coverage disabled */ }
    })
    .catch((err) => {
        console.error(err);
        try { v8.takeCoverage(); } catch { /* coverage disabled */ }
        process.exitCode = 1;
    });
