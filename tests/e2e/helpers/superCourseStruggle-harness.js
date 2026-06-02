// @ts-nocheck
/**
 * Coverage harness for the Super Chat (cross-course) struggle attribution path:
 *   - src/models/User.js → updateUserStruggleState(..., options)
 *       • source threading into the activity record
 *       • skipActivityLog suppression (Option B: per-event logging is done by
 *         the caller, so the activation row is NOT written here)
 *   - src/services/superCourseService.js → getSuperCourseApprovedTopics
 *       • maps the pool to {courseId, courseName, approvedTopics}
 *       • courseName falls back to courseCode/courseId
 *       • courses with no approved topics are dropped
 *
 * Uses lightweight fake Mongo collections (no live DB).
 */

const assert = require('assert/strict');
const path = require('path');
const v8 = require('v8');

const User = require(path.resolve(__dirname, '../../../src/models/User'));
const superCourseService = require(path.resolve(__dirname, '../../../src/services/superCourseService'));
const { trackSuperCourseStruggle } = require(path.resolve(__dirname, '../../../src/routes/studentSuperCourse'));

// Minimal LLM stub: returns a canned analyzeMessageAcrossCourses JSON payload.
class FakeLLM {
    constructor(content) { this.content = content; }
    async sendMessage() { return { content: this.content }; }
}

function matchesPrimitive(doc, query) {
    for (const [k, v] of Object.entries(query)) {
        if (typeof v !== 'object' && doc[k] !== v) return false;
    }
    return true;
}

class FakeCollection {
    constructor() {
        this.docs = [];
        this.findOneAndUpdateCount = 0;
    }
    async findOne(query) {
        return this.docs.find((d) => matchesPrimitive(d, query)) || null;
    }
    async insertOne(doc) {
        this.docs.push(doc);
        return { acknowledged: true, insertedId: 'id-' + this.docs.length };
    }
    async updateOne(filter, update) {
        this.lastUpdate = { filter, update };
        return { matchedCount: 1, modifiedCount: 1 };
    }
    async findOneAndUpdate() {
        // Used by PersistenceTopic.incrementStudentCount; return a doc shaped
        // like the real driver result so the follow-up updateOne runs.
        this.findOneAndUpdateCount += 1;
        return {
            value: { _id: 'p1', studentIds: ['u1'], topic: 'plant diagnostics' },
            lastErrorObject: { updatedExisting: true },
        };
    }
    find() {
        const all = this.docs;
        return {
            sort: () => ({
                limit: (n) => ({ toArray: async () => all.slice(0, n) }),
                toArray: async () => all,
            }),
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

// Build a user already at count=2 on a topic, so the next struggle activates it
// (count → 3, isActive true, isNewActivation true).
function seededUser() {
    return {
        userId: 'u1',
        displayName: 'Stu Dent',
        struggleState: { topics: [{ topic: 'plant diagnostics', count: 2, lastStruggle: new Date('2026-05-01'), isActive: false }] },
    };
}

async function run() {
    // ---- superCourse + skipActivityLog: counter advances, persistence runs,
    //      but NO activation row is written here (caller logs per-event) ----
    {
        const users = new FakeCollection();
        users.docs = [seededUser()];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();
        const db = makeDb({ users, struggleActivity: struggle, persistenceTopics: persist });

        const res = await User.updateUserStruggleState(
            db, 'u1',
            { topic: 'Plant Diagnostics', isStruggling: true },
            'BIOC200',
            { source: 'superCourse', skipActivityLog: true }
        );

        assert.equal(res.success, true);
        assert.equal(res.state.count, 3);
        assert.equal(res.state.isActive, true);          // blended Directive Mode
        assert.equal(struggle.docs.length, 0);           // activation row suppressed
        assert.ok(persist.findOneAndUpdateCount >= 1);   // persistence still updated
    }

    // ---- default options: activation row IS written, tagged source 'course' ----
    {
        const users = new FakeCollection();
        users.docs = [seededUser()];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();
        const db = makeDb({ users, struggleActivity: struggle, persistenceTopics: persist });

        await User.updateUserStruggleState(
            db, 'u1',
            { topic: 'Plant Diagnostics', isStruggling: true },
            'BIOC200'
        );

        assert.equal(struggle.docs.length, 1);
        assert.equal(struggle.docs[0].source, 'course');
        assert.equal(struggle.docs[0].state, 'Active');
    }

    // ---- superCourse without skip: activation row written, tagged superCourse ----
    {
        const users = new FakeCollection();
        users.docs = [seededUser()];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();
        const db = makeDb({ users, struggleActivity: struggle, persistenceTopics: persist });

        await User.updateUserStruggleState(
            db, 'u1',
            { topic: 'Plant Diagnostics', isStruggling: true },
            'BIOC200',
            { source: 'superCourse' }
        );

        assert.equal(struggle.docs.length, 1);
        assert.equal(struggle.docs[0].source, 'superCourse');
    }

    // ---- below-threshold struggle: no activation, no activity row, no persistence ----
    {
        const users = new FakeCollection();
        users.docs = [{ userId: 'u1', displayName: 'Stu', struggleState: { topics: [] } }];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();
        const db = makeDb({ users, struggleActivity: struggle, persistenceTopics: persist });

        const res = await User.updateUserStruggleState(
            db, 'u1',
            { topic: 'New Topic', isStruggling: true },
            'BIOC200',
            { source: 'superCourse', skipActivityLog: true }
        );

        assert.equal(res.state.count, 1);
        assert.equal(res.state.isActive, false);
        assert.equal(struggle.docs.length, 0);
        assert.equal(persist.findOneAndUpdateCount, 0);
    }

    // ---- getSuperCourseApprovedTopics: maps pool, fallbacks, drops empty ----
    {
        const courses = new FakeCollection();
        courses.docs = [
            { courseId: 'C1', courseName: 'One', approvedStruggleTopics: ['Plant Diagnostics', 'Photosynthesis'] },
            { courseId: 'C2', courseCode: 'BIOC2', approvedStruggleTopics: ['Cellular Respiration'] }, // name falls back to code
            { courseId: 'C3', approvedStruggleTopics: [] },                                            // dropped (no topics)
            { courseId: 'C4' },                                                                        // dropped (no topics field)
        ];
        const db = makeDb({ courses });

        const out = await superCourseService.getSuperCourseApprovedTopics(db, {});
        assert.equal(out.length, 2);

        const c1 = out.find((o) => o.courseId === 'C1');
        assert.deepEqual(c1.approvedTopics, ['Plant Diagnostics', 'Photosynthesis']);
        assert.equal(c1.courseName, 'One');

        const c2 = out.find((o) => o.courseId === 'C2');
        assert.equal(c2.courseName, 'BIOC2'); // courseCode fallback
    }

    // =====================================================================
    // trackSuperCourseStruggle (route helper): state correctness + directive
    // =====================================================================
    const POOL_COURSES = [{ courseId: 'C1', courseName: 'One', approvedStruggleTopics: ['Plant Diagnostics'] }];
    // candidate index 0 == Plant Diagnostics / C1
    const MAPPED_STRUGGLE = '{"isStruggling": true, "matchedIndex": 0, "matchConfidence": 0.9}';

    function makeTrackingDb(courses, users, struggle, persist) {
        return makeDb({ courses, users, struggleActivity: struggle, persistenceTopics: persist });
    }

    // trackSuperCourseStruggle caches its TrackerService at module scope (built
    // from the first llmService it sees), so all calls below MUST share one LLM
    // instance whose response we mutate between cases — exactly how production
    // reuses the single app.locals.llm.
    const sharedLLM = new FakeLLM(MAPPED_STRUGGLE);

    // ---- first struggle on a topic (count 1) → logged 'Inactive', no directive ----
    {
        sharedLLM.content = MAPPED_STRUGGLE;
        const courses = new FakeCollection(); courses.docs = POOL_COURSES;
        const users = new FakeCollection(); users.docs = [{ userId: 'u1', displayName: 'Stu', struggleState: { topics: [] } }];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();

        const result = await trackSuperCourseStruggle({
            db: makeTrackingDb(courses, users, struggle, persist),
            llmService: sharedLLM,
            user: { userId: 'u1', displayName: 'Stu' },
            message: "I don't get plant diagnostics",
            includeInactiveCourses: false,
        });

        assert.equal(struggle.docs.length, 1);
        assert.equal(struggle.docs[0].state, 'Inactive');     // below threshold
        assert.equal(struggle.docs[0].source, 'superCourse');
        assert.equal(result.directiveModeActive, false);
        assert.equal(result.identifiedTopic, null);
    }

    // ---- struggle that reaches threshold (count 2 → 3) → 'Active' + directive ----
    {
        sharedLLM.content = MAPPED_STRUGGLE;
        const courses = new FakeCollection(); courses.docs = POOL_COURSES;
        const users = new FakeCollection();
        users.docs = [{ userId: 'u1', displayName: 'Stu', struggleState: { topics: [{ topic: 'plant diagnostics', count: 2, isActive: false }] } }];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();

        const result = await trackSuperCourseStruggle({
            db: makeTrackingDb(courses, users, struggle, persist),
            llmService: sharedLLM,
            user: { userId: 'u1', displayName: 'Stu' },
            message: 'still confused about plant diagnostics',
            includeInactiveCourses: false,
        });

        assert.equal(struggle.docs.length, 1);
        assert.equal(struggle.docs[0].state, 'Active');       // directive threshold reached
        assert.equal(result.directiveModeActive, true);
        assert.equal(result.identifiedTopic, 'Plant Diagnostics');
        assert.ok(persist.findOneAndUpdateCount >= 1);
    }

    // ---- no struggle detected → no row, no directive ----
    {
        sharedLLM.content = '{"isStruggling": false, "matchedIndex": -1, "matchConfidence": 0}';
        const courses = new FakeCollection(); courses.docs = POOL_COURSES;
        const users = new FakeCollection(); users.docs = [{ userId: 'u1', struggleState: { topics: [] } }];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();

        const result = await trackSuperCourseStruggle({
            db: makeTrackingDb(courses, users, struggle, persist),
            llmService: sharedLLM,
            user: { userId: 'u1' },
            message: 'what is ATP?',
            includeInactiveCourses: false,
        });

        assert.equal(struggle.docs.length, 0);
        assert.equal(result.directiveModeActive, false);
    }

    // ---- no approved topics in pool → returns noDirective, never calls LLM ----
    {
        sharedLLM.content = MAPPED_STRUGGLE; // irrelevant: should bail before LLM
        const courses = new FakeCollection(); courses.docs = [{ courseId: 'C1', approvedStruggleTopics: [] }];
        const users = new FakeCollection(); users.docs = [{ userId: 'u1', struggleState: { topics: [] } }];
        const struggle = new FakeCollection();
        const persist = new FakeCollection();

        const result = await trackSuperCourseStruggle({
            db: makeTrackingDb(courses, users, struggle, persist),
            llmService: sharedLLM,
            user: { userId: 'u1' },
            message: 'anything',
            includeInactiveCourses: false,
        });

        assert.equal(struggle.docs.length, 0);
        assert.equal(result.directiveModeActive, false);
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
