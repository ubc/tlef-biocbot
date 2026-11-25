/**
 * BiocBot on the UBC GenAI gamification toolkit
 * (@ubc/genai-toolkit-gamification-*, rung 4 of its PRD).
 *
 * Gamification listens on BiocBot's events (src/services/events.js), counts
 * what students do against the rules a course's instructors publish, and
 * announces what a student earned as `gamification.*` events on the same bus.
 * It stores in BiocBot's own MongoDB, in four `gamification_*` collections:
 * rules, what each student has earned, whether they hid gamification, and the
 * events it counted. Students are their pseudonymous `user_<uuid>` ids, as on
 * every event; never a name or an email.
 *
 * It counts, and src/routes/gamification.js lets a student read their own
 * awards and instructors publish rules at /api/gamification. No page uses
 * those routes yet, so no one sees anything, and it's all off unless
 * BIOCBOT_GAMIFICATION=1 (.env-example).
 *
 * The packages are on GitHub Packages, so, like pub/sub, they are optional
 * dependencies. Without them, or without pub/sub, nothing here starts.
 */

const CORE_PACKAGE = '@ubc/genai-toolkit-gamification-core';
const STORE_PACKAGE = '@ubc/genai-toolkit-gamification-store-mongo';
const PUBSUB_PACKAGE = '@ubc/genai-toolkit-gamification-pubsub';

/**
 * The events instructors can build rules on, in the order the rule builder
 * lists them. A chat about a unit is the main one, so it comes first: "describe
 * it" falls back to the first that fits. Messages and practice questions are
 * volume (capped points only). Struggle is never a metric: it's sensitive, and
 * the listener never hears it.
 */
const METRICS = Object.freeze([
    'chat.session.started',
    'chat.mode.changed',
    'quiz.question.answered',
    'chat.message.sent'
]);

/** Days and weeks (streaks, "3 different days") are counted in UBC's time. */
const TIME_ZONE = 'America/Vancouver';

/**
 * Each course turns gamification on for itself (the toolkit's PRD: "Instructor
 * turns gamification on per course"). It's off until an instructor turns it
 * on, at /instructor/gamification. While it's off nothing is counted for the
 * course and its students see nothing. The switch is the course's
 * `gamification.enabled`, which holds nothing encrypted.
 *
 * Counting asks for every event, so the answer is kept for a short while. A
 * switch on this server takes effect at once; on another node (staging has
 * two) within SWITCH_TTL_MS.
 */
const SWITCH_TTL_MS = 30 * 1000;
/** @type {Map<string, { on: boolean, at: number }>} */
const switches = new Map();

/**
 * Whether `course` has gamification on.
 *
 * @param {import('mongodb').Db} db
 * @param {string} course
 * @returns {Promise<boolean>}
 */
async function isCourseOn(db, course) {
    const known = switches.get(course);
    if (known && Date.now() - known.at < SWITCH_TTL_MS) return known.on;
    const doc = await db.collection('courses').findOne({ courseId: course }, { projection: { gamification: 1 } });
    const on = doc?.gamification?.enabled === true;
    switches.set(course, { on, at: Date.now() });
    return on;
}

/**
 * Turns gamification on or off for `course`.
 *
 * @param {import('mongodb').Db} db
 * @param {string} course
 * @param {boolean} on
 * @param {string} [userId] - Who changed it
 * @returns {Promise<boolean>} Whether the course was found
 */
async function setCourseOn(db, course, on, userId) {
    const result = await db.collection('courses').updateOne(
        { courseId: course },
        { $set: { 'gamification.enabled': on === true, 'gamification.updatedAt': new Date(), 'gamification.updatedBy': userId || null } }
    );
    switches.set(course, { on: on === true, at: Date.now() });
    return result.matchedCount > 0;
}

/** For tests: forgets the switches kept in memory. */
function forgetCourseSwitches() {
    switches.clear();
}

/**
 * BiocBot's publisher as gamification's listener sees it: only events from
 * courses that have gamification on. An event's course is checked as it's
 * heard; if the check fails, the event isn't counted.
 */
function onlyCoursesThatCount(events, courseOn, logger) {
    // A new object rather than one inheriting from `events`: the publisher is
    // frozen, so overriding a method on an heir would be silently ignored.
    return Object.freeze({
        dictionary: events.dictionary,
        publish: (...args) => events.publish(...args),
        subscribe: (...args) => events.subscribe(...args),
        subscribeAll: (listener, options) => events.subscribeAll(async event => {
            if (typeof event.course !== 'string') return listener(event);
            let on = false;
            try {
                on = await courseOn(event.course);
            } catch (error) {
                logger.error('❌ [GAMIFICATION] Could not read whether a course counts:', error && error.message);
            }
            return on ? listener(event) : undefined;
        }, options)
    });
}

/** @type {{ core: any, store: any, pubsub: any } | null | undefined} */
let toolkit;

/**
 * @returns {{ core: any, store: any, pubsub: any } | null} Null where the
 *   packages aren't installed
 */
function loadGamificationToolkit() {
    if (toolkit === undefined) {
        try {
            toolkit = { core: require(CORE_PACKAGE), store: require(STORE_PACKAGE), pubsub: require(PUBSUB_PACKAGE) };
        } catch (error) {
            if (error.code !== 'MODULE_NOT_FOUND') throw error;
            toolkit = null;
        }
    }
    return toolkit;
}

/**
 * BiocBot's catalog: the palette its instructors build rules from, made from
 * its event dictionary so each event is described once.
 *
 * @param {any} dictionary - BiocBot's dictionary (`events.dictionary`)
 * @returns {any} The toolkit's `Catalog`
 */
function buildCatalog(dictionary) {
    return loadGamificationToolkit().pubsub.catalogFromDictionary(dictionary, { app: 'BiocBot', metrics: METRICS });
}

/** @type {any | null} */
let gamification = null;

/**
 * Starts counting: makes BiocBot's gamification and its listener. Called once
 * at startup, from src/listeners/index.js.
 *
 * @param {{
 *   events: any,
 *   db?: import('mongodb').Db,
 *   store?: any,
 *   courseOn?: (course: string) => Promise<boolean>,
 *   logger?: Pick<Console, 'log' | 'error'>
 * }} options - `events` is BiocBot's publisher (getEvents()). `db` is
 *   BiocBot's database; tests pass an in-memory `store` instead. `courseOn`
 *   says which courses count; with `db` it's each course's own switch, and
 *   without either every course counts (tests).
 * @returns {{ gamification: any, stop: () => void } | null} Null where the
 *   packages aren't installed
 */
function startGamification({ events, db, store, courseOn = db ? course => isCourseOn(db, course) : null, logger = console }) {
    const loaded = loadGamificationToolkit();
    if (!loaded || !events) return null;

    let storeToUse = store;
    if (!storeToUse) {
        const mongoStore = loaded.store.createMongoStore(db);
        // Safe on every start, and not waited for: these indexes are for
        // lookups only. A retried event counts once regardless, because the
        // store keys each event by its id (`_id`). Two processes saving the
        // same student's state can't overwrite each other: the store checks a
        // version before it saves (0.1.0-rc.2).
        mongoStore.ensureIndexes().catch(error => {
            logger.error('❌ [GAMIFICATION] Could not create its indexes:', error && error.message);
        });
        storeToUse = mongoStore;
    }

    gamification = loaded.core.createGamification({
        catalog: buildCatalog(events.dictionary),
        store: storeToUse,
        timeZone: TIME_ZONE,
        logger
    });
    const heard = courseOn ? onlyCoursesThatCount(events, courseOn, logger) : events;
    const stopListening = loaded.pubsub.listenForGamification({ events: heard, gamification, logger });

    return {
        gamification,
        stop: () => {
            stopListening();
            gamification = null;
        }
    };
}

/**
 * BiocBot's gamification, once startGamification has run; null before, or
 * where it's off. src/server.js mounts its routes with it.
 *
 * @returns {any | null}
 */
function getGamification() {
    return gamification;
}

module.exports = {
    SWITCH_TTL_MS,
    isCourseOn,
    setCourseOn,
    forgetCourseSwitches,
    METRICS,
    TIME_ZONE,
    loadGamificationToolkit,
    buildCatalog,
    startGamification,
    getGamification
};
