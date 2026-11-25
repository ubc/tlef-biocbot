/**
 * /api/gamification: the gamification toolkit's router
 * (@ubc/genai-toolkit-gamification-server), with BiocBot's own answers to
 * "who is asking?", and the switch each course turns it on with. Mounted by
 * src/server.js only while gamification is counting (BIOCBOT_GAMIFICATION=1,
 * src/services/gamification.js), after sign-in. The pages are
 * /instructor/gamification and /student/achievements.
 *
 * Every route is under /courses/:course (the toolkit's README lists its own):
 *
 * - GET /enabled: whether the course has gamification on, for anyone in it.
 *   PUT /enabled { enabled }: its instructors (and system admins) turn it on
 *   or off.
 * - A student reads only their own awards (GET /me) and can hide
 *   gamification (PUT /me/opt-out), only while the course has it on. "View
 *   as Student" sees the student view, but its opt-out isn't saved.
 * - The course's instructors (and system admins) see and change its rules,
 *   whether or not it's on yet, so they can set it up first. "Describe it"
 *   uses the course's own AI model, or the built-in drafter where the course
 *   has none.
 * - The course's TAs see its rules without changing them, as the toolkit's
 *   PRD has TAs read-only.
 *
 * No route takes a student's id, so nobody can read another student's awards.
 */

const express = require('express');
const CourseModel = require('../models/Course');
const { hasSystemAdminAccess } = require('../services/authorization');
const { LANES } = require('../services/llmLanes');
const gamificationService = require('../services/gamification');

/** A draft is a small JSON object, but reasoning models spend tokens before it. */
const DRAFT_MAX_TOKENS = 2000;

const SERVER_PACKAGE = '@ubc/genai-toolkit-gamification-server';

/** @returns {any | null} The toolkit's server package, or null where it isn't installed */
function loadRouterPackage() {
    try {
        return require(SERVER_PACKAGE);
    } catch (error) {
        if (error.code !== 'MODULE_NOT_FOUND') throw error;
        return null;
    }
}

/**
 * The student asking about `course`: their pseudonymous id, marked `preview`
 * for "View as Student". userHasCourseAccess gives a preview exactly the
 * course its id names, and a real student only an active course they're
 * enrolled in.
 */
async function learnerIn(db, user, course) {
    if (!user || user.role !== 'student' || typeof user.userId !== 'string' || user.userId === '') return null;
    if (!(await CourseModel.userHasCourseAccess(db, course, user.userId, 'student'))) return null;
    return { id: user.userId, preview: user.isPreview === true };
}

/** A system admin, or one of the course's instructors. Never a preview, which is a student. */
async function isCourseInstructor(db, user, course) {
    if (!user || user.isPreview === true) return false;
    if (hasSystemAdminAccess(user)) return true;
    return user.role === 'instructor' && CourseModel.userHasCourseAccess(db, course, user.userId, 'instructor');
}

/** One of the course's TAs. */
async function isCourseTa(db, user, course) {
    if (!user || user.isPreview === true || user.role !== 'ta') return false;
    return CourseModel.userHasCourseAccess(db, course, user.userId, 'ta');
}

/**
 * "Describe it" with the course's own AI model, or nothing (the built-in
 * drafter) where the course has no usable model or key.
 */
async function courseDrafter(req, course, logger = console) {
    const registry = req.app.locals.llmRegistry;
    if (!registry) return null;
    let ai;
    try {
        ai = await registry.forCourse(req.app.locals.db, course);
    } catch (error) {
        logger.warn?.('⚠️ [GAMIFICATION] No AI model for "describe it"; using the built-in drafter:', error && error.message);
        return null;
    }
    if (!ai || !ai.llm) return null;
    return {
        complete: async ({ system, user }) => {
            const response = await ai.llm.sendMessage(user, {
                lane: LANES.BACKEND,
                systemPrompt: system,
                temperature: 0.1,
                maxTokens: DRAFT_MAX_TOKENS
            });
            return (response && response.content) || '';
        }
    };
}

/**
 * BiocBot's gamification routes, or null where the toolkit's server package
 * isn't installed or gamification isn't counting.
 *
 * Who may do what is read through `req.app.locals.db`, the database every
 * other route uses, so courses and enrollment read the same here as anywhere.
 *
 * @param {{
 *   gamification: any,
 *   logger?: Pick<Console, 'error' | 'warn'>,
 *   toolkit?: any,
 *   courseOn?: (db: any, course: string) => Promise<boolean>,
 *   setCourseOn?: (db: any, course: string, on: boolean, userId?: string) => Promise<boolean>
 * }} options
 * @returns {import('express').Router | null}
 */
function createGamificationRoutes({
    gamification,
    logger = console,
    toolkit = loadRouterPackage(),
    courseOn = gamificationService.isCourseOn,
    setCourseOn = gamificationService.setCourseOn
}) {
    if (!toolkit || !gamification) return null;
    const dbOf = req => req.app.locals.db;
    const router = express.Router();
    router.use(express.json());

    router.get('/courses/:course/enabled', async (req, res, next) => {
        try {
            const db = dbOf(req);
            const { course } = req.params;
            const canChange = await isCourseInstructor(db, req.user, course);
            const inCourse = canChange || (await isCourseTa(db, req.user, course)) || (await learnerIn(db, req.user, course)) !== null;
            if (!inCourse) return res.status(403).json({ error: "You aren't in this course." });
            res.set('Cache-Control', 'no-store');
            return res.json({ running: true, enabled: await courseOn(db, course), canChange });
        } catch (error) {
            return next(error);
        }
    });

    router.put('/courses/:course/enabled', async (req, res, next) => {
        try {
            const db = dbOf(req);
            const { course } = req.params;
            if (!(await isCourseInstructor(db, req.user, course))) {
                return res.status(403).json({ error: "You can't turn gamification on or off in this course." });
            }
            const enabled = req.body && req.body.enabled;
            if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'Send enabled: true or false.' });
            if (!(await setCourseOn(db, course, enabled, req.user.userId))) return res.status(404).json({ error: 'No such course.' });
            return res.json({ running: true, enabled, canChange: true });
        } catch (error) {
            return next(error);
        }
    });

    router.use(toolkit.createGamificationRouter({
        gamification,
        // A course that hasn't turned gamification on has no awards to show.
        learner: async (req, course) => ((await courseOn(dbOf(req), course)) ? learnerIn(dbOf(req), req.user, course) : null),
        canEditRules: (req, course) => isCourseInstructor(dbOf(req), req.user, course),
        canViewRules: async (req, course) =>
            (await isCourseInstructor(dbOf(req), req.user, course)) || isCourseTa(dbOf(req), req.user, course),
        drafter: (req, course) => courseDrafter(req, course, logger),
        logger
    }));

    // The switch's own failures answer like the toolkit's: a short message,
    // never the app's error page.
    // eslint-disable-next-line no-unused-vars
    router.use((error, req, res, next) => {
        logger.error('❌ [GAMIFICATION] A request failed:', error && error.message);
        res.status(500).json({ error: 'Gamification could not do that. Nothing else in the app was affected.' });
    });
    return router;
}

/**
 * Where gamification isn't running (BIOCBOT_GAMIFICATION unset, or the
 * toolkit isn't installed), the one route every page asks, answered with a
 * plain no: pages add no gamification link, and the browser logs no 404.
 *
 * @returns {import('express').Router}
 */
function createGamificationOffRoutes() {
    const router = express.Router();
    router.get('/courses/:course/enabled', (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.json({ running: false, enabled: false, canChange: false });
    });
    return router;
}

module.exports = {
    SERVER_PACKAGE,
    loadRouterPackage,
    learnerIn,
    isCourseInstructor,
    isCourseTa,
    courseDrafter,
    createGamificationRoutes,
    createGamificationOffRoutes
};
