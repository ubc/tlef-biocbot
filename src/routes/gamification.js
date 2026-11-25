/**
 * /api/gamification: the gamification toolkit's router
 * (@ubc/genai-toolkit-gamification-server), with BiocBot's own answers to
 * "who is asking?". Mounted by src/server.js only while gamification is
 * counting (BIOCBOT_GAMIFICATION=1, src/services/gamification.js), after
 * sign-in. There is no page using it yet.
 *
 * Every route is under /courses/:course (the toolkit's README lists them):
 *
 * - A student reads only their own awards (GET /me) and can hide
 *   gamification (PUT /me/opt-out). "View as Student" sees the student view,
 *   but its opt-out isn't saved.
 * - The course's instructors (and system admins) see and change its rules.
 * - The course's TAs see its rules without changing them, as the toolkit's
 *   PRD has TAs read-only.
 *
 * No route takes a student's id, so nobody can read another student's awards.
 */

const CourseModel = require('../models/Course');
const { hasSystemAdminAccess } = require('../services/authorization');

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
 * BiocBot's gamification router, or null where the toolkit's server package
 * isn't installed or gamification isn't counting.
 *
 * Who may do what is read through `req.app.locals.db`, the database every
 * other route uses, so courses and enrollment read the same here as anywhere.
 *
 * @param {{ gamification: any, logger?: Pick<Console, 'error'>, toolkit?: any }} options
 * @returns {import('express').Router | null}
 */
function createGamificationRoutes({ gamification, logger = console, toolkit = loadRouterPackage() }) {
    if (!toolkit || !gamification) return null;
    const dbOf = req => req.app.locals.db;
    return toolkit.createGamificationRouter({
        gamification,
        learner: (req, course) => learnerIn(dbOf(req), req.user, course),
        canEditRules: (req, course) => isCourseInstructor(dbOf(req), req.user, course),
        canViewRules: async (req, course) =>
            (await isCourseInstructor(dbOf(req), req.user, course)) || isCourseTa(dbOf(req), req.user, course),
        logger
    });
}

module.exports = {
    SERVER_PACKAGE,
    loadRouterPackage,
    learnerIn,
    isCourseInstructor,
    isCourseTa,
    createGamificationRoutes
};
