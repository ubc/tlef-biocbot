let academicApiClient = null;

function loadCourseListSyncModule() {
    try {
        return require('@ubc/ubc-genai-toolkit-course-list-sync');
    } catch (error) {
        if (error.code !== 'MODULE_NOT_FOUND') {
            throw error;
        }
    }

    const error = new Error(
        'UBC course list sync toolkit is not installed. Install @ubc/ubc-genai-toolkit-course-list-sync before using academic sync.'
    );
    error.code = 'ACADEMIC_API_TOOLKIT_MISSING';
    throw error;
}

function createAcademicApiClient() {
    const { CourseListSyncModule } = loadCourseListSyncModule();
    const usingMock = process.env.UBC_API_USE_MOCK === 'true';

    return new CourseListSyncModule({
        clientId: process.env.UBC_API_CLIENT_ID || (usingMock ? 'mock-client' : undefined),
        clientSecret: process.env.UBC_API_CLIENT_SECRET || (usingMock ? 'mock-secret' : undefined),
        env: process.env.UBC_API_ENV || 'dev'
    });
}

function getAcademicApiClient() {
    if (!academicApiClient) {
        academicApiClient = createAcademicApiClient();
    }

    return academicApiClient;
}

function setAcademicApiClientForTests(client) {
    academicApiClient = client;
}

/**
 * Instance-wide product gate for every academic-API feature (Class List Sync,
 * roster-driven student enrolment, instructor-of-record join, "set up another
 * section"). Stored on the `global` settings doc alongside `allowLocalLogin`,
 * and defaults OFF so staging/prod — where no academic API is wired up yet —
 * behave exactly as they did before this feature landed.
 *
 * Fails closed: a missing setting, missing db, or any read error all resolve to
 * false, so the feature can never accidentally turn itself on.
 */
async function isAcademicApiEnabled(db) {
    if (!db) return false;

    try {
        const settings = await db.collection('settings').findOne(
            { _id: 'global' },
            { projection: { academicApiEnabled: 1 } }
        );
        return !!(settings && settings.academicApiEnabled);
    } catch (error) {
        console.error('Failed to read academicApiEnabled setting:', error.message);
        return false;
    }
}

module.exports = {
    createAcademicApiClient,
    getAcademicApiClient,
    setAcademicApiClientForTests,
    isAcademicApiEnabled
};
