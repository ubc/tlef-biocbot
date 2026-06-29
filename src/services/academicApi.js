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

module.exports = {
    createAcademicApiClient,
    getAcademicApiClient,
    setAcademicApiClientForTests
};
