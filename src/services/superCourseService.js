const QdrantService = require('./qdrantService');
const prompts = require('./prompts');
const CourseModel = require('../models/Course');

const SUPER_COURSE_SETTINGS_ID = 'superCourseChat';

function resolveSuperCourseChatSettings(settingsDoc = {}) {
    const defaults = prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS;

    return {
        studentTopK: CourseModel.normalizeRagTopK(settingsDoc.studentTopK, defaults.studentTopK),
        instructorTopK: CourseModel.normalizeRagTopK(settingsDoc.instructorTopK, defaults.instructorTopK),
        includeInactiveCourses: settingsDoc.includeInactiveCourses === true,
        showStudentSuperCourse: settingsDoc.showStudentSuperCourse === true,
        instructorPrompt: typeof settingsDoc.instructorPrompt === 'string' && settingsDoc.instructorPrompt.trim()
            ? settingsDoc.instructorPrompt
            : defaults.instructorPrompt,
        studentPrompt: typeof settingsDoc.studentPrompt === 'string' && settingsDoc.studentPrompt.trim()
            ? settingsDoc.studentPrompt
            : defaults.studentPrompt
    };
}

async function getSuperCourseChatSettings(db) {
    const settingsDoc = await db.collection('settings').findOne({ _id: SUPER_COURSE_SETTINGS_ID });
    return resolveSuperCourseChatSettings(settingsDoc || {});
}

function buildSuperCoursePoolQuery(includeInactiveCourses = false) {
    const query = {
        allowInSuperCourse: { $ne: false },
        status: { $ne: 'deleted' }
    };

    if (!includeInactiveCourses) {
        query.$or = [
            { status: { $exists: false } },
            { status: null },
            { status: 'active' }
        ];
    }

    return query;
}

async function getSuperCourseRetrievalPool(db, options = {}) {
    const includeInactiveCourses = options.includeInactiveCourses === true;
    const courses = await db.collection('courses')
        .find(buildSuperCoursePoolQuery(includeInactiveCourses), {
            projection: {
                courseId: 1,
                courseName: 1,
                courseCode: 1,
                status: 1
            }
        })
        .sort({ courseName: 1, courseId: 1 })
        .toArray();

    return courses.filter(course => course && course.courseId);
}

async function searchSuperCourse(db, query, limit, options = {}) {
    const pool = await getSuperCourseRetrievalPool(db, options);
    const courseIds = pool.map(course => course.courseId);

    if (courseIds.length === 0) {
        return { pool, results: [] };
    }

    const qdrant = new QdrantService();
    await qdrant.initialize();
    const results = await qdrant.searchDocuments(query, { courseId: courseIds }, limit);

    return { pool, results };
}

function buildCourseNameLookup(pool = []) {
    return new Map(pool.map(course => [
        course.courseId,
        course.courseName || course.courseCode || course.courseId
    ]));
}

function buildSuperCourseContext(searchResults = [], pool = []) {
    const courseNameById = buildCourseNameLookup(pool);
    return searchResults
        .map(result => {
            const courseName = courseNameById.get(result.courseId) || result.courseId || 'Unknown course';
            const lectureName = result.lectureName || 'Unknown unit';
            const fileName = result.fileName || 'Unknown source';
            return `From ${courseName} / ${lectureName} (${fileName}):\n${result.chunkText || ''}`;
        })
        .join('\n\n---\n\n');
}

function buildSuperCoursePoolSummary(pool = []) {
    if (!pool.length) {
        return 'No courses are currently included in the Super Course source pool.';
    }

    return pool
        .map(course => `${course.courseName || course.courseCode || course.courseId} (${course.courseId})`)
        .join('; ');
}

function buildSuperCourseCitations(searchResults = [], pool = []) {
    const courseNameById = buildCourseNameLookup(pool);
    return searchResults.map(result => ({
        courseId: result.courseId || null,
        courseName: courseNameById.get(result.courseId) || result.courseId || null,
        lectureName: result.lectureName || null,
        fileName: result.fileName || null,
        documentId: result.documentId || null,
        score: result.score
    }));
}

function buildSuperCourseSourceAttribution(searchResults = [], pool = []) {
    const poolCourses = pool.map(course => ({
        courseId: course.courseId,
        courseName: course.courseName || course.courseCode || course.courseId,
        status: course.status || null
    }));

    if (!searchResults.length) {
        return {
            source: 'general-biochemistry',
            description: poolCourses.length
                ? 'No indexed Super Course chunks were retrieved for this question'
                : 'No courses are currently included in the Super Course source pool',
            documents: [],
            poolCourses
        };
    }

    const courseNameById = buildCourseNameLookup(pool);
    const seen = new Set();
    const documents = [];

    for (const result of searchResults) {
        const key = result.documentId || `${result.courseId}:${result.lectureName}:${result.fileName}`;
        if (seen.has(key)) continue;
        seen.add(key);

        documents.push({
            courseId: result.courseId || null,
            courseName: courseNameById.get(result.courseId) || result.courseId || null,
            unitName: result.lectureName || null,
            documentId: result.documentId || null,
            fileName: result.fileName || null,
            documentType: result.documentType || result.type || null,
            score: result.score
        });
    }

    const description = documents
        .slice(0, 3)
        .map(doc => `${doc.courseName || doc.courseId || 'Course'}${doc.unitName ? ` / ${doc.unitName}` : ''}`)
        .join('; ');

    return {
        source: 'super-course',
        description: description ? `From: ${description}` : 'From uploaded Super Course material',
        documents,
        poolCourses
    };
}

module.exports = {
    SUPER_COURSE_SETTINGS_ID,
    resolveSuperCourseChatSettings,
    getSuperCourseChatSettings,
    buildSuperCoursePoolQuery,
    getSuperCourseRetrievalPool,
    searchSuperCourse,
    buildSuperCourseContext,
    buildSuperCoursePoolSummary,
    buildSuperCourseCitations,
    buildSuperCourseSourceAttribution
};
