const express = require('express');
const router = express.Router();
const CourseModel = require('../models/Course');
const { getAcademicApiClient } = require('../services/academicApi');
const { syncCourseRoster } = require('../services/academicRosterSync');

router.use(express.json());

function getAcademicApi(req) {
    return req.app.locals.academicApi || getAcademicApiClient();
}

function getDisplayValue(value, preferredKeys = ['code', 'description', 'name', 'value', 'id']) {
    if (value == null) return '';
    if (typeof value === 'string' || typeof value === 'number') return String(value);
    if (typeof value !== 'object') return '';

    for (const key of preferredKeys) {
        if (value[key] != null && typeof value[key] !== 'object') {
            return String(value[key]);
        }
    }

    return '';
}

function getSectionId(section = {}) {
    return section.courseSectionId || section.id || section.sectionId || section.referenceId || '';
}

function normalizeSectionForPicker(section = {}) {
    const subject = getDisplayValue(section.course?.courseSubject || section.courseSubject || section.subjectCode);
    const number = getDisplayValue(section.course?.courseNumber || section.courseNumber);
    const sectionNumber = getDisplayValue(section.sectionNumber || section.courseSectionNumber || section.number);
    const title = getDisplayValue(section.course?.courseTitle || section.courseTitle || section.course?.title || section.title, ['description', 'name', 'value', 'code']);
    const displayName = [subject, number, sectionNumber ? `Section ${sectionNumber}` : '']
        .filter(Boolean)
        .join(' ') || title || getSectionId(section) || 'Unnamed section';

    return {
        ...section,
        picker: {
            sectionId: getSectionId(section),
            displayName,
            meta: [
                getSectionId(section),
                getDisplayValue(section.sectionStatus || section.status, ['description', 'name', 'code', 'value']),
                title
            ].filter(Boolean).join(' · ')
        }
    };
}

// Map of academic section id -> the first non-deleted course linked to it, so we
// can tell which sections already have a BiocBot course (one course per section).
async function getLinkedSectionCourseMap(db) {
    const courses = await db.collection('courses').find(
        { status: { $ne: 'deleted' }, 'academicSync.sectionIds.0': { $exists: true } },
        { projection: { courseId: 1, 'academicSync.sectionIds': 1 } }
    ).toArray();

    const map = new Map();
    for (const course of courses) {
        for (const sectionId of (course.academicSync?.sectionIds || [])) {
            if (!map.has(sectionId)) {
                map.set(sectionId, course.courseId);
            }
        }
    }
    return map;
}

async function requireInstructorCourse(req, res, courseId) {
    const db = req.app.locals.db;
    const user = req.user;

    if (!db) {
        res.status(503).json({ success: false, message: 'Database connection not available' });
        return null;
    }

    if (!user || user.role !== 'instructor') {
        res.status(403).json({ success: false, message: 'Only instructors can manage academic roster sync' });
        return null;
    }

    const course = await CourseModel.getCourseById(db, courseId);
    if (!course || course.status === 'deleted') {
        res.status(404).json({ success: false, message: 'Course not found' });
        return null;
    }

    const hasAccess = course.instructorId === user.userId ||
        (Array.isArray(course.instructors) && course.instructors.includes(user.userId));

    if (!hasAccess) {
        res.status(403).json({ success: false, message: 'You can only manage sync for your own courses' });
        return null;
    }

    return course;
}

router.get('/academic-periods', async (req, res) => {
    try {
        const campus = req.query.campus || process.env.UBC_API_DEFAULT_CAMPUS || 'V';
        const periods = await getAcademicApi(req).getAcademicPeriods(campus);

        return res.json({
            success: true,
            data: periods
        });
    } catch (error) {
        console.error('Error fetching academic periods:', error);
        return res.status(error.code === 'ACADEMIC_API_TOOLKIT_MISSING' ? 503 : 502).json({
            success: false,
            message: error.message || 'Failed to fetch academic periods'
        });
    }
});

router.get('/instructor-sections', async (req, res) => {
    try {
        const user = req.user;
        const academicPeriod = req.query.academicPeriod || process.env.UBC_API_CURRENT_ACADEMIC_PERIOD;

        if (!user || user.role !== 'instructor') {
            return res.status(403).json({ success: false, message: 'Only instructors can fetch instructor sections' });
        }

        if (!user.puid) {
            return res.status(400).json({
                success: false,
                message: 'Your account is missing a PUID from CWL/Shibboleth'
            });
        }

        if (!academicPeriod) {
            return res.status(400).json({ success: false, message: 'academicPeriod is required' });
        }

        const sections = await getAcademicApi(req).getInstructorSections(user.puid, academicPeriod);

        // Flag sections that already have a BiocBot course linked to them, so the
        // picker can mark them "Already set up" and prevent creating duplicates.
        const db = req.app.locals.db;
        const linkedSectionCourses = db ? await getLinkedSectionCourseMap(db) : new Map();

        return res.json({
            success: true,
            data: (sections || []).map((section) => {
                const normalized = normalizeSectionForPicker(section);
                const linkedCourseId = linkedSectionCourses.get(normalized.picker.sectionId) || null;
                normalized.picker.alreadySetUp = !!linkedCourseId;
                normalized.picker.linkedCourseId = linkedCourseId;
                return normalized;
            })
        });
    } catch (error) {
        console.error('Error fetching instructor sections:', error);
        return res.status(error.code === 'ACADEMIC_API_TOOLKIT_MISSING' ? 503 : 502).json({
            success: false,
            message: error.message || 'Failed to fetch instructor sections'
        });
    }
});

router.get('/courses/:courseId', async (req, res) => {
    try {
        const course = await requireInstructorCourse(req, res, req.params.courseId);
        if (!course) return;

        return res.json({
            success: true,
            data: {
                courseId: course.courseId,
                academicSync: course.academicSync || null
            }
        });
    } catch (error) {
        console.error('Error reading academic sync status:', error);
        return res.status(500).json({ success: false, message: 'Failed to read academic sync status' });
    }
});

router.put('/courses/:courseId/link', async (req, res) => {
    try {
        const db = req.app.locals.db;
        const course = await requireInstructorCourse(req, res, req.params.courseId);
        if (!course) return;

        const sectionIds = Array.isArray(req.body.sectionIds)
            ? req.body.sectionIds.map((value) => String(value || '').trim()).filter(Boolean)
            : [];
        const academicPeriod = String(req.body.academicPeriod || '').trim();

        if (!academicPeriod) {
            return res.status(400).json({ success: false, message: 'academicPeriod is required' });
        }

        if (sectionIds.length === 0) {
            return res.status(400).json({ success: false, message: 'Select at least one section' });
        }

        const now = new Date();
        const academicSync = {
            ...(course.academicSync || {}),
            academicPeriod,
            sectionIds,
            linkedAt: now,
            linkedBy: req.user.userId
        };

        await db.collection('courses').updateOne(
            { courseId: course.courseId },
            { $set: { academicSync, updatedAt: now } }
        );

        return res.json({
            success: true,
            message: 'Academic sections linked',
            data: { courseId: course.courseId, academicSync }
        });
    } catch (error) {
        console.error('Error linking academic sections:', error);
        return res.status(500).json({ success: false, message: 'Failed to link academic sections' });
    }
});

router.post('/courses/:courseId/sync', async (req, res) => {
    try {
        const db = req.app.locals.db;
        const course = await requireInstructorCourse(req, res, req.params.courseId);
        if (!course) return;

        const result = await syncCourseRoster(db, course.courseId, {
            academicApi: getAcademicApi(req),
            academicPeriod: req.body.academicPeriod,
            sectionIds: req.body.sectionIds
        });

        if (!result.success) {
            return res.status(400).json({ success: false, message: result.error || 'Roster sync failed' });
        }

        return res.json({
            success: true,
            message: 'Roster synced',
            data: result
        });
    } catch (error) {
        console.error('Error syncing academic roster:', error);
        return res.status(error.code === 'ACADEMIC_API_TOOLKIT_MISSING' ? 503 : 502).json({
            success: false,
            message: error.message || 'Failed to sync academic roster'
        });
    }
});

module.exports = router;
