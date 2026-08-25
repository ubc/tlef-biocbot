/**
 * Settings Routes
 * Handles settings-related API endpoints
 */

const express = require('express');
const router = express.Router();
const { normalizeErrorResponses } = require('../middleware/apiResponse');
const prompts = require('../services/prompts');
const flashcardService = require('../services/flashcardService');
const CourseModel = require('../models/Course');
const SuperchatModel = require('../models/Superchat');
const { hasSystemAdminAccess, normalizeEmail } = require('../services/authorization');
const {
    adminCatalogForProvider,
    catalogForProvider,
    configuredDefaultModel,
    configuredProvider,
    isAllowedEmbeddingModel,
    normalizeReasoningEffort,
    supportsReasoning
} = require('../services/llmModels');
const {
    activeProviderOf,
    buildKeySubdocument,
    credentialForProvider,
    decryptApiKey,
    publicKeySummary,
    publicProviderKeyState,
    validateApiKey
} = require('../services/llmKeyStore');
const adminModelSettings = require('../services/adminModelSettings');
const scopeModelSettings = require('../services/scopeModelSettings');
const providerKeys = require('../services/providerKeyService');
const migrations = require('../services/providerMigrationService');
const migrationRunner = require('../services/providerMigrationRunner');
const superCourse = require('../services/superCourseService');
const {
    PROVIDERS,
    SELECTABLE_PROVIDERS,
    normalizeProvider,
    providerCatalog,
    providerLabel
} = require('../services/llmProviders');
const { buildEmbeddingProfile } = require('../services/embeddingConfig');
const {
    listSystemAdmins,
    grantSystemAdminByEmail,
    revokeSystemAdminByEmail
} = require('../services/systemAdmin');

router.use(normalizeErrorResponses);
const { isAcademicApiEnabled } = require('../services/academicApi');

function requireSystemAdmin(req, res) {
    if (!req.user) {
        res.status(401).json({ success: false, error: 'Not authenticated' });
        return false;
    }

    if (!hasSystemAdminAccess(req.user)) {
        res.status(403).json({ success: false, error: 'Access denied' });
        return false;
    }

    return true;
}

function requestedLlmScope(req) {
    const source = req.method === 'GET' ? req.query : (req.body || {});
    const type = source.scopeType;
    const id = source.scopeId;
    if (!type && !id) return null;
    if (!['course', 'superchat', 'notes', 'superCourseChat'].includes(type) || !id) {
        const error = new Error('A valid model-settings scopeType and scopeId are required.');
        error.code = 'INVALID_LLM_SCOPE';
        throw error;
    }
    return { type, id };
}

async function allModelSettings(db, scope) {
    return scope
        ? scopeModelSettings.getAll(db, scope)
        : adminModelSettings.getAllProviderSettings(db, { force: true, throwOnError: true });
}

async function oneModelSettings(db, scope, provider) {
    return scope
        ? scopeModelSettings.getProviderSettings(db, scope, provider)
        : adminModelSettings.getProviderSettings(db, provider, { force: true });
}

function scopedModelRoster(settings = {}) {
    return settings.modelsDiscovered === true && (!settings.availableModels || settings.availableModels.length === 0)
        ? ['__no_models_available__']
        : (settings.availableModels || []);
}

const SUPER_COURSE_SETTINGS_ID = 'superCourseChat';

function normalizeTopKForSettings(value) {
    return CourseModel.normalizeRagTopK(value, null);
}

function buildAiSettingsResponse(course) {
    return {
        superchatIds: CourseModel.getCourseSuperchatIds(course),
        ragSettings: CourseModel.resolveRagSettings(course),
        defaults: {
            studentTopK: CourseModel.DEFAULT_STUDENT_RAG_TOP_K,
            minTopK: CourseModel.MIN_RAG_TOP_K,
            maxTopK: CourseModel.MAX_RAG_TOP_K
        }
    };
}

function normalizeNoteRatioForSettings(value, fallback) {
    const num = Number(value);
    if (!Number.isFinite(num) || num < 0 || num > 1) return fallback;
    // Snap to 2 decimals to keep stored values clean.
    return Math.round(num * 100) / 100;
}

// Keep only known level keys; empty strings are allowed (middle = neutral baseline).
function normalizeLevelModifiersForSettings(value, keys, defaults) {
    const source = value && typeof value === 'object' ? value : {};
    const result = {};
    for (const key of keys) {
        result[key] = typeof source[key] === 'string' ? source[key] : defaults[key];
    }
    return result;
}

function resolveSuperCourseChatSettings(settingsDoc = {}) {
    const defaults = prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS;
    return {
        studentTopK: CourseModel.normalizeRagTopK(settingsDoc.studentTopK, defaults.studentTopK),
        instructorTopK: CourseModel.normalizeRagTopK(settingsDoc.instructorTopK, defaults.instructorTopK),
        includeInactiveCourses: settingsDoc.includeInactiveCourses === true,
        showStudentSuperCourse: settingsDoc.showStudentSuperCourse === true,
        includeNotesInRetrieval: settingsDoc.includeNotesInRetrieval !== false,
        noteRetrievalRatio: normalizeNoteRatioForSettings(settingsDoc.noteRetrievalRatio, defaults.noteRetrievalRatio),
        noteMinScore: normalizeNoteRatioForSettings(settingsDoc.noteMinScore, defaults.noteMinScore),
        instructorPrompt: typeof settingsDoc.instructorPrompt === 'string' && settingsDoc.instructorPrompt.trim()
            ? settingsDoc.instructorPrompt
            : defaults.instructorPrompt,
        studentPrompt: typeof settingsDoc.studentPrompt === 'string' && settingsDoc.studentPrompt.trim()
            ? settingsDoc.studentPrompt
            : defaults.studentPrompt,
        studentLevelModifiers: normalizeLevelModifiersForSettings(
            settingsDoc.studentLevelModifiers,
            prompts.STUDENT_LEVEL_KEYS,
            defaults.studentLevelModifiers
        ),
        instructorLevelModifiers: normalizeLevelModifiersForSettings(
            settingsDoc.instructorLevelModifiers,
            prompts.INSTRUCTOR_LEVEL_KEYS,
            defaults.instructorLevelModifiers
        )
    };
}

function buildSuperCourseChatDefaults() {
    return {
        ...prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS,
        minTopK: CourseModel.MIN_RAG_TOP_K,
        maxTopK: CourseModel.MAX_RAG_TOP_K
    };
}

// Allow the course's own instructor OR a system admin to manage a course's
// settings. Admins short-circuit; otherwise ownership is verified.
async function requireCourseSettingsAccess(db, req, res, courseId) {
    if (req.user && hasSystemAdminAccess(req.user)) return true;
    return requireInstructorForCourseSettings(db, req, res, courseId);
}

async function requireInstructorForCourseSettings(db, req, res, courseId) {
    if (!req.user) {
        res.status(401).json({ success: false, error: 'Not authenticated' });
        return false;
    }

    if (req.user.role !== 'instructor') {
        res.status(403).json({ success: false, error: 'Instructor access required' });
        return false;
    }

    // Distinguish "course does not exist" (400) from "course exists but you can't touch it" (403).
    const existing = await db.collection('courses').findOne(
        { courseId, status: { $ne: 'deleted' } },
        { projection: { instructorId: 1, instructors: 1 } }
    );

    if (!existing) {
        res.status(400).json({ success: false, message: 'Course not found' });
        return false;
    }

    const owns = existing.instructorId === req.user.userId
        || (Array.isArray(existing.instructors) && existing.instructors.includes(req.user.userId));

    if (!owns) {
        res.status(403).json({ success: false, error: 'Access denied for this course' });
        return false;
    }

    return true;
}

/**
 * GET /api/settings/can-delete-all
 * Check if the current user has system admin access
 */
router.get('/can-delete-all', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                error: 'Not authenticated',
                canDeleteAll: false
            });
        }

        const canDeleteAll = hasSystemAdminAccess(req.user);

        res.json({
            success: true,
            canDeleteAll,
            isSystemAdmin: canDeleteAll
        });

    } catch (error) {
        console.error('Error checking delete all permission:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to check delete all permission',
            canDeleteAll: false
        });
    }
});

router.get('/system-admins', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const admins = await listSystemAdmins(db);

        res.json({
            success: true,
            admins
        });
    } catch (error) {
        console.error('Error fetching system admins:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch system admins'
        });
    }
});

router.post('/system-admins', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const email = normalizeEmail(req.body && req.body.email);
        const result = await grantSystemAdminByEmail(db, email, {
            grantedBy: normalizeEmail(req.user.email)
        });

        if (!result.success) {
            return res.status(400).json(result);
        }

        res.json({
            success: true,
            email: result.email,
            message: 'System admin access granted.'
        });
    } catch (error) {
        console.error('Error granting system admin access:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to grant system admin access'
        });
    }
});

router.post('/system-admins/revoke', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const email = normalizeEmail(req.body && req.body.email);
        const result = await revokeSystemAdminByEmail(db, email);

        if (!result.success) {
            return res.status(400).json(result);
        }

        res.json({
            success: true,
            email: result.email,
            message: 'System admin access revoked.'
        });
    } catch (error) {
        console.error('Error revoking system admin access:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to revoke system admin access'
        });
    }
});

router.get('/ai-settings', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const courseId = req.query.courseId;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        if (!(await requireCourseSettingsAccess(db, req, res, courseId))) {
            return;
        }

        const course = await db.collection('courses').findOne(
            { courseId, status: { $ne: 'deleted' } },
            { projection: { courseId: 1, ragSettings: 1, superchatIds: 1 } }
        );

        if (!course) {
            return res.status(404).json({ success: false, message: 'Course not found' });
        }

        // Include the available buckets so the per-course checklist can render
        // names + current membership in one round-trip.
        const buckets = await SuperchatModel.listSuperchats(db);

        res.json({
            success: true,
            courseId,
            settings: buildAiSettingsResponse(course),
            availableSuperchats: buckets.map(b => ({
                superchatId: b.superchatId,
                name: b.name,
                yearLevel: b.yearLevel ?? null
            }))
        });
    } catch (error) {
        console.error('Error fetching AI settings:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch AI settings' });
    }
});

router.put('/ai-settings', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const { courseId, superchatIds, studentTopK } = req.body || {};
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        if (!(await requireCourseSettingsAccess(db, req, res, courseId))) {
            return;
        }

        const topK = normalizeTopKForSettings(studentTopK);
        if (topK === null) {
            return res.status(400).json({
                success: false,
                message: `Student Chat Top-K must be an integer from ${CourseModel.MIN_RAG_TOP_K} to ${CourseModel.MAX_RAG_TOP_K}`
            });
        }

        const normalizedSuperchatIds = CourseModel.normalizeSuperchatIds(superchatIds);

        const result = await db.collection('courses').updateOne(
            { courseId, status: { $ne: 'deleted' } },
            {
                $set: {
                    superchatIds: normalizedSuperchatIds,
                    'ragSettings.student.topK': topK,
                    updatedAt: new Date(),
                    lastUpdatedById: req.user.userId
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: 'Course not found' });
        }

        res.json({
            success: true,
            courseId,
            message: 'AI settings saved',
            settings: {
                superchatIds: normalizedSuperchatIds,
                ragSettings: { student: { topK } },
                defaults: buildAiSettingsResponse({}).defaults
            }
        });
    } catch (error) {
        console.error('Error saving AI settings:', error);
        res.status(500).json({ success: false, message: 'Failed to save AI settings' });
    }
});

router.post('/ai-settings/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const { courseId } = req.body || {};
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        if (!(await requireCourseSettingsAccess(db, req, res, courseId))) {
            return;
        }

        const result = await db.collection('courses').updateOne(
            { courseId, status: { $ne: 'deleted' } },
            {
                $set: {
                    superchatIds: [],
                    'ragSettings.student.topK': CourseModel.DEFAULT_STUDENT_RAG_TOP_K,
                    updatedAt: new Date(),
                    lastUpdatedById: req.user.userId
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ success: false, message: 'Course not found' });
        }

        res.json({
            success: true,
            courseId,
            message: 'AI settings reset to defaults',
            settings: {
                superchatIds: [],
                ragSettings: { student: { topK: CourseModel.DEFAULT_STUDENT_RAG_TOP_K } },
                defaults: buildAiSettingsResponse({}).defaults
            }
        });
    } catch (error) {
        console.error('Error resetting AI settings:', error);
        res.status(500).json({ success: false, message: 'Failed to reset AI settings' });
    }
});

router.get('/super-course-chat', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const settingsDoc = await db.collection('settings').findOne({ _id: SUPER_COURSE_SETTINGS_ID });
        res.json({
            success: true,
            settings: resolveSuperCourseChatSettings(settingsDoc || {}),
            defaults: buildSuperCourseChatDefaults()
        });
    } catch (error) {
        console.error('Error fetching super course chat settings:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch super course chat settings' });
    }
});

router.put('/super-course-chat', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const body = req.body || {};
        const studentTopK = normalizeTopKForSettings(body.studentTopK);
        const instructorTopK = normalizeTopKForSettings(body.instructorTopK);

        if (studentTopK === null || instructorTopK === null) {
            return res.status(400).json({
                success: false,
                message: `Top-K values must be integers from ${CourseModel.MIN_RAG_TOP_K} to ${CourseModel.MAX_RAG_TOP_K}`
            });
        }

        if (typeof body.instructorPrompt !== 'string' || !body.instructorPrompt.trim()
            || typeof body.studentPrompt !== 'string' || !body.studentPrompt.trim()) {
            return res.status(400).json({ success: false, message: 'Instructor and student prompts are required' });
        }

        const settings = {
            studentTopK,
            instructorTopK,
            includeInactiveCourses: body.includeInactiveCourses === true,
            showStudentSuperCourse: body.showStudentSuperCourse === true,
            includeNotesInRetrieval: body.includeNotesInRetrieval !== false,
            noteRetrievalRatio: normalizeNoteRatioForSettings(
                body.noteRetrievalRatio,
                prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS.noteRetrievalRatio
            ),
            noteMinScore: normalizeNoteRatioForSettings(
                body.noteMinScore,
                prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS.noteMinScore
            ),
            instructorPrompt: body.instructorPrompt,
            studentPrompt: body.studentPrompt,
            studentLevelModifiers: normalizeLevelModifiersForSettings(
                body.studentLevelModifiers,
                prompts.STUDENT_LEVEL_KEYS,
                prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS.studentLevelModifiers
            ),
            instructorLevelModifiers: normalizeLevelModifiersForSettings(
                body.instructorLevelModifiers,
                prompts.INSTRUCTOR_LEVEL_KEYS,
                prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS.instructorLevelModifiers
            )
        };

        await db.collection('settings').updateOne(
            { _id: SUPER_COURSE_SETTINGS_ID },
            {
                $set: {
                    ...settings,
                    updatedAt: new Date(),
                    updatedBy: normalizeEmail(req.user.email)
                },
                $setOnInsert: { createdAt: new Date() }
            },
            { upsert: true }
        );

        res.json({
            success: true,
            message: 'Super Course chat settings saved',
            settings
        });
    } catch (error) {
        console.error('Error saving super course chat settings:', error);
        res.status(500).json({ success: false, message: 'Failed to save super course chat settings' });
    }
});

router.post('/super-course-chat/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const settings = { ...prompts.DEFAULT_SUPER_COURSE_CHAT_SETTINGS };
        await db.collection('settings').updateOne(
            { _id: SUPER_COURSE_SETTINGS_ID },
            {
                $set: {
                    ...settings,
                    updatedAt: new Date(),
                    updatedBy: normalizeEmail(req.user.email)
                },
                $setOnInsert: { createdAt: new Date() }
            },
            { upsert: true }
        );

        res.json({
            success: true,
            message: 'Super Course chat settings reset to defaults',
            settings,
            defaults: buildSuperCourseChatDefaults()
        });
    } catch (error) {
        console.error('Error resetting super course chat settings:', error);
        res.status(500).json({ success: false, message: 'Failed to reset super course chat settings' });
    }
});


/**
 * GET /api/settings/prompts
 * Get current system prompts (merged with defaults) for a specific course
 */
router.get('/prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const courseId = req.query.courseId;
        
        // If no courseId provided, return defaults (or could return global default if we kept it)
        if (!courseId) {
            return res.json({
                success: true,
                prompts: {
                    ...prompts.DEFAULT_PROMPTS,
                    flashcardSourceTokenBudget: flashcardService.DEFAULT_SOURCE_TOKEN_BUDGET,
                    additiveRetrieval: false,
                    additionalMaterialSecondarySearch: false
                },
                isCourseSpecific: false,
                courseId: null
            });
        }

        // Query the course document
        const course = await db.collection('courses').findOne({ courseId });

        // Retrieve prompts from course or use defaults
        const coursePrompts = course ? (course.prompts || {}) : {};
        
        const result = {
            base: coursePrompts.base || prompts.DEFAULT_PROMPTS.base,
            protege: coursePrompts.protege || prompts.DEFAULT_PROMPTS.protege,
            tutor: coursePrompts.tutor || prompts.DEFAULT_PROMPTS.tutor,
            explain: coursePrompts.explain || prompts.DEFAULT_PROMPTS.explain,
            directive: coursePrompts.directive || prompts.DEFAULT_PROMPTS.directive,
            quizHelp: coursePrompts.quizHelp || prompts.DEFAULT_PROMPTS.quizHelp,
            chatSummary: coursePrompts.chatSummary || prompts.DEFAULT_PROMPTS.chatSummary,
            flashcards: prompts.appendRichContentFormattingRules(
                coursePrompts.flashcards || prompts.DEFAULT_PROMPTS.flashcards
            ),
            flashcardSourceTokenBudget: flashcardService.normalizeSourceTokenBudget(
                coursePrompts.flashcardSourceTokenBudget
            ),
            // Course-level additive retrieval setting
            additiveRetrieval: course ? !!course.isAdditiveRetrieval : false,
            // Course-level secondary search for additional materials (off by default)
            additionalMaterialSecondarySearch: course ? !!course.additionalMaterialSecondarySearch : false,
            // Student idle timeout (seconds), default to 4 minutes (240s)
            studentIdleTimeout: coursePrompts.studentIdleTimeout || 240,
            // Chat session inactivity boundary (seconds), default to 30 minutes
            studentSessionTimeout: coursePrompts.studentSessionTimeout || 1800
        };

        res.json({
            success: true,
            prompts: result,
            isCourseSpecific: true,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error fetching prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch prompts'
        });
    }
});

/**
 * POST /api/settings/prompts
 * Save custom system prompts for a specific course
 */
router.post('/prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const {
            base,
            protege,
            tutor,
            explain,
            directive,
            quizHelp,
            chatSummary,
            flashcards,
            flashcardSourceTokenBudget,
            additiveRetrieval,
            additionalMaterialSecondarySearch,
            studentIdleTimeout,
            studentSessionTimeout,
            courseId
        } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to save settings' });
        }

        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }

        // Validation - ensure they are strings (prompts) and boolean (additiveRetrieval)
        if (
            typeof base !== 'string' ||
            typeof protege !== 'string' ||
            typeof tutor !== 'string' ||
            typeof explain !== 'string' ||
            typeof directive !== 'string' ||
            (chatSummary !== undefined && typeof chatSummary !== 'string') ||
            (flashcards !== undefined && typeof flashcards !== 'string')
        ) {
            return res.status(400).json({ success: false, message: 'Invalid prompt format' });
        }

        // Validate timeout if present
        let timeoutVal = 240; // Default
        if (studentIdleTimeout !== undefined) {
             timeoutVal = parseInt(studentIdleTimeout);
             if (isNaN(timeoutVal) || timeoutVal < 30 || timeoutVal > 1200) { // 30s to 20m
                 return res.status(400).json({ success: false, message: 'Invalid idle timeout value' });
             }
        }

        let sessionTimeoutVal = 1800; // Default 30 minutes
        if (studentSessionTimeout !== undefined) {
            sessionTimeoutVal = parseInt(studentSessionTimeout);
            if (isNaN(sessionTimeoutVal) || sessionTimeoutVal < 30 || sessionTimeoutVal > 86400) {
                return res.status(400).json({ success: false, message: 'Invalid chat session timeout value' });
            }
        }

        let flashcardTokenBudget = flashcardService.DEFAULT_SOURCE_TOKEN_BUDGET;
        if (flashcardSourceTokenBudget !== undefined) {
            flashcardTokenBudget = Number(flashcardSourceTokenBudget);
            if (
                !Number.isInteger(flashcardTokenBudget) ||
                flashcardTokenBudget < flashcardService.MIN_SOURCE_TOKENS ||
                flashcardTokenBudget > flashcardService.MAX_SOURCE_TOKENS
            ) {
                return res.status(400).json({
                    success: false,
                    message: `Flashcard source token budget must be between ${flashcardService.MIN_SOURCE_TOKENS} and ${flashcardService.MAX_SOURCE_TOKENS}`
                });
            }
        }

        const normalizedFlashcardPrompt = prompts.appendRichContentFormattingRules(
            flashcards && flashcards.trim() ? flashcards : prompts.DEFAULT_PROMPTS.flashcards
        );

        // Update the course document directly
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $set: { 
                    'prompts.base': base, 
                    'prompts.protege': protege, 
                    'prompts.tutor': tutor,
                    'prompts.explain': explain,
                    'prompts.directive': directive,
                    'prompts.quizHelp': quizHelp || prompts.DEFAULT_PROMPTS.quizHelp,
                    'prompts.chatSummary': chatSummary && chatSummary.trim() ? chatSummary : prompts.DEFAULT_PROMPTS.chatSummary,
                    'prompts.flashcards': normalizedFlashcardPrompt,
                    'prompts.flashcardSourceTokenBudget': flashcardTokenBudget,
                    'prompts.studentIdleTimeout': timeoutVal,
                    'prompts.studentSessionTimeout': sessionTimeoutVal,
                    isAdditiveRetrieval: !!additiveRetrieval,
                    additionalMaterialSecondarySearch: !!additionalMaterialSecondarySearch,
                    updatedAt: new Date()
                } 
            }
        );

        res.json({
            success: true,
            message: 'Course settings saved successfully',
            courseId: courseId,
            prompts: { flashcards: normalizedFlashcardPrompt }
        });
    } catch (error) {
        console.error('Error saving prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save prompts'
        });
    }
});

/**
 * POST /api/settings/prompts/reset
 * Reset system prompts to defaults for a specific course
 */
router.post('/prompts/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const { courseId } = req.body;
        
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to reset settings' });
        }

        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }

        // Unset the prompts field and isAdditiveRetrieval in the course document
        await db.collection('courses').updateOne(
            { courseId: courseId },
            {
                $unset: { prompts: "" },
                $set: {
                    isAdditiveRetrieval: true, // Default to true
                    additionalMaterialSecondarySearch: false // Default to off
                }
            }
        );

        res.json({
            success: true,
            message: 'Course settings reset to user defaults',
            prompts: prompts.DEFAULT_PROMPTS,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error resetting prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset prompts'
        });
    }
});

/**
 * GET /api/settings/academic-api-enabled
 * Lightweight read of the instance-wide academic-API gate. Available to any
 * authenticated user (not just admins) so instructor onboarding, the home page,
 * and the student course picker can show/hide the matching UI. Returns false on
 * any error so the UI defaults to the safe, pre-feature experience.
 */
router.get('/academic-api-enabled', async (req, res) => {
    try {
        const enabled = await isAcademicApiEnabled(req.app.locals.db);
        res.json({ success: true, enabled });
    } catch (error) {
        console.error('Error reading academic API gate:', error);
        res.json({ success: true, enabled: false });
    }
});

/**
 * GET /api/settings/global
 * Get global settings (e.g. login restrictions)
 * Requires system admin access
 */
router.get('/global', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        // Get global settings
        const settings = await db.collection('settings').findOne({ _id: 'global' });

        res.json({
            success: true,
            settings: {
                allowLocalLogin: settings ? settings.allowLocalLogin !== false : true, // Default true
                academicApiEnabled: !!(settings && settings.academicApiEnabled) // Default off
            }
        });

    } catch (error) {
        console.error('Error fetching global settings:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch global settings' });
    }
});

/**
 * POST /api/settings/global
 * Update global settings
 * Requires system admin access
 */
router.post('/global', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        // Only update the fields that were sent, so the login toggle and the
        // academic-API toggle (saved from separate sections) don't clobber each
        // other.
        const set = {
            updatedAt: new Date(),
            updatedBy: normalizeEmail(req.user.email)
        };
        if (typeof req.body.allowLocalLogin !== 'undefined') {
            set.allowLocalLogin = !!req.body.allowLocalLogin;
        }
        if (typeof req.body.academicApiEnabled !== 'undefined') {
            set.academicApiEnabled = !!req.body.academicApiEnabled;
        }

        await db.collection('settings').updateOne(
            { _id: 'global' },
            { $set: set },
            { upsert: true }
        );

        const updated = await db.collection('settings').findOne({ _id: 'global' });

        res.json({
            success: true,
            message: 'Global settings updated',
            settings: {
                allowLocalLogin: updated ? updated.allowLocalLogin !== false : true,
                academicApiEnabled: !!(updated && updated.academicApiEnabled)
            }
        });

    } catch (error) {
        console.error('Error updating global settings:', error);
        res.status(500).json({ success: false, error: 'Failed to update global settings' });
    }
});

// Obfuscated index maps for the body-class debug tag.
// Numbers are intentionally meaningless to end users; only the dev team
// knows that e.g. "llm-2 reasoning-1" = gpt-5-nano + minimal.
// Non-reasoning models (gpt-4.1-mini) intentionally omit reasoning-*.
const LLM_TAG_INDEX = {
    'gpt-4.1-mini': 1,
    'gpt-5-nano': 2,
    'gpt-5.4-nano': 3,
    'gpt-5.6-luna': 4,
    'qwen3.6-35b-a3b': 5,
    'gpt-oss-120b': 6
};
const REASONING_TAG_INDEX = {
    minimal: 1,
    low: 2,
    medium: 3,
    high: 4,
    none: 5,
    xhigh: 6,
    max: 7
};

/**
 * GET /api/settings/llm-tag
 * Public endpoint returning obfuscated indices for the active LLM model
 * and reasoning effort. Used by the frontend to add hidden body classes
 * (llm-N and, when supported, reasoning-N) so the dev team can identify
 * the active config from DevTools without exposing model names to end users.
 */
router.get('/llm-tag', async (req, res) => {
    try {
        const db = req.app.locals.db;
        const provider = configuredProvider();
        const catalog = catalogForProvider(provider, configuredDefaultModel(provider));

        let model = catalog.defaultModel;
        let reasoningEffort = normalizeReasoningEffort(provider, model);

        if (db) {
            // Per-platform settings; the tag reflects the env-configured platform.
            const stored = await adminModelSettings.getProviderSettings(db, provider, { force: true, throwOnError: true });
            if (catalog.allowedModels.includes(stored.chatModel)) model = stored.chatModel;
            reasoningEffort = stored.reasoningEffort;
        }
        reasoningEffort = normalizeReasoningEffort(provider, model, reasoningEffort);

        res.json({
            success: true,
            llmIndex: LLM_TAG_INDEX[model] || 0,
            reasoningIndex: supportsReasoning(provider, model) ? (REASONING_TAG_INDEX[reasoningEffort] || 0) : 0
        });
    } catch (error) {
        console.error('Error fetching LLM tag:', error);
        res.status(500).json({ success: false });
    }
});

/**
 * Invalidate every cache that depends on the admin model settings.
 */
function invalidateModelCaches(req) {
    adminModelSettings.invalidateCache();
    const llmService = req.app.locals.llm;
    if (llmService && typeof llmService.invalidateModelSettingsCache === 'function') {
        llmService.invalidateModelSettingsCache();
    }
    if (req.app.locals.llmRegistry && typeof req.app.locals.llmRegistry.clear === 'function') {
        req.app.locals.llmRegistry.clear();
    }
}

/**
 * GET /api/settings/llm
 * Per-platform model settings (system admins only).
 *
 * Model controls are grouped by platform — GPT and Sandbox each have their own
 * chat model, embedding model and reasoning effort. Instructors never see this.
 */
router.get('/llm', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const scope = requestedLlmScope(req);
        const { providers, pendingEmbedding } = await allModelSettings(db, scope);
        let visibleProviders = SELECTABLE_PROVIDERS;
        if (scope) {
            const target = scopeModelSettings.targetFor(scope);
            const owner = await db.collection(target.collection).findOne(target.filter);
            visibleProviders = SELECTABLE_PROVIDERS.filter(provider => credentialForProvider(owner, provider)?.ciphertext);
        }
        const platforms = visibleProviders.map((provider) => {
            const current = providers[provider];
            const catalog = adminCatalogForProvider(provider, scopedModelRoster(current));
            const backend = adminModelSettings.chatSettingsForLane(current, 'backend');
            const profile = current.embeddingModel
                ? buildEmbeddingProfile({
                    provider,
                    embeddingModel: current.embeddingModel,
                    revision: current.embeddingRevision,
                    vectorSize: current.vectorSize || undefined
                })
                : null;

            return {
                provider,
                label: providerLabel(provider),
                chatModel: current.chatModel,
                backendChatModel: backend.chatModel,
                embeddingModel: current.embeddingModel,
                embeddingRevision: current.embeddingRevision,
                reasoningEffort: current.reasoningEffort,
                backendReasoningEffort: backend.reasoningEffort,
                backendInheritsFrontend: current.backendInheritsFrontend,
                configured: current.configured,
                configurationStatus: current.configurationStatus || (current.configured ? 'ready' : 'needs_admin_configuration'),
                modelsDiscovered: current.modelsDiscovered === true || current.availableModels.length > 0,
                supportsReasoning: supportsReasoning(provider, current.chatModel),
                backendSupportsReasoning: supportsReasoning(provider, backend.chatModel),
                allowedModels: catalog.allowedModels,
                allowedEmbeddingModels: catalog.allowedEmbeddingModels,
                allowedReasoningEfforts: catalog.reasoningEffortsByModel[current.chatModel] || [],
                allowedBackendReasoningEfforts: catalog.reasoningEffortsByModel[backend.chatModel] || [],
                reasoningEffortsByModel: catalog.reasoningEffortsByModel,
                defaultReasoningEffortByModel: catalog.defaultReasoningEffortByModel,
                collection: profile?.collection || null,
                notesCollection: profile?.notesCollection || null,
                vectorSize: profile?.vectorSize || null,
                profileKey: profile?.key || null,
                pendingEmbedding: pendingEmbedding[provider] || null
            };
        });

        const activeProvider = normalizeProvider(configuredProvider());
        const active = platforms.find(platform => platform.provider === activeProvider) || platforms[0];

        res.json({
            success: true,
            scope,
            isDefaultTemplate: !scope,
            platforms,
            // Legacy single-platform shape, kept so older clients keep working.
            settings: {
                model: active.chatModel,
                reasoningEffort: active.reasoningEffort,
                supportsReasoning: active.supportsReasoning,
                allowedModels: active.allowedModels,
                allowedReasoningEfforts: active.allowedReasoningEfforts,
                reasoningEffortsByModel: active.reasoningEffortsByModel,
                defaultReasoningEffortByModel: active.defaultReasoningEffortByModel,
                provider: active.provider
            }
        });
    } catch (error) {
        console.error('Error fetching LLM settings:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch LLM settings' });
    }
});

/**
 * POST /api/settings/llm/reasoning-efforts
 * Probe one discovered proxy model and return only reasoning efforts accepted
 * by a real chat operation. The proxy roster does not expose capabilities, so
 * this intentionally does not infer support from the model id.
 */
router.post('/llm/reasoning-efforts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!requireSystemAdmin(req, res)) return;

        const provider = normalizeProvider(req.body?.provider);
        const model = req.body?.model;
        const scope = requestedLlmScope(req);
        if (provider !== PROVIDERS.PROXY) {
            return res.status(400).json({ success: false, error: 'Reasoning discovery is only available for UBC LLM Proxy models.' });
        }

        const current = await oneModelSettings(db, scope, provider);
        if (!current.availableModels.includes(model)) {
            return res.status(400).json({
                success: false,
                error: `Invalid chat model for ${providerLabel(provider)}: ${model || '(missing)'}`
            });
        }

        const reasoningEfforts = await providerKeys.discoverProxyReasoningEfforts(db, model, scope);
        return res.json({ success: true, provider, model, reasoningEfforts });
    } catch (error) {
        console.error('Error discovering proxy reasoning efforts:', error);
        return res.status(400).json({ success: false, error: error.message, code: error.code });
    }
});

/**
 * POST /api/settings/llm
 * Update a platform's chat model / reasoning effort. Chat changes are
 * immediate — no vectors are involved.
 */
router.post('/llm', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const body = req.body || {};
        const scope = requestedLlmScope(req);
        const provider = normalizeProvider(body.provider, configuredProvider());
        const chatModel = body.chatModel || body.model;

        if (provider === PROVIDERS.PROXY) {
            const current = await oneModelSettings(db, scope, provider);
            const backendInheritsFrontend = typeof body.backendInheritsFrontend === 'boolean'
                ? body.backendInheritsFrontend
                : true;
            const selections = [{ model: chatModel, reasoningEffort: body.reasoningEffort }];
            if (!backendInheritsFrontend) {
                selections.push({
                    model: body.backendChatModel,
                    reasoningEffort: body.backendReasoningEffort
                });
            }
            const unavailable = selections.find(selection => !current.availableModels.includes(selection.model));
            if (unavailable) {
                return res.status(400).json({
                    success: false,
                    error: `Invalid chat model for ${providerLabel(provider)}: ${unavailable.model}`
                });
            }
            try {
                await providerKeys.validateProxyChatSettings(db, selections, scope);
            } catch (error) {
                return res.status(400).json({ success: false, error: error.message, code: error.code });
            }
        }

        let saved;
        try {
            saved = scope
                ? await scopeModelSettings.saveChatSettings(
                    db,
                    scope,
                    provider,
                    {
                        chatModel,
                        reasoningEffort: body.reasoningEffort,
                        backendChatModel: body.backendChatModel,
                        backendReasoningEffort: body.backendReasoningEffort,
                        backendInheritsFrontend: typeof body.backendInheritsFrontend === 'boolean'
                            ? body.backendInheritsFrontend
                            : undefined
                    },
                    normalizeEmail(req.user.email)
                )
                : await adminModelSettings.saveChatSettings(
                db,
                provider,
                {
                    chatModel,
                    reasoningEffort: body.reasoningEffort,
                    backendChatModel: body.backendChatModel,
                    backendReasoningEffort: body.backendReasoningEffort,
                    backendInheritsFrontend: typeof body.backendInheritsFrontend === 'boolean'
                        ? body.backendInheritsFrontend
                        : undefined
                },
                normalizeEmail(req.user.email)
            );
        } catch (error) {
            if (error.code === 'INVALID_CHAT_MODEL') {
                return res.status(400).json({ success: false, error: error.message });
            }
            throw error;
        }

        invalidateModelCaches(req);

        res.json({
            success: true,
            message: `${providerLabel(provider)} chat model updated`,
            provider,
            scope,
            settings: {
                model: saved.chatModel,
                chatModel: saved.chatModel,
                reasoningEffort: saved.reasoningEffort,
                supportsReasoning: saved.supportsReasoning
            }
        });
    } catch (error) {
        console.error('Error updating LLM settings:', error);
        res.status(500).json({ success: false, error: 'Failed to update LLM settings' });
    }
});

/**
 * POST /api/settings/llm/embedding/impact
 * Dry run for an embedding-model change: what would have to be re-indexed.
 * The admin sees this before confirming; nothing is written.
 */
router.post('/llm/embedding/impact', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!requireSystemAdmin(req, res)) return;

        const body = req.body || {};
        const scope = requestedLlmScope(req);
        const provider = normalizeProvider(body.provider, configuredProvider());
        const embeddingModel = body.embeddingModel;
        const current = await oneModelSettings(db, scope, provider);
        if (!isAllowedEmbeddingModel(provider, embeddingModel, scopedModelRoster(current))) {
            return res.status(400).json({
                success: false,
                error: `Invalid embedding model for ${providerLabel(provider)}`
            });
        }

        let vectorSize = current.vectorSize || undefined;
        if (provider === PROVIDERS.PROXY) {
            try {
                ({ vectorSize } = await providerKeys.validateProxyEmbeddingModel(db, embeddingModel, scope));
            } catch (error) {
                return res.status(400).json({ success: false, error: error.message, code: error.code });
            }
        }

        const profile = buildEmbeddingProfile({
            provider,
            embeddingModel,
            revision: body.embeddingRevision || undefined,
            vectorSize
        });
        const surfaces = scope
            ? { ...(await providerKeys.migrationScopeContent(db, scope)), surfaces: [scope] }
            : { courseIds: [], includeNotes: false, surfaces: [] };
        const work = await migrations.calculateWork({
            db,
            profile,
            courseIds: surfaces.courseIds,
            includeNotes: surfaces.includeNotes
        });

        res.json({
            success: true,
            provider,
            scope,
            profile: {
                key: profile.key,
                collection: profile.collection,
                notesCollection: profile.notesCollection,
                vectorSize: profile.vectorSize
            },
            impact: {
                surfaces: surfaces.surfaces,
                courses: surfaces.courseIds.length,
                includeNotes: surfaces.includeNotes,
                itemsToReindex: work.items.length,
                itemsAlreadyCurrent: work.skipped
            }
        });
    } catch (error) {
        console.error('Error calculating embedding change impact:', error);
        res.status(500).json({ success: false, error: 'Failed to calculate impact' });
    }
});

/**
 * POST /api/settings/llm/embedding
 * Stage an embedding-model change. A new profile (and therefore a new
 * collection) is created; the previous profile stays ACTIVE and its collection
 * is never deleted, so a rollback is just re-selecting the old model.
 */
router.post('/llm/embedding', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!requireSystemAdmin(req, res)) return;

        const body = req.body || {};
        const scope = requestedLlmScope(req);
        const provider = normalizeProvider(body.provider, configuredProvider());
        const embeddingModel = body.embeddingModel;
        const embeddingRevision = body.embeddingRevision || undefined;
        const current = await oneModelSettings(db, scope, provider);

        if (!isAllowedEmbeddingModel(provider, embeddingModel, scopedModelRoster(current))) {
            return res.status(400).json({
                success: false,
                error: `Invalid embedding model for ${providerLabel(provider)}`
            });
        }

        let vectorSize = current.vectorSize || undefined;
        if (provider === PROVIDERS.PROXY) {
            try {
                ({ vectorSize } = await providerKeys.validateProxyEmbeddingModel(db, embeddingModel, scope));
            } catch (error) {
                return res.status(400).json({ success: false, error: error.message, code: error.code });
            }
        }
        const profile = buildEmbeddingProfile({
            provider,
            embeddingModel,
            revision: embeddingRevision,
            vectorSize
        });
        const sameConfiguredProfile = current.embeddingModel === embeddingModel
            && current.embeddingRevision === profile.revision;

        // The unscoped document is only a template for future AI surfaces. It
        // has no retrieval pool and therefore changes immediately without a
        // re-indexing job.
        if (!scope) {
            await adminModelSettings.stagePendingEmbedding(db, provider, {
                embeddingModel,
                embeddingRevision: profile.revision,
                vectorSize: profile.vectorSize,
                migrationId: null
            });
            await adminModelSettings.activatePendingEmbedding(db, provider, {
                embeddingModel,
                embeddingRevision: profile.revision
            });
            invalidateModelCaches(req);
            return res.json({
                success: true,
                message: `${providerLabel(provider)} default embedding model updated for future AI configurations.`,
                provider,
                scope: null,
                migration: null
            });
        }

        // A collection-routing or chunking change can make records stale even
        // when the configured model id/revision did not change. Calculate work
        // before declaring a no-op so an installation that previously mixed
        // OpenAI and Proxy vectors can rebuild Proxy into its isolated collection.
        let surfaces = null;
        if (sameConfiguredProfile) {
            surfaces = await providerKeys.migrationScopeContent(db, scope);
            const work = await migrations.calculateWork({
                db,
                profile,
                courseIds: surfaces.courseIds,
                includeNotes: surfaces.includeNotes
            });
            if (work.items.length === 0) {
                return res.json({
                    success: true,
                    message: `${providerLabel(provider)} already uses this embedding profile`,
                    migration: null
                });
            }
        }

        // One embedding change at a time per scope/platform. Two overlapping jobs
        // would fight over the single staged setting, and the first to finish
        // would activate a model the other is still indexing.
        const active = await migrations.findActiveMigration(db, scope);
        if (active) {
            return res.status(409).json({
                success: false,
                code: 'EMBEDDING_MIGRATION_ACTIVE',
                error: `A ${providerLabel(provider)} embedding change is already re-indexing. `
                    + 'Cancel it before staging another model.',
                migration: migrations.publicMigrationView(active)
            });
        }

        surfaces ||= await providerKeys.migrationScopeContent(db, scope);
        const { job } = await migrations.createMigration(db, {
            scope,
            kind: 'embedding-model',
            fromProvider: provider,
            toProvider: provider,
            profile,
            courseIds: surfaces.courseIds,
            includeNotes: surfaces.includeNotes,
            requestedBy: normalizeEmail(req.user.email)
        });

        await scopeModelSettings.stagePendingEmbedding(db, scope, provider, {
            embeddingModel,
            embeddingRevision: profile.revision,
            vectorSize: profile.vectorSize,
            migrationId: job.migrationId
        });

        migrationRunner.startMigration(db, job.migrationId);

        res.status(202).json({
            success: true,
            message: `Re-indexing for the new ${providerLabel(provider)} embedding model. `
                + 'The current embedding model stays active until it finishes.',
            provider,
            scope,
            migration: migrations.publicMigrationView(job)
        });
    } catch (error) {
        if (error.code === 'INVALID_EMBEDDING_MODEL') {
            return res.status(400).json({ success: false, error: error.message });
        }
        console.error('Error staging embedding model change:', error);
        res.status(500).json({ success: false, error: 'Failed to stage embedding model change' });
    }
});

/**
 * POST /api/settings/llm/embedding/rollback
 * Abandon a staged embedding-model change: stop the re-indexing job and drop
 * the partial vectors it wrote for the new profile. The ACTIVE model's
 * collection is never touched, so the platform simply keeps using it.
 */
router.post('/llm/embedding/rollback', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!requireSystemAdmin(req, res)) return;

        const scope = requestedLlmScope(req);
        const provider = normalizeProvider((req.body || {}).provider, configuredProvider());

        // Read the staged change before clearing it — it holds the id of the
        // background job that would otherwise keep re-embedding into a profile
        // nobody is going to use.
        const { pendingEmbedding } = await allModelSettings(db, scope);
        const pending = pendingEmbedding[provider];
        let cleanup = null;

        if (pending && pending.migrationId) {
            const job = await migrations.getMigration(db, pending.migrationId);
            if (job && migrations.ACTIVE_STATUSES.includes(job.status)) {
                const result = await migrationRunner.cancelAndCleanup(
                    db,
                    pending.migrationId,
                    normalizeEmail(req.user.email)
                );
                cleanup = result && result.cleanup;
            }
        }

        if (scope) await scopeModelSettings.clearPendingEmbedding(db, scope, provider);
        else await adminModelSettings.clearPendingEmbedding(db, provider);
        invalidateModelCaches(req);

        res.json({
            success: true,
            message: `Reverted to the active ${providerLabel(provider)} embedding model. `
                + 'Its vectors were not touched.',
            cleanup
        });
    } catch (error) {
        console.error('Error rolling back embedding model change:', error);
        res.status(500).json({ success: false, error: 'Failed to roll back embedding model change' });
    }
});

/**
 * Every surface running on a platform, and therefore every course whose
 * content must be re-indexed when that platform's embedding model changes.
 */
async function affectedSurfacesForProvider(db, provider) {
    const surfaces = [];
    const courseIds = new Set();
    let includeNotes = false;

    const courses = await db.collection('courses')
        .find({ isDeleted: { $ne: true } })
        .project({ courseId: 1, courseName: 1, activeLlmProvider: 1, llmApiKey: 1, llmCredentials: 1 })
        .toArray();

    for (const course of courses) {
        if (activeProviderOf(course) === provider) {
            courseIds.add(course.courseId);
            surfaces.push({ type: 'course', id: course.courseId, name: course.courseName || course.courseId });
        }
    }

    const buckets = await db.collection('superchats')
        .find({ isDeleted: { $ne: true } })
        .toArray();
    for (const bucket of buckets) {
        if (activeProviderOf(bucket) !== provider) continue;
        surfaces.push({ type: 'superchat', id: bucket.superchatId, name: bucket.name || bucket.superchatId });
        // Membership is course-side, so ask for the bucket's retrieval pool
        // rather than reading a course list off the bucket document.
        const scope = await superCourse.superCourseContentScope(db, {
            superchatId: bucket.superchatId,
            settingsDoc: bucket
        });
        for (const courseId of scope.courseIds) courseIds.add(courseId);
        if (scope.includeNotes) includeNotes = true;
    }

    for (const settingsId of ['notesLlm', 'superCourseChat']) {
        const doc = await db.collection('settings').findOne({ _id: settingsId });
        if (!doc) continue;
        if (activeProviderOf(doc) !== provider) continue;

        if (settingsId === 'notesLlm') {
            includeNotes = true;
            surfaces.push({ type: 'notes', id: 'notesLlm', name: 'Instructor Notes' });
        } else {
            surfaces.push({ type: 'superCourseChat', id: 'superCourseChat', name: 'Instructor Super Course chat' });
            const scope = await superCourse.superCourseContentScope(db, { settingsDoc: doc });
            for (const courseId of scope.courseIds) courseIds.add(courseId);
            if (scope.includeNotes) includeNotes = true;
        }
    }

    return { surfaces, courseIds: [...courseIds].filter(Boolean), includeNotes };
}

/**
 * GET /api/settings/question-prompts
 * Get question generation prompts for a specific course
 * Requires system admin access
 */
router.get('/question-prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const courseId = req.query.courseId;
        
        // If no courseId provided, return defaults
        if (!courseId) {
            return res.json({
                success: true,
                prompts: prompts.DEFAULT_QUESTION_PROMPTS,
                isCourseSpecific: false,
                courseId: null
            });
        }

        // Query the course document
        const course = await db.collection('courses').findOne({ courseId });

        // Retrieve question prompts from course or use defaults
        const courseQuestionPrompts = course ? (course.questionPrompts || {}) : {};
        
        const result = {
            systemPrompt: prompts.appendRichContentFormattingRules(
                courseQuestionPrompts.systemPrompt || prompts.DEFAULT_QUESTION_PROMPTS.systemPrompt
            ),
            trueFalse: courseQuestionPrompts.trueFalse || prompts.DEFAULT_QUESTION_PROMPTS.trueFalse,
            multipleChoice: courseQuestionPrompts.multipleChoice || prompts.DEFAULT_QUESTION_PROMPTS.multipleChoice,
            shortAnswer: courseQuestionPrompts.shortAnswer || prompts.DEFAULT_QUESTION_PROMPTS.shortAnswer
        };

        res.json({
            success: true,
            prompts: result,
            isCourseSpecific: true,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error fetching question prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch question prompts'
        });
    }
});

/**
 * POST /api/settings/question-prompts
 * Save custom question generation prompts for a specific course
 * Requires system admin access
 */
router.post('/question-prompts', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { systemPrompt, trueFalse, multipleChoice, shortAnswer, courseId } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to save question prompts' });
        }

        // Validation - ensure they are all strings
        if (typeof systemPrompt !== 'string' || typeof trueFalse !== 'string' || 
            typeof multipleChoice !== 'string' || typeof shortAnswer !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid prompt format - all prompts must be strings' });
        }

        const normalizedSystemPrompt = prompts.appendRichContentFormattingRules(systemPrompt);

        // Update the course document with question prompts
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $set: { 
                    'questionPrompts.systemPrompt': normalizedSystemPrompt,
                    'questionPrompts.trueFalse': trueFalse,
                    'questionPrompts.multipleChoice': multipleChoice,
                    'questionPrompts.shortAnswer': shortAnswer,
                    updatedAt: new Date()
                } 
            }
        );

        res.json({
            success: true,
            message: 'Question generation prompts saved successfully',
            courseId: courseId,
            prompts: {
                systemPrompt: normalizedSystemPrompt,
                trueFalse,
                multipleChoice,
                shortAnswer
            }
        });
    } catch (error) {
        console.error('Error saving question prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save question prompts'
        });
    }
});

/**
 * POST /api/settings/question-prompts/reset
 * Reset question generation prompts to defaults for a specific course
 * Requires system admin access
 */
router.post('/question-prompts/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { courseId } = req.body;
        
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required to reset question prompts' });
        }

        // Unset the questionPrompts field in the course document
        await db.collection('courses').updateOne(
            { courseId: courseId },
            { 
                $unset: { questionPrompts: "" }
            }
        );

        res.json({
            success: true,
            message: 'Question generation prompts reset to defaults',
            prompts: prompts.DEFAULT_QUESTION_PROMPTS,
            courseId: courseId
        });
    } catch (error) {
        console.error('Error resetting question prompts:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset question prompts'
        });
    }
});

/**
 * GET /api/settings/quiz
 * Get quiz practice settings for a course
 */
router.get('/quiz', async (req, res) => {
    try {
        const { courseId } = req.query;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId parameter' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        const CourseModel = require('../models/Course');
        const settings = await CourseModel.getQuizSettings(db, courseId);

        res.json({ success: true, settings });
    } catch (error) {
        console.error('Error fetching quiz settings:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch quiz settings' });
    }
});

/**
 * POST /api/settings/quiz
 * Save quiz practice settings for a course
 */
router.post('/quiz', async (req, res) => {
    try {
        const {
            courseId,
            enabled,
            testableUnits,
            allowLectureMaterialAccess,
            allowSourceAttributionDownloads
        } = req.body;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }

        const instructorId = req.user ? req.user.userId : null;
        const CourseModel = require('../models/Course');
        const result = await CourseModel.updateQuizSettings(db, courseId, {
            enabled,
            testableUnits,
            allowLectureMaterialAccess,
            allowSourceAttributionDownloads
        }, instructorId);

        if (result.success) {
            res.json({ success: true, message: 'Quiz settings saved successfully' });
        } else {
            res.status(400).json({ success: false, message: result.error || 'Failed to save quiz settings' });
        }
    } catch (error) {
        console.error('Error saving quiz settings:', error);
        res.status(500).json({ success: false, message: 'Failed to save quiz settings' });
    }
});

/**
 * GET /api/settings/chat-survey
 * Get chat usefulness survey settings for a course
 */
router.get('/chat-survey', async (req, res) => {
    try {
        const { courseId } = req.query;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId parameter' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!await requireCourseSettingsAccess(db, req, res, courseId)) {
            return;
        }

        const result = await CourseModel.getChatSurveySettings(db, courseId);
        if (!result.success) {
            return res.status(400).json({ success: false, message: result.error || 'Failed to fetch chat survey settings' });
        }

        return res.json({
            success: true,
            settings: result.settings,
            defaults: result.defaults
        });
    } catch (error) {
        console.error('Error fetching chat survey settings:', error);
        return res.status(500).json({ success: false, message: 'Failed to fetch chat survey settings' });
    }
});

/**
 * POST /api/settings/chat-survey
 * Save chat usefulness survey settings for a course
 */
router.post('/chat-survey', async (req, res) => {
    try {
        const {
            courseId,
            enabled,
            triggerMessageCount,
            promptText,
            introText,
            accuracyPrompt,
            satisfactionPrompt,
            allowFreeText
        } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'Missing courseId' });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!await requireCourseSettingsAccess(db, req, res, courseId)) {
            return;
        }

        const result = await CourseModel.updateChatSurveySettings(db, courseId, {
            enabled,
            triggerMessageCount,
            promptText,
            introText,
            accuracyPrompt,
            satisfactionPrompt,
            allowFreeText
        }, req.user ? req.user.userId : null);

        if (!result.success) {
            return res.status(400).json({ success: false, message: result.error || 'Failed to save chat survey settings' });
        }

        return res.json({
            success: true,
            message: 'Chat survey settings saved successfully',
            settings: result.settings
        });
    } catch (error) {
        console.error('Error saving chat survey settings:', error);
        return res.status(500).json({ success: false, message: 'Failed to save chat survey settings' });
    }
});

/**
 * GET /api/settings/anonymize-students
 * Get the anonymize students setting for the current instructor and course
 */
router.get('/anonymize-students', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        const courseId = req.query.courseId;
        if (!courseId) {
            return res.status(400).json({ success: false, error: 'courseId is required' });
        }
        const db = req.app.locals.db;
        const CourseModel = require('../models/Course');
        const result = await CourseModel.getAnonymizeStudents(db, courseId, req.user.userId);
        res.json({ success: true, enabled: result.enabled || false });
    } catch (error) {
        console.error('Error fetching anonymize students setting:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch setting' });
    }
});

/**
 * POST /api/settings/anonymize-students
 * Update the anonymize students setting for the current instructor and course
 */
router.post('/anonymize-students', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Not authenticated' });
        }
        const { courseId, enabled } = req.body;
        if (!courseId) {
            return res.status(400).json({ success: false, error: 'courseId is required' });
        }
        const db = req.app.locals.db;
        if (!await requireInstructorForCourseSettings(db, req, res, courseId)) {
            return;
        }
        const CourseModel = require('../models/Course');
        const result = await CourseModel.updateAnonymizeStudents(db, courseId, req.user.userId, !!enabled);
        if (result.success) {
            res.json({ success: true, message: 'Anonymize students setting saved' });
        } else {
            res.status(400).json({ success: false, message: result.error || 'Failed to save setting' });
        }
    } catch (error) {
        console.error('Error saving anonymize students setting:', error);
        res.status(500).json({ success: false, error: 'Failed to save setting' });
    }
});

/**
 * GET /api/settings/mental-health-prompt
 * Get mental health detection prompt for a course (or default)
 */
router.get('/mental-health-prompt', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const courseId = req.query.courseId;

        if (!courseId) {
            return res.json({
                success: true,
                prompt: prompts.DEFAULT_MENTAL_HEALTH_DETECTION_PROMPT,
                isCourseSpecific: false
            });
        }

        const course = await db.collection('courses').findOne({ courseId });
        const prompt = (course && course.mentalHealthDetectionPrompt) || prompts.DEFAULT_MENTAL_HEALTH_DETECTION_PROMPT;

        res.json({
            success: true,
            prompt,
            isCourseSpecific: !!(course && course.mentalHealthDetectionPrompt),
            courseId
        });
    } catch (error) {
        console.error('Error fetching mental health detection prompt:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch mental health detection prompt' });
    }
});

/**
 * POST /api/settings/mental-health-prompt
 * Save custom mental health detection prompt for a course
 */
router.post('/mental-health-prompt', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { prompt, courseId } = req.body;

        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }
        if (typeof prompt !== 'string') {
            return res.status(400).json({ success: false, message: 'Invalid prompt format' });
        }

        await db.collection('courses').updateOne(
            { courseId },
            { $set: { mentalHealthDetectionPrompt: prompt, updatedAt: new Date() } }
        );

        res.json({ success: true, message: 'Mental health detection prompt saved', courseId });
    } catch (error) {
        console.error('Error saving mental health detection prompt:', error);
        res.status(500).json({ success: false, message: 'Failed to save mental health detection prompt' });
    }
});

/**
 * POST /api/settings/mental-health-prompt/reset
 * Reset mental health detection prompt to default for a course
 */
router.post('/mental-health-prompt/reset', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const { courseId } = req.body;
        if (!courseId) {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }

        await db.collection('courses').updateOne(
            { courseId },
            { $unset: { mentalHealthDetectionPrompt: '' } }
        );

        res.json({
            success: true,
            message: 'Mental health detection prompt reset to default',
            prompt: prompts.DEFAULT_MENTAL_HEALTH_DETECTION_PROMPT,
            courseId
        });
    } catch (error) {
        console.error('Error resetting mental health detection prompt:', error);
        res.status(500).json({ success: false, message: 'Failed to reset mental health detection prompt' });
    }
});

const NOTES_SCOPE = { type: 'notes', id: 'notesLlm' };
const SUPER_COURSE_CHAT_SCOPE = { type: 'superCourseChat', id: 'superCourseChat' };

router.get('/notes-llm-key', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const state = await providerKeys.surfaceKeyState(db, NOTES_SCOPE);
        res.json({ success: true, providers: providerCatalog(), ...state });
    } catch (error) {
        console.error('Error fetching notes API key status:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch notes API key status' });
    }
});

router.put('/notes-llm-key', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const result = await providerKeys.saveSurfaceKey(db, {
            scope: NOTES_SCOPE,
            provider: normalizeProvider(req.body && req.body.llmProvider),
            apiKey: req.body && req.body.apiKey,
            updatedBy: req.user.userId,
            registry: req.app.locals.llmRegistry
        });

        if (result.ok) {
            await db.collection('settings').updateOne(
                { _id: 'notesLlm' },
                { $set: { updatedBy: normalizeEmail(req.user.email) } }
            );
            if (result.httpStatus === 200) result.body.message = 'Notes API key saved';
        }

        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error saving notes API key:', error);
        res.status(500).json({ success: false, message: 'Failed to save notes API key' });
    }
});

/**
 * POST /api/settings/notes-llm-key/provider
 * Switch Instructor Notes back to a platform whose key is already stored.
 */
router.post('/notes-llm-key/provider', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!requireSystemAdmin(req, res)) return;

        const result = await providerKeys.switchToStoredProvider(db, {
            scope: NOTES_SCOPE,
            provider: normalizeProvider(req.body && req.body.llmProvider),
            requestedBy: req.user.userId,
            registry: req.app.locals.llmRegistry
        });
        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error switching notes platform:', error);
        res.status(500).json({ success: false, message: 'Failed to switch platform' });
    }
});

router.post('/notes-llm-key/provider/prepare', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireSystemAdmin(req, res)) return;
        const result = await providerKeys.prepareStoredProvider(db, {
            scope: NOTES_SCOPE,
            provider: normalizeProvider(req.body && req.body.llmProvider),
            requestedBy: req.user.userId
        });
        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error preparing notes material:', error);
        res.status(500).json({ success: false, message: 'Failed to prepare notes material' });
    }
});

router.post('/notes-llm-key/test', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const result = await providerKeys.testSurfaceKey(db, {
            scope: NOTES_SCOPE,
            provider: req.body && req.body.llmProvider,
            registry: req.app.locals.llmRegistry
        });

        if (result.body.code === 'LLM_KEY_MISSING') {
            result.body.message = 'No API key is saved for instructor notes.';
        } else if (result.ok) {
            result.body.message = 'Notes API key is valid';
        }

        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error testing notes API key:', error);
        res.status(500).json({ success: false, message: 'Failed to test notes API key' });
    }
});

// ---------------------------------------------------------------------------
// Instructor Super Course chat key — the dedicated key powering the global
// instructor chat (its own key, not borrowed from a student bucket). Lives on
// the superCourseChat settings doc alongside that chat's other settings.
// ---------------------------------------------------------------------------
router.get('/instructor-superchat-llm-key', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const state = await providerKeys.surfaceKeyState(db, SUPER_COURSE_CHAT_SCOPE);
        res.json({ success: true, providers: providerCatalog(), ...state });
    } catch (error) {
        console.error('Error fetching instructor Super Course chat API key status:', error);
        res.status(500).json({ success: false, message: 'Failed to fetch instructor Super Course chat API key status' });
    }
});

router.put('/instructor-superchat-llm-key', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const result = await providerKeys.saveSurfaceKey(db, {
            scope: SUPER_COURSE_CHAT_SCOPE,
            provider: normalizeProvider(req.body && req.body.llmProvider),
            apiKey: req.body && req.body.apiKey,
            updatedBy: req.user.userId,
            registry: req.app.locals.llmRegistry
        });

        if (result.ok) {
            await db.collection('settings').updateOne(
                { _id: SUPER_COURSE_SETTINGS_ID },
                { $set: { updatedBy: normalizeEmail(req.user.email) } }
            );
            if (result.httpStatus === 200) {
                result.body.message = 'Instructor Super Course chat API key saved';
            }
        }

        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error saving instructor Super Course chat API key:', error);
        res.status(500).json({ success: false, message: 'Failed to save instructor Super Course chat API key' });
    }
});

/**
 * POST /api/settings/instructor-superchat-llm-key/provider
 * Switch the instructor Super Course chat back to a stored platform.
 */
router.post('/instructor-superchat-llm-key/provider', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!requireSystemAdmin(req, res)) return;

        const result = await providerKeys.switchToStoredProvider(db, {
            scope: SUPER_COURSE_CHAT_SCOPE,
            provider: normalizeProvider(req.body && req.body.llmProvider),
            requestedBy: req.user.userId,
            registry: req.app.locals.llmRegistry
        });
        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error switching instructor Super Course chat platform:', error);
        res.status(500).json({ success: false, message: 'Failed to switch platform' });
    }
});

router.post('/instructor-superchat-llm-key/provider/prepare', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) return res.status(503).json({ success: false, message: 'Database connection not available' });
        if (!requireSystemAdmin(req, res)) return;
        const result = await providerKeys.prepareStoredProvider(db, {
            scope: SUPER_COURSE_CHAT_SCOPE,
            provider: normalizeProvider(req.body && req.body.llmProvider),
            requestedBy: req.user.userId
        });
        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error preparing instructor Super Course chat material:', error);
        res.status(500).json({ success: false, message: 'Failed to prepare instructor Super Course chat material' });
    }
});

router.post('/instructor-superchat-llm-key/test', async (req, res) => {
    try {
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }

        if (!requireSystemAdmin(req, res)) {
            return;
        }

        const result = await providerKeys.testSurfaceKey(db, {
            scope: SUPER_COURSE_CHAT_SCOPE,
            provider: req.body && req.body.llmProvider,
            registry: req.app.locals.llmRegistry
        });

        if (result.body.code === 'LLM_KEY_MISSING') {
            result.body.message = 'No API key is saved for the instructor Super Course chat.';
        } else if (result.ok) {
            result.body.message = 'Instructor Super Course chat API key is valid';
        }

        res.status(result.httpStatus).json(result.body);
    } catch (error) {
        console.error('Error testing instructor Super Course chat API key:', error);
        res.status(500).json({ success: false, message: 'Failed to test instructor Super Course chat API key' });
    }
});

module.exports = router;
