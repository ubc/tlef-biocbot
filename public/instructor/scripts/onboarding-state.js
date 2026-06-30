/**
 * Shared top-level state for the instructor onboarding page.
 * Classic scripts share one global lexical scope, so these `let`/`const`
 * declarations are visible to every onboarding-*.js module and must load
 * FIRST (before all other onboarding scripts).
 */

// Global state for onboarding
let onboardingState = {
    currentStep: 1,
    totalSteps: 3,
    currentSubstep: 'objectives',
    substeps: ['objectives', 'materials', 'questions'],
    courseData: {},
    academicSync: {
        academicPeriod: '',
        selectedSectionIds: [],
        sections: []
    },
    uploadedFile: null,
    createdCourseId: null,
    isSubmitting: false, // Prevent multiple submissions
    existingCourseId: null // Store existing course ID if found
};

// Upload modal state
let uploadedFile = null;

let currentWeek = null;

let currentContentType = null;

let canBypassOnboardingInstructorCourseCodes = false;
let onboardingSelectedCourseRequiresCode = true;
let onboardingSelectedCourseJoinReason = 'courseCode';
// Instance-wide academic-API gate. Off by default so the Class List Sync UI
// stays hidden until we confirm the feature is enabled for this instance.
let onboardingAcademicApiEnabled = false;

// Assessment Questions Functionality
// Global variables for assessment questions
let assessmentQuestions = {
    'Onboarding': []
};

let editingQuestionObjectiveContext = null;

let autoLinkConfirmationContext = null;

const API_BASE_URL = '';

// AI Generation State
let aiGenerationCount = 0;

let lastGeneratedContent = null;

let currentQuestionType = null;
