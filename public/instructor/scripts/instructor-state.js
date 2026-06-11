/**
 * Shared top-level state for the instructor documents/settings pages.
 * Classic scripts share one global lexical scope, so these `let`/`const`
 * declarations are visible to every instructor-*.js module and must load
 * FIRST (before all other instructor scripts).
 */

// API base URL configuration - change this if proxy isn't working
const API_BASE_URL = '';

// AI generation tracking variables
let aiGenerationCount = 0;

let lastGeneratedContent = null;

let currentQuestionType = null;

// Modal functionality for content upload
let uploadedFile = null;

let currentWeek = null;

let currentContentType = null;

// Global variables to prevent multiple API calls and redirects
let courseIdCache = null;

let courseIdPromise = null;

let redirectInProgress = false;

// Store current publish status for comparison during polling
let currentPublishStatus = {};

// Track recent local changes to avoid false positives in polling
// Format: { lectureName: timestamp }
let recentLocalChanges = {};

const LOCAL_CHANGE_COOLDOWN = 5000;

/**
 * Polling interval reference for publish status updates
 */
let publishStatusPollingInterval = null;

// Mode Questions Modal functionality
let currentQuestions = [];

let questionCounter = 1;

// Global variables for assessment questions
let assessmentQuestions = {
    'Week 1': [],
    'Week 2': [],
    'Week 3': []
};

let editingQuestionObjectiveContext = null;

let autoLinkConfirmationContext = null;
