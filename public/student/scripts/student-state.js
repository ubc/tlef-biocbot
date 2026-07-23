/**
 * Shared top-level state for the student chat page.
 * Classic scripts share one global lexical scope, so these declarations are
 * visible to every student-*.js module and must load FIRST (before all other
 * student scripts). The window.* assignments snapshot initial values for
 * auto-save and stay immediately after their declarations.
 */

// Calibration Questions functionality
let currentCalibrationQuestions = [];

let currentPassThreshold = 2;

let currentQuestionIndex = 0;

let studentAnswers = [];

window.studentEvaluations = [];

window.currentAssessmentScore = null;

// Make variables globally accessible for auto-save
window.currentCalibrationQuestions = currentCalibrationQuestions;

window.studentAnswers = studentAnswers;
