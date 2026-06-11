/**
 * Instructor onboarding page boot script.
 *
 * The implementation lives in feature modules loaded before this file:
 *   common/scripts/ui-utils.js, common/scripts/topic-review.js (shared)
 *   onboarding-state.js      — shared page state (must load first)
 *   onboarding-course-setup.js, onboarding-flow.js,
 *   onboarding-objectives-questions.js, onboarding-ai-generation.js,
 *   onboarding-upload.js
 * All are classic scripts sharing the global scope; functions referenced by
 * inline onclick handlers in onboarding.html stay reachable as globals.
 */

document.addEventListener('DOMContentLoaded', async function() {
    // Initialize onboarding functionality
    initializeOnboarding();
    
    // Initialize guided substep functionality
    initializeGuidedSubsteps();
    
    // Wait for authentication to be ready before loading courses
    await waitForAuth();

    canBypassOnboardingInstructorCourseCodes = await checkCourseCodeBypassPermission();
    applyJoinCourseCodePermission();

    await checkOnboardingStatus();
    
    // Load available courses for course selection
    loadAvailableCourses();
});

/**
 * Wait for authentication to be initialized
 * @returns {Promise<void>}
 */
async function waitForAuth() {
    // Wait for auth.js to initialize
    let attempts = 0;
    const maxAttempts = 50; // 5 seconds max wait
    
    while (attempts < maxAttempts) {
        if (typeof getCurrentInstructorId === 'function' && getCurrentInstructorId()) {
            console.log('✅ [AUTH] Authentication ready');
            return;
        }
        
        // Wait 100ms before next attempt
        await new Promise(resolve => setTimeout(resolve, 100));
        attempts++;
    }
    
    console.warn('⚠️ [AUTH] Authentication not ready after 5 seconds, proceeding anyway');
}
