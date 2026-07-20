/**
 * Idle Timer Logic
 * Shared across student pages (Chat, History, Flagged)
 */

(function() {
    // State variables
    let idleTimer;
    let countdownInterval;

    /**
     * Initialize Idle Timer
     * Fetches course settings for timeout and sets up listeners
     */
    async function initializeIdleTimer() {
        try {
            console.log('🕒 [IDLE] Initializing idle timer...');
            
            // Ensure modal exists
            injectIdleModal();
            
            const courseId = localStorage.getItem('selectedCourseId');
            if (!courseId) {
                console.log('🕒 [IDLE] No course ID found');
                return;
            }

            // Fetch course details to get timeout setting
            // Assuming authenticatedFetch is available globally from auth.js
            if (typeof authenticatedFetch !== 'function') {
                console.warn('🕒 [IDLE] authenticatedFetch not found, cannot load settings');
                return;
            }

            const response = await authenticatedFetch(`/api/courses/${courseId}`);
            const result = await response.json();
            
            if (!result.success || !result.data) {
                console.log('🕒 [IDLE] Failed to fetch course data', result);
                return;
            }

            // Get timeout in seconds (default 240s / 4 mins)
            const timeoutSeconds = result.data.studentIdleTimeout || 240;
            console.log(`🕒 [IDLE] Timeout set to ${timeoutSeconds} seconds (${timeoutSeconds/60} mins)`);
            
            // Setup the timer
            setupIdleListeners(timeoutSeconds);
            
        } catch (error) {
            console.warn('Failed to initialize idle timer:', error);
        }
    }

    /**
     * Inject Modal HTML if not present
     */
    function injectIdleModal() {
        if (document.getElementById('idle-timeout-modal')) {
            return;
        }

        const modalHtml = `
            <div id="idle-timeout-modal" class="modal-overlay" style="display: none;">
                <div class="modal-content" role="alertdialog" aria-modal="true" aria-labelledby="idle-modal-title" aria-describedby="idle-modal-desc">
                    <div class="modal-header">
                        <h2 id="idle-modal-title" tabindex="-1">Are you still there?</h2>
                    </div>
                    <div class="modal-body" id="idle-modal-desc" role="status">
                        <p>You have been idle for a while.</p>
                        <p>You will be automatically signed out in <span id="idle-countdown-display" style="font-weight: bold; color: var(--primary-color);">--:--</span>.</p>
                    </div>
                    <div class="modal-footer">
                        <button id="idle-signout-btn" class="secondary-button">Sign Out</button>
                        <button id="idle-stay-btn" class="primary-button">I'm Still Here</button>
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }

    /**
     * Setup Idle Listeners and Warning Logic
     * @param {number} timeoutSeconds - Total timeout in seconds
     */
    function setupIdleListeners(timeoutSeconds) {
        // Warning appears at 50% of the time
        const warningMs = (timeoutSeconds * 1000) / 2;
        const countdownSecondsStart = timeoutSeconds / 2;
        
        const resetTimer = () => {
            const modal = document.getElementById('idle-timeout-modal');
            const isModalOpen = modal && modal.style.display !== 'none';
            
            // If modal is open, IGNORE interaction (let countdown continue)
            if (isModalOpen) {
                return;
            }

            // Clear all timers
            clearTimeout(idleTimer);
            clearInterval(countdownInterval);
            
            // Start waiting for the first half
            // console.log(`🕒 [IDLE] Timer reset. Waiting ${warningMs/1000}s for warning.`);
            idleTimer = setTimeout(() => startCountdownMode(countdownSecondsStart), warningMs);
        };
        
        const startCountdownMode = (countdownStart) => {
            console.log('🕒 [IDLE] Warning time reached. Starting countdown.');
            showIdleModal();
            
            let remainingSeconds = countdownStart;
            updateCountdownDisplay(remainingSeconds);
            
            countdownInterval = setInterval(() => {
                remainingSeconds--;
                // console.log(`🕒 [IDLE] Countdown: ${remainingSeconds}s`);
                updateCountdownDisplay(remainingSeconds);
                
                if (remainingSeconds <= 0) {
                    console.log('🕒 [IDLE] Countdown expired. Signing out.');
                    clearInterval(countdownInterval);
                    handleAutoLogout();
                }
            }, 1000);
        };

        const updateCountdownDisplay = (seconds) => {
            const display = document.getElementById('idle-countdown-display');
            if (display) {
                const mins = Math.floor(seconds / 60);
                const secs = Math.floor(seconds % 60);
                display.textContent = `${mins}:${secs.toString().padStart(2, '0')}`;
            }
        };
        
        const handleAutoLogout = () => {
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) {
                logoutBtn.click();
            } else {
                // Fallback if button not found or we want direct action
                window.location.href = '/logout';
            }
        };
        
        const showIdleModal = () => {
            const modal = document.getElementById('idle-timeout-modal');
            const signoutBtn = document.getElementById('idle-signout-btn');
            const stayBtn = document.getElementById('idle-stay-btn');
            
            if (modal) {
                modal.style.display = 'flex'; // Uses flex because of .modal-overlay css
                window.a11yModal?.open(modal, { initialFocus: '#idle-stay-btn', escapable: false });
                
                // Handle buttons
                // Need to remove old listeners to avoid duplicates if re-initialized? 
                // Creating new function references each time setupIdleListeners called?
                // Actually setupIdleListeners is called once per page load usually.
                
                signoutBtn.onclick = () => {
                    console.log('🕒 [IDLE] User clicked Sign Out');
                    handleAutoLogout();
                };
                
                stayBtn.onclick = () => {
                    console.log('🕒 [IDLE] User confirmed stay');
                    window.a11yModal?.close(modal);
                    modal.style.display = 'none';
                    resetTimer(); // Restart timer logic
                };
            }
        };
        
        // Events to listen for
        const events = ['mousemove', 'mousedown', 'keypress', 'touchmove', 'scroll'];
        
        events.forEach(event => {
            document.addEventListener(event, resetTimer, true);
        });
        
        // Start initial timer
        resetTimer();
    }

    // Expose to window
    window.initializeIdleTimer = initializeIdleTimer;

})();
