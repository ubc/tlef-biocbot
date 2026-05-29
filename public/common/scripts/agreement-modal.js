/**
 * User Agreement Modal
 * Handles the first-time user agreement modal that appears for new students
 */

class AgreementModal {
    constructor() {
        this.modal = null;
        this.isVisible = false;
        this.agreementChecked = false;
        this.init();
    }

    /**
     * Initialize the agreement modal
     */
    init() {
        this.createModal();
        this.setupEventListeners();
    }

    /**
     * Create the modal HTML structure
     */
    createModal() {
        const copy = this.getCopyForCurrentContext();

        // Create modal overlay
        const overlay = document.createElement('div');
        overlay.className = 'agreement-modal-overlay';
        overlay.id = 'agreement-modal-overlay';
        overlay.style.display = 'none';

        // Create modal content
        overlay.innerHTML = `
            <div class="agreement-modal" id="agreement-modal" tabindex="-1">
                <div class="agreement-modal-header">
                    <h2>${copy.title}</h2>
                    <p class="subtitle">${copy.subtitle}</p>
                </div>
                
                <div class="agreement-modal-body">
                    <div class="agreement-section">
                        <h3>What is BiocBot?</h3>
                        <p>${copy.intro}</p>
                    </div>

                    <div class="agreement-section">
                        <h3>Information We Store</h3>
                        <p>As with most applications we store usage data. This data includes the conversations you have with BiocBot. This both enables you to return to the application after some time to resume a conversation and enables us, after deidentifying the data, to assess the tool.</p>
                        <p>To provide you with the best learning experience, BiocBot collects and stores:</p>
                        <ul>
                            <li><strong>Your questions and conversations</strong> - To improve responses and track your learning progress</li>
                            <li><strong>Course interaction data</strong> - To personalize your learning experience</li>
                            <li><strong>Learning analytics</strong> - To help instructors understand course effectiveness</li>
                            <li><strong>Account information</strong> - Your name, email, and course enrollment details</li>
                        </ul>
                        <p>All data is stored securely and used only for educational purposes within your course.</p>
                    </div>

                    <div class="agreement-section">
                        <h3>Rules and Guidelines</h3>
                        <p>To ensure a positive learning environment for everyone, please follow these guidelines:</p>
                        <ul>
                            <li><strong>Academic Integrity:</strong> Use BiocBot to enhance your learning, not to replace your own work</li>
                            <li><strong>Respectful Communication:</strong> Maintain a professional and respectful tone in all interactions</li>
                            <li><strong>Appropriate Content:</strong> Ask questions related to your course material and biology topics</li>
                            <li><strong>Privacy Respect:</strong> Do not share personal or private information about yourself or others</li>
                            <li><strong>Copyright Respect:</strong> Do not enter copyrighted information or materials that you do not have permission to use</li>
                            <li><strong>Constructive Use:</strong> Use BiocBot to ask thoughtful questions that help you learn</li>
                        </ul>
                    </div>

                    <div class="agreement-section">
                        <h3>AI Service Notice</h3>
                        <p>BiocBot sends your conversations to a UBC-approved AI service so it can respond to your questions. That AI service does not store your conversations.</p>
                        <p>Please do not enter personal, private, confidential, or copyrighted information into BiocBot.</p>
                    </div>

                    <div class="agreement-checkbox-container">
                        <input type="checkbox" id="agreement-checkbox" class="agreement-checkbox">
                        <label for="agreement-checkbox" class="agreement-checkbox-label">
                            <strong>I understand and agree</strong> to the terms outlined above. I will use BiocBot responsibly and in accordance with UBC's academic integrity policies, found here:
                            <a href="https://academicintegrity.ubc.ca/student-start/" target="_blank">https://academicintegrity.ubc.ca/student-start/</a>
                        </label>
                    </div>
                </div>

                <div class="agreement-modal-footer">
                    <button type="button" class="agreement-btn agreement-btn-secondary" id="close-modal-btn" style="display: none;">
                        Close
                    </button>
                    <button type="button" class="agreement-btn agreement-btn-primary" id="agree-btn" disabled>
                        I Agree - Continue
                    </button>
                </div>
            </div>
        `;

        // Add to document
        document.body.appendChild(overlay);
        this.modal = overlay;
    }

    getCopyForCurrentContext() {
        const path = window.location.pathname;

        if (path.includes('/instructor/')) {
            return {
                title: 'Welcome to BiocBot Instructor Tools',
                subtitle: 'Your AI-Supported Course Management Workspace',
                intro: 'BiocBot helps instructors manage course materials, review student activity, and support learning through AI-assisted course tools. It can organize content, surface student questions, and help you monitor course interactions.'
            };
        }

        if (path.includes('/ta/')) {
            return {
                title: 'Welcome to BiocBot TA Tools',
                subtitle: 'Your Teaching Assistant Support Workspace',
                intro: 'BiocBot helps teaching assistants work with assigned course materials and student support workflows. It can help you review flagged content and access the course tools your instructor has enabled.'
            };
        }

        return {
            title: 'Welcome to BiocBot',
            subtitle: 'Your AI-Powered Study Assistant',
            intro: 'BiocBot is an AI-powered study assistant designed to help you learn biology concepts through interactive conversations. It can answer your questions, provide explanations, and guide you through course materials in a personalized way.'
        };
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        const checkbox = this.modal.querySelector('#agreement-checkbox');
        const agreeBtn = this.modal.querySelector('#agree-btn');
        const closeBtn = this.modal.querySelector('#close-modal-btn');

        // Handle checkbox change
        checkbox.addEventListener('change', (e) => {
            this.agreementChecked = e.target.checked;
            agreeBtn.disabled = !this.agreementChecked;
        });

        // Handle agree button click
        agreeBtn.addEventListener('click', () => {
            this.handleAgreement();
        });

        // Handle close button click
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                this.hide();
            });
        }

        // Prevent modal from being closed by clicking outside (unless read-only)
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                if (this.isReadOnly) {
                    this.hide();
                } else {
                    e.preventDefault();
                    e.stopPropagation();
                }
            }
        });

        // Prevent modal from being closed by escape key (unless read-only)
        document.addEventListener('keydown', (e) => {
            if (this.isVisible && e.key === 'Escape') {
                if (this.isReadOnly) {
                    this.hide();
                } else {
                    e.preventDefault();
                    e.stopPropagation();
                }
            }
        });
    }

    /**
     * Show the agreement modal
     * @param {boolean} readOnly - If true, show in read-only mode (no checkbox, closeable)
     */
    show(readOnly = false) {
        if (this.isVisible) return;

        this.isVisible = true;
        this.isReadOnly = readOnly;
        this.modal.style.display = 'flex';
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
        
        // Focus on the modal for accessibility
        const modalElement = this.modal.querySelector('#agreement-modal');
        modalElement.focus();
        
        // Reset state
        this.agreementChecked = false;
        const checkboxContainer = this.modal.querySelector('.agreement-checkbox-container');
        const checkbox = this.modal.querySelector('#agreement-checkbox');
        const agreeBtn = this.modal.querySelector('#agree-btn');
        const closeBtn = this.modal.querySelector('#close-modal-btn');
        
        checkbox.checked = false;
        agreeBtn.disabled = true;

        if (readOnly) {
            // Read-only mode: hide agreement controls, show close button
            if (checkboxContainer) checkboxContainer.style.display = 'none';
            if (agreeBtn) agreeBtn.style.display = 'none';
            if (closeBtn) closeBtn.style.display = 'block';
        } else {
            // Normal mode: show agreement controls, hide close button
            if (checkboxContainer) checkboxContainer.style.display = 'block';
            if (agreeBtn) agreeBtn.style.display = 'block';
            if (closeBtn) closeBtn.style.display = 'none';
        }
    }

    /**
     * Hide the agreement modal
     */
    hide() {
        if (!this.isVisible) return;

        this.isVisible = false;
        this.modal.style.display = 'none';
        document.body.style.overflow = ''; // Restore scrolling
    }

    /**
     * Handle user agreement
     */
    async handleAgreement() {
        if (!this.agreementChecked) return;

        const agreeBtn = this.modal.querySelector('#agree-btn');
        const originalText = agreeBtn.textContent;
        
        try {
            // Show loading state
            agreeBtn.textContent = 'Processing...';
            agreeBtn.classList.add('loading');
            agreeBtn.disabled = true;

            // Send agreement to server
            console.log('Sending agreement request to server...');
            const response = await fetch('/api/user-agreement/agree', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include', // Include cookies for authentication
                body: JSON.stringify({
                    agreementVersion: '1.0'
                })
            });
            
            console.log('Agreement response status:', response.status);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();

            if (result.success) {
                // Agreement recorded successfully
                this.hide();
                
                // Dispatch custom event to notify other components
                document.dispatchEvent(new CustomEvent('userAgreementAccepted', {
                    detail: { agreementVersion: result.data.agreementVersion }
                }));
                
                console.log('User agreement recorded successfully');
            } else {
                throw new Error(result.message || 'Failed to record agreement');
            }

        } catch (error) {
            console.error('Error recording user agreement:', error);
            
            // Show error message
            alert('Failed to record your agreement. Please try again.');
            
            // Reset button state
            agreeBtn.textContent = originalText;
            agreeBtn.classList.remove('loading');
            agreeBtn.disabled = false;
        }
    }

    /**
     * Check if user has already agreed to terms
     */
    async checkAgreementStatus() {
        try {
            console.log('🔍 [AGREEMENT] Checking agreement status...');
            const response = await fetch('/api/user-agreement/status', {
                credentials: 'include' // Include cookies for authentication
            });
            
            console.log('🔍 [AGREEMENT] Response status:', response.status);
            
            if (!response.ok) {
                const errorText = await response.text();
                console.error('🔍 [AGREEMENT] Error response:', errorText);
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            console.log('🔍 [AGREEMENT] Agreement status result:', result);

            if (result.success) {
                return result.data.hasAgreed;
            } else {
                throw new Error(result.message || 'Failed to check agreement status');
            }

        } catch (error) {
            console.error('Error checking agreement status:', error);
            return false; // Default to showing modal if we can't check
        }
    }

    /**
     * Initialize and show modal if user hasn't agreed
     */
    async initializeForUser() {
        // Wait for authentication to be ready
        await this.waitForAuthentication();
        
        const hasAgreed = await this.checkAgreementStatus();
        
        if (!hasAgreed) {
            // Small delay to ensure page is fully loaded
            setTimeout(() => {
                this.show();
            }, 500);
        }
    }

    /**
     * Wait for authentication to be ready
     */
    async waitForAuthentication() {
        let attempts = 0;
        const maxAttempts = 50; // 5 seconds max wait
        
        while (attempts < maxAttempts) {
            try {
                // Try to make a simple API call to check if we're authenticated
                const response = await fetch('/api/user-agreement/status', {
                    credentials: 'include'
                });
                
                if (response.status !== 401) {
                    console.log('🔐 [AGREEMENT] Authentication ready');
                    return;
                }
            } catch (error) {
                // Continue waiting
            }
            
            // Wait 100ms before next attempt
            await new Promise(resolve => setTimeout(resolve, 100));
            attempts++;
        }
        
        console.warn('⚠️ [AGREEMENT] Authentication not ready after 5 seconds, proceeding anyway');
    }
}

// Create global instance
window.agreementModal = new AgreementModal();

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Only initialize for students (not instructors)
    if (window.location.pathname.includes('/student/')) {
        window.agreementModal.initializeForUser();
    }
});

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AgreementModal;
}
