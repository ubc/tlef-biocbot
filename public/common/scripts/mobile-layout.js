/**
 * Mobile Layout Manager
 * Handles collapsible header functionality for mobile devices
 */

document.addEventListener('DOMContentLoaded', () => {
    initMobileLayout();
});

function initMobileLayout() {
    const logoContainer = document.querySelector('.logo-container');
    if (!logoContainer) return;

    // Create Toggle Button
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'mobile-header-toggle';
    toggleBtn.innerHTML = '<span class="toggle-icon">▲</span>'; // Start with "Collapse" arrow
    toggleBtn.title = 'Toggle Header';
    
    // Append to logo container
    logoContainer.appendChild(toggleBtn);
    
    // Function to update icon
    const updateIcon = (isCollapsed) => {
        toggleBtn.innerHTML = `<span class="toggle-icon">${isCollapsed ? '▼' : '▲'}</span>`;
    };
    updateIcon(document.body.classList.contains('mobile-collapsed'));

    // Toggle Handler
    toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation(); // Prevent bubbling
        document.body.classList.toggle('mobile-collapsed');
        const isCollapsed = document.body.classList.contains('mobile-collapsed');
        updateIcon(isCollapsed);
        
        // Save preference?
        // localStorage.setItem('mobileHeaderCollapsed', isCollapsed);
    });

    // Check saved preference? (Optional, maybe later)
}
