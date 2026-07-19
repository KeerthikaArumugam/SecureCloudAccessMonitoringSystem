/**
 * dashboard.js
 * AI-Powered Secure Cloud Access Monitoring System
 * SOC Dashboard — supplemental interactivity
 */

'use strict';

// Auto-refresh threat score indicator every 30s (demo)
(function refreshThreatBadge() {
  const badge = document.getElementById('threatBadge');
  if (!badge) return;

  const levels = [
    { label: 'LOW THREAT',    cls: 'threat-low',    icon: 'bi-shield-fill-check' },
    { label: 'MEDIUM THREAT', cls: 'threat-medium',  icon: 'bi-dash-circle-fill'  },
    { label: 'HIGH THREAT',   cls: 'threat-high',   icon: 'bi-exclamation-triangle-fill' }
  ];

  // Keep badge in sync with static Jinja value — only demo pulse
  setInterval(() => {
    badge.classList.add('pulse-glow');
    setTimeout(() => badge.classList.remove('pulse-glow'), 1500);
  }, 30000);
})();

// Highlight topbar title on sidebar nav click (fallback for browsers
// that may not run the inline script before this file)
document.addEventListener('DOMContentLoaded', () => {
  // Responsive: auto-close sidebar overlay on resize
  window.addEventListener('resize', () => {
    const sidebar = document.getElementById('dashSidebar');
    if (sidebar && window.innerWidth > 992) {
      sidebar.classList.remove('open');
    }
  }, { passive: true });
});
