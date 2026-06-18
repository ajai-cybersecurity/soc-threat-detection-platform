/* SOC Platform – Main JavaScript */

// ── Live Clock ────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('live-clock');
  if (el) el.textContent = new Date().toUTCString().slice(0, 25) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ── Sidebar Toggle ────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
  const toggleBtn = document.getElementById('sidebar-toggle');
  const sidebar   = document.getElementById('sidebar');
  const main      = document.getElementById('main-content');

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', function () {
      if (window.innerWidth <= 768) {
        sidebar.classList.toggle('mobile-open');
      } else {
        sidebar.classList.toggle('collapsed');
        if (main) main.classList.toggle('full-width');
      }
    });
  }

  // Auto-dismiss alerts
  setTimeout(() => {
    document.querySelectorAll('.alert.alert-success, .alert.alert-info').forEach(a => {
      a.style.transition = 'opacity .5s';
      a.style.opacity = '0';
      setTimeout(() => a.remove(), 500);
    });
  }, 4000);
});

// ── Toast Notifications ───────────────────────────────────────
function showToast(message, severity = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const icons = { critical: 'radiation', high: 'exclamation-triangle-fill', medium: 'exclamation-circle', info: 'info-circle' };
  const toast = document.createElement('div');
  toast.className = `soc-toast ${severity}`;
  toast.innerHTML = `
    <i class="bi bi-${icons[severity] || icons.info} text-${severity === 'critical' ? 'danger' : severity === 'high' ? 'warning' : 'info'}"></i>
    <div class="flex-grow-1 small">${message}</div>
    <button type="button" class="btn-close btn-close-white btn-sm" onclick="this.parentElement.remove()"></button>
  `;
  container.appendChild(toast);
  setTimeout(() => { if (toast.parentElement) toast.remove(); }, 8000);
}

// ── Copy to Clipboard ─────────────────────────────────────────
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard', 'info'));
}

// ── Confirm Delete ────────────────────────────────────────────
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', function (e) {
    if (!confirm(this.dataset.confirm)) e.preventDefault();
  });
});

// ── Number formatting ─────────────────────────────────────────
document.querySelectorAll('.kpi-value').forEach(el => {
  const n = parseInt(el.textContent.replace(/,/g, ''), 10);
  if (!isNaN(n)) el.textContent = n.toLocaleString();
});
