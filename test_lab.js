/**
 * PhishShield AI - Interactive Test Lab Controller
 * Manifest V3 CSP Compliant: zero inline scripts, zero inline event handlers.
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Simulate dynamic chat message injection
  const btnChat = document.getElementById("btn-inject-chat");
  if (btnChat) {
    btnChat.addEventListener("click", () => {
      const area = document.getElementById("dynamic-injection-area");
      if (!area) return;
      const msg = document.createElement("div");
      msg.className = "link-row";
      msg.style.borderLeft = "3px solid #ef4444";
      msg.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <span class="link-label" style="color: #f87171;">[Incoming Urgent Direct Message]</span>
          <span style="font-size: 10px; color: #64748b;">Just now</span>
        </div>
        <p style="font-size: 12px; color: #cbd5e1;">Hey, your account security was compromised! Confirm your login here:</p>
        <a href="http://discord-gift-nitro-claim.xyz/verify">http://discord-gift-nitro-claim.xyz/verify</a>
      `;
      area.prepend(msg);
    });
  }

  // 2. Simulate fake popup modal injection
  const btnModal = document.getElementById("btn-inject-modal");
  if (btnModal) {
    btnModal.addEventListener("click", () => {
      const existing = document.getElementById("active-mock-modal");
      if (existing) existing.remove();

      const overlay = document.createElement("div");
      overlay.className = "mock-modal-overlay";
      overlay.id = "active-mock-modal";

      overlay.innerHTML = `
        <div class="mock-modal">
          <div style="font-size: 32px; margin-bottom: 8px;">⚠️</div>
          <h3 style="font-size: 18px; margin-bottom: 8px; color: #ffffff;">Session Expiration Notice</h3>
          <p style="font-size: 13px; color: #94a3b8; margin-bottom: 16px;">
            Your Microsoft Office 365 session has expired. Re-authenticate to avoid losing unsaved document changes.
          </p>
          <div class="link-row" style="text-align: left; margin-bottom: 12px;">
            <a href="http://m1crosoft-office365-login.top/auth">Click here to re-authenticate with Microsoft</a>
          </div>
          <button id="btn-mock-modal-close" class="mock-modal-close">
            Dismiss Test Modal
          </button>
        </div>
      `;

      document.body.appendChild(overlay);

      const closeBtn = document.getElementById("btn-mock-modal-close");
      if (closeBtn) {
        closeBtn.addEventListener("click", () => {
          overlay.remove();
        });
      }
    });
  }

  // 3. Clear dynamic area
  const btnClear = document.getElementById("btn-clear");
  if (btnClear) {
    btnClear.addEventListener("click", () => {
      const area = document.getElementById("dynamic-injection-area");
      if (area) area.innerHTML = "";
    });
  }

  // 4. Adapt navigation link for server mode vs local file mode
  if (window.location.protocol !== "file:") {
    const dashLink = document.getElementById("nav-dashboard-link");
    if (dashLink) {
      dashLink.href = (window.location.protocol === "http:" || window.location.protocol === "https:") ? "/" : "dashboard.html";
    }
  }
});
