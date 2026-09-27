/**
 * PhishShield AI - Test Page Controller
 * Manifest V3 CSP Compliant: zero inline scripts.
 */

document.addEventListener("DOMContentLoaded", () => {
  const btnSpawn = document.getElementById("btn-spawn");
  if (btnSpawn) {
    btnSpawn.addEventListener("click", () => {
      const container = document.getElementById("dynamic-container");
      if (!container) return;

      const item = document.createElement("div");
      item.style.padding = "10px";
      item.style.background = "#0f172a";
      item.style.borderRadius = "8px";
      item.style.border = "1px solid #334155";
      item.style.marginTop = "8px";
      item.innerHTML = `
        <span style="font-size: 12px; color: #cbd5e1;">[New Message Received]</span><br>
        <a href="http://chase-security-update.top/login">Urgent Chase Alert: Click here to verify account</a>
      `;
      container.appendChild(item);
    });
  }
});
