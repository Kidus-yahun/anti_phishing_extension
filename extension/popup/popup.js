/**
 * PhishShield AI - Popup Controller Script
 */

document.addEventListener("DOMContentLoaded", async () => {
  const statusCard = document.getElementById("status-card");
  const statusIcon = document.getElementById("status-icon");
  const statusTitle = document.getElementById("status-title");
  const statusSubtitle = document.getElementById("status-subtitle");
  const tabThreatsCount = document.getElementById("tab-threats-count");
  const allTimeCount = document.getElementById("all-time-count");
  const toggleProtection = document.getElementById("toggle-protection");
  const backendDot = document.getElementById("backend-dot");
  const backendText = document.getElementById("backend-text");
  const btnOpenDashboard = document.getElementById("btn-open-dashboard");

  // 1. Query Current Active Tab
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (activeTab && activeTab.id) {
    const tabKey = `tab_${activeTab.id}`;
    const data = await chrome.storage.local.get([tabKey, "totalBlockedAllTime", "protectionEnabled"]);

    const tabStats = data[tabKey];
    const threatCount = tabStats ? tabStats.threatCount || 0 : 0;
    const totalAllTime = data.totalBlockedAllTime || 0;
    const isProtected = data.protectionEnabled !== false;

    // Update Toggle
    toggleProtection.checked = isProtected;

    // Update Counts
    tabThreatsCount.textContent = String(threatCount);
    allTimeCount.textContent = String(totalAllTime);

    // Update Status Card
    if (threatCount > 0) {
      statusCard.className = "status-card danger";
      statusIcon.textContent = "🛑";
      statusTitle.textContent = `${threatCount} Phishing Threat${threatCount > 1 ? "s" : ""} Blocked!`;
      statusSubtitle.textContent = "High-visibility warning badges were applied to dangerous links on this page.";
    } else {
      statusCard.className = "status-card safe";
      statusIcon.textContent = "✅";
      statusTitle.textContent = "Current Tab is Safe";
      statusSubtitle.textContent = "No phishing links or homograph attacks detected on this page.";
    }
  }

  // 2. Check Backend Health
  try {
    const response = await chrome.runtime.sendMessage({ type: "CHECK_BACKEND_HEALTH" });
    if (response && response.online) {
      backendDot.className = "dot online";
      backendText.textContent = "ML Engine Online";
    } else {
      backendDot.className = "dot";
      backendText.textContent = "Standalone Mode";
    }
  } catch (e) {
    backendDot.className = "dot";
    backendText.textContent = "Standalone Mode";
  }

  // 3. Toggle Protection Listener
  toggleProtection.addEventListener("change", async (e) => {
    await chrome.storage.local.set({ protectionEnabled: e.target.checked });
  });

  // 4. Open Web Dashboard Listener
  btnOpenDashboard.addEventListener("click", async () => {
    await chrome.tabs.create({ url: "http://127.0.0.1:8000" });
  });
});
