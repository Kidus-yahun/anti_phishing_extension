/**
 * PhishShield AI - Popup Controller Script
 * Manages instant ON/OFF toggling, live tab stats, and background ML checks.
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

  let activeTabId = null;
  let currentThreatCount = 0;

  /**
   * Update visual popup state based on enabled/disabled and threat counts
   */
  function updatePopupUI(isEnabled, threatCount) {
    toggleProtection.checked = isEnabled;

    if (!isEnabled) {
      statusCard.className = "status-card disabled";
      statusIcon.textContent = "⏸️";
      statusTitle.textContent = "Protection is Paused";
      statusSubtitle.textContent = "Real-time link scanning, warnings, and blockers are currently turned off.";
      tabThreatsCount.textContent = "0";
    } else {
      tabThreatsCount.textContent = String(threatCount);

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
  }

  // 1. Query Current Active Tab & State
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (activeTab && activeTab.id) {
    activeTabId = activeTab.id;
    const tabKey = `tab_${activeTab.id}`;
    const data = await chrome.storage.local.get([tabKey, "totalBlockedAllTime", "protectionEnabled"]);

    const tabStats = data[tabKey];
    currentThreatCount = tabStats ? tabStats.threatCount || 0 : 0;
    const totalAllTime = data.totalBlockedAllTime || 0;
    const isProtected = data.protectionEnabled !== false; // default true

    allTimeCount.textContent = String(totalAllTime);
    updatePopupUI(isProtected, currentThreatCount);
  }

  // 2. Toggle Protection Event Listener
  toggleProtection.addEventListener("change", async (e) => {
    const isEnabled = e.target.checked;

    // Save state globally
    await chrome.storage.local.set({ protectionEnabled: isEnabled });

    // Send direct toggle message to the active tab's content script
    if (activeTabId) {
      try {
        await chrome.tabs.sendMessage(activeTabId, {
          type: "SET_PROTECTION_STATE",
          enabled: isEnabled
        });
      } catch (err) {
        // Tab might be internal page or restricted
      }

      // If turning OFF, clear badge immediately
      if (!isEnabled) {
        try {
          await chrome.action.setBadgeText({ tabId: activeTabId, text: "" });
        } catch (err) {}
      }
    }

    // Update popup UI instantly
    updatePopupUI(isEnabled, isEnabled ? currentThreatCount : 0);
  });

  // 3. Check Backend Health
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

  // 4. Open Web Dashboard Listener
  btnOpenDashboard.addEventListener("click", async () => {
    await chrome.tabs.create({ url: "http://127.0.0.1:8000" });
  });
});
