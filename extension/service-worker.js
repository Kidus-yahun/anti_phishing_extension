/**
 * PhishShield AI - Background Service Worker (Manifest V3)
 * Manages badge notifications, tab security state, and backend connectivity.
 */

// Handle installation
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[PhishShield AI] Background service worker initialized.");
  await chrome.storage.local.set({
    protectionEnabled: true,
    totalBlockedAllTime: 0,
    apiEndpoint: "http://127.0.0.1:8000"
  });
});

// Handle incoming messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (message.type === "UPDATE_TAB_THREATS") {
        const tabId = sender.tab ? sender.tab.id : null;
        const count = message.threatCount || 0;
        const { protectionEnabled = true } = await chrome.storage.local.get("protectionEnabled");

        if (tabId) {
          // Update extension toolbar badge
          if (protectionEnabled && count > 0) {
            await chrome.action.setBadgeText({ tabId, text: String(count) });
            await chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" });
          } else {
            await chrome.action.setBadgeText({ tabId, text: "" });
          }

          // Read previous count to only accumulate new threats (prevents infinite ballooning)
          const tabData = await chrome.storage.local.get([`tab_${tabId}`, "totalBlockedAllTime"]);
          const prevTabStats = tabData[`tab_${tabId}`];
          const prevCount = prevTabStats ? prevTabStats.threatCount || 0 : 0;
          const totalAllTime = tabData.totalBlockedAllTime || 0;
          const diff = Math.max(0, count - prevCount);

          await chrome.storage.local.set({
            [`tab_${tabId}`]: {
              threatCount: protectionEnabled ? count : 0,
              url: sender.tab.url || "",
              updatedAt: Date.now()
            },
            totalBlockedAllTime: totalAllTime + (protectionEnabled ? diff : 0)
          });
        }

        sendResponse({ success: true });
      } else if (message.type === "CHECK_BACKEND_HEALTH") {
        const { apiEndpoint = "http://127.0.0.1:8000" } = await chrome.storage.local.get("apiEndpoint");
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);

          const res = await fetch(`${apiEndpoint}/api/health`, {
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          const data = await res.json();
          sendResponse({ online: true, data });
        } catch (e) {
          sendResponse({ online: false, error: e.message });
        }
      }
    } catch (err) {
      console.error("[PhishShield AI] Service Worker Error:", err);
      sendResponse({ success: false, error: err.message });
    }
  })();

  return true; // Keep message channel open for async response
});

// Clean up tab stats when closed
chrome.tabs.onRemoved.addListener(async (tabId) => {
  try {
    await chrome.storage.local.remove(`tab_${tabId}`);
  } catch (e) {
    // Ignored
  }
});
