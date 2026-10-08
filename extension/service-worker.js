/**
 * PhishShield AI - Background Service Worker (Manifest V3)
 * Manages badge notifications, tab security state, and backend connectivity.
 */

// Helper to safely send response without throwing if the port closed
function safeSendResponse(sendResponse, payload) {
  try {
    sendResponse(payload);
  } catch (e) {
    // Port closed before async response arrived - safe to ignore
  }
}

// Handle installation
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[PhishShield AI] Background service worker initialized.");
  try {
    await chrome.storage.local.set({
      protectionEnabled: true,
      totalBlockedAllTime: 0,
      apiEndpoint: "http://127.0.0.1:8000"
    });
  } catch (e) {
    // Ignored
  }
});

// Handle incoming messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (!message || typeof message !== "object") {
        safeSendResponse(sendResponse, { success: false, error: "Invalid message payload" });
        return;
      }

      if (message.type === "UPDATE_TAB_THREATS") {
        let tabId = sender.tab ? sender.tab.id : null;
        let tabUrl = sender.tab ? (sender.tab.url || "") : "";

        if (!tabId) {
          try {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (activeTab) {
              tabId = activeTab.id;
              tabUrl = activeTab.url || "";
            }
          } catch (e) {
            // Ignored
          }
        }

        const count = typeof message.threatCount === "number" ? message.threatCount : 0;
        const { protectionEnabled = true } = await chrome.storage.local.get("protectionEnabled").catch(() => ({}));

        if (tabId) {
          // Safely update toolbar badge (catches if tab was closed or navigated away)
          try {
            if (protectionEnabled && count > 0) {
              await chrome.action.setBadgeText({ tabId, text: String(count) }).catch(() => {});
              await chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" }).catch(() => {});
            } else {
              await chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
            }
          } catch (e) {
            // Ignored: tab may have closed during async execution
          }

          // Read previous count to only accumulate new threats (prevents infinite ballooning)
          try {
            const tabData = await chrome.storage.local.get([`tab_${tabId}`, "totalBlockedAllTime"]).catch(() => ({}));
            const prevTabStats = tabData[`tab_${tabId}`];
            const prevCount = prevTabStats ? prevTabStats.threatCount || 0 : 0;
            const totalAllTime = tabData.totalBlockedAllTime || 0;
            const diff = Math.max(0, count - prevCount);

            await chrome.storage.local.set({
              [`tab_${tabId}`]: {
                threatCount: protectionEnabled ? count : 0,
                url: tabUrl,
                updatedAt: Date.now()
              },
              totalBlockedAllTime: totalAllTime + (protectionEnabled ? diff : 0)
            }).catch(() => {});
          } catch (e) {
            // Ignored
          }
        }

        safeSendResponse(sendResponse, { success: true });
      } else if (message.type === "CHECK_BACKEND_HEALTH") {
        const { apiEndpoint = "http://127.0.0.1:8000" } = await chrome.storage.local.get("apiEndpoint").catch(() => ({}));
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);

          const res = await fetch(`${apiEndpoint}/api/health`, {
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (res.ok) {
            const data = await res.json();
            safeSendResponse(sendResponse, { online: true, data });
          } else {
            safeSendResponse(sendResponse, { online: false, error: "HTTP " + res.status });
          }
        } catch (e) {
          safeSendResponse(sendResponse, { online: false, error: e.message || "Offline" });
        }
      } else if (message.type === "VERIFY_LINK_WITH_MODEL") {
        const { apiEndpoint = "http://127.0.0.1:8000" } = await chrome.storage.local.get("apiEndpoint").catch(() => ({}));
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 1200);

          const res = await fetch(`${apiEndpoint}/api/verify-link`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              url: message.url || "",
              text: message.text || "",
              context: message.context || ""
            }),
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (res.ok) {
            const data = await res.json();
            safeSendResponse(sendResponse, { success: true, data });
          } else {
            safeSendResponse(sendResponse, { success: false, error: "HTTP " + res.status });
          }
        } catch (e) {
          safeSendResponse(sendResponse, { success: false, error: e.message || "Backend offline" });
        }
      } else {
        safeSendResponse(sendResponse, { success: false, error: "Unknown message type" });
      }
    } catch (err) {
      console.warn("[PhishShield AI] Service Worker handled notice:", err && err.message ? err.message : err);
      safeSendResponse(sendResponse, { success: false, error: err && err.message ? err.message : String(err) });
    }
  })();

  return true; // Keep message channel open for async response
});

// Clean up tab stats when closed
chrome.tabs.onRemoved.addListener(async (tabId) => {
  try {
    await chrome.storage.local.remove(`tab_${tabId}`).catch(() => {});
  } catch (e) {
    // Ignored
  }
});
