/**
 * PhishShield AI - Background Service Worker (Manifest V3)
 * Manages per-tab toolbar risk badges (safe/suspicious/dangerous),
 * scan history and stats tracking in chrome.storage, shortlink expansion,
 * and backend ML communication.
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
    const existing = await chrome.storage.local.get([
      "protectionEnabled",
      "stats",
      "scanHistory",
      "trustedDomains",
      "apiEndpoint"
    ]);

    await chrome.storage.local.set({
      protectionEnabled: existing.protectionEnabled !== false,
      stats: existing.stats || { sitesChecked: 0, threatsBlocked: 0 },
      scanHistory: existing.scanHistory || [],
      trustedDomains: existing.trustedDomains || [],
      apiEndpoint: existing.apiEndpoint || "http://127.0.0.1:8000"
    });
  } catch (e) {
    // Ignored
  }
});

/**
 * Update Toolbar Badge with risk status per tab
 */
async function updateTabBadge(tabId, status, isEnabled) {
  if (!tabId) return;

  try {
    if (!isEnabled) {
      await chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
      await chrome.action.setTitle({ tabId, title: "PhishShield AI: Protection Paused" }).catch(() => {});
      return;
    }

    if (status === "dangerous") {
      await chrome.action.setBadgeText({ tabId, text: "DANG" }).catch(() => {});
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" }).catch(() => {});
      await chrome.action.setTitle({ tabId, title: "PhishShield AI: Dangerous Phishing Threat Detected!" }).catch(() => {});
    } else if (status === "suspicious") {
      await chrome.action.setBadgeText({ tabId, text: "WARN" }).catch(() => {});
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" }).catch(() => {});
      await chrome.action.setTitle({ tabId, title: "PhishShield AI: Suspicious Activity Detected" }).catch(() => {});
    } else {
      await chrome.action.setBadgeText({ tabId, text: "SAFE" }).catch(() => {});
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" }).catch(() => {});
      await chrome.action.setTitle({ tabId, title: "PhishShield AI: Current Tab is Safe" }).catch(() => {});
    }
  } catch (err) {
    // Tab might have closed during async dispatch
  }
}

// Handle incoming messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (!message || typeof message !== "object") {
        safeSendResponse(sendResponse, { success: false, error: "Invalid message payload" });
        return;
      }

      // ── 1. Tab Threat & Risk Status Update ─────────────────────────────────────
      if (message.type === "UPDATE_TAB_THREATS") {
        let tabId = sender.tab ? sender.tab.id : null;
        let tabUrl = sender.tab ? (sender.tab.url || message.url || "") : (message.url || "");
        let tabHost = message.host || (tabUrl ? new URL(tabUrl).hostname : "");

        if (!tabId) {
          try {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (activeTab) {
              tabId = activeTab.id;
              tabUrl = activeTab.url || tabUrl;
              tabHost = tabUrl ? new URL(tabUrl).hostname : tabHost;
            }
          } catch (e) {}
        }

        const count = typeof message.threatCount === "number" ? message.threatCount : 0;
        const status = message.status || (count > 0 ? "dangerous" : "safe");
        const flags = Array.isArray(message.flags) ? message.flags : [];

        const { protectionEnabled = true, stats = { sitesChecked: 0, threatsBlocked: 0 }, scanHistory = [] } =
          await chrome.storage.local.get(["protectionEnabled", "stats", "scanHistory"]).catch(() => ({}));

        if (tabId) {
          // Update toolbar badge per tab
          await updateTabBadge(tabId, status, protectionEnabled);

          // Update tab storage
          const tabKey = `tab_${tabId}`;
          const prevTabData = (await chrome.storage.local.get(tabKey).catch(() => ({})))[tabKey];
          const prevCount = prevTabData ? prevTabData.threatCount || 0 : 0;
          const threatDiff = Math.max(0, count - prevCount);
          const isNewSite = !prevTabData || prevTabData.url !== tabUrl;

          // Update stats
          const updatedSitesChecked = stats.sitesChecked + (isNewSite ? 1 : 0);
          const updatedThreatsBlocked = stats.threatsBlocked + (status === "dangerous" && isNewSite ? 1 : threatDiff);

          // Update scan history (max 100 entries)
          let updatedHistory = [...scanHistory];
          if (isNewSite && tabUrl && !tabUrl.startsWith("chrome://") && !tabUrl.startsWith("edge://")) {
            const historyItem = {
              id: "scan_" + Date.now(),
              url: tabUrl,
              host: tabHost,
              status,
              threatCount: count,
              flags,
              timestamp: Date.now()
            };
            updatedHistory.unshift(historyItem);
            if (updatedHistory.length > 100) {
              updatedHistory = updatedHistory.slice(0, 100);
            }
          }

          await chrome.storage.local.set({
            [tabKey]: {
              threatCount: count,
              status,
              flags,
              url: tabUrl,
              host: tabHost,
              updatedAt: Date.now()
            },
            stats: {
              sitesChecked: updatedSitesChecked,
              threatsBlocked: updatedThreatsBlocked
            },
            scanHistory: updatedHistory
          }).catch(() => {});
        }

        safeSendResponse(sendResponse, { success: true });

      // ── 2. Expand Shortlinks (bit.ly, t.co, etc.) ─────────────────────────────
      } else if (message.type === "EXPAND_SHORTLINK") {
        const shortUrl = message.url;
        if (!shortUrl) {
          safeSendResponse(sendResponse, { success: false, error: "No URL provided" });
          return;
        }

        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2800);

          const res = await fetch(shortUrl, {
            method: "HEAD",
            redirect: "follow",
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          const expandedUrl = res.url || shortUrl;
          const expandedHost = new URL(expandedUrl).hostname;
          safeSendResponse(sendResponse, { success: true, expandedUrl, expandedHost });
        } catch (e) {
          safeSendResponse(sendResponse, { success: false, error: e.message || "Failed to resolve shortlink" });
        }

      // ── 3. Check Backend Health ───────────────────────────────────────────────
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

      // ── 4. Verify Link with Backend Model ────────────────────────────────────
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
