/**
 * PhishShield AI - Popup Controller Script (Manifest V3)
 * Full bilingual support (English & Amharic), per-tab risk statuses,
 * "Why was this flagged?" explanation engine, and scan stats/history.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const statusCard = document.getElementById("status-card");
  const statusIcon = document.getElementById("status-icon");
  const statusTitle = document.getElementById("status-title");
  const statusSubtitle = document.getElementById("status-subtitle");
  const statusBadgeTag = document.getElementById("status-badge-tag");
  const logoSubtitle = document.getElementById("logo-subtitle");

  const btnToggleLang = document.getElementById("btn-toggle-lang");
  const toggleProtection = document.getElementById("toggle-protection");

  const whyFlaggedCard = document.getElementById("why-flagged-card");
  const whyFlaggedLabel = document.getElementById("why-flagged-label");
  const whyFlaggedList = document.getElementById("why-flagged-list");
  const btnTrustDomain = document.getElementById("btn-trust-domain");
  const trustBtnLabel = document.getElementById("trust-btn-label");

  const statSitesChecked = document.getElementById("stat-sites-checked");
  const statThreatsBlocked = document.getElementById("stat-threats-blocked");
  const labelSitesChecked = document.getElementById("label-sites-checked");
  const labelThreatsBlocked = document.getElementById("label-threats-blocked");
  const btnResetStats = document.getElementById("btn-reset-stats");

  const btnToggleHistory = document.getElementById("btn-toggle-history");
  const historyDrawer = document.getElementById("history-drawer");
  const historyList = document.getElementById("history-list");
  const labelScanHistory = document.getElementById("label-scan-history");

  const btnOpenDashboard = document.getElementById("btn-open-dashboard");
  const labelOpenDashboard = document.getElementById("label-open-dashboard");
  const backendDot = document.getElementById("backend-dot");
  const backendText = document.getElementById("backend-text");
  const linkTestLab = document.getElementById("link-test-lab");
  const labelTestLab = document.getElementById("label-test-lab");

  let activeTabId = null;
  let activeTabHost = "";
  let activeTabUrl = "";
  let currentStatus = "safe";
  let currentThreatCount = 0;
  let currentFlags = [];
  let isProtectionEnabled = true;
  let currentLanguage = "en";

  // Modern SVG Icons
  const ICON_SHIELD_SAFE = `
    <svg class="status-svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`;

  const ICON_SHIELD_WARN = `
    <svg class="status-svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;

  const ICON_SHIELD_DANGER = `
    <svg class="status-svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;

  const ICON_SHIELD_PAUSED = `
    <svg class="status-svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="10" y1="15" x2="10" y2="9"/>
      <line x1="14" y1="15" x2="14" y2="9"/>
    </svg>`;

  function t(key) {
    if (window.PhishShieldI18n && window.PhishShieldI18n.t) {
      return window.PhishShieldI18n.t(key, currentLanguage);
    }
    return key;
  }

  function translateReason(reason) {
    if (window.PhishShieldI18n && window.PhishShieldI18n.translateReason) {
      return window.PhishShieldI18n.translateReason(reason, currentLanguage);
    }
    return reason;
  }

  /**
   * Update visual popup state based on enabled/disabled, risk status, and language
   */
  function renderUI() {
    // 1. Language Toggle Button text
    btnToggleLang.textContent = currentLanguage === "am" ? "English" : "አማርኛ";

    // 2. Static Labels
    labelSitesChecked.textContent = t("statSitesChecked");
    labelThreatsBlocked.textContent = t("statThreatsBlocked");
    labelOpenDashboard.textContent = t("openDashboard");
    labelTestLab.textContent = t("testLab");
    labelScanHistory.textContent = currentLanguage === "am" ? "የቅርብ ጊዜ የፍተሻ ታሪክ" : "Recent Scan Activity";
    trustBtnLabel.textContent = currentLanguage === "am" ? "ይህን ድረ-ገጽ እመነው" : "Trust Site";
    logoSubtitle.textContent = currentLanguage === "am" ? "የእውነተኛ ጊዜ የደህንነት ጠባቂ" : "Real-Time Threat Guardian";

    toggleProtection.checked = isProtectionEnabled;

    if (!isProtectionEnabled) {
      statusCard.className = "status-card disabled";
      statusIcon.innerHTML = ICON_SHIELD_PAUSED;
      statusBadgeTag.textContent = "OFF";
      statusBadgeTag.className = "status-badge-tag tag-paused";
      statusTitle.textContent = t("statusPausedTitle");
      statusSubtitle.textContent = t("statusPausedDesc");
      renderWhyFlagged(false, []);
      return;
    }

    if (currentStatus === "dangerous" || currentThreatCount > 0) {
      statusCard.className = "status-card danger";
      statusIcon.innerHTML = ICON_SHIELD_DANGER;
      statusBadgeTag.textContent = "DANG";
      statusBadgeTag.className = "status-badge-tag tag-danger";
      statusTitle.textContent = t("statusDangerousTitle");
      statusSubtitle.textContent = t("statusDangerousDesc");
      renderWhyFlagged(true, currentFlags);
    } else if (currentStatus === "suspicious") {
      statusCard.className = "status-card warning";
      statusIcon.innerHTML = ICON_SHIELD_WARN;
      statusBadgeTag.textContent = "WARN";
      statusBadgeTag.className = "status-badge-tag tag-warning";
      statusTitle.textContent = t("statusSuspiciousTitle");
      statusSubtitle.textContent = t("statusSuspiciousDesc");
      renderWhyFlagged(true, currentFlags);
    } else {
      statusCard.className = "status-card safe";
      statusIcon.innerHTML = ICON_SHIELD_SAFE;
      statusBadgeTag.textContent = "SAFE";
      statusBadgeTag.className = "status-badge-tag tag-safe";
      statusTitle.textContent = t("statusSafeTitle");
      statusSubtitle.textContent = t("statusSafeDesc");
      renderWhyFlagged(false, []);
    }
  }

  /**
   * Render the "Why was this flagged?" / "Why is this safe?" section
   */
  function renderWhyFlagged(isFlagged, flags) {
    whyFlaggedList.innerHTML = "";

    if (isFlagged && flags && flags.length > 0) {
      whyFlaggedCard.classList.remove("safe-mode");
      whyFlaggedLabel.textContent = t("whyFlagged");
      btnTrustDomain.style.display = "inline-flex";

      flags.forEach((flag) => {
        const li = document.createElement("li");
        li.innerHTML = `
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <span>${translateReason(flag)}</span>
        `;
        whyFlaggedList.appendChild(li);
      });
    } else {
      whyFlaggedCard.classList.add("safe-mode");
      whyFlaggedLabel.textContent = t("whySafe");
      btnTrustDomain.style.display = "none";

      const li = document.createElement("li");
      li.className = "reason-clean";
      li.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
        <span>${t("noThreatsFound")}</span>
      `;
      whyFlaggedList.appendChild(li);
    }
  }

  /**
   * Render Recent Scan History Drawer
   */
  function renderScanHistory(history = []) {
    historyList.innerHTML = "";
    if (!history || history.length === 0) {
      const empty = document.createElement("li");
      empty.className = "history-empty";
      empty.textContent = currentLanguage === "am" ? "እስካሁን ምንም የፍተሻ ታሪክ የለም" : "No scan activity recorded yet.";
      historyList.appendChild(empty);
      return;
    }

    history.slice(0, 15).forEach((item) => {
      const li = document.createElement("li");
      li.className = "history-item";

      const timeAgo = formatTimeAgo(item.timestamp);
      const tagClass = item.status === "dangerous" ? "hist-dang" : item.status === "suspicious" ? "hist-warn" : "hist-safe";
      const tagText = item.status === "dangerous" ? "DANG" : item.status === "suspicious" ? "WARN" : "SAFE";

      li.innerHTML = `
        <div class="hist-info">
          <span class="hist-host">${item.host || "unknown"}</span>
          <span class="hist-time">${timeAgo}</span>
        </div>
        <span class="hist-badge ${tagClass}">${tagText}</span>
      `;
      historyList.appendChild(li);
    });
  }

  function formatTimeAgo(ts) {
    if (!ts) return "";
    const diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
  }

  // ── 1. Query Current Active Tab & Load State ───────────────────────────────
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  const stored = await chrome.storage.local.get([
    "protectionEnabled",
    "userLanguage",
    "stats",
    "scanHistory",
    "trustedDomains"
  ]);

  isProtectionEnabled = stored.protectionEnabled !== false;
  currentLanguage = stored.userLanguage || "en";

  const stats = stored.stats || { sitesChecked: 0, threatsBlocked: 0 };
  statSitesChecked.textContent = String(stats.sitesChecked || 0);
  statThreatsBlocked.textContent = String(stats.threatsBlocked || 0);

  renderScanHistory(stored.scanHistory || []);

  if (activeTab && activeTab.id) {
    activeTabId = activeTab.id;
    activeTabUrl = activeTab.url || "";
    try {
      activeTabHost = activeTabUrl ? new URL(activeTabUrl).hostname.replace(/^www\./, "") : "";
    } catch (e) {}

    const tabKey = `tab_${activeTab.id}`;
    const tabData = (await chrome.storage.local.get(tabKey))[tabKey];

    if (tabData) {
      currentStatus = tabData.status || "safe";
      currentThreatCount = tabData.threatCount || 0;
      currentFlags = tabData.flags || [];
    }

    // Direct real-time query to tab content script
    try {
      const liveResp = await chrome.tabs.sendMessage(activeTab.id, { type: "GET_TAB_THREATS" });
      if (liveResp) {
        currentThreatCount = liveResp.threatCount || 0;
        currentStatus = liveResp.pageStatus || (currentThreatCount > 0 ? "dangerous" : "safe");
        if (liveResp.pageFlags && liveResp.pageFlags.length > 0) {
          currentFlags = liveResp.pageFlags;
        }
        if (liveResp.language) {
          // If no explicit user override, match page language
          if (!stored.userLanguage) {
            currentLanguage = liveResp.language;
          }
        }
      }
    } catch (e) {
      // Tab may be an internal page
    }
  }

  renderUI();

  // ── 2. Language Toggle Event ───────────────────────────────────────────────
  btnToggleLang.addEventListener("click", async () => {
    currentLanguage = currentLanguage === "am" ? "en" : "am";
    await chrome.storage.local.set({ userLanguage: currentLanguage });

    // Notify active tab content script
    if (activeTabId) {
      try {
        await chrome.tabs.sendMessage(activeTabId, {
          type: "SET_LANGUAGE",
          language: currentLanguage
        });
      } catch (e) {}
    }

    renderUI();
    const latestData = await chrome.storage.local.get("scanHistory");
    renderScanHistory(latestData.scanHistory || []);
  });

  // ── 3. Toggle Protection Switch ───────────────────────────────────────────
  toggleProtection.addEventListener("change", async (e) => {
    isProtectionEnabled = e.target.checked;
    await chrome.storage.local.set({ protectionEnabled: isProtectionEnabled });

    if (activeTabId) {
      try {
        await chrome.tabs.sendMessage(activeTabId, {
          type: "SET_PROTECTION_STATE",
          enabled: isProtectionEnabled
        });
      } catch (err) {}

      if (!isProtectionEnabled) {
        try {
          await chrome.action.setBadgeText({ tabId: activeTabId, text: "" });
        } catch (err) {}
      }
    }

    renderUI();
  });

  // ── 4. Trust Domain Button ────────────────────────────────────────────────
  btnTrustDomain.addEventListener("click", async () => {
    if (!activeTabHost) return;

    const data = await chrome.storage.local.get("trustedDomains");
    const list = Array.isArray(data.trustedDomains) ? data.trustedDomains : [];
    if (!list.includes(activeTabHost)) {
      list.push(activeTabHost);
      await chrome.storage.local.set({ trustedDomains: list });
    }

    currentStatus = "safe";
    currentFlags = [];
    currentThreatCount = 0;

    if (activeTabId) {
      try {
        await chrome.action.setBadgeText({ tabId: activeTabId, text: "SAFE" });
        await chrome.action.setBadgeBackgroundColor({ tabId: activeTabId, color: "#10b981" });
      } catch (e) {}
    }

    renderUI();
    alert(t("siteTrustedNotice"));
  });

  // ── 5. Toggle Scan History Drawer ─────────────────────────────────────────
  btnToggleHistory.addEventListener("click", () => {
    const isCollapsed = historyDrawer.classList.contains("collapsed");
    if (isCollapsed) {
      historyDrawer.classList.remove("collapsed");
      btnToggleHistory.classList.add("open");
    } else {
      historyDrawer.classList.add("collapsed");
      btnToggleHistory.classList.remove("open");
    }
  });

  // ── 6. Reset All-Time Counter ─────────────────────────────────────────────
  btnResetStats.addEventListener("click", async () => {
    await chrome.storage.local.set({
      stats: { sitesChecked: 0, threatsBlocked: 0 }
    });
    statSitesChecked.textContent = "0";
    statThreatsBlocked.textContent = "0";
  });

  // ── 7. Check Backend Health ───────────────────────────────────────────────
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

  // ── 8. Open Threat Dashboard & Test Lab ───────────────────────────────────
  btnOpenDashboard.addEventListener("click", async () => {
    await chrome.tabs.create({ url: chrome.runtime.getURL("dashboard.html") });
  });

  linkTestLab.addEventListener("click", async (e) => {
    e.preventDefault();
    await chrome.tabs.create({ url: chrome.runtime.getURL("test_lab.html") });
  });
});
