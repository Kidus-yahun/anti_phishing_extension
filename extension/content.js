/**
 * PhishShield AI - Content Script (Manifest V3)
 * Real-time DOM link inspection, floating security pill (Image 2 style),
 * Shadow DOM warning overlay for risky pages, link-hover tooltips,
 * Ethiopian phishing & Amharic scam detection, and bilingual support.
 */

(() => {
  if (window.__PHISHSHIELD_LOADED__) return;
  window.__PHISHSHIELD_LOADED__ = true;

  let isProtectionActive = false;
  let flaggedThreats = [];
  let isScanning = false;
  let pillElement = null;
  let threatsPanelElement = null;
  let safeToastTimer = null;
  let tooltipElement = null;
  let pageOverlayElement = null;
  let mutationObserver = null;
  let debounceTimer = null;
  let activeLanguage = "en";
  let pageSafetyResult = null;
  let trustedDomainsList = [];

  // Shadow DOM host reference (used strictly for overlays and tooltips to isolate styles)
  let shadowHost = null;
  let shadowRoot = null;

  // Intercept click listener store to allow clean removal
  const interceptedLinks = new Map();
  const shortlinkCache = new Map();

  // Modern SVG Icons (Image 2 style with glow)
  const SVG_SHIELD_CHECK = `
    <svg class="phishshield-pill-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 0 6px rgba(96, 165, 250, 0.5)); flex-shrink: 0;">
      <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z" fill="url(#phishshield-pill-gradient)"/>
      <path d="m9 12 2 2 4-4" stroke="#0b1120" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
      <defs>
        <linearGradient id="phishshield-pill-gradient" x1="4" y1="2" x2="20" y2="22" gradientUnits="userSpaceOnUse">
          <stop stop-color="#60a5fa"/>
          <stop offset="1" stop-color="#4f46e5"/>
        </linearGradient>
      </defs>
    </svg>`;

  const SVG_ALERT_OCTAGON = `
    <svg class="phishshield-svg-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;

  const SVG_ALERT_BADGE = `
    <svg class="phishshield-badge-svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;

  const SVG_MODAL_HERO = `
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#fb7185" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;

  const SVG_SHIELD_ALERT = `
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <line x1="12" y1="8" x2="12" y2="12"/>
      <line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>`;

  const SVG_ARROW_LEFT = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <line x1="19" y1="12" x2="5" y2="12"/>
      <polyline points="12 19 5 12 12 5"/>
    </svg>`;

  const SVG_CHECK_CIRCLE = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
      <polyline points="22 4 12 14.01 9 11.01"/>
    </svg>`;

  const SVG_CLOSE = `
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"></line>
      <line x1="6" y1="6" x2="18" y2="18"></line>
    </svg>`;

  /**
   * Helper translation function
   */
  function t(key) {
    if (window.PhishShieldI18n && window.PhishShieldI18n.t) {
      return window.PhishShieldI18n.t(key, activeLanguage);
    }
    return key;
  }

  function translateReason(reason) {
    if (window.PhishShieldI18n && window.PhishShieldI18n.translateReason) {
      return window.PhishShieldI18n.translateReason(reason, activeLanguage);
    }
    return reason;
  }

  /**
   * Acquire or initialize Shadow Root for Overlays and Tooltips
   */
  function getShadowRoot() {
    if (shadowRoot && shadowHost && shadowHost.isConnected) {
      return shadowRoot;
    }
    shadowHost = document.getElementById("phishshield-overlay-host");
    if (!shadowHost) {
      shadowHost = document.createElement("div");
      shadowHost.id = "phishshield-overlay-host";
      shadowHost.style.position = "fixed";
      shadowHost.style.top = "0";
      shadowHost.style.left = "0";
      shadowHost.style.width = "100vw";
      shadowHost.style.height = "100vh";
      shadowHost.style.zIndex = "2147483647";
      shadowHost.style.pointerEvents = "none";
      (document.body || document.documentElement).appendChild(shadowHost);
    }
    if (!shadowHost.shadowRoot) {
      shadowRoot = shadowHost.attachShadow({ mode: "open" });
      injectShadowStyles(shadowRoot);
    } else {
      shadowRoot = shadowHost.shadowRoot;
    }
    return shadowRoot;
  }

  /**
   * Inject complete glassmorphism styles and bundled font into Shadow Root
   */
  function injectShadowStyles(root) {
    const fontUrl = chrome.runtime.getURL("fonts/NotoSansEthiopic-Regular.woff2");
    const style = document.createElement("style");
    style.textContent = `
      @font-face {
        font-family: 'Noto Sans Ethiopic';
        font-style: normal;
        font-weight: 400;
        src: url('${fontUrl}') format('woff2');
        unicode-range: U+030E, U+1200-1399, U+2D80-2DDE, U+AB01-AB2E;
      }

      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: 'Noto Sans Ethiopic', 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        -webkit-font-smoothing: antialiased;
      }

      /* Injected Full-Page Warning Overlay */
      #phishshield-page-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(11, 13, 20, 0.88);
        -webkit-backdrop-filter: blur(28px) saturate(190%);
        backdrop-filter: blur(28px) saturate(190%);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
        pointer-events: auto;
        z-index: 2147483647;
        animation: overlay-fade 240ms cubic-bezier(0.16, 1, 0.3, 1);
      }

      @keyframes overlay-fade {
        from { opacity: 0; transform: scale(0.96); }
        to { opacity: 1; transform: scale(1); }
      }

      #phishshield-page-card {
        background: rgba(19, 24, 37, 0.94);
        -webkit-backdrop-filter: blur(32px);
        backdrop-filter: blur(32px);
        border: 1px solid rgba(244, 63, 94, 0.45);
        border-radius: 24px;
        max-width: 600px;
        width: 100%;
        max-height: 90vh;
        overflow-y: auto;
        padding: 36px 32px;
        box-shadow: 0 32px 80px rgba(0, 0, 0, 0.7), 0 0 48px rgba(244, 63, 94, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25);
        color: #ffffff;
        text-align: center;
        position: relative;
      }

      .phishshield-overlay-header-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
      }

      .phishshield-lang-pill-btn {
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(255, 255, 255, 0.16);
        color: #93c5fd;
        padding: 5px 12px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 600;
        cursor: pointer;
        transition: all 180ms ease;
      }

      .phishshield-lang-pill-btn:hover {
        background: rgba(96, 165, 250, 0.2);
        border-color: rgba(96, 165, 250, 0.4);
      }

      .phishshield-risk-tag {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        padding: 4px 10px;
        border-radius: 9999px;
        background: rgba(244, 63, 94, 0.18);
        color: #fb7185;
        border: 1px solid rgba(244, 63, 94, 0.35);
      }

      .phishshield-overlay-icon-wrap {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 72px;
        height: 72px;
        border-radius: 20px;
        background: rgba(244, 63, 94, 0.14);
        border: 1px solid rgba(244, 63, 94, 0.35);
        box-shadow: 0 0 32px rgba(244, 63, 94, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        margin-bottom: 18px;
      }

      .phishshield-overlay-title {
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.3px;
        color: #ffffff;
        margin-bottom: 10px;
        line-height: 1.3;
      }

      .phishshield-overlay-desc {
        font-size: 13.5px;
        font-weight: 400;
        color: rgba(255, 255, 255, 0.72);
        line-height: 1.55;
        margin-bottom: 20px;
      }

      .phishshield-url-box {
        background: rgba(0, 0, 0, 0.4);
        border: 1px solid rgba(255, 255, 255, 0.14);
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.45);
        border-radius: 12px;
        padding: 12px 14px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12.5px;
        color: #fb7185;
        word-break: break-all;
        margin-bottom: 20px;
        text-align: left;
      }

      .phishshield-why-container {
        text-align: left;
        margin-bottom: 24px;
      }

      .phishshield-why-title {
        font-size: 13px;
        font-weight: 600;
        color: #fecdd3;
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 10px;
      }

      .phishshield-reasons-list {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .phishshield-reasons-list li {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(244, 63, 94, 0.22);
        border-radius: 10px;
        padding: 10px 14px;
        font-size: 12px;
        color: #fda4af;
        display: flex;
        align-items: flex-start;
        gap: 10px;
        line-height: 1.45;
      }

      .phishshield-reasons-list li svg {
        flex-shrink: 0;
        margin-top: 2px;
      }

      .phishshield-overlay-actions {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }

      .phishshield-btn-goback {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.28);
        padding: 13px 22px;
        font-size: 13.5px;
        font-weight: 600;
        letter-spacing: 0.2px;
        border-radius: 12px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        box-shadow: 0 8px 24px rgba(16, 185, 129, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.35);
        transition: transform 180ms ease, box-shadow 180ms ease;
      }

      .phishshield-btn-goback:hover {
        transform: translateY(-1px);
        box-shadow: 0 10px 30px rgba(16, 185, 129, 0.5);
      }

      .phishshield-btn-row {
        display: flex;
        gap: 10px;
        justify-content: space-between;
      }

      .phishshield-btn-trust {
        flex: 1;
        background: rgba(255, 255, 255, 0.08);
        color: #cbd5e1;
        border: 1px solid rgba(255, 255, 255, 0.16);
        padding: 10px 14px;
        font-size: 12px;
        font-weight: 500;
        border-radius: 10px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        transition: all 180ms ease;
      }

      .phishshield-btn-trust:hover {
        background: rgba(96, 165, 250, 0.16);
        border-color: rgba(96, 165, 250, 0.35);
        color: #93c5fd;
      }

      .phishshield-btn-proceed {
        flex: 1;
        background: transparent;
        color: rgba(255, 255, 255, 0.5);
        border: 1px solid transparent;
        padding: 10px 14px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        border-radius: 10px;
        text-decoration: underline;
        transition: color 180ms ease;
      }

      .phishshield-btn-proceed:hover {
        color: #fb7185;
      }

      /* Link-Hover Tooltip */
      #phishshield-link-tooltip {
        position: fixed;
        z-index: 2147483646;
        pointer-events: none;
        background: rgba(15, 23, 42, 0.94);
        -webkit-backdrop-filter: blur(18px);
        backdrop-filter: blur(18px);
        border: 1px solid rgba(255, 255, 255, 0.16);
        border-radius: 10px;
        padding: 8px 12px;
        box-shadow: 0 10px 28px rgba(0, 0, 0, 0.48), 0 0 14px rgba(96, 165, 250, 0.15);
        color: #f1f5f9;
        font-size: 12px;
        max-width: 380px;
        word-break: break-all;
        opacity: 0;
        transform: translateY(4px);
        transition: opacity 140ms ease, transform 140ms ease;
      }

      #phishshield-link-tooltip.visible {
        opacity: 1;
        transform: translateY(0);
      }

      .phishshield-tt-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        margin-bottom: 4px;
      }

      .phishshield-tt-tag {
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        padding: 2px 7px;
        border-radius: 9999px;
      }

      .phishshield-tt-safe {
        background: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.3);
      }

      .phishshield-tt-suspicious {
        background: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid rgba(245, 158, 11, 0.3);
      }

      .phishshield-tt-danger {
        background: rgba(239, 68, 68, 0.22);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
      }

      .phishshield-tt-domain {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-weight: 600;
        color: #60a5fa;
      }

      .phishshield-tt-reason {
        font-size: 11px;
        color: #fda4af;
        margin-top: 3px;
        line-height: 1.35;
      }

      /* Intercept Click Modal Overlay */
      #phishshield-modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(11, 13, 20, 0.85);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        backdrop-filter: blur(20px) saturate(180%);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
        pointer-events: auto;
        z-index: 2147483647;
        animation: phishshield-modal-fade 180ms ease-out;
      }

      @keyframes phishshield-modal-fade {
        from { opacity: 0; }
        to { opacity: 1; }
      }

      #phishshield-modal-card {
        position: relative;
        background: linear-gradient(145deg, rgba(26, 16, 23, 0.96) 0%, rgba(15, 12, 19, 0.98) 100%);
        border: 1px solid rgba(244, 63, 94, 0.4);
        box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.8), 0 0 35px rgba(244, 63, 94, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.15);
        border-radius: 20px;
        max-width: 520px;
        width: 100%;
        max-height: 90vh;
        overflow-y: auto;
        padding: 32px 28px;
        text-align: center;
        color: #ffffff;
        pointer-events: auto;
        box-sizing: border-box;
        animation: phishshield-card-scale 220ms cubic-bezier(0.16, 1, 0.3, 1);
      }

      @keyframes phishshield-card-scale {
        from { opacity: 0; transform: scale(0.92); }
        to { opacity: 1; transform: scale(1); }
      }

      #phishshield-modal-close-btn {
        position: absolute;
        top: 16px;
        right: 16px;
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(255, 255, 255, 0.14);
        color: #94a3b8;
        width: 32px;
        height: 32px;
        border-radius: 50%;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 150ms ease;
      }

      #phishshield-modal-close-btn:hover {
        background: rgba(255, 255, 255, 0.2);
        color: #ffffff;
        transform: scale(1.06);
      }

      .phishshield-modal-icon-wrap {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 64px;
        height: 64px;
        border-radius: 18px;
        background: rgba(244, 63, 94, 0.15);
        border: 1px solid rgba(244, 63, 94, 0.35);
        box-shadow: 0 0 24px rgba(244, 63, 94, 0.3);
        margin-bottom: 16px;
      }

      .phishshield-modal-title {
        font-size: 19px;
        font-weight: 700;
        letter-spacing: -0.3px;
        color: #ffffff;
        margin-bottom: 8px;
        line-height: 1.3;
      }

      .phishshield-modal-desc {
        font-size: 13px;
        font-weight: 400;
        color: rgba(255, 255, 255, 0.72);
        line-height: 1.5;
        margin-bottom: 18px;
      }

      .phishshield-modal-actions {
        display: flex;
        flex-direction: column;
        gap: 10px;
        margin-top: 10px;
      }

      .phishshield-btn-safe {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.28);
        padding: 12px 22px;
        font-size: 13px;
        font-weight: 600;
        border-radius: 12px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        box-shadow: 0 6px 20px rgba(16, 185, 129, 0.35);
        transition: transform 150ms ease, box-shadow 150ms ease;
      }

      .phishshield-btn-safe:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 26px rgba(16, 185, 129, 0.48);
      }

      .phishshield-btn-unsafe {
        background: transparent;
        color: rgba(255, 255, 255, 0.55);
        border: 1px solid transparent;
        padding: 8px 14px;
        font-size: 12px;
        cursor: pointer;
        border-radius: 8px;
        text-decoration: underline;
        transition: color 150ms ease;
      }

      .phishshield-btn-unsafe:hover {
        color: #fb7185;
      }
    `;
    root.appendChild(style);
  }

  /**
   * Initialize state on page load
   */
  async function init() {
    let isEnabled = true;
    try {
      if (chrome.storage && chrome.storage.local) {
        const data = await chrome.storage.local.get(["protectionEnabled", "userLanguage", "trustedDomains"]);
        isEnabled = data.protectionEnabled !== false; // default true
        trustedDomainsList = Array.isArray(data.trustedDomains) ? data.trustedDomains : [];

        // Resolve active language
        if (data.userLanguage === "am" || data.userLanguage === "en") {
          activeLanguage = data.userLanguage;
        } else if (window.PhishShieldI18n && window.PhishShieldI18n.isAmharicPage(document)) {
          activeLanguage = "am";
        } else {
          activeLanguage = "en";
        }
      } else {
        isEnabled = true;
        if (window.PhishShieldI18n && window.PhishShieldI18n.isAmharicPage(document)) {
          activeLanguage = "am";
        }
      }
    } catch (e) {
      isEnabled = true;
    }

    // Load local Threat Intelligence Database into heuristics
    try {
      if (chrome.runtime && chrome.runtime.getURL) {
        const feedUrl = chrome.runtime.getURL("threat_domains.json");
        const res = await fetch(feedUrl);
        const threatData = await res.json();
        if (threatData && Array.isArray(threatData.domains) && window.PhishShieldHeuristics && window.PhishShieldHeuristics.initThreatDatabase) {
          window.PhishShieldHeuristics.initThreatDatabase(threatData.domains);
        }
      }
    } catch (e) {}

    if (isEnabled) {
      enableProtection();
    }

    setupStateListeners();
    setupTooltipListener();
  }

  /**
   * Listen for real-time toggle events and storage changes
   */
  function setupStateListeners() {
    if (chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "local") {
          if (changes.protectionEnabled !== undefined) {
            const isEnabled = changes.protectionEnabled.newValue !== false;
            if (isEnabled && !isProtectionActive) {
              enableProtection();
            } else if (!isEnabled && isProtectionActive) {
              disableProtection();
            }
          }
          if (changes.userLanguage !== undefined) {
            activeLanguage = changes.userLanguage.newValue || "en";
            updateLanguageUI();
          }
          if (changes.trustedDomains !== undefined) {
            trustedDomainsList = Array.isArray(changes.trustedDomains.newValue) ? changes.trustedDomains.newValue : [];
            if (pageOverlayElement && window.PhishShieldHeuristics) {
              const currentHost = window.location.hostname.replace(/^www\./, "");
              if (trustedDomainsList.includes(currentHost)) {
                removePageWarningOverlay();
                notifyServiceWorker("safe", 0, []);
              }
            }
          }
        }
      });
    }

    if (chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === "GET_TAB_THREATS") {
          sendResponse({
            threatCount: flaggedThreats.length,
            active: isProtectionActive,
            pageStatus: pageSafetyResult ? pageSafetyResult.status : "safe",
            pageFlags: pageSafetyResult ? pageSafetyResult.flags : [],
            language: activeLanguage,
            threats: flaggedThreats.map((t) => ({ url: t.url, flags: t.flags }))
          });
          return true;
        }

        if (message.type === "SET_PROTECTION_STATE") {
          if (message.enabled && !isProtectionActive) {
            enableProtection();
          } else if (!message.enabled && isProtectionActive) {
            disableProtection();
          }
          sendResponse({ success: true, active: isProtectionActive });
        }

        if (message.type === "SET_LANGUAGE") {
          activeLanguage = message.language === "am" ? "am" : "en";
          updateLanguageUI();
          sendResponse({ success: true, language: activeLanguage });
        }
      });
    }
  }

  /**
   * Update all text elements when language is changed
   */
  function updateLanguageUI() {
    updatePill();
    if (pageOverlayElement && pageSafetyResult) {
      renderPageWarningOverlay(pageSafetyResult);
    }
  }

  /**
   * TURN ON: Evaluate page safety, activate protection, scan links, start observer, show pill
   */
  function enableProtection() {
    if (isProtectionActive) return;
    isProtectionActive = true;

    // 1. Create floating pill in bottom corner (matching Image 2)
    createFloatingPill();

    // 2. Evaluate current webpage safety
    evaluateCurrentPageSafety();

    // 3. Scan DOM links
    scanPageLinks();

    // 4. Observe dynamic additions
    observeMutations();
  }

  /**
   * TURN OFF: Completely clean DOM, remove badges, remove click handlers, hide pill & overlay
   */
  function disableProtection() {
    isProtectionActive = false;

    // 1. Stop MutationObserver
    if (mutationObserver) {
      mutationObserver.disconnect();
      mutationObserver = null;
    }
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }

    // 2. Remove all injected warning badges
    const badges = document.querySelectorAll(".phishshield-inline-badge");
    badges.forEach((b) => b.remove());

    // 3. Remove flagged styling & click interception
    interceptedLinks.forEach((handler, link) => {
      link.classList.remove("phishshield-flagged-link");
      link.removeAttribute("title");
      link.removeAttribute("data-phishshield-inspected");
      link.removeEventListener("click", handler, true);
    });
    interceptedLinks.clear();

    document.querySelectorAll("a[data-phishshield-inspected]").forEach((a) => {
      a.removeAttribute("data-phishshield-inspected");
    });

    // 4. Remove floating pill
    closeThreatsPanel();
    if (safeToastTimer) {
      clearTimeout(safeToastTimer);
      safeToastTimer = null;
    }
    const existingPill = document.getElementById("phishshield-floating-pill");
    if (existingPill) existingPill.remove();
    pillElement = null;

    // 5. Clean up Shadow DOM overlay elements
    if (shadowRoot) {
      removePageWarningOverlay();
      const activeModal = shadowRoot.getElementById("phishshield-modal-overlay");
      if (activeModal) activeModal.remove();

      if (tooltipElement) {
        tooltipElement.remove();
        tooltipElement = null;
      }
    }

    // 6. Reset threats and notify service worker
    flaggedThreats = [];
    notifyServiceWorker("safe", 0, []);
  }

  /**
   * Close non-intrusive threats panel flyout
   */
  function closeThreatsPanel() {
    if (threatsPanelElement) {
      threatsPanelElement.remove();
      threatsPanelElement = null;
    }
  }

  /**
   * Toggle sleek non-distracting threats list flyout anchored above the pill
   */
  function toggleThreatsPanel() {
    if (threatsPanelElement) {
      closeThreatsPanel();
      return;
    }

    if (!pillElement || flaggedThreats.length === 0) return;

    threatsPanelElement = document.createElement("div");
    threatsPanelElement.id = "phishshield-threats-panel";

    const titleText = activeLanguage === "am" ? "የተገኙ የማጭበርበሪያ አገናኞች" : "Detected Phishing Links";
    const descText = activeLanguage === "am" ? "ወደ አገናኙ በቀጥታ ለመሄድ ይጫኑ፡" : "Click any threat to jump to its location on page:";
    const locateLabel = activeLanguage === "am" ? "አሳይ" : "Jump to";

    let itemsHtml = "";
    flaggedThreats.forEach((threat, idx) => {
      const cleanUrl = String(threat.url || "").replace(/^https?:\/\//i, "");
      const primaryReason = threat.flags && threat.flags[0] ? translateReason(threat.flags[0]) : (activeLanguage === "am" ? "አደገኛ አገናኝ" : "Dangerous Phishing Destination");
      itemsHtml += `
        <li class="phishshield-panel-item" data-threat-index="${idx}">
          <div class="phishshield-panel-item-top">
            <span class="phishshield-panel-item-url" title="${threat.url}">${cleanUrl}</span>
            <span class="phishshield-panel-item-action">
              ${locateLabel}
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
            </span>
          </div>
          <div class="phishshield-panel-item-reason">${primaryReason}</div>
        </li>
      `;
    });

    threatsPanelElement.innerHTML = `
      <div class="phishshield-panel-header">
        <div class="phishshield-panel-title-wrap">
          ${SVG_ALERT_OCTAGON}
          <span class="phishshield-panel-title">${titleText}</span>
          <span class="phishshield-panel-badge-count">${flaggedThreats.length}</span>
        </div>
        <button class="phishshield-panel-close-btn" id="phishshield-close-threats-btn" aria-label="Close" title="Close">
          ${SVG_CLOSE}
        </button>
      </div>
      <p class="phishshield-panel-desc">${descText}</p>
      <ul class="phishshield-panel-list">
        ${itemsHtml}
      </ul>
    `;

    pillElement.appendChild(threatsPanelElement);

    threatsPanelElement.querySelector("#phishshield-close-threats-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      closeThreatsPanel();
    });

    threatsPanelElement.querySelectorAll(".phishshield-panel-item").forEach((item) => {
      item.addEventListener("click", (e) => {
        e.stopPropagation();
        const idx = parseInt(item.getAttribute("data-threat-index"), 10);
        const threat = flaggedThreats[idx];
        if (threat && threat.element) {
          threat.element.scrollIntoView({ behavior: "smooth", block: "center" });
          threat.element.classList.remove("phishshield-focused-threat");
          void threat.element.offsetWidth;
          threat.element.classList.add("phishshield-focused-threat");
          setTimeout(() => {
            if (threat.element) threat.element.classList.remove("phishshield-focused-threat");
          }, 2000);
        }
      });
    });

    const outsideListener = (e) => {
      if (threatsPanelElement && !threatsPanelElement.contains(e.target) && !pillElement.contains(e.target)) {
        closeThreatsPanel();
        document.removeEventListener("click", outsideListener);
      }
    };
    setTimeout(() => document.addEventListener("click", outsideListener), 50);
  }

  /**
   * Show brief non-intrusive safe toast when pill is tapped on a clean page
   */
  function showSafeToast() {
    if (!pillElement) return;
    const existing = pillElement.querySelector("#phishshield-safe-toast");
    if (existing) existing.remove();
    if (safeToastTimer) clearTimeout(safeToastTimer);

    const toast = document.createElement("div");
    toast.id = "phishshield-safe-toast";
    const safeText = activeLanguage === "am" ? "ምንም ዓይነት አጠራጣሪ አገናኝ አልተገኘም። ገጹ ደህንነቱ የተጠበቀ ነው።" : "No threats found. All page links verified safe.";
    toast.innerHTML = `${SVG_CHECK_CIRCLE}<span>${safeText}</span>`;
    pillElement.appendChild(toast);

    safeToastTimer = setTimeout(() => {
      if (toast && toast.isConnected) toast.remove();
      safeToastTimer = null;
    }, 2800);
  }

  /**
   * Create floating security pill in the bottom corner (Image 2 style)
   */
  function createFloatingPill() {
    if (!isProtectionActive) return;
    if (document.getElementById("phishshield-floating-pill")) {
      pillElement = document.getElementById("phishshield-floating-pill");
      return;
    }

    if (!document.body) {
      window.addEventListener("DOMContentLoaded", createFloatingPill, { once: true });
      return;
    }

    pillElement = document.createElement("div");
    pillElement.id = "phishshield-floating-pill";

    const badge = document.createElement("div");
    badge.className = "phishshield-pill-badge phishshield-pill-safe";
    const protectedLabel = activeLanguage === "am" ? "ፊሽሺልድ፡ ጥበቃ ላይ" : "PhishShield: Protected";
    badge.innerHTML = `${SVG_SHIELD_CHECK}<span>${protectedLabel}</span>`;

    badge.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!isProtectionActive) return;

      if (flaggedThreats.length > 0) {
        toggleThreatsPanel();
      } else {
        showSafeToast();
      }
    });

    pillElement.appendChild(badge);
    document.body.appendChild(pillElement);
  }

  /**
   * Update floating pill status
   */
  function updatePill() {
    if (!isProtectionActive) return;
    if (!pillElement || !pillElement.isConnected) {
      createFloatingPill();
      if (!pillElement) return;
    }

    const badge = pillElement.querySelector(".phishshield-pill-badge");
    if (!badge) return;

    if (flaggedThreats.length > 0) {
      badge.className = "phishshield-pill-badge phishshield-pill-threat";
      const threatLabel = activeLanguage === "am" ? `${flaggedThreats.length} የማጭበርበሪያ አገናኝ ታግዷል` : `${flaggedThreats.length} Phishing Link${flaggedThreats.length > 1 ? "s" : ""} Blocked`;
      badge.innerHTML = `${SVG_ALERT_OCTAGON}<span>${threatLabel}</span>`;
    } else {
      if (threatsPanelElement) {
        closeThreatsPanel();
      }
      badge.className = "phishshield-pill-badge phishshield-pill-safe";
      const protectedLabel = activeLanguage === "am" ? "ፊሽሺልድ፡ ጥበቃ ላይ" : "PhishShield: Protected";
      badge.innerHTML = `${SVG_SHIELD_CHECK}<span>${protectedLabel}</span>`;
    }
  }

  /**
   * Evaluate the page itself for Ethiopian lookalikes, credential scams, or homographs
   */
  function evaluateCurrentPageSafety() {
    if (!window.PhishShieldHeuristics || !window.PhishShieldHeuristics.evaluatePageSafety) return;

    pageSafetyResult = window.PhishShieldHeuristics.evaluatePageSafety(
      document,
      window.location.hostname,
      window.location.href,
      trustedDomainsList
    );

    // If page is dangerous or suspicious and not trusted, show injected Shadow DOM overlay
    if ((pageSafetyResult.status === "dangerous" || pageSafetyResult.status === "suspicious") && !pageSafetyResult.isTrusted) {
      renderPageWarningOverlay(pageSafetyResult);
    }

    notifyServiceWorker(pageSafetyResult.status, flaggedThreats.length, pageSafetyResult.flags);
  }

  /**
   * Render Injected Full-Page Warning Overlay inside Shadow DOM
   */
  function renderPageWarningOverlay(result) {
    if (!isProtectionActive) return;
    const root = getShadowRoot();
    if (!root) return;

    removePageWarningOverlay();

    pageOverlayElement = document.createElement("div");
    pageOverlayElement.id = "phishshield-page-overlay";

    const isDangerous = result.status === "dangerous";
    const titleText = isDangerous ? t("overlayTitleDanger") : t("overlayTitleWarning");
    const safeUrl = String(result.url).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const reasonsHtml = result.flags.map((flag) => {
      const localized = translateReason(flag);
      return `<li>${SVG_ALERT_OCTAGON}<span>${localized}</span></li>`;
    }).join("");

    const card = document.createElement("div");
    card.id = "phishshield-page-card";

    card.innerHTML = `
      <div class="phishshield-overlay-header-bar">
        <span class="phishshield-risk-tag">${isDangerous ? "DANGEROUS / አደገኛ" : "SUSPICIOUS / አጠራጣሪ"}</span>
        <button id="phishshield-overlay-lang-btn" class="phishshield-lang-pill-btn" title="Toggle Language">
          ${activeLanguage === "am" ? "English" : "አማርኛ"}
        </button>
      </div>

      <div class="phishshield-overlay-icon-wrap">
        ${SVG_SHIELD_ALERT}
      </div>

      <h1 class="phishshield-overlay-title">${titleText}</h1>
      <p class="phishshield-overlay-desc">${t("overlayDesc")}</p>

      <div class="phishshield-url-box">${safeUrl}</div>

      <div class="phishshield-why-container">
        <div class="phishshield-why-title">
          ${SVG_ALERT_OCTAGON}
          <span>${t("whyFlagged")}</span>
        </div>
        <ul class="phishshield-reasons-list">
          ${reasonsHtml}
        </ul>
      </div>

      <div class="phishshield-overlay-actions">
        <button id="phishshield-btn-goback" class="phishshield-btn-goback">
          ${SVG_ARROW_LEFT}
          <span>${t("btnGoBack")}</span>
        </button>
        <div class="phishshield-btn-row">
          <button id="phishshield-btn-trust" class="phishshield-btn-trust">
            ${SVG_CHECK_CIRCLE}
            <span>${t("btnTrustSite")}</span>
          </button>
          <button id="phishshield-btn-proceed" class="phishshield-btn-proceed">
            ${t("btnProceedAnyway")}
          </button>
        </div>
      </div>
    `;

    pageOverlayElement.appendChild(card);
    root.appendChild(pageOverlayElement);

    // Event Handlers
    card.querySelector("#phishshield-overlay-lang-btn").addEventListener("click", async () => {
      activeLanguage = activeLanguage === "am" ? "en" : "am";
      try {
        await chrome.storage.local.set({ userLanguage: activeLanguage });
      } catch (e) {}
      renderPageWarningOverlay(result);
    });

    card.querySelector("#phishshield-btn-goback").addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "about:blank";
      }
    });

    card.querySelector("#phishshield-btn-proceed").addEventListener("click", () => {
      const confirmMsg = t("confirmProceed");
      if (confirm(confirmMsg)) {
        removePageWarningOverlay();
      }
    });

    card.querySelector("#phishshield-btn-trust").addEventListener("click", async () => {
      const currentHost = window.location.hostname.replace(/^www\./, "");
      try {
        const data = await chrome.storage.local.get("trustedDomains");
        const list = Array.isArray(data.trustedDomains) ? data.trustedDomains : [];
        if (!list.includes(currentHost)) {
          list.push(currentHost);
          await chrome.storage.local.set({ trustedDomains: list });
        }
      } catch (e) {}
      removePageWarningOverlay();
      notifyServiceWorker("safe", flaggedThreats.length, []);
      alert(t("siteTrustedNotice"));
    });
  }

  function removePageWarningOverlay() {
    if (pageOverlayElement) {
      pageOverlayElement.remove();
      pageOverlayElement = null;
    }
  }

  /**
   * Link-Hover Tooltip showing real destination domain and safety status
   */
  function setupTooltipListener() {
    document.addEventListener("mouseover", handleLinkHover, true);
    document.addEventListener("focusin", handleLinkHover, true);
    document.addEventListener("mouseout", handleLinkUnhover, true);
    document.addEventListener("focusout", handleLinkUnhover, true);
    window.addEventListener("scroll", handleLinkUnhover, { passive: true });
  }

  async function handleLinkHover(e) {
    if (!isProtectionActive) return;
    const link = e.target.closest("a[href]");
    if (!link) return;

    const href = link.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) return;

    let parsed;
    try {
      parsed = new URL(link.href, window.location.href);
    } catch (err) {
      return;
    }

    const host = parsed.hostname || "";
    if (!host) return;

    // Evaluate destination safety
    const decodedHost = window.PhishShieldHeuristics ? window.PhishShieldHeuristics.toUnicodeHost(host) : host;
    const isShort = window.PhishShieldHeuristics ? window.PhishShieldHeuristics.isShortlink(host) : false;
    let evalResult = window.PhishShieldHeuristics ? window.PhishShieldHeuristics.evaluateLinkSafety(link, link.href) : { riskScore: 0, flags: [] };

    let statusType = "safe";
    let statusText = t("tooltipStatusSafe");
    if (evalResult.riskScore >= 60) {
      statusType = "danger";
      statusText = t("tooltipStatusDangerous");
    } else if (evalResult.riskScore >= 30) {
      statusType = "suspicious";
      statusText = t("tooltipStatusSuspicious");
    }

    let expandedHost = "";
    if (isShort) {
      if (shortlinkCache.has(link.href)) {
        expandedHost = shortlinkCache.get(link.href);
      } else {
        chrome.runtime.sendMessage({ type: "EXPAND_SHORTLINK", url: link.href }, (resp) => {
          if (resp && resp.expandedHost) {
            shortlinkCache.set(link.href, resp.expandedHost);
            if (tooltipElement && tooltipElement.classList.contains("visible")) {
              const expEl = tooltipElement.querySelector(".phishshield-tt-expanded");
              if (expEl) expEl.textContent = `${t("tooltipExpandsTo")} ${resp.expandedHost}`;
            }
          }
        });
      }
    }

    showLinkTooltip(link, decodedHost, statusType, statusText, evalResult.flags[0] || "", expandedHost);
  }

  function handleLinkUnhover(e) {
    if (tooltipElement) {
      tooltipElement.classList.remove("visible");
    }
  }

  function showLinkTooltip(targetLink, domain, statusType, statusText, reason, expandedHost) {
    const root = getShadowRoot();
    if (!root) return;

    if (!tooltipElement) {
      tooltipElement = document.createElement("div");
      tooltipElement.id = "phishshield-link-tooltip";
      root.appendChild(tooltipElement);
    }

    const rect = targetLink.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) return;

    const tagClass = statusType === "danger" ? "phishshield-tt-danger" : statusType === "suspicious" ? "phishshield-tt-suspicious" : "phishshield-tt-safe";
    const localizedReason = reason ? translateReason(reason) : "";

    tooltipElement.innerHTML = `
      <div class="phishshield-tt-top">
        <span class="phishshield-tt-domain">${domain}</span>
        <span class="phishshield-tt-tag ${tagClass}">${statusText}</span>
      </div>
      ${expandedHost ? `<div class="phishshield-tt-expanded" style="font-size:11px;color:#93c5fd;margin-top:2px;">${t("tooltipExpandsTo")} ${expandedHost}</div>` : ""}
      ${localizedReason ? `<div class="phishshield-tt-reason">${localizedReason}</div>` : ""}
    `;

    const tooltipHeight = 44;
    let top = rect.top - tooltipHeight - 6;
    if (top < 10) {
      top = rect.bottom + 6;
    }
    let left = Math.max(10, Math.min(rect.left, window.innerWidth - 320));

    tooltipElement.style.top = `${top}px`;
    tooltipElement.style.left = `${left}px`;
    tooltipElement.classList.add("visible");
  }

  /**
   * Scan page links in batches using requestAnimationFrame
   */
  async function scanPageLinks() {
    if (!isProtectionActive || isScanning) return;
    isScanning = true;

    try {
      const allLinks = Array.from(document.querySelectorAll("a[href]:not([data-phishshield-inspected])"));
      const BATCH_SIZE = 25;

      for (let i = 0; i < allLinks.length; i += BATCH_SIZE) {
        if (!isProtectionActive) break;

        const batch = allLinks.slice(i, i + BATCH_SIZE);

        await new Promise((resolve) => {
          requestAnimationFrame(() => {
            batch.forEach((link) => {
              if (isProtectionActive) {
                inspectLink(link);
              }
            });
            resolve();
          });
        });

        if (window.scheduler && window.scheduler.yield) {
          await window.scheduler.yield();
        }
      }

      if (isProtectionActive) {
        updatePill();
        const overallStatus = pageSafetyResult && pageSafetyResult.status === "dangerous" ? "dangerous" : flaggedThreats.length > 0 ? "dangerous" : (pageSafetyResult && pageSafetyResult.status === "suspicious") ? "suspicious" : "safe";
        notifyServiceWorker(overallStatus, flaggedThreats.length, pageSafetyResult ? pageSafetyResult.flags : []);
      }
    } catch (err) {
      console.error("[PhishShield AI] Error scanning links:", err);
    } finally {
      isScanning = false;
    }
  }

  /**
   * Evaluate a single anchor element using structural checks, Ethiopian heuristics, and ML model
   */
  function inspectLink(link) {
    if (!isProtectionActive) return;

    link.setAttribute("data-phishshield-inspected", "true");

    const rawHref = link.getAttribute("href") || "";
    if (!window.PhishShieldHeuristics) return;

    const evaluation = window.PhishShieldHeuristics.evaluateLinkSafety(link, link.href || rawHref);

    if (evaluation.isPhishing) {
      applyFlaggedThreat(link, evaluation);
      return;
    }

    // Query Laya AI Decision Model asynchronously for external links
    try {
      const targetUrl = link.href || rawHref;
      if (!targetUrl || targetUrl.startsWith("#") || targetUrl.startsWith("javascript:") || targetUrl.startsWith("mailto:")) return;

      const linkHost = new URL(targetUrl, window.location.href).hostname || "";
      const currentHost = window.location.hostname || "";
      if (
        window.PhishShieldHeuristics.isSameSiteOrSubdomain(linkHost, currentHost) ||
        (window.PhishShieldHeuristics.isTrustedDomain && window.PhishShieldHeuristics.isTrustedDomain(linkHost))
      ) {
        return;
      }

      chrome.runtime.sendMessage({
        type: "VERIFY_LINK_WITH_MODEL",
        url: targetUrl,
        text: (link.innerText || link.textContent || "").trim()
      }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success || !response.data) {
          return;
        }

        const modelRes = response.data;
        if (modelRes.is_phishing && isProtectionActive && !interceptedLinks.has(link)) {
          const modelEval = {
            url: targetUrl,
            host: linkHost,
            riskScore: modelRes.score || 80,
            flags: modelRes.flags && modelRes.flags.length > 0 ? modelRes.flags : [modelRes.reason]
          };
          applyFlaggedThreat(link, modelEval);
        }
      });
    } catch (e) {}
  }

  function applyFlaggedThreat(link, evaluation) {
    if (!isProtectionActive || interceptedLinks.has(link)) return;

    flaggedThreats.push({
      element: link,
      url: evaluation.url,
      host: evaluation.host,
      flags: evaluation.flags,
      riskScore: evaluation.riskScore
    });

    applyThreatUI(link, evaluation);
    updatePill();

    const overallStatus = "dangerous";
    notifyServiceWorker(overallStatus, flaggedThreats.length, pageSafetyResult ? pageSafetyResult.flags : []);
  }

  /**
   * Apply high-visibility styling, badge, and click interception
   */
  function applyThreatUI(link, evaluation) {
    if (!isProtectionActive) return;

    link.classList.add("phishshield-flagged-link");
    link.setAttribute("title", "⚠️ PhishShield Warning: Potential Phishing Link!");

    // Create high-visibility inline warning badge
    const badge = document.createElement("span");
    badge.className = "phishshield-inline-badge";
    badge.innerHTML = `${SVG_ALERT_BADGE}<span>${t("badgePhishing")}</span>`;
    badge.setAttribute("title", evaluation.flags.map((f) => translateReason(f)).join(" | "));

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      showWarningModal(evaluation.url, evaluation.flags);
    });

    if (link.parentNode) {
      link.parentNode.insertBefore(badge, link.nextSibling);
    }

    const clickHandler = (e) => {
      if (!isProtectionActive) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      showWarningModal(evaluation.url, evaluation.flags);
      return false;
    };

    interceptedLinks.set(link, clickHandler);
    link.addEventListener("click", clickHandler, true);
  }

  /**
   * Observe dynamically added content
   */
  function observeMutations() {
    if (!isProtectionActive) return;
    if (!document.body) {
      window.addEventListener("DOMContentLoaded", observeMutations, { once: true });
      return;
    }

    mutationObserver = new MutationObserver((mutations) => {
      if (!isProtectionActive) return;

      let hasNewAnchors = false;
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          hasNewAnchors = true;
          break;
        }
      }

      if (hasNewAnchors) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          if (isProtectionActive) {
            scanPageLinks();
          }
        }, 400);
      }
    });

    mutationObserver.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  /**
   * Show full-screen active warning modal for clicked link inside Shadow DOM
   */
  function showWarningModal(url, flags) {
    if (!isProtectionActive) return;

    const root = getShadowRoot();
    if (!root) return;

    const existing = root.getElementById("phishshield-modal-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "phishshield-modal-overlay";

    const card = document.createElement("div");
    card.id = "phishshield-modal-card";

    const safeUrl = String(url).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const reasonsHtml = flags.map((f) => `<li>${SVG_ALERT_OCTAGON} <span>${translateReason(f)}</span></li>`).join("");

    card.innerHTML = `
      <button id="phishshield-modal-close-btn" aria-label="Close" title="Close warning">
        ${SVG_CLOSE}
      </button>
      <div class="phishshield-modal-icon-wrap">
        ${SVG_MODAL_HERO}
      </div>
      <h2 class="phishshield-modal-title">${t("overlayTitleDanger")}</h2>
      <p class="phishshield-modal-desc">${t("overlayDesc")}</p>

      <div class="phishshield-url-box">${safeUrl}</div>

      <div class="phishshield-why-container">
        <div class="phishshield-why-title">${t("whyFlagged")}</div>
        <ul class="phishshield-reasons-list">
          ${reasonsHtml}
        </ul>
      </div>

      <div class="phishshield-modal-actions">
        <button id="phishshield-btn-stay-safe" class="phishshield-btn-safe">
          ${SVG_ARROW_LEFT}
          <span>${t("btnGoBack")}</span>
        </button>
        <button id="phishshield-btn-proceed-unsafe" class="phishshield-btn-unsafe">
          ${t("btnProceedAnyway")}
        </button>
      </div>
    `;

    overlay.appendChild(card);
    root.appendChild(overlay);

    const closeModal = () => {
      overlay.remove();
      document.removeEventListener("keydown", escHandler);
    };

    const escHandler = (e) => {
      if (e.key === "Escape") {
        closeModal();
      }
    };
    document.addEventListener("keydown", escHandler);

    card.querySelector("#phishshield-modal-close-btn").addEventListener("click", closeModal);
    card.querySelector("#phishshield-btn-stay-safe").addEventListener("click", closeModal);

    card.querySelector("#phishshield-btn-proceed-unsafe").addEventListener("click", () => {
      if (confirm(t("confirmProceed"))) {
        closeModal();
        window.location.href = url;
      }
    });

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        closeModal();
      }
    });
  }

  /**
   * Notify service worker of tab risk status and detected threats
   */
  async function notifyServiceWorker(status = "safe", count = 0, flags = []) {
    try {
      if (chrome.runtime && chrome.runtime.sendMessage) {
        await chrome.runtime.sendMessage({
          type: "UPDATE_TAB_THREATS",
          status,
          threatCount: count,
          flags,
          url: window.location.href,
          host: window.location.hostname
        });
      }
    } catch (e) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
