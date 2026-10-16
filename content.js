/**
 * PhishShield AI - Content Script
 * Real-time DOM link inspection, glassmorphic inline badges, click interception modal, and floating status pill.
 * Fully encapsulated in Shadow DOM for zero style interference from host webpages.
 */

(() => {
  if (window.__PHISHSHIELD_LOADED__) return;
  window.__PHISHSHIELD_LOADED__ = true;

  let isProtectionActive = false;
  let flaggedThreats = [];
  let isScanning = false;
  let pillElement = null;
  let mutationObserver = null;
  let debounceTimer = null;

  // Shadow DOM host reference
  let shadowHost = null;
  let shadowRoot = null;

  // Intercept click listener store to allow clean removal
  const interceptedLinks = new Map();

  // Modern SVG Icons (Image 2 Glassmorphism Style)
  const SVG_SHIELD_CHECK = `
    <svg class="phishshield-pill-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 0 6px rgba(96, 165, 250, 0.5));">
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

  const SVG_STAY_SAFE_BTN = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="m9 12 2 2 4-4"/>
    </svg>`;

  /**
   * Acquire or initialize Shadow Root
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
      shadowHost.style.width = "0";
      shadowHost.style.height = "0";
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
   * Inject complete glassmorphism styles into Shadow Root
   */
  function injectShadowStyles(root) {
    const style = document.createElement("style");
    style.textContent = `
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans Ethiopic", sans-serif;
        -webkit-font-smoothing: antialiased;
      }

      /* Floating Security Pill */
      #phishshield-floating-pill {
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483646;
        user-select: none;
        pointer-events: auto;
        transition: transform 200ms ease, opacity 200ms ease;
      }

      .phishshield-pill-badge {
        display: inline-flex;
        align-items: center;
        gap: 9px;
        padding: 9px 18px;
        border-radius: 9999px;
        font-size: 13px;
        font-weight: 500;
        letter-spacing: 0.2px;
        color: #e2e8f0;
        cursor: pointer;
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        backdrop-filter: blur(20px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.18);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.28);
        transition: transform 180ms ease, box-shadow 180ms ease, background 180ms ease;
      }

      .phishshield-pill-badge:hover {
        transform: translateY(-2px);
      }

      .phishshield-pill-badge:active {
        transform: scale(0.98);
      }

      .phishshield-pill-safe {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.72) 0%, rgba(15, 23, 42, 0.82) 100%);
        border-color: rgba(255, 255, 255, 0.18);
        color: #e2e8f0;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.28);
      }

      .phishshield-pill-safe:hover {
        background: linear-gradient(135deg, rgba(51, 65, 85, 0.8) 0%, rgba(30, 41, 59, 0.88) 100%);
        box-shadow: 0 12px 36px rgba(0, 0, 0, 0.42), 0 0 20px rgba(96, 165, 250, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.35);
      }

      .phishshield-pill-threat {
        background: linear-gradient(135deg, rgba(39, 17, 26, 0.85) 0%, rgba(20, 10, 16, 0.92) 100%);
        border-color: rgba(244, 63, 94, 0.4);
        color: #fecdd3;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.38), 0 0 24px rgba(244, 63, 94, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.25);
        animation: pill-pulse 2.2s infinite ease-in-out;
      }

      @keyframes pill-pulse {
        0%, 100% {
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 18px rgba(244, 63, 94, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25);
        }
        50% {
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 32px rgba(244, 63, 94, 0.48), inset 0 1px 0 rgba(255, 255, 255, 0.35);
        }
      }

      /* Full-Screen Warning Modal */
      #phishshield-modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(11, 13, 18, 0.72);
        -webkit-backdrop-filter: blur(20px) saturate(160%);
        backdrop-filter: blur(20px) saturate(160%);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
        pointer-events: auto;
        z-index: 2147483647;
        animation: modal-fade 200ms cubic-bezier(0.16, 1, 0.3, 1);
      }

      @keyframes modal-fade {
        from { opacity: 0; transform: scale(0.97); }
        to { opacity: 1; transform: scale(1); }
      }

      #phishshield-modal-card {
        background: rgba(21, 26, 38, 0.85);
        -webkit-backdrop-filter: blur(24px) saturate(180%);
        backdrop-filter: blur(24px) saturate(180%);
        border: 1px solid rgba(244, 63, 94, 0.36);
        border-radius: 20px;
        max-width: 540px;
        width: 100%;
        padding: 32px;
        box-shadow: 0 24px 64px rgba(0, 0, 0, 0.55), 0 0 40px rgba(244, 63, 94, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.22);
        color: #ffffff;
        text-align: center;
        position: relative;
        overflow: hidden;
      }

      #phishshield-modal-card::before {
        content: "";
        position: absolute;
        top: 0;
        left: 15%;
        right: 15%;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(244, 63, 94, 0.8), transparent);
      }

      .phishshield-modal-icon-wrap {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 64px;
        height: 64px;
        border-radius: 18px;
        background: rgba(244, 63, 94, 0.12);
        border: 1px solid rgba(244, 63, 94, 0.3);
        box-shadow: 0 0 24px rgba(244, 63, 94, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        margin-bottom: 16px;
      }

      .phishshield-modal-title {
        font-size: 18px;
        font-weight: 600;
        letter-spacing: -0.3px;
        color: #ffffff;
        text-transform: uppercase;
        margin-bottom: 8px;
      }

      .phishshield-modal-desc {
        font-size: 13px;
        font-weight: 400;
        color: rgba(255, 255, 255, 0.65);
        line-height: 1.5;
        margin-bottom: 20px;
      }

      .phishshield-url-box {
        background: rgba(0, 0, 0, 0.35);
        border: 1px solid rgba(255, 255, 255, 0.14);
        box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.4);
        border-radius: 12px;
        padding: 12px 14px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12px;
        color: #fb7185;
        word-break: break-all;
        margin-bottom: 18px;
        text-align: left;
      }

      .phishshield-reasons-list {
        list-style: none;
        padding: 0;
        margin: 0 0 24px 0;
        text-align: left;
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .phishshield-reasons-list li {
        background: rgba(255, 255, 255, 0.06);
        -webkit-backdrop-filter: blur(10px);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(244, 63, 94, 0.25);
        border-radius: 10px;
        padding: 9px 13px;
        font-size: 12px;
        color: #fca5a5;
        display: flex;
        align-items: center;
        gap: 9px;
      }

      .phishshield-modal-actions {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }

      .phishshield-btn-safe {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.28);
        padding: 13px 22px;
        font-size: 13px;
        font-weight: 600;
        letter-spacing: 0.2px;
        border-radius: 12px;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        box-shadow: 0 8px 24px rgba(16, 185, 129, 0.38), inset 0 1px 0 rgba(255, 255, 255, 0.35);
        transition: transform 180ms ease, box-shadow 180ms ease;
      }

      .phishshield-btn-safe:hover {
        transform: translateY(-1px);
        box-shadow: 0 10px 30px rgba(16, 185, 129, 0.52), inset 0 1px 0 rgba(255, 255, 255, 0.45);
      }

      .phishshield-btn-safe:active {
        transform: scale(0.98);
      }

      .phishshield-btn-unsafe {
        background: transparent;
        color: rgba(255, 255, 255, 0.5);
        border: none;
        padding: 8px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        text-decoration: underline;
        transition: color 180ms ease;
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
    try {
      if (chrome.storage && chrome.storage.local) {
        const data = await chrome.storage.local.get("protectionEnabled");
        const isEnabled = data.protectionEnabled !== false; // default true

        if (isEnabled) {
          enableProtection();
        }
      } else {
        enableProtection();
      }
    } catch (e) {
      enableProtection();
    }

    setupStateListeners();
  }

  /**
   * Listen for real-time toggle events from popup or storage changes
   */
  function setupStateListeners() {
    if (chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "local" && changes.protectionEnabled !== undefined) {
          const isEnabled = changes.protectionEnabled.newValue !== false;
          if (isEnabled && !isProtectionActive) {
            enableProtection();
          } else if (!isEnabled && isProtectionActive) {
            disableProtection();
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
      });
    }
  }

  /**
   * TURN ON: Activate protection, scan links, start observer, show pill
   */
  function enableProtection() {
    if (isProtectionActive) return;
    isProtectionActive = true;

    createFloatingPill();
    scanPageLinks();
    observeMutations();
  }

  /**
   * TURN OFF: Completely clean DOM, remove badges, remove click handlers, hide pill
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

    // 2. Remove all injected warning badges in the host page
    const badges = document.querySelectorAll(".phishshield-inline-badge");
    badges.forEach((b) => b.remove());

    // 3. Remove flagged styling & click interception from links
    interceptedLinks.forEach((handler, link) => {
      link.classList.remove("phishshield-flagged-link");
      link.removeAttribute("title");
      link.removeAttribute("data-phishshield-inspected");
      link.removeEventListener("click", handler, true);
    });
    interceptedLinks.clear();

    // Reset inspected attributes on clean links
    document.querySelectorAll("a[data-phishshield-inspected]").forEach((a) => {
      a.removeAttribute("data-phishshield-inspected");
    });

    // 4. Clean up Shadow DOM overlay elements
    if (shadowRoot) {
      const activeModal = shadowRoot.getElementById("phishshield-modal-overlay");
      if (activeModal) activeModal.remove();

      if (pillElement) {
        pillElement.remove();
        pillElement = null;
      }
    }

    // 5. Reset threats and notify service worker
    flaggedThreats = [];
    notifyServiceWorker(0);
  }

  /**
   * Scan page links in batches using requestAnimationFrame
   */
  async function scanPageLinks() {
    if (!isProtectionActive || isScanning) return;
    isScanning = true;

    try {
      const allLinks = Array.from(document.querySelectorAll('a[href]:not([data-phishshield-inspected])'));
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
        notifyServiceWorker(flaggedThreats.length);
      }
    } catch (err) {
      console.error("[PhishShield AI] Error scanning links:", err);
    } finally {
      isScanning = false;
    }
  }

  /**
   * Evaluate a single anchor element using client structural checks and Laya AI Model
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
      if (window.PhishShieldHeuristics.isSameSiteOrSubdomain(linkHost, currentHost)) {
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
    } catch (e) {
      // Ignored
    }
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
    notifyServiceWorker(flaggedThreats.length);
  }

  /**
   * Apply high-visibility styling, badge, and click interception
   */
  function applyThreatUI(link, evaluation) {
    if (!isProtectionActive) return;

    link.classList.add("phishshield-flagged-link");
    link.setAttribute("title", "⚠️ PhishShield Warning: Potential Phishing Link!");

    // Create high-visibility glass inline warning badge
    const badge = document.createElement("span");
    badge.className = "phishshield-inline-badge";
    badge.innerHTML = `${SVG_ALERT_BADGE}<span>PHISHING LINK: DO NOT TOUCH</span>`;
    badge.setAttribute("title", evaluation.flags.join(" | "));

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
   * Create floating security pill inside Shadow DOM
   */
  function createFloatingPill() {
    if (!isProtectionActive) return;
    const root = getShadowRoot();
    if (!root || root.getElementById("phishshield-floating-pill")) return;

    pillElement = document.createElement("div");
    pillElement.id = "phishshield-floating-pill";

    const badge = document.createElement("div");
    badge.className = "phishshield-pill-badge phishshield-pill-safe";
    badge.innerHTML = `${SVG_SHIELD_CHECK}<span>PhishShield: Protected</span>`;

    badge.addEventListener("click", () => {
      if (!isProtectionActive) return;

      if (flaggedThreats.length > 0) {
        const firstThreat = flaggedThreats[0];
        if (firstThreat && firstThreat.element) {
          firstThreat.element.scrollIntoView({ behavior: "smooth", block: "center" });
          showWarningModal(firstThreat.url, firstThreat.flags);
        }
      } else {
        alert("PhishShield AI: No suspicious or phishing links found on this page.");
      }
    });

    pillElement.appendChild(badge);
    root.appendChild(pillElement);
  }

  /**
   * Update floating pill status inside Shadow DOM
   */
  function updatePill() {
    if (!isProtectionActive || !pillElement) return;

    const badge = pillElement.querySelector(".phishshield-pill-badge");
    if (!badge) return;

    if (flaggedThreats.length > 0) {
      badge.className = "phishshield-pill-badge phishshield-pill-threat";
      badge.innerHTML = `${SVG_ALERT_OCTAGON}<span>${flaggedThreats.length} Phishing Link${flaggedThreats.length > 1 ? "s" : ""} Blocked</span>`;
    } else {
      badge.className = "phishshield-pill-badge phishshield-pill-safe";
      badge.innerHTML = `${SVG_SHIELD_CHECK}<span>PhishShield: Protected</span>`;
    }
  }

  /**
   * Show full-screen active warning modal inside Shadow DOM
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
    const reasonsHtml = flags.map((f) => `<li>${SVG_ALERT_OCTAGON} <span>${f}</span></li>`).join("");

    card.innerHTML = `
      <div class="phishshield-modal-icon-wrap">
        ${SVG_MODAL_HERO}
      </div>
      <h2 class="phishshield-modal-title">Warning: Malicious Link Blocked</h2>
      <p class="phishshield-modal-desc">
        PhishShield AI detected that this destination is highly deceptive and appears to be a social engineering attack designed to harvest credentials or compromise your system.
      </p>

      <div class="phishshield-url-box">${safeUrl}</div>

      <ul class="phishshield-reasons-list">
        ${reasonsHtml}
      </ul>

      <div class="phishshield-modal-actions">
        <button id="phishshield-btn-stay-safe" class="phishshield-btn-safe">
          ${SVG_STAY_SAFE_BTN}
          <span>Stay Safe (Do Not Open)</span>
        </button>
        <button id="phishshield-btn-proceed-unsafe" class="phishshield-btn-unsafe">
          I understand the risks, proceed anyway (Unsafe)
        </button>
      </div>
    `;

    overlay.appendChild(card);
    root.appendChild(overlay);

    card.querySelector("#phishshield-btn-stay-safe").addEventListener("click", () => {
      overlay.remove();
    });

    card.querySelector("#phishshield-btn-proceed-unsafe").addEventListener("click", () => {
      if (confirm("DANGER: Are you sure you want to visit this flagged phishing site? Your accounts may be compromised.")) {
        overlay.remove();
        window.location.href = url;
      }
    });

    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        overlay.remove();
      }
    });
  }

  /**
   * Notify service worker of detected threats on this tab
   */
  async function notifyServiceWorker(count) {
    try {
      if (chrome.runtime && chrome.runtime.sendMessage) {
        await chrome.runtime.sendMessage({
          type: "UPDATE_TAB_THREATS",
          threatCount: count
        });
      }
    } catch (e) {
      // Ignored if extension context invalidated
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
