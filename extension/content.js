/**
 * PhishShield AI - Content Script
 * Real-time DOM link inspection, high-visibility badges, click interception modal, and floating status pill.
 * Fully supports ON/OFF toggle state with instant DOM cleanup and re-activation.
 */

(() => {
  let isProtectionActive = false;
  let flaggedThreats = [];
  let isScanning = false;
  let pillElement = null;
  let mutationObserver = null;
  let debounceTimer = null;

  // Intercept click listener store to allow clean removal
  const interceptedLinks = new Map();

  /**
   * Initialize state on page load
   */
  async function init() {
    try {
      const data = await chrome.storage.local.get("protectionEnabled");
      const isEnabled = data.protectionEnabled !== false; // default true

      if (isEnabled) {
        enableProtection();
      }
    } catch (e) {
      // Default to enabled if storage read fails
      enableProtection();
    }

    setupStateListeners();
  }

  /**
   * Listen for real-time toggle events from popup or storage changes
   */
  function setupStateListeners() {
    // 1. Storage change listener across all tabs
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

    // 2. Direct runtime message listener from popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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

    // 2. Remove all injected warning badges
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

    // Reset all inspected attributes on clean links as well
    document.querySelectorAll("a[data-phishshield-inspected]").forEach((a) => {
      a.removeAttribute("data-phishshield-inspected");
    });

    // 4. Remove any active warning modal
    const activeModal = document.getElementById("phishshield-modal-overlay");
    if (activeModal) activeModal.remove();

    // 5. Remove or hide floating pill
    if (pillElement) {
      pillElement.remove();
      pillElement = null;
    }

    // 6. Reset threats and notify service worker
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
   * Evaluate a single anchor element
   */
  function inspectLink(link) {
    if (!isProtectionActive) return;

    link.setAttribute("data-phishshield-inspected", "true");

    const rawHref = link.getAttribute("href") || "";
    if (!window.PhishShieldHeuristics) return;

    const evaluation = window.PhishShieldHeuristics.evaluateLinkSafety(link, link.href || rawHref);

    if (evaluation.isPhishing) {
      flaggedThreats.push({
        element: link,
        url: evaluation.url,
        host: evaluation.host,
        flags: evaluation.flags,
        riskScore: evaluation.riskScore
      });

      applyThreatUI(link, evaluation);
    }
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
    badge.textContent = "PHISHING LINK: DO NOT TOUCH";
    badge.setAttribute("title", evaluation.flags.join(" | "));

    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      showWarningModal(evaluation.url, evaluation.flags);
    });

    // Insert badge directly after the link
    if (link.parentNode) {
      link.parentNode.insertBefore(badge, link.nextSibling);
    }

    // Intercept click on the link itself
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
   * Observe dynamically added content (SPAs, social feeds, webmail)
   */
  function observeMutations() {
    if (!isProtectionActive) return;

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
   * Create Grammarly-style floating security pill
   */
  function createFloatingPill() {
    if (!isProtectionActive || document.getElementById("phishshield-floating-pill")) return;

    pillElement = document.createElement("div");
    pillElement.id = "phishshield-floating-pill";

    const badge = document.createElement("div");
    badge.className = "phishshield-pill-badge phishshield-pill-safe";
    badge.innerHTML = `<span>🛡️</span><span>PhishShield Protected</span>`;

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
    document.body.appendChild(pillElement);
  }

  /**
   * Update floating pill status
   */
  function updatePill() {
    if (!isProtectionActive || !pillElement) return;

    const badge = pillElement.querySelector(".phishshield-pill-badge");
    if (!badge) return;

    if (flaggedThreats.length > 0) {
      badge.className = "phishshield-pill-badge phishshield-pill-threat";
      badge.innerHTML = `<span>⚠️</span><span>${flaggedThreats.length} Phishing Link${flaggedThreats.length > 1 ? "s" : ""} Blocked</span>`;
    } else {
      badge.className = "phishshield-pill-badge phishshield-pill-safe";
      badge.innerHTML = `<span>🛡️</span><span>PhishShield Protected</span>`;
    }
  }

  /**
   * Show full-screen active warning modal
   */
  function showWarningModal(url, flags) {
    if (!isProtectionActive) return;

    // Remove existing modal if open
    const existing = document.getElementById("phishshield-modal-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "phishshield-modal-overlay";

    const card = document.createElement("div");
    card.id = "phishshield-modal-card";

    const safeUrl = String(url).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const reasonsHtml = flags.map((f) => `<li><span>⚠️</span> <span>${f}</span></li>`).join("");

    card.innerHTML = `
      <div class="phishshield-modal-icon">🛑</div>
      <h2 class="phishshield-modal-title">WARNING: MALICIOUS LINK BLOCKED!</h2>
      <p class="phishshield-modal-desc">
        PhishShield AI detected that this destination is highly suspicious and appears to be a social engineering / phishing attack designed to steal your credentials or compromise your system.
      </p>

      <div class="phishshield-url-box">${safeUrl}</div>

      <ul class="phishshield-reasons-list">
        ${reasonsHtml}
      </ul>

      <div class="phishshield-modal-actions">
        <button id="phishshield-btn-stay-safe" class="phishshield-btn-safe">
          <span>🛡️</span> Stay Safe (Do Not Touch)
        </button>
        <button id="phishshield-btn-proceed-unsafe" class="phishshield-btn-unsafe">
          I understand the risks, proceed anyway (Unsafe)
        </button>
      </div>
    `;

    overlay.appendChild(card);
    document.body.appendChild(overlay);

    document.getElementById("phishshield-btn-stay-safe").addEventListener("click", () => {
      overlay.remove();
    });

    document.getElementById("phishshield-btn-proceed-unsafe").addEventListener("click", () => {
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

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
