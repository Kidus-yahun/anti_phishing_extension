/**
 * PhishShield AI - Content Script
 * Real-time DOM link inspection, high-visibility badges, click interception modal, and floating status pill.
 */

(() => {
  let flaggedThreats = [];
  let isScanning = false;
  let pillElement = null;

  // Initialize
  function init() {
    createFloatingPill();
    scanPageLinks();
    observeMutations();
  }

  /**
   * Scan page links in batches using requestAnimationFrame to prevent main thread blocking
   */
  async function scanPageLinks() {
    if (isScanning) return;
    isScanning = true;

    try {
      const allLinks = Array.from(document.querySelectorAll('a[href]:not([data-phishshield-inspected])'));
      const BATCH_SIZE = 25;

      for (let i = 0; i < allLinks.length; i += BATCH_SIZE) {
        const batch = allLinks.slice(i, i + BATCH_SIZE);

        await new Promise((resolve) => {
          requestAnimationFrame(() => {
            batch.forEach((link) => {
              inspectLink(link);
            });
            resolve();
          });
        });

        if (window.scheduler && window.scheduler.yield) {
          await window.scheduler.yield();
        }
      }

      updatePill();
      notifyServiceWorker();
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
    link.addEventListener(
      "click",
      (e) => {
        e.preventDefault();
        e.stopImmediatePropagation();
        showWarningModal(evaluation.url, evaluation.flags);
        return false;
      },
      true // Capture phase to intercept before page listeners
    );
  }

  /**
   * Observe dynamically added content (SPAs, social feeds, webmail)
   */
  function observeMutations() {
    let debounceTimer = null;
    const observer = new MutationObserver((mutations) => {
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
          scanPageLinks();
        }, 400);
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  /**
   * Create Grammarly-style floating security pill
   */
  function createFloatingPill() {
    if (document.getElementById("phishshield-floating-pill")) return;

    pillElement = document.createElement("div");
    pillElement.id = "phishshield-floating-pill";

    const badge = document.createElement("div");
    badge.className = "phishshield-pill-badge phishshield-pill-safe";
    badge.innerHTML = `<span>🛡️</span><span>PhishShield Protected</span>`;

    badge.addEventListener("click", () => {
      if (flaggedThreats.length > 0) {
        // Scroll smoothly to the first threat
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
    if (!pillElement) return;

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
    // Remove existing modal if open
    const existing = document.getElementById("phishshield-modal-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "phishshield-modal-overlay";

    const card = document.createElement("div");
    card.id = "phishshield-modal-card";

    // Escape HTML to prevent injection
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

    // Event listeners
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
  async function notifyServiceWorker() {
    try {
      if (chrome.runtime && chrome.runtime.sendMessage) {
        await chrome.runtime.sendMessage({
          type: "UPDATE_TAB_THREATS",
          threatCount: flaggedThreats.length
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
