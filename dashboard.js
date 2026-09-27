/**
 * PhishShield AI - Extension Dashboard Controller
 * Manifest V3 CSP-compliant: zero inline handlers, zero remote scripts.
 * Dual-Mode: Deep Laya System-1 Model (when backend online) + ClientThreatEngine (when offline).
 */

// Embedded Client-Side Threat Engine (Guarantees 100% offline analysis)
const ClientThreatEngine = {
  analyzeText(text) {
    if (!text || typeof text !== 'string') return { score: 0, flags: [] };

    let score = 0;
    const flags = [];
    const lower = text.toLowerCase();

    // 1. Urgency & deadline panic triggers
    const urgencyKeywords = [
      { pattern: /within 24 hours/i, label: "Immediate 24-hour deadline threat detected" },
      { pattern: /immediate action required/i, label: "Panic-inducing urgency trigger ('immediate action required')" },
      { pattern: /urgent/i, label: "Urgency flag ('urgent') pressure trigger" },
      { pattern: /act now/i, label: "Impulsive action trigger ('act now')" },
      { pattern: /account (will be|has been) suspended/i, label: "Account suspension coercion threat" },
      { pattern: /unauthorized access detected/i, label: "False security alarm trigger ('unauthorized access detected')" },
      { pattern: /security breach/i, label: "Fabricated security breach alert" },
      { pattern: /restricted access/i, label: "Account restriction coercion" }
    ];

    urgencyKeywords.forEach(u => {
      if (u.pattern.test(lower)) {
        score += 25;
        flags.push(u.label);
      }
    });

    // 2. Credential & Financial Harvesting Patterns
    const credentialKeywords = [
      { pattern: /verify your account/i, label: "Credential verification lure ('verify your account')" },
      { pattern: /confirm your password/i, label: "Direct password credential request" },
      { pattern: /enter your (ssn|social security)/i, label: "Sensitive identity data request (SSN)" },
      { pattern: /update billing (information|details)/i, label: "Financial billing data harvesting pattern" },
      { pattern: /claim your reward/i, label: "Deceptive incentive/lottery lure" },
      { pattern: /click the link below/i, label: "Unsolicited click coercion link" },
      { pattern: /log in immediately/i, label: "Immediate authentication coercion lure" }
    ];

    credentialKeywords.forEach(c => {
      if (c.pattern.test(lower)) {
        score += 20;
        flags.push(c.label);
      }
    });

    // 3. Authority Impersonation
    const authorityKeywords = [
      { pattern: /(paypal|apple|microsoft|google|amazon|netflix|bank) security team/i, label: "Brand authority impersonation (Security Department)" },
      { pattern: /it helpdesk/i, label: "Corporate IT Helpdesk impersonation lure" },
      { pattern: /system administrator/i, label: "System Administrator identity impersonation" }
    ];

    authorityKeywords.forEach(a => {
      if (a.pattern.test(lower)) {
        score += 20;
        flags.push(a.label);
      }
    });

    return { score: Math.min(100, score), flags };
  },

  analyzeUrl(url) {
    if (!url || typeof url !== 'string') return { score: 0, flags: [] };

    let score = 0;
    const flags = [];

    // Parse URL safely
    let parsed;
    try {
      let testUrl = url.trim();
      if (!testUrl.startsWith('http://') && !testUrl.startsWith('https://')) {
        testUrl = 'http://' + testUrl;
      }
      parsed = new URL(testUrl);
    } catch (e) {
      return { score: 50, flags: ["Malformed or invalid URL structure"] };
    }

    const hostname = parsed.hostname.toLowerCase();

    // 1. Cyrillic / IDN Homograph attack detection
    const cyrillicRegex = /[\u0400-\u04FF]/;
    if (cyrillicRegex.test(hostname) || hostname.startsWith("xn--")) {
      score += 90;
      flags.push("CRITICAL: Internationalized Homograph Domain (IDN) spoofing attack detected");
    }

    // 2. Raw IP address hostname
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      score += 75;
      flags.push("High Risk: Raw IPv4 address used as host instead of legitimate domain");
    }

    // 3. Credential spoofing '@' symbol
    if (url.includes('@')) {
      score += 65;
      flags.push("Credential spoofing trick: URL authority contains '@' character");
    }

    // 4. Autonomous Typosquatting / Character substitution checks
    const brandPatterns = [
      { pattern: /paypa[l1i]/, brand: "PayPal", legit: "paypal.com" },
      { pattern: /micros[o0]ft/, brand: "Microsoft", legit: "microsoft.com" },
      { pattern: /g[o0]{2}gle/, brand: "Google", legit: "google.com" },
      { pattern: /app[l1i]e/, brand: "Apple", legit: "apple.com" },
      { pattern: /amaz[o0]n/, brand: "Amazon", legit: "amazon.com" },
      { pattern: /netf[l1i]x/, brand: "Netflix", legit: "netflix.com" }
    ];

    for (const b of brandPatterns) {
      if (b.pattern.test(hostname) && !hostname.endsWith(b.legit)) {
        score += 85;
        flags.push(`Deceptive typosquatting impersonating ${b.brand} detected in domain (${hostname})`);
      }
    }

    // 5. High-Risk TLDs
    const highRiskTLDs = ['.zip', '.top', '.tk', '.xyz', '.ml', '.ga', '.cf', '.gq', '.work'];
    for (const tld of highRiskTLDs) {
      if (hostname.endsWith(tld)) {
        score += 35;
        flags.push(`Suspicious top-level domain (${tld}) frequently leveraged in automated phishing`);
        break;
      }
    }

    // 6. Suspicious subdomain chaining
    const parts = hostname.split('.');
    if (parts.length > 4) {
      score += 25;
      flags.push("Excessive subdomain depth indicating evasive dynamic hosting");
    }

    return { score: Math.min(100, score), flags };
  },

  analyzeHeaders(headers) {
    if (!headers || typeof headers !== 'string') return { score: 0, flags: [] };

    let score = 0;
    const flags = [];
    const lower = headers.toLowerCase();

    if (lower.includes("spf=fail") || lower.includes("spf=softfail")) {
      score += 45;
      flags.push("SPF Validation Failed: Sender IP is unauthorized by domain policy");
    }
    if (lower.includes("dkim=fail")) {
      score += 40;
      flags.push("DKIM Signature Failed: Cryptographic email signature was tampered or invalid");
    }
    if (lower.includes("dmarc=fail")) {
      score += 50;
      flags.push("DMARC Enforcement Failed: Alignment policy violation");
    }

    // Extract From vs Return-Path
    const fromMatch = headers.match(/from:\s*.*?<(.+?)>/i) || headers.match(/from:\s*([^\s<]+@[^\s>]+)/i);
    const returnMatch = headers.match(/return-path:\s*<(.+?)>/i);

    if (fromMatch && returnMatch) {
      const fromDomain = fromMatch[1].split('@')[1];
      const returnDomain = returnMatch[1].split('@')[1];
      if (fromDomain && returnDomain && fromDomain.toLowerCase() !== returnDomain.toLowerCase()) {
        score += 50;
        flags.push(`From domain (@${fromDomain}) does not match Return-Path domain (@${returnDomain})`);
      }
    }

    return { score: Math.min(100, score), flags };
  },

  calculateRisk(nlpRes, urlRes, headerRes) {
    const scores = [];
    const weights = [];

    if (nlpRes && nlpRes.score !== undefined) {
      scores.push(nlpRes.score);
      weights.push(0.40);
    }
    if (urlRes && urlRes.score !== undefined) {
      scores.push(urlRes.score);
      weights.push(0.35);
    }
    if (headerRes && headerRes.score !== undefined) {
      scores.push(headerRes.score);
      weights.push(0.25);
    }

    const totalWeight = weights.reduce((a, b) => a + b, 0);
    let composite = 0;
    if (totalWeight > 0) {
      composite = scores.reduce((sum, s, i) => sum + s * (weights[i] / totalWeight), 0);
    }
    composite = Math.round(Math.min(100, Math.max(0, composite)) * 10) / 10;

    let riskLevel = "SAFE";
    let badgeColor = "green";
    let verdict = "Low risk detected. Content appears legitimate.";

    if (composite < 25) {
      riskLevel = "SAFE";
      badgeColor = "green";
      verdict = "Low risk detected. Content appears legitimate.";
    } else if (composite < 50) {
      riskLevel = "LOW RISK";
      badgeColor = "yellow";
      verdict = "Minor risk factors detected. Exercise standard caution.";
    } else if (composite < 75) {
      riskLevel = "MEDIUM RISK";
      badgeColor = "orange";
      verdict = "Multiple suspicious indicators found. Likely phishing or social engineering.";
    } else {
      riskLevel = "HIGH / CRITICAL RISK";
      badgeColor = "red";
      verdict = "CRITICAL PHISHING THREAT! Highly deceptive indicators detected. Do not click links or enter credentials.";
    }

    const allFlags = [
      ...(nlpRes ? nlpRes.flags : []),
      ...(urlRes ? urlRes.flags : []),
      ...(headerRes ? headerRes.flags : [])
    ];

    return {
      risk_score: composite,
      risk_level: riskLevel,
      badge_color: badgeColor,
      verdict: verdict,
      flags: allFlags,
      mode: "Standalone Local Client Engine"
    };
  }
};

// Preset samples
const samples = {
  laya_stealth: {
    text: "Dear valued partner, our quarterly cloud billing reconciliation protocol has detected anomalous session artifacts on your enterprise tenant. Please re-authenticate your single sign-on security certificate within 24 hours to prevent seamless service disconnection.",
    url: "http://identity-sso-portal.com/adfs/ls/auth",
    header: "From: Enterprise Cloud Identity <security@auth-service-notices.com>\nReturn-Path: <bounce@unrelated-marketing-hub.net>\nAuthentication-Results: spf=fail dkim=fail"
  },
  phishing: {
    text: "URGENT: Your PayPal account has been temporarily restricted due to unauthorized login attempts from Russia! Click the link below immediately and confirm your password within 24 hours to restore full account access, or your funds will be permanently locked.",
    url: "http://paypa1-security-verification.xyz/login.php",
    header: "From: PayPal Support Team <service@paypal.notice-center.com>\nReturn-Path: <bounce@suspicious-mailer.net>\nAuthentication-Results: spf=softfail dkim=fail"
  },
  homograph: {
    text: "Security Advisory: Please verify your Apple ID credentials to prevent Apple Pay service suspension.",
    url: "http://www.apple.com-id-manage.top/verify",
    header: "From: Apple Support <noreply@apple.com>\nReturn-Path: <hacker@external-mail.org>\nAuthentication-Results: spf=fail"
  },
  safe: {
    text: "Hi team, please review the pull request for the anti-phishing extension when you get a chance today. Thanks!",
    url: "https://github.com/Kidus-yahun/anti_phishing_extension",
    header: "From: notifications@github.com\nReturn-Path: <bounces@github.com>\nAuthentication-Results: spf=pass dkim=pass dmarc=pass"
  }
};

// State variables
let apiBase = "http://127.0.0.1:8000";
let isServerOnline = false;

// DOM Initialization
if (typeof document !== 'undefined') {
  document.addEventListener("DOMContentLoaded", async () => {
    setupNavigation();
    initPresets();
    initForm();
    await checkEngineStatus();
    await loadExtensionStats();
  });
}

// Setup links
function setupNavigation() {
  const testLabLink = document.getElementById("nav-test-lab");
  if (testLabLink) {
    testLabLink.href = "test_lab.html";
  }
}

// Check Backend Engine Status (timeout: 1200ms)
async function checkEngineStatus() {
  const badge = document.getElementById("ai-model-badge");
  const dot = document.getElementById("ai-status-dot");
  const text = document.getElementById("ai-model-text");

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);

    const res = await fetch(`${apiBase}/api/health`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      isServerOnline = true;
      badge.className = "status-pill online";
      dot.className = "status-dot pulse";
      text.textContent = "Laya System-1 Model Active (Backend Online)";
      return;
    }
  } catch (e) {
    // Backend offline
  }

  isServerOnline = false;
  badge.className = "status-pill offline";
  dot.className = "status-dot";
  text.textContent = "Standalone Local Engine (Extension Offline Mode)";
}

// Load real-time stats from Chrome storage
async function loadExtensionStats() {
  if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    try {
      const data = await chrome.storage.local.get(["totalBlockedAllTime", "protectionEnabled"]);
      const total = data.totalBlockedAllTime || 0;
      const statTotalEl = document.getElementById("stat-total-blocked");
      if (statTotalEl) {
        statTotalEl.textContent = String(total);
      }
    } catch (e) {
      // Ignored
    }
  }
}

// Wire up preset buttons
function initPresets() {
  const buttons = document.querySelectorAll("[data-preset]");
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const presetKey = btn.getAttribute("data-preset");
      const sample = samples[presetKey];
      if (sample) {
        document.getElementById("input-text").value = sample.text;
        document.getElementById("input-url").value = sample.url;
        document.getElementById("input-header").value = sample.header;
      }
    });
  });
}

// Wire up analysis form
function initForm() {
  const form = document.getElementById("analyze-form");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const text = document.getElementById("input-text").value.trim();
    const url = document.getElementById("input-url").value.trim();
    const header = document.getElementById("input-header").value.trim();

    if (!text && !url && !header) {
      alert("Please provide at least one input (Text, URL, or Headers).");
      return;
    }

    // Toggle loading UI
    document.getElementById("initial-state").classList.add("hidden");
    document.getElementById("analysis-output").classList.add("hidden");
    document.getElementById("loading-state").classList.remove("hidden");

    try {
      let result = null;

      // 1. Try querying backend if online
      if (isServerOnline) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2000);

          const response = await fetch(`${apiBase}/api/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text, url, headers: header }),
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (response.ok) {
            result = await response.json();
          }
        } catch (netErr) {
          console.warn("[PhishShield Extension] Backend unavailable, running client engine:", netErr);
        }
      }

      // 2. Fallback to client-side threat engine (runs 100% offline)
      if (!result) {
        const nlpRes = ClientThreatEngine.analyzeText(text);
        const urlRes = ClientThreatEngine.analyzeUrl(url);
        const headerRes = ClientThreatEngine.analyzeHeaders(header);
        result = ClientThreatEngine.calculateRisk(nlpRes, urlRes, headerRes);
      }

      renderResults(result);

    } catch (err) {
      alert("Threat analysis error: " + err.message);
    } finally {
      document.getElementById("loading-state").classList.add("hidden");
    }
  });
}

// Render analysis results to DOM
function renderResults(data) {
  document.getElementById("analysis-output").classList.remove("hidden");

  const score = data.risk_score;
  const level = data.risk_level;
  const color = data.badge_color;
  const verdict = data.verdict;
  const flags = data.flags || [];
  const mode = data.mode || (isServerOnline ? "Laya System-1 Model Active" : "Standalone Local Client Engine");

  // Score text
  const scoreEl = document.getElementById("out-score");
  scoreEl.textContent = Math.round(score) + "%";

  const gaugeBar = document.getElementById("gauge-bar");
  const badgeEl = document.getElementById("out-badge");
  const circum = 440; // 2 * pi * 70
  const offset = circum - (circum * Math.min(100, Math.max(0, score))) / 100;

  let strokeColor = "#10b981";
  let textColor = "#34d399";
  let bgRgba = "rgba(16, 185, 129, 0.15)";
  let borderRgba = "rgba(16, 185, 129, 0.4)";

  if (color === "red") {
    strokeColor = "#f43f5e";
    textColor = "#fb7185";
    bgRgba = "rgba(244, 63, 94, 0.18)";
    borderRgba = "rgba(244, 63, 94, 0.45)";
  } else if (color === "orange") {
    strokeColor = "#f97316";
    textColor = "#fb923c";
    bgRgba = "rgba(249, 115, 22, 0.18)";
    borderRgba = "rgba(249, 115, 22, 0.45)";
  } else if (color === "yellow") {
    strokeColor = "#f59e0b";
    textColor = "#fbbf24";
    bgRgba = "rgba(245, 158, 11, 0.18)";
    borderRgba = "rgba(245, 158, 11, 0.45)";
  }

  if (gaugeBar) {
    gaugeBar.style.stroke = strokeColor;
    gaugeBar.style.color = strokeColor;
    gaugeBar.style.strokeDashoffset = offset;
  }
  scoreEl.style.color = textColor;
  scoreEl.style.textShadow = `0 0 16px ${strokeColor}66`;

  badgeEl.className = "risk-badge";
  badgeEl.style.background = bgRgba;
  badgeEl.style.color = textColor;
  badgeEl.style.borderColor = borderRgba;
  badgeEl.style.boxShadow = `0 0 16px ${strokeColor}33`;
  badgeEl.textContent = level;
  document.getElementById("out-verdict").textContent = verdict;
  document.getElementById("engine-mode-tag").textContent = "⚡ Engine: " + mode;
  document.getElementById("flag-count").textContent = flags.length + " flags detected";

  // Render flags
  const flagsContainer = document.getElementById("out-flags");
  flagsContainer.innerHTML = "";

  if (flags.length === 0) {
    const safeDiv = document.createElement("div");
    safeDiv.className = "flag-item";
    safeDiv.style.borderColor = "rgba(16, 185, 129, 0.3)";
    safeDiv.style.background = "rgba(16, 185, 129, 0.08)";
    safeDiv.innerHTML = `
      <span class="flag-icon" style="color: #34d399;">🛡️</span>
      <span style="color: #34d399; font-weight: 500;">No suspicious phishing patterns found across analyzed vectors.</span>
    `;
    flagsContainer.appendChild(safeDiv);
  } else {
    flags.forEach(flag => {
      const flagDiv = document.createElement("div");
      flagDiv.className = "flag-item";
      flagDiv.innerHTML = `
        <span class="flag-icon" style="color: #fbbf24;">⚠️</span>
        <span>${escapeHtml(flag)}</span>
      `;
      flagsContainer.appendChild(flagDiv);
    });
  }
}

function escapeHtml(str) {
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}
