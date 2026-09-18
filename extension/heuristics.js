/**
 * PhishShield AI - Client-Side Real-Time Link Heuristics
 * Provides instant, zero-latency phishing & deceptive domain analysis in the browser.
 */

const POPULAR_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "netflix", "bankofamerica", "chase", "wellsfargo", "github",
  "linkedin", "dropbox", "binance", "coinbase", "instagram",
  "twitter", "discord", "steam", "whatsapp", "telegram"
];

const SUSPICIOUS_TLDS = new Set([
  "top", "xyz", "club", "work", "click", "zip", "mov", "cc", "ru",
  "country", "kim", "science", "gq", "cf", "tk", "ml", "ga"
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
  "goo.gl", "tiny.cc", "rb.gy", "cutt.ly"
]);

function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;

  let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const cost = s1[i] === s2[j] ? 0 : 1;
      curr.push(Math.min(
        curr[j] + 1,       // insertion
        prev[j + 1] + 1,   // deletion
        prev[j] + cost     // substitution
      ));
    }
    prev = curr;
  }
  return prev[s2.length];
}

function isIpAddress(host) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

function hasHomographAttack(host) {
  if (!host) return false;
  // Check for Punycode prefix
  if (host.toLowerCase().includes("xn--")) return true;
  // Check for non-ASCII characters in domain name
  for (let i = 0; i < host.length; i++) {
    if (host.charCodeAt(i) > 127) return true;
  }
  return false;
}

function checkTyposquatting(host) {
  if (!host) return { isTypo: false, reason: "" };

  const cleanHost = host.toLowerCase().replace(/^www\./, "");
  const parts = cleanHost.split(".");
  const mainDomain = parts[0] || cleanHost;

  // Check both main domain and hyphenated tokens (e.g. paypa1-update)
  const tokens = mainDomain.split("-");

  for (const token of tokens) {
    for (const brand of POPULAR_BRANDS) {
      if (token === brand) continue;

      const dist = levenshteinDistance(token, brand);
      if (dist > 0 && dist <= 2 && token.length >= 4) {
        return {
          isTypo: true,
          reason: `Possible typosquatting of brand '${brand}' (detected: '${token}')`
        };
      }

      if (token.includes(brand) && token.length > brand.length) {
        return {
          isTypo: true,
          reason: `Brand name '${brand}' deceptively embedded inside domain '${host}'`
        };
      }
    }
  }

  return { isTypo: false, reason: "" };
}

function checkAnchorTextMismatch(anchorText, actualUrl) {
  if (!anchorText || !actualUrl) return { isMismatch: false, reason: "" };

  const text = anchorText.trim().toLowerCase();
  
  // Check if link text looks like a URL or domain
  const urlLikeMatch = text.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})/i);
  if (!urlLikeMatch) return { isMismatch: false, reason: "" };

  const displayedDomain = urlLikeMatch[1].toLowerCase().replace(/^www\./, "");
  const actualHost = actualUrl.hostname ? actualUrl.hostname.toLowerCase().replace(/^www\./, "") : "";

  if (displayedDomain && actualHost && displayedDomain !== actualHost && !actualHost.endsWith("." + displayedDomain)) {
    return {
      isMismatch: true,
      reason: `Deceptive link: Display text claims '${displayedDomain}' but link leads to '${actualHost}'`
    };
  }

  return { isMismatch: false, reason: "" };
}

/**
 * Main link analyzer function
 * @param {HTMLAnchorElement} anchorEl 
 * @param {string} rawHref 
 * @returns {object} Analysis result with risk assessment and flags
 */
function evaluateLinkSafety(anchorEl, rawHref) {
  if (!rawHref || rawHref.startsWith("javascript:") || rawHref.startsWith("#") || rawHref.startsWith("mailto:")) {
    return { isPhishing: false, riskScore: 0, flags: [] };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(rawHref, window.location.href);
  } catch (e) {
    return { isPhishing: false, riskScore: 0, flags: [] };
  }

  const host = parsedUrl.hostname || "";
  const scheme = parsedUrl.protocol.replace(":", "").toLowerCase();
  const flags = [];
  let score = 0;

  // Skip browser-internal or anchor targets
  if (parsedUrl.origin === window.location.origin && parsedUrl.pathname === window.location.pathname) {
    return { isPhishing: false, riskScore: 0, flags: [] };
  }

  // 1. Homograph / IDN Attack
  if (hasHomographAttack(host)) {
    score += 45;
    flags.push("Homograph attack detected (non-ASCII / Cyrillic character spoofing)");
  }

  // 2. Typosquatting Check
  const typoResult = checkTyposquatting(host);
  if (typoResult.isTypo) {
    score += 40;
    flags.push(typoResult.reason);
  }

  // 3. Anchor Text vs Actual URL Mismatch
  const anchorText = anchorEl ? anchorEl.innerText || anchorEl.textContent || "" : "";
  const mismatchResult = checkAnchorTextMismatch(anchorText, parsedUrl);
  if (mismatchResult.isMismatch) {
    score += 40;
    flags.push(mismatchResult.reason);
  }

  // 4. Raw IP address hostname
  if (isIpAddress(host)) {
    score += 35;
    flags.push(`Raw IP address hostname used (${host})`);
  }

  // 5. Suspicious TLD
  const tld = host.split(".").pop().toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 25;
    flags.push(`High-risk top-level domain (.${tld})`);
  }

  // 6. Suspicious credential embedding via @ symbol
  if (rawHref.includes("@")) {
    score += 35;
    flags.push("URL contains '@' symbol (often used for credential embedding or hostname spoofing)");
  }

  // 7. Excessive subdomains
  const parts = host.split(".");
  if (parts.length >= 5) {
    score += 20;
    flags.push(`Excessive subdomains detected (${parts.length - 2} levels)`);
  }

  // 8. Insecure HTTP for login or account keywords
  const pathAndQuery = (parsedUrl.pathname + parsedUrl.search).toLowerCase();
  if (scheme === "http" && (pathAndQuery.includes("login") || pathAndQuery.includes("signin") || pathAndQuery.includes("verify") || pathAndQuery.includes("banking"))) {
    score += 25;
    flags.push("Insecure HTTP protocol used for sensitive login/banking destination");
  }

  const isPhishing = score >= 35;

  return {
    isPhishing,
    riskScore: Math.min(100, score),
    host,
    url: parsedUrl.href,
    flags
  };
}

// Make available to content script
if (typeof window !== "undefined") {
  window.PhishShieldHeuristics = {
    evaluateLinkSafety,
    checkTyposquatting,
    hasHomographAttack,
    checkAnchorTextMismatch,
    isIpAddress
  };
}
