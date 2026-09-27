/**
 * PhishShield AI - Autonomous Link Heuristics Engine
 * Eliminates fragile hardcoded domain lists and avoids false positives on legitimate websites
 * by targeting objective structural deception and delegating dynamic analysis to the Laya System-1 Model.
 */

// Target popular high-value brands commonly imitated in phishing attacks
const MONITORED_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "netflix", "bankofamerica", "chase", "wellsfargo", "github",
  "linkedin", "dropbox", "binance", "coinbase", "instagram"
];

// Phishing action lures commonly used in combosquatting attacks
const PHISHING_COMBO_LURES = [
  "login", "signin", "verify", "verification", "auth", "security",
  "account", "update", "billing", "support", "password", "portal"
];

const HIGH_RISK_TLDS = new Set([
  "top", "xyz", "club", "work", "click", "zip", "mov", "gq", "cf", "tk", "ml", "ga"
]);

/**
 * Check if the link target belongs to the current website (first-party navigation)
 */
function isSameSiteOrSubdomain(linkHost, currentHost) {
  if (!linkHost || !currentHost) return false;
  const h1 = linkHost.toLowerCase().replace(/^www\./, "");
  const h2 = currentHost.toLowerCase().replace(/^www\./, "");
  if (h1 === h2) return true;
  if (h1.endsWith("." + h2) || h2.endsWith("." + h1)) return true;
  return false;
}

/**
 * Detect Homograph / IDN Attacks (Cyrillic/Greek/non-ASCII spoofing)
 */
function hasHomographAttack(host) {
  if (!host) return false;
  if (host.toLowerCase().includes("xn--")) return true;
  for (let i = 0; i < host.length; i++) {
    if (host.charCodeAt(i) > 127) return true;
  }
  return false;
}

/**
 * Check for intentional visual typosquatting substitutions (e.g. 1->l, 0->o, vv->w)
 * without erroneously flagging innocent English words (e.g. stream, apply, base, team).
 */
function checkDeceptiveTyposquatting(host) {
  if (!host) return { isTypo: false, reason: "", score: 0 };

  const cleanHost = host.toLowerCase().replace(/^www\./, "");
  const parts = cleanHost.split(".");
  const mainDomain = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const tld = parts.length >= 2 ? parts[parts.length - 1] : "";
  const tokens = mainDomain.split("-");

  for (const brand of MONITORED_BRANDS) {
    // 1. Intentional Character/Digit Substitution (e.g. paypa1, micros0ft, g00gle)
    for (const token of tokens) {
      if (token !== brand) {
        const normalized = token
          .replace(/1/g, "l")
          .replace(/0/g, "o")
          .replace(/vv/g, "w")
          .replace(/rn/g, "m");

        if (normalized === brand && token !== brand) {
          return {
            isTypo: true,
            reason: `Deceptive typosquatting: Brand '${brand}' spoofed using character substitution in '${host}'`,
            score: 75
          };
        }
      }
    }

    // 2. High-Risk Combosquatting (Brand + Phishing Lure Keyword e.g. chase-security-update.top)
    if (mainDomain.includes(brand) && mainDomain !== brand) {
      const foundLure = PHISHING_COMBO_LURES.find((kw) => mainDomain.includes(kw));
      const isBadTld = HIGH_RISK_TLDS.has(tld);

      if (foundLure || isBadTld) {
        const lureDesc = foundLure ? `'${foundLure}' lure` : `.${tld} TLD`;
        return {
          isTypo: true,
          reason: `Combosquatting attack: Impersonating '${brand}' paired with ${lureDesc} in '${host}'`,
          score: 70
        };
      }
    }
  }

  return { isTypo: false, reason: "", score: 0 };
}

/**
 * High-precision anchor text mismatch check:
 * Only triggers if anchor text explicitly pretends to be a full URL/domain
 * AND the target is NOT an internal first-party navigation.
 */
function checkAnchorTextMismatch(anchorText, parsedUrl, currentHost) {
  if (!anchorText || !parsedUrl) return { isMismatch: false, reason: "" };

  const text = anchorText.trim().toLowerCase();

  // MUST look like an explicit URL / domain claim
  const isExplicitUrl =
    text.startsWith("http://") ||
    text.startsWith("https://") ||
    text.startsWith("www.") ||
    /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(text);

  if (!isExplicitUrl) {
    return { isMismatch: false, reason: "" };
  }

  const match = text.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})/i);
  if (!match) return { isMismatch: false, reason: "" };

  const displayedDomain = match[1].toLowerCase().replace(/^www\./, "");
  const actualHost = parsedUrl.hostname ? parsedUrl.hostname.toLowerCase().replace(/^www\./, "") : "";

  if (isSameSiteOrSubdomain(actualHost, currentHost)) {
    return { isMismatch: false, reason: "" };
  }

  if (displayedDomain && actualHost && displayedDomain !== actualHost && !actualHost.endsWith("." + displayedDomain)) {
    return {
      isMismatch: true,
      reason: `Deceptive link: Display text claims '${displayedDomain}' but link leads to '${actualHost}'`
    };
  }

  return { isMismatch: false, reason: "" };
}

function isIpAddress(host) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Fast Client-Side Link Inspection
 * Identifies unambiguous structural deception immediately, without false-flagging legitimate sites.
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
  const currentHost = window.location.hostname || "";
  const flags = [];
  let score = 0;

  // 1. Same-site / internal navigation is ALWAYS safe
  if (isSameSiteOrSubdomain(host, currentHost)) {
    return { isPhishing: false, riskScore: 0, host, url: parsedUrl.href, flags: [] };
  }

  // 2. Homograph / Cyrillic Punycode Spoofing
  if (hasHomographAttack(host)) {
    score += 80;
    flags.push("Homograph attack detected (non-ASCII character or Punycode domain spoofing)");
  }

  // 3. Raw IP Address Hostname
  if (isIpAddress(host)) {
    score += 75;
    flags.push(`Raw IP address hostname used (${host})`);
  }

  // 4. Embedded authority credentials (user:password@host)
  if (parsedUrl.username || parsedUrl.password) {
    score += 80;
    flags.push("URL contains embedded credentials/hostname spoofing via authority '@'");
  }

  // 5. Deceptive Anchor Text Mismatch
  const anchorText = anchorEl ? anchorEl.innerText || anchorEl.textContent || "" : "";
  const mismatchResult = checkAnchorTextMismatch(anchorText, parsedUrl, currentHost);
  if (mismatchResult.isMismatch) {
    score += 75;
    flags.push(mismatchResult.reason);
  }

  // 6. Deceptive Typosquatting / Combosquatting
  const typoResult = checkDeceptiveTyposquatting(host);
  if (typoResult.isTypo) {
    score += typoResult.score;
    flags.push(typoResult.reason);
  }

  const isPhishing = score >= 60;

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
    hasHomographAttack,
    checkAnchorTextMismatch,
    isIpAddress,
    isSameSiteOrSubdomain,
    checkDeceptiveTyposquatting
  };
}
