/**
 * PhishShield AI - High-Precision Link Heuristics Engine
 * Eliminates false positives on major platforms (YouTube, Google, GitHub, etc.)
 * while maintaining strict detection for genuine phishing attacks.
 */

// 1. Authenticated Major Global Domains (Never false-flag authentic domains)
const TRUSTED_DOMAINS = new Set([
  "google.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com",
  "github.com", "github.io", "wikipedia.org", "wikimedia.org",
  "microsoft.com", "live.com", "office.com", "outlook.com", "bing.com",
  "apple.com", "icloud.com",
  "amazon.com", "aws.amazon.com",
  "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com",
  "twitter.com", "x.com", "t.co",
  "linkedin.com", "reddit.com", "netflix.com", "spotify.com",
  "twitch.tv", "discord.com", "discord.gg", "steamcommunity.com", "steampowered.com",
  "cloudflare.com", "stackoverflow.com", "stackexchange.com",
  "mozilla.org", "w3.org", "medium.com"
]);

// 2. High-value brands targeted by phishers
const POPULAR_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "netflix", "bankofamerica", "chase", "wellsfargo", "github",
  "linkedin", "dropbox", "binance", "coinbase", "instagram",
  "twitter", "discord", "steam", "whatsapp", "telegram"
];

const SUSPICIOUS_TLDS = new Set([
  "top", "xyz", "club", "work", "click", "zip", "mov", "country",
  "kim", "science", "gq", "cf", "tk", "ml", "ga"
]);

/**
 * Check if a host belongs to a verified trusted domain
 */
function isTrustedDomain(host) {
  if (!host) return false;
  const clean = host.toLowerCase().replace(/^www\./, "");
  if (TRUSTED_DOMAINS.has(clean)) return true;
  for (const trusted of TRUSTED_DOMAINS) {
    if (clean.endsWith("." + trusted)) {
      return true;
    }
  }
  return false;
}

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
 * Levenshtein Distance
 */
function levenshteinDistance(s1, s2) {
  if (s1.length < s2.length) return levenshteinDistance(s2, s1);
  if (s2.length === 0) return s1.length;
  let prev = Array.from({ length: s2.length + 1 }, (_, i) => i);
  for (let i = 0; i < s1.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < s2.length; j++) {
      const cost = s1[i] === s2[j] ? 0 : 1;
      curr.push(Math.min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost));
    }
    prev = curr;
  }
  return prev[s2.length];
}

/**
 * Check for deceptive brand typosquatting or combosquatting
 */
function checkTyposquatting(host) {
  if (!host) return { isTypo: false, reason: "" };

  const cleanHost = host.toLowerCase().replace(/^www\./, "");
  const parts = cleanHost.split(".");
  // Inspect registered domain label (e.g. 'paypa1' from 'paypa1-security.com')
  const mainDomain = parts.length >= 2 ? parts[parts.length - 2] : parts[0];

  const tokens = mainDomain.split("-");

  for (const token of tokens) {
    for (const brand of POPULAR_BRANDS) {
      if (token === brand) continue; // Exact brand match (authenticity verified separately)

      const dist = levenshteinDistance(token, brand);
      if (dist > 0 && dist <= 2 && token.length >= 4) {
        return {
          isTypo: true,
          reason: `Possible typosquatting of brand '${brand}' (detected: '${token}' in '${host}')`
        };
      }

      if (token.includes(brand) && token.length > brand.length + 3) {
        return {
          isTypo: true,
          reason: `Brand name '${brand}' embedded inside domain '${host}'`
        };
      }
    }
  }

  return { isTypo: false, reason: "" };
}

/**
 * High-precision anchor text mismatch check:
 * Only triggers if anchor text explicitly pretends to be a full URL/domain
 * AND the target is NOT an internal first-party navigation.
 */
function checkAnchorTextMismatch(anchorText, parsedUrl, currentHost) {
  if (!anchorText || !parsedUrl) return { isMismatch: false, reason: "" };

  const text = anchorText.trim().toLowerCase();

  // MUST look like an explicit URL (e.g. starts with http://, https://, www. or is a domain)
  const isExplicitUrl =
    text.startsWith("http://") ||
    text.startsWith("https://") ||
    text.startsWith("www.") ||
    /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(text);

  if (!isExplicitUrl) {
    // Normal video titles like "Learn Node.js in 100s" or "Claude.ai vs ChatGPT" are NOT anchor spoofs
    return { isMismatch: false, reason: "" };
  }

  // Extract domain from anchor text
  const match = text.match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})/i);
  if (!match) return { isMismatch: false, reason: "" };

  const displayedDomain = match[1].toLowerCase().replace(/^www\./, "");
  const actualHost = parsedUrl.hostname ? parsedUrl.hostname.toLowerCase().replace(/^www\./, "") : "";

  // If the target is the current site, it's not a phishing deception
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
 * High-Precision Link Safety Evaluation
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
  const scheme = parsedUrl.protocol.replace(":", "").toLowerCase();
  const flags = [];
  let score = 0;

  // 1. Check Homograph Attack FIRST (Cyrillic spoofing)
  const isHomograph = hasHomographAttack(host);
  if (isHomograph) {
    score += 60;
    flags.push("Homograph attack detected (non-ASCII / Cyrillic character spoofing)");
  }

  // 2. Safe Whitelist Checks (Trusted Global Domains & Same-Site Navigation)
  // If NOT a homograph attack, and belongs to a trusted domain or current site, it is SAFE.
  if (!isHomograph) {
    if (isTrustedDomain(host) || isSameSiteOrSubdomain(host, currentHost)) {
      return { isPhishing: false, riskScore: 0, host, url: parsedUrl.href, flags: [] };
    }
  }

  // 3. Typosquatting / Combosquatting Check
  const typoResult = checkTyposquatting(host);
  if (typoResult.isTypo) {
    score += 45;
    flags.push(typoResult.reason);
  }

  // 4. Anchor Text vs Actual Destination Mismatch
  const anchorText = anchorEl ? anchorEl.innerText || anchorEl.textContent || "" : "";
  const mismatchResult = checkAnchorTextMismatch(anchorText, parsedUrl, currentHost);
  if (mismatchResult.isMismatch) {
    score += 45;
    flags.push(mismatchResult.reason);
  }

  // 5. Raw IP address hostname
  if (isIpAddress(host)) {
    score += 40;
    flags.push(`Raw IP address hostname used (${host})`);
  }

  // 6. Suspicious Credential Embedding via Authority '@'
  // Only flags if '@' is in userinfo (before host), NOT in path like /@username
  if (parsedUrl.username || parsedUrl.password) {
    score += 45;
    flags.push("URL contains embedded credentials/hostname spoofing via authority '@'");
  }

  // 7. Suspicious TLD
  const tld = host.split(".").pop().toLowerCase();
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 30;
    flags.push(`High-risk top-level domain (.${tld})`);
  }

  // 8. Insecure HTTP for login or banking keywords
  const pathAndQuery = (parsedUrl.pathname + parsedUrl.search).toLowerCase();
  if (scheme === "http" && (pathAndQuery.includes("login") || pathAndQuery.includes("signin") || pathAndQuery.includes("verify") || pathAndQuery.includes("banking"))) {
    score += 30;
    flags.push("Insecure HTTP protocol used for sensitive login/banking destination");
  }

  // Requires high confidence (score >= 40)
  const isPhishing = score >= 40 && flags.length > 0;

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
    isIpAddress,
    isTrustedDomain
  };
}
