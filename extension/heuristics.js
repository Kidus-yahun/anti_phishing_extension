/**
 * PhishShield AI - Autonomous Threat & Heuristics Engine
 * Combines structural deception analysis, RFC-compliant Punycode decoding,
 * Levenshtein distance brand lookalike analysis (Ethiopian and Global targets),
 * Ethiopic-Latin mixed-script homograph detection, and Amharic credential scam heuristics.
 */

// Global high-value monitored brands
const MONITORED_GLOBAL_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "facebook",
  "netflix", "bankofamerica", "chase", "wellsfargo", "github",
  "linkedin", "dropbox", "binance", "coinbase", "instagram"
];

// Ethiopian high-value monitored financial and telecom institutions
const ETHIOPIAN_TARGETS = [
  {
    name: "Telebirr",
    key: "telebirr",
    officialDomains: ["telebirr.et", "ethiotel.et", "ethiotelecom.et"],
    brandTokens: ["telebirr", "tele-birr", "telebir"],
    i18nKey: "telebirrLookalike"
  },
  {
    name: "Commercial Bank of Ethiopia (CBE)",
    key: "cbe",
    officialDomains: ["combanketh.et", "cbe.com.et"],
    brandTokens: ["combanketh", "cbebirr", "cbe-birr", "cbebank", "cbe"],
    i18nKey: "cbeLookalike"
  },
  {
    name: "Awash Bank",
    key: "awash",
    officialDomains: ["awashbank.com"],
    brandTokens: ["awashbank", "awashbirr", "awash-bank", "awash"],
    i18nKey: "awashLookalike"
  },
  {
    name: "Dashen Bank",
    key: "dashen",
    officialDomains: ["dashenbanksc.com"],
    brandTokens: ["dashenbank", "amole", "dashen-bank", "dashen"],
    i18nKey: "dashenLookalike"
  },
  {
    name: "Ethio Telecom",
    key: "ethiotelecom",
    officialDomains: ["ethiotelecom.et", "ethiotel.et"],
    brandTokens: ["ethiotelecom", "ethio-telecom", "ethiotel"],
    i18nKey: "ethiocomeLookalike"
  },
  {
    name: "Safaricom Ethiopia",
    key: "safaricom",
    officialDomains: ["safaricom.et", "mpesa.et"],
    brandTokens: ["safaricom", "safaricom-et", "mpesa"],
    i18nKey: "safaricomLookalike"
  }
];

// Phishing action lures commonly used in combosquatting attacks
const PHISHING_COMBO_LURES = [
  "login", "signin", "verify", "verification", "auth", "security",
  "account", "update", "billing", "support", "password", "portal",
  "claim", "bonus", "prize", "airtime", "free", "gift", "reward", "birr"
];

const HIGH_RISK_TLDS = new Set([
  "top", "xyz", "club", "work", "click", "zip", "mov", "gq", "cf", "tk", "ml", "ga", "date", "racing", "kim"
]);

const KNOWN_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "ow.ly",
  "shorturl.at", "goo.gl", "qr.ae", "rebrand.ly", "bl.ink", "buff.ly",
  "snip.ly", "clck.ru", "trib.al", "s.id", "vo.la"
]);

// Non-domain file extensions that must NEVER be parsed as domain TLDs
const NON_DOMAIN_FILE_EXTENSIONS = new Set([
  "exe", "msi", "bat", "cmd", "scr", "pif", "bin", "run", "gadget",
  "dmg", "pkg", "deb", "rpm", "apk", "apks", "xapk", "aab", "ipa", "msix", "appx", "appimage",
  "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "lz", "lzma", "zst", "tzst",
  "iso", "img", "vmdk", "vdi", "qcow2", "vhd", "toast",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv", "tsv",
  "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "ico", "tif", "tiff", "psd", "raw",
  "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma", "mid", "midi",
  "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "3gp",
  "py", "pyw", "js", "mjs", "cjs", "ts", "rb", "php", "java", "cpp", "cxx", "hpp", "cs",
  "sh", "bash", "zsh", "fish", "ps1", "psm1", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "log", "md", "markdown",
  "jar", "war", "ear", "whl", "egg", "gem", "node", "dylib", "dll",
  "sig", "asc", "sha256", "sha512", "md5", "torrent", "patch", "diff"
]);

// Amharic phishing lures and credential harvesting triggers
const AMHARIC_SCAM_PHRASES = [
  { phrase: "የቴሌብር ፓስወርድ", weight: 95 },
  { phrase: "የቴሌብር ፒን", weight: 95 },
  { phrase: "የቴሌብር ሚስጥር ቁጥር", weight: 95 },
  { phrase: "የይለፍ ቃል ያስገቡ", weight: 80 },
  { phrase: "የባንክ ሂሳብዎን ያረጋግጡ", weight: 90 },
  { phrase: "ሂሳብዎ ታግዷል", weight: 90 },
  { phrase: "አካውንትዎ ተቆልፏል", weight: 90 },
  { phrase: "ገንዘብዎን ለመቀበል", weight: 85 },
  { phrase: "ገንዘብ ለመቀበል", weight: 85 },
  { phrase: "የብር ሽልማት", weight: 85 },
  { phrase: "የ10,000 ብር ሽልማት", weight: 90 },
  { phrase: "ሽልማትዎን ይውሰዱ", weight: 90 },
  { phrase: "ነፃ የኢንተርኔት ፓኬጅ", weight: 85 },
  { phrase: "ነፃ የአየር ሰዓት", weight: 85 },
  { phrase: "የማረጋገጫ ኮድ", weight: 85 },
  { phrase: "የማረጋገጫ ኮድ ያስገቡ", weight: 90 },
  { phrase: "የሲቢኢ ብር", weight: 85 },
  { phrase: "አሁኑኑ ያረጋግጡ", weight: 80 },
  { phrase: "ወዲያውኑ ይላኩ", weight: 80 }
];

/**
 * Levenshtein distance calculation
 */
function getLevenshteinDistance(a, b) {
  if (!a || !b) return (a || b || "").length;
  if (a === b) return 0;

  const al = a.length;
  const bl = b.length;
  const row = [];

  for (let j = 0; j <= bl; j++) row[j] = j;

  for (let i = 1; i <= al; i++) {
    let prev = i;
    for (let j = 1; j <= bl; j++) {
      let val;
      if (a[i - 1] === b[j - 1]) {
        val = row[j - 1];
      } else {
        val = Math.min(row[j - 1] + 1, prev + 1, row[j] + 1);
      }
      row[j - 1] = prev;
      prev = val;
    }
    row[bl] = prev;
  }

  return row[bl];
}

/**
 * Standard RFC 3492 Punycode decoder
 */
function decodePunycode(input) {
  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;
  const delimiter = "-";

  let n = initialN;
  let i = 0;
  let bias = initialBias;
  const output = [];

  const delimIdx = input.lastIndexOf(delimiter);
  if (delimIdx > 0) {
    for (let j = 0; j < delimIdx; j++) {
      output.push(input.charCodeAt(j));
    }
  }

  let inIdx = delimIdx > 0 ? delimIdx + 1 : 0;
  const inLen = input.length;

  while (inIdx < inLen) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (inIdx >= inLen) return input; // Malformed punycode, return original
      const byte = input.charCodeAt(inIdx++);
      let digit;
      if (byte >= 48 && byte <= 57) digit = byte - 22;
      else if (byte >= 65 && byte <= 90) digit = byte - 65;
      else if (byte >= 97 && byte <= 122) digit = byte - 97;
      else digit = base;

      i += digit * w;
      const t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
      if (digit < t) break;
      w *= (base - t);
    }

    const outLen = output.length + 1;
    // Adapt bias
    let delta = oldi === 0 ? Math.floor(i / damp) : Math.floor((i - oldi) / 2);
    delta += Math.floor(delta / outLen);
    let k = 0;
    while (delta > Math.floor(((base - tmin) * tmax) / 2)) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    bias = Math.floor(k + ((base - tmin + 1) * delta) / (delta + skew));

    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

/**
 * Decode full hostname from Punycode to Unicode
 */
function toUnicodeHost(host) {
  if (!host) return "";
  try {
    return host.split(".").map((part) => {
      const lower = part.toLowerCase();
      if (lower.startsWith("xn--")) {
        return decodePunycode(lower.slice(4));
      }
      return part;
    }).join(".");
  } catch (e) {
    return host;
  }
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
 * Check if host matches any official domain for a brand
 */
function isOfficialDomain(host, officialDomains) {
  if (!host) return false;
  const clean = host.toLowerCase().replace(/^www\./, "");
  for (const official of officialDomains) {
    const cleanOfficial = official.toLowerCase().replace(/^www\./, "");
    if (clean === cleanOfficial || clean.endsWith("." + cleanOfficial)) {
      return true;
    }
  }
  return false;
}

/**
 * Check if a host is an Ethiopian brand lookalike using Levenshtein distance & combosquatting
 */
function checkEthiopianBrandLookalike(host) {
  if (!host) return { isLookalike: false, reason: "", score: 0, target: null };

  const unicodeHost = toUnicodeHost(host).toLowerCase().replace(/^www\./, "");
  const parts = unicodeHost.split(".");
  const sld = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const tld = parts.length >= 2 ? parts[parts.length - 1] : "";
  const tokens = sld.split(/[-_.]+/);

  for (const target of ETHIOPIAN_TARGETS) {
    // If it's already an official verified domain, never flag it
    if (isOfficialDomain(unicodeHost, target.officialDomains)) {
      continue;
    }

    for (const token of tokens) {
      if (!token || token.length < 3) continue;

      // 1. Direct Levenshtein distance check on token vs target brand keywords
      for (const brandToken of target.brandTokens) {
        // If identical token appears in unauthorized domain
        if (token === brandToken) {
          // Check if paired with phishing lures or unauthorized TLD
          const isLure = PHISHING_COMBO_LURES.some((kw) => sld.includes(kw));
          const isBadTld = HIGH_RISK_TLDS.has(tld);
          if (isLure || isBadTld || !unicodeHost.endsWith(".et")) {
            return {
              isLookalike: true,
              reason: `Unauthorized impersonation of ${target.name} detected in '${host}'`,
              i18nKey: target.i18nKey,
              target: target.name,
              score: 90
            };
          }
        }

        // Levenshtein distance of 1 or 2 (typosquatting)
        const dist = getLevenshteinDistance(token, brandToken);
        if (dist > 0 && dist <= 2 && token.length >= 4) {
          return {
            isLookalike: true,
            reason: `Lookalike of ${target.name} detected via character edit distance (${token} ~ ${brandToken}) in '${host}'`,
            i18nKey: target.i18nKey,
            target: target.name,
            score: 95
          };
        }
      }
    }

    // 2. Full SLD containment check
    for (const brandToken of target.brandTokens) {
      if (sld.includes(brandToken) && !isOfficialDomain(unicodeHost, target.officialDomains)) {
        return {
          isLookalike: true,
          reason: `Deceptive domain impersonating ${target.name} found in '${host}'`,
          i18nKey: target.i18nKey,
          target: target.name,
          score: 85
        };
      }
    }
  }

  return { isLookalike: false, reason: "", score: 0, target: null };
}

/**
 * Detect mixed-script homograph attacks (Ethiopic mixed with Latin or Punycode spoofing)
 */
function checkMixedScriptAndHomograph(host) {
  if (!host) return { isHomograph: false, reason: "", score: 0 };

  const unicodeHost = toUnicodeHost(host);
  const isPunycode = host.toLowerCase().includes("xn--");

  let hasEthiopic = false;
  let hasLatin = false;

  for (let i = 0; i < unicodeHost.length; i++) {
    const code = unicodeHost.charCodeAt(i);
    // Ethiopic Unicode Block: U+1200 - U+137F
    if (code >= 0x1200 && code <= 0x137F) {
      hasEthiopic = true;
    } else if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
      hasLatin = true;
    }
  }

  // Mixed Ethiopic and Latin in domain labels is an unambiguous attack
  if (hasEthiopic && hasLatin) {
    return {
      isHomograph: true,
      reason: `Mixed-script attack: Ethiopic (U+1200-U+137F) and Latin characters mixed in domain '${unicodeHost}'`,
      i18nKey: "mixedScriptAttack",
      score: 95
    };
  }

  // Punycode representation of internationalized domain
  if (isPunycode) {
    return {
      isHomograph: true,
      reason: `Punycode IDN domain detected ('${host}' decodes to '${unicodeHost}')`,
      i18nKey: "punycodeSpoof",
      score: 80
    };
  }

  // General non-ASCII check
  for (let i = 0; i < host.length; i++) {
    if (host.charCodeAt(i) > 127) {
      return {
        isHomograph: true,
        reason: `Non-ASCII homograph characters detected in '${host}'`,
        i18nKey: "punycodeSpoof",
        score: 80
      };
    }
  }

  return { isHomograph: false, reason: "", score: 0 };
}

/**
 * Check if a host is a known shortlink service
 */
function isShortlink(host) {
  if (!host) return false;
  const clean = host.toLowerCase().replace(/^www\./, "");
  return KNOWN_SHORTENERS.has(clean);
}

/**
 * Check for intentional visual typosquatting on global brands
 */
function checkGlobalTyposquatting(host) {
  if (!host) return { isTypo: false, reason: "", score: 0 };

  const cleanHost = host.toLowerCase().replace(/^www\./, "");
  const parts = cleanHost.split(".");
  const mainDomain = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  const tld = parts.length >= 2 ? parts[parts.length - 1] : "";
  const tokens = mainDomain.split(/[-_.]+/);

  for (const brand of MONITORED_GLOBAL_BRANDS) {
    for (const token of tokens) {
      const normVariants = [
        token.replace(/1/g, "l").replace(/0/g, "o").replace(/vv/g, "w").replace(/rn/g, "m"),
        token.replace(/1/g, "i").replace(/0/g, "o").replace(/vv/g, "w").replace(/rn/g, "m"),
        token.replace(/1/g, "l"),
        token.replace(/1/g, "i")
      ];

      if (token !== brand && normVariants.includes(brand)) {
        return {
          isTypo: true,
          reason: `Deceptive typosquatting: Brand '${brand}' spoofed using character substitution in '${host}'`,
          i18nKey: "brandTyposquatting",
          score: 75
        };
      }
    }

    if (mainDomain.includes(brand) && mainDomain !== brand) {
      const foundLure = PHISHING_COMBO_LURES.find((kw) => mainDomain.includes(kw));
      const isBadTld = HIGH_RISK_TLDS.has(tld);

      if (foundLure || isBadTld) {
        const lureDesc = foundLure ? `'${foundLure}' lure` : `.${tld} TLD`;
        return {
          isTypo: true,
          reason: `Combosquatting attack: Impersonating '${brand}' paired with ${lureDesc} in '${host}'`,
          i18nKey: "combosquatting",
          score: 70
        };
      }
    }
  }

  return { isTypo: false, reason: "", score: 0 };
}

/**
 * Extracts explicit domain claim from anchor text
 */
function extractClaimedDomain(anchorText, parsedUrl) {
  if (!anchorText) return null;
  const text = anchorText.trim().toLowerCase();
  if (!text) return null;

  if (parsedUrl && parsedUrl.pathname) {
    const pathLower = parsedUrl.pathname.toLowerCase();
    const filename = pathLower.split("/").filter(Boolean).pop() || "";
    if (filename && (text === filename || pathLower.endsWith("/" + text) || text.endsWith(filename))) {
      return null;
    }
  }

  const urlMatch = text.match(/(?:^|\s)https?:\/\/([a-z0-9.-]+)/i);
  if (urlMatch) {
    const rawHost = urlMatch[1].replace(/^www\./, "");
    const parts = rawHost.split(".");
    const ext = parts[parts.length - 1];
    if (!NON_DOMAIN_FILE_EXTENSIONS.has(ext)) return rawHost;
  }

  const wwwMatch = text.match(/(?:^|\s)www\.([a-z0-9.-]+\.[a-z]{2,})/i);
  if (wwwMatch) {
    const rawHost = wwwMatch[1].replace(/^www\./, "");
    const parts = rawHost.split(".");
    const ext = parts[parts.length - 1];
    if (!NON_DOMAIN_FILE_EXTENSIONS.has(ext)) return rawHost;
  }

  const domainCandidateMatch = text.match(/^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})(?:\/.*)?$/i);
  if (domainCandidateMatch) {
    const candidate = domainCandidateMatch[1].replace(/^www\./, "");
    const parts = candidate.split(".");
    const ext = parts[parts.length - 1];
    if (!NON_DOMAIN_FILE_EXTENSIONS.has(ext)) return candidate;
  }

  return null;
}

/**
 * High-precision anchor text mismatch check
 */
function checkAnchorTextMismatch(anchorText, parsedUrl, currentHost) {
  if (!anchorText || !parsedUrl) return { isMismatch: false, reason: "" };

  const displayedDomain = extractClaimedDomain(anchorText, parsedUrl);
  if (!displayedDomain) return { isMismatch: false, reason: "" };

  const actualHost = parsedUrl.hostname ? parsedUrl.hostname.toLowerCase().replace(/^www\./, "") : "";

  if (isSameSiteOrSubdomain(actualHost, currentHost)) {
    return { isMismatch: false, reason: "" };
  }

  if (displayedDomain && actualHost && displayedDomain !== actualHost && !actualHost.endsWith("." + displayedDomain)) {
    return {
      isMismatch: true,
      reason: `Deceptive link: Display text claims '${displayedDomain}' but link leads to '${actualHost}'`,
      i18nKey: "anchorMismatch"
    };
  }

  return { isMismatch: false, reason: "" };
}

function isIpAddress(host) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Scan document forms for high-urgency Amharic credential harvesting scam phrases
 */
function checkAmharicCredentialScamInForms(doc = document, currentHost = "") {
  if (!doc) return { detected: false, flags: [], score: 0 };

  // Skip verified legitimate institutional domains
  for (const target of ETHIOPIAN_TARGETS) {
    if (isOfficialDomain(currentHost, target.officialDomains)) {
      return { detected: false, flags: [], score: 0 };
    }
  }

  const forms = doc.querySelectorAll("form");
  const flags = [];
  let maxScore = 0;

  forms.forEach((form) => {
    // Check if form requests sensitive input (password, pin, phone, account, otp)
    const sensitiveInputs = form.querySelectorAll(
      'input[type="password"], input[type="tel"], input[name*="pin" i], input[name*="pass" i], input[name*="account" i], input[name*="otp" i], input[name*="phone" i]'
    );

    if (sensitiveInputs.length === 0) return;

    // Check text inside form and in immediate parents/headings
    const formText = (form.innerText || form.textContent || "").toLowerCase();
    const parentText = form.parentElement ? (form.parentElement.innerText || "").toLowerCase() : "";
    const combinedText = formText + " " + parentText;

    for (const item of AMHARIC_SCAM_PHRASES) {
      if (combinedText.includes(item.phrase)) {
        flags.push(`Amharic credential harvesting scam phrase detected near input form: '${item.phrase}'`);
        maxScore = Math.max(maxScore, item.weight);
      }
    }
  });

  return {
    detected: flags.length > 0,
    flags,
    score: maxScore
  };
}

/**
 * Comprehensive Page-Level Safety Evaluation
 */
function evaluatePageSafety(doc = document, host = window.location.hostname, url = window.location.href, trustedDomains = []) {
  const flags = [];
  let score = 0;
  const cleanHost = (host || "").toLowerCase().replace(/^www\./, "");

  // 1. Check user trusted domains
  if (Array.isArray(trustedDomains) && trustedDomains.some((d) => cleanHost === d || cleanHost.endsWith("." + d))) {
    return {
      status: "safe",
      riskScore: 0,
      flags: [],
      isTrusted: true,
      host: cleanHost,
      url
    };
  }

  // 2. Ethiopian Brand Lookalikes
  const ethiopianLookalike = checkEthiopianBrandLookalike(cleanHost);
  if (ethiopianLookalike.isLookalike) {
    score += ethiopianLookalike.score;
    flags.push(ethiopianLookalike.reason);
  }

  // 3. Mixed-Script & Homographs
  const homograph = checkMixedScriptAndHomograph(cleanHost);
  if (homograph.isHomograph) {
    score += homograph.score;
    flags.push(homograph.reason);
  }

  // 4. Global Brand Typosquatting
  const globalTypo = checkGlobalTyposquatting(cleanHost);
  if (globalTypo.isTypo) {
    score += globalTypo.score;
    flags.push(globalTypo.reason);
  }

  // 5. Raw IP Address Hostname
  if (isIpAddress(cleanHost)) {
    score += 75;
    flags.push(`Raw IP address hostname used (${cleanHost})`);
  }

  // 6. Amharic Credential Harvesting Forms
  const formScam = checkAmharicCredentialScamInForms(doc, cleanHost);
  if (formScam.detected) {
    score += formScam.score;
    flags.push(...formScam.flags);
  }

  let status = "safe";
  if (score >= 60) {
    status = "dangerous";
  } else if (score >= 30) {
    status = "suspicious";
  }

  return {
    status,
    riskScore: Math.min(100, score),
    flags,
    host: cleanHost,
    url,
    isTrusted: false
  };
}

/**
 * Evaluate single link safety with complete heuristic coverage
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

  // 1. Same-site navigation is safe
  if (isSameSiteOrSubdomain(host, currentHost)) {
    return {
      isPhishing: false,
      riskScore: 0,
      host,
      url: parsedUrl.href,
      flags: []
    };
  }

  // 2. Ethiopian Brand Lookalikes
  const ethiopianLookalike = checkEthiopianBrandLookalike(host);
  if (ethiopianLookalike.isLookalike) {
    score += ethiopianLookalike.score;
    flags.push(ethiopianLookalike.reason);
  }

  // 3. Mixed-Script & Homograph Attacks
  const homograph = checkMixedScriptAndHomograph(host);
  if (homograph.isHomograph) {
    score += homograph.score;
    flags.push(homograph.reason);
  }

  // 4. Raw IP Address Hostname
  if (isIpAddress(host)) {
    score += 75;
    flags.push(`Raw IP address hostname used (${host})`);
  }

  // 5. Embedded Authority Credentials
  if (parsedUrl.username || parsedUrl.password) {
    score += 80;
    flags.push("URL contains embedded credentials/hostname spoofing via authority '@'");
  }

  // 6. Deceptive Anchor Text Mismatch
  const anchorText = anchorEl ? anchorEl.innerText || anchorEl.textContent || "" : "";
  const mismatchResult = checkAnchorTextMismatch(anchorText, parsedUrl, currentHost);
  if (mismatchResult.isMismatch) {
    score += 75;
    flags.push(mismatchResult.reason);
  }

  // 7. Global Typosquatting
  const typoResult = checkGlobalTyposquatting(host);
  if (typoResult.isTypo) {
    score += typoResult.score;
    flags.push(typoResult.reason);
  }

  // 8. Shortlink Detection
  if (isShortlink(host)) {
    score += 35;
    flags.push(`Shortened link detected (${host}) masking destination`);
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

// Make available to content script and global contexts
const PhishShieldHeuristics = {
  getLevenshteinDistance,
  decodePunycode,
  toUnicodeHost,
  isShortlink,
  isSameSiteOrSubdomain,
  isOfficialDomain,
  isIpAddress,
  checkEthiopianBrandLookalike,
  checkMixedScriptAndHomograph,
  checkGlobalTyposquatting,
  checkAnchorTextMismatch,
  checkAmharicCredentialScamInForms,
  evaluatePageSafety,
  evaluateLinkSafety,
  ETHIOPIAN_TARGETS,
  AMHARIC_SCAM_PHRASES
};

if (typeof window !== "undefined") {
  window.PhishShieldHeuristics = PhishShieldHeuristics;
}
if (typeof globalThis !== "undefined") {
  globalThis.PhishShieldHeuristics = PhishShieldHeuristics;
}
