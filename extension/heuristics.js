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
 * Known trusted global tech, social, and infrastructure ecosystems
 */
const TRUSTED_DOMAINS = new Set([
  // Google / Alphabet
  "google.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com",
  "gmail.com", "googleapis.com", "gstatic.com", "googletagmanager.com", "googleusercontent.com",
  "google-analytics.com", "android.com", "chrome.com",

  // GitHub & Developer Ecosystem
  "github.com", "github.io", "githubstatus.com", "githubassets.com", "githubusercontent.com",
  "github.community", "github.dev", "gh.io", "gitlab.com", "bitbucket.org",
  "stackoverflow.com", "stackexchange.com", "npmjs.com", "pypi.org", "python.org",
  "mozilla.org", "w3.org",

  // Microsoft
  "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "bing.com",
  "microsoftonline.com", "microsoftteams.com", "azure.com", "visualstudio.com",
  "windows.com", "msn.com", "skype.com", "xbox.com", "azureedge.net",

  // Apple
  "apple.com", "icloud.com", "appleid.apple.com", "itunes.com", "cdn-apple.com",

  // Amazon
  "amazon.com", "aws.amazon.com", "amazonaws.com", "amazonpay.com", "media-amazon.com", "primevideo.com",

  // Meta Ecosystem
  "meta.com", "meta.ai", "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com", "fbcdn.net", "threads.net",

  // Social & Media
  "twitter.com", "x.com", "t.co", "twimg.com", "linkedin.com", "licdn.com",
  "reddit.com", "redditstatic.com", "netflix.com", "nflxext.com", "spotify.com", "scdn.co",
  "twitch.tv", "discord.com", "discord.gg", "discordapp.com", "discordstatus.com",
  "telegram.org", "t.me",

  // Security, Infrastructure, Browsers & Common Services
  "steamcommunity.com", "steampowered.com", "steamstatic.com",
  "cloudflare.com", "cloudflarestatus.com", "statuspage.io",
  "openai.com", "chatgpt.com", "wikipedia.org", "wikimedia.org", "medium.com", "adobe.com",
  "opera.com", "mega.nz"
]);

/**
 * Check if host belongs to an authenticated trusted ecosystem
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
 * Check if a host is an Ethiopian brand lookalike using Levenshtein distance & combosquatting
 */
function checkEthiopianBrandLookalike(host) {
  if (!host || isTrustedDomain(host)) return { isLookalike: false, reason: "", score: 0, target: null };

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

        // Levenshtein distance typosquatting
        // Require length-based threshold, prefix preservation, and character normalization
        // to prevent false positives on completely unrelated short words (e.g. meta, mega, opera vs mpesa; apple, adobe vs amole)
        const normToken = token
          .replace(/0/g, "o")
          .replace(/1/g, "l")
          .replace(/3/g, "e")
          .replace(/4/g, "a")
          .replace(/5/g, "s")
          .replace(/@/g, "a");

        const dist = getLevenshteinDistance(normToken, brandToken);
        const minLen = Math.min(normToken.length, brandToken.length);
        const prefixLen = Math.min(2, minLen);
        const samePrefix = normToken.slice(0, prefixLen) === brandToken.slice(0, prefixLen);
        const lenDiff = Math.abs(normToken.length - brandToken.length);

        const isTypoMatch = brandToken.length < 6
          ? (dist === 1 && lenDiff <= 1 && samePrefix)
          : (dist > 0 && dist <= 2 && lenDiff <= 2 && samePrefix);

        if (isTypoMatch) {
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
      const matchesSld = brandToken.length < 5
        ? (tokens.includes(brandToken) || sld === brandToken || sld.startsWith(brandToken + "-") || sld.endsWith("-" + brandToken))
        : sld.includes(brandToken);

      if (matchesSld && !isOfficialDomain(unicodeHost, target.officialDomains)) {
        const isLure = PHISHING_COMBO_LURES.some((kw) => sld.includes(kw));
        const isBadTld = HIGH_RISK_TLDS.has(tld);
        if (isLure || isBadTld || !unicodeHost.endsWith(".et") || brandToken.length >= 6) {
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
  if (!host || isTrustedDomain(host)) return { isTypo: false, reason: "", score: 0 };

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

// Threat Intelligence Database (OpenPhish Community Feed & Verified IOCs)
const SEED_THREAT_DOMAINS = [
  "022222222z222234.vercel.app",
  "12z2zas.pages.dev",
  "3658993.cc",
  "3865nx-61wkw-c63-1gh-e9dci.pages.dev",
  "9000-firebase-mneeee-1780309173719.cluster-l2bgochoazbomqgfmlhuvdvgiy.cloudworkstations.dev",
  "9dp7mj.7773653.com",
  "accountactivationsecurityteam.vercel.app",
  "allegrolokalnie.nr-h2n-8sn4-sn23.sbs",
  "aminu-gal-expenses.netlify.app",
  "anz-internetbanking.blogspot.com",
  "appar24linetop-clean.duckdns.org",
  "apps-upheld.teleporthq.app",
  "ar-netflix-clone.vercel.app",
  "ar24security-3920b0.gitlab.io",
  "atatmyaccount.blogspot.com",
  "authenticateuseridentity.vercel.app",
  "b00j6-ec8l0f-kv2u-vfpn-tn4.pages.dev",
  "bankofamerica-login.vercel.app",
  "bervani-kxt-felmora-p7t2hk48.pages.dev",
  "bigb-omega.vercel.app",
  "bmktp2bpzgo-pjlgzlsi-7h6g0b-bmk90c.pages.dev",
  "bridge-browser.framer.website",
  "casinobet365gr-com.pages.dev",
  "central-crimson-l5ks1k8d.edgeone.dev",
  "cerruiops.click",
  "chatbox-verify-supportupgrade.vercel.app",
  "comcast-2-iota.vercel.app",
  "comcast-seven.vercel.app",
  "comcastmaileroauthes.weebly.com",
  "confiraachadodalu.com",
  "cont17ct-felra-biz-qurvi-donex.pages.dev",
  "cont17ct-moveka-biz-zurel-pavri.pages.dev",
  "cont17ct-pavari-biz-kemul-zorta.pages.dev",
  "correors.qpon",
  "credits-community.xyz",
  "damp-wildflower-8190.scannedfilles.workers.dev",
  "dbs-secure.vercel.app",
  "dbs.swis.blog",
  "descontosdesenrolar26.shop",
  "detaillogs.servicecostumenr-8998we7hr.crabdance.com",
  "digital-assets.top",
  "edevlet.vatandasgiris.org",
  "elbrushome.hostel.town",
  "es-empresas.cc",
  "f005.backblazeb2.com",
  "f76.hkwordpress.com",
  "facebook-clone-git-main-taha-sirajs-projects.vercel.app",
  "facebooknenys.blogspot.com",
  "fseryy.pages.dev",
  "g5.lu",
  "gemini-login-b.webflow.io",
  "gemini.alybot.dpdns.org",
  "gemini.anzerio.ddns.net",
  "geminii-logen.gitbook.io",
  "get-ledgerlive-desktop-us.pages.dev",
  "giveshopee33.blogspot.com",
  "grade.us",
  "gray-beach-0fc576a03.4.azurestaticapps.net",
  "h13l-ef4x8l-t94092-h505a3.pages.dev",
  "hanm.vercel.app",
  "help-trezzerwallet.gitbook.io",
  "help8877999.vercel.app",
  "hight2210-tfjnutpk.4everland.app",
  "hlgf400lkwg-zktp2plx-9n0n4g-hlg66w.pages.dev",
  "hlgf488lkwg-zktp2plx-9n8n5g-hlg17w.pages.dev",
  "index-catty-neww.vercel.app",
  "index-newproject.vercel.app",
  "indexxjjo.vercel.app",
  "infobcl.site",
  "information-meridian-digest.s2504002.workers.dev",
  "instabest.vercel.app",
  "instagram-clone-olive-five.vercel.app",
  "instagramlogin68.blogspot.com",
  "instagramlogin99.blogspot.com",
  "ioledger-wa.pages.dev",
  "ivana-alawi-bmw-f30.blogspot.com",
  "jedibguylu.github.io",
  "jke3s-z23-zzzs-83azk-05-10-2026-aa.pages.dev",
  "jvillalobos.com",
  "kaushaltiwariweb.github.io",
  "kleinanzeigen-verify.website",
  "kukcoin-jlogi6.godaddysites.com",
  "ledger-live-downloadd.pages.dev",
  "lfax-y8p8-5gbqr3-l2gc4j-89bu.pages.dev",
  "live-ledgrs.pages.dev",
  "lk.1x-bet.mobi",
  "lnk.ink",
  "logine-orang.vercel.app",
  "manoharchary.github.io",
  "marlavi-kxt-belfeta-c5x7dp83.pages.dev",
  "merrill-edge.vercel.app",
  "metamask-docs-75mpj2s96-consensys-ddffed67.vercel.app",
  "metamask.walletportal.app",
  "milevwinery.com",
  "moon-go-shop.pages.dev",
  "moonpay-commerce-ijsgokz66-heliofi.vercel.app",
  "moonpay-paybox-guide.vercel.app",
  "mteamasklogxin.gitbook.io",
  "murvik-tensha-e4a8d1-gb1504hh-h2406wne.pages.dev",
  "mvrn8625nhw-hlgf4fyn-5q0p2g-zk166a.pages.dev",
  "my-account-netfilx.com",
  "my-instagram-frontend.vercel.app",
  "my-top-juno-webmail-site.webflow.io",
  "mydpd.audjd.cc",
  "mydpd.jdevr.xyz",
  "mygeminiloignz.gitbook.io",
  "myjunoupdatenow.framer.website",
  "mypmgrca-dpq4xiqwj2ki.edgeone.dev",
  "navyaparakh17.github.io",
  "nervoro-kxt-zanvori-c6x5fc79.pages.dev",
  "net16ct-zavo-biz-melu-noki.pages.dev",
  "netflix-clone-olive-delta.vercel.app",
  "netflix-upgraded-clone.vercel.app",
  "new-indexproject.vercel.app",
  "newww-lo1dpfdfiles.vercel.app",
  "nj4cdk.7773653.com",
  "norzavi-kxt-belfeta-c8x5hq42.pages.dev",
  "overview--en--trzer-en.typedream.app",
  "pdf-viewer-five-virid.vercel.app",
  "poderema.teye.xyz",
  "premium.spotfi.eu",
  "proboss.be",
  "project-0mgdh.vercel.app",
  "psyki-1.github.io",
  "pyuqk5.id8954388.shop",
  "q9jvx5-mw6e-xse-set-jyz-8in5i.pages.dev",
  "qavfari-mpt-xelzoro-k6d3pe95.pages.dev",
  "qbxj52b68dr-ywsd7pli-3n4l8g-qbx29c.pages.dev",
  "qbxj54avstr-hlgf4mja-3q2p4g-qbx03c.pages.dev",
  "qbxj552skrp-ywsd7yw-3p6p0e-qbx99c.pages.dev",
  "qbxj572lowi-ywsd7yw-3n4m1g-qbx13c.pages.dev",
  "qg4u9y.id8954388.shop",
  "qjrsh83-vnxld104vzk-0o5n7g-mkg28.pages.dev",
  "qkjwejkqwq1231.duckdns.org",
  "ql3e20-jmpl91-61tvz-re4o8.pages.dev",
  "qorlixva-mek572918463.vercel.app",
  "quitarhojecomdesconto.shop",
  "r.oblox.com.et",
  "repairing.game-en.com",
  "resource-pathway-briefing.s2503998.workers.dev",
  "resource-perspective-hub.s2503959.workers.dev",
  "ritzcarltonmilleniasingapore.spahotel.guru",
  "roblox.com.am",
  "roblox.com.bi",
  "roblox.com.ml",
  "roblox.com.pt",
  "roblox.et",
  "roblox.ly",
  "roblox.ss",
  "sahilkubal007.github.io",
  "santander-inicio.vercel.app",
  "schwarzteam.eu",
  "scp-comunicaciones.com",
  "securityawareness.office-teams.net",
  "seller.wefe.cc",
  "share-edge-og1u.p-4bpdi3hp.workers.dev",
  "skinsaway.lol",
  "sleepdynamics-9sd7f2n.web.app",
  "sopping-17.blogspot.com",
  "sp10ct10-cavnek-biz-vuleri.pages.dev",
  "sp11ct-ravlen-biz8-hesvik-zormek.pages.dev",
  "sp11ct-venlor-biz8-kormik-frasel.pages.dev",
  "sp12ct-frador-biz-kelsik-vormel.pages.dev",
  "sp14ct-dorsel-biz-hovrik-zarnem.pages.dev",
  "sp15ct-zavqor-biz-kelun-mavix.pages.dev",
  "sp18ct10-wulvak-biz-qenari.pages.dev",
  "sp1ct10-helrek-biz-rumzo-zemti.pages.dev",
  "sp1ct10-hurrek-biz-rumzo-vemti-c0w.pages.dev",
  "sp20ct10-korvemo-biz-lunati.pages.dev",
  "sp20ct10-mavrevo-biz-zunali.pages.dev",
  "sp20ct10-morlevo-biz-taniku.pages.dev",
  "sp20ct10-morvako-biz-zelumi.pages.dev",
  "sp20ct10-morviko-biz-zanetu.pages.dev",
  "sp20ct10-narviro-biz-zumeko.pages.dev",
  "sp20ct10-ravleto-biz-munaki.pages.dev",
  "sp20ct10-vemrilo-biz-zaneku.pages.dev",
  "sp20ct10-zanlevo-biz-murati.pages.dev",
  "sp24ct-nelo-biz-kavor-muki.pages.dev",
  "sp25ct-melko-biz-vurani-tekza.pages.dev",
  "sp25ct-tavuri-biz-zemalo-koren.pages.dev",
  "sp25ct-velora-biz-zaneki-murul.pages.dev",
  "sp25ct-zunelo-biz-mareku-vorik.pages.dev",
  "sp26ct-murvo-biz-kelma-pesro.pages.dev",
  "sp26ct-zumki-biz-rulen-mavko.pages.dev",
  "sp26ct10-davmelo-biz-kunati.pages.dev",
  "sp26ct10-kavlemi-biz-dunavo.pages.dev",
  "sp26ct10-kavmelo-biz-turani.pages.dev",
  "sp26ct10-kavzelo-biz-rumani.pages.dev",
  "sp26ct10-melvemi-biz-dunaro.pages.dev",
  "sp26ct10-ravzuni-biz-kelavo.pages.dev",
  "sp26ct10-rumlevo-biz-zunati.pages.dev",
  "sp26ct10-rumrako-biz-lumeni.pages.dev",
  "sp26ct10-rumveko-biz-taluni.pages.dev",
  "sp26ct10-velvako-biz-kumari.pages.dev",
  "sp26ct10-vemvako-biz-zureno.pages.dev",
  "sp26ct10-vemzelo-biz-kanuri.pages.dev",
  "sp26ct10-zanleko-biz-vuremi.pages.dev",
  "sp26ct10-zulvako-biz-taremi.pages.dev",
  "sp28ct-bulem-biz-qazev-zotek.pages.dev",
  "sp28ct-dunav-biz-zorel-qatek.pages.dev",
  "sp28ct-dureq-biz-qamel-ranek.pages.dev",
  "sp28ct-fanur-biz-qozem-vitek.pages.dev",
  "sp28ct-farel-biz-vumel-zitek.pages.dev",
  "sp28ct-garem-biz-zumel-qitek.pages.dev",
  "sp28ct-gazur-biz-zemav-vitek.pages.dev",
  "sp28ct-gunem-biz-zorel-ranek.pages.dev",
  "sp28ct-karel-biz-vuzem-zonak.pages.dev",
  "sp28ct-murev-biz-qazun-zolek.pages.dev",
  "sp28ct-vunor-biz-qalem-zirek.pages.dev",
  "sp30ct-tazul-biz-rovex-nalik.pages.dev",
  "sp30ct-vorak-biz-kemix-zulon.pages.dev",
  "sp31ct-zunemi-biz-kavlo-pured.pages.dev",
  "spf777.com.mx",
  "sso-uphouldcdn.teleporthq.app",
  "start-t-trrezzero.gitbook.io",
  "stayokaydenhaag.hostel.town",
  "steamcommuminty.cam",
  "steamcommvnlty.com",
  "strong-auth.cyou",
  "supriyavishwakarma.github.io",
  "system-settings-account-toppro.vercel.app",
  "taskerx.800876.xyz",
  "tenant-data.help",
  "terquna-kxt-felmavi-p9t4fc27.pages.dev",
  "the-gemini-protocol.pages.dev",
  "tokanim-cdn16-hk16.club",
  "tokanim-cdn35-hk08.homes",
  "tokemim-cdn34-hk34.club",
  "tokinim-cdn41-hk41.club",
  "tokinix-cdn21-hk21.club",
  "tooodo.vercel.app",
  "trezorbridge.framer.website",
  "trust-wallet-login.vercel.app",
  "trustsenderbyfrt.vercel.app",
  "tusmo.so",
  "txorliva-kext927461835.vercel.app",
  "ubu-two.vercel.app",
  "ue8471.craftum.io",
  "upc-websrv-service-web-clean.weebly.com",
  "upload.thenxtsmp.net",
  "uq6189.craftum.io",
  "user-fabiof.flazio.online",
  "validacion2026.yzz.me",
  "varneta-kxt-qervani-c2x7dw85.pages.dev",
  "velunoraglobalcartmarket2.top",
  "velunoraglobalcartmarket3.top",
  "velunoraglobalcartmarket4.top",
  "verication-casefb368-olive.vercel.app",
  "verication-casefb3681-three.vercel.app",
  "vip-spinradar.click",
  "vnxld62mjwr-mkgptrel-0n1m3g-yl299a.pages.dev",
  "vnxld71dran-ylktp55lpw-1m3k8d-qj2294m.pages.dev",
  "vnxld72cqjr-ylktp64ylk-0q4n2d-bcf51t.pages.dev",
  "vs4539876-glitch.github.io",
  "vwwv-roblox.co",
  "webdisket-g7dvffckcxbxgsfq.westus3-01.azurewebsites.net",
  "webmail-oauth.lygrunfeng.com",
  "webmail-service-xfinity.vercel.app",
  "webs-serv-hisp-eed-ch.weebly.com",
  "whatsapp-indonesia877.blogspot.com",
  "www-chase-com.csy-launcher.com",
  "wzq04.vercel.app",
  "xavfelo-mpt-qurmani-r2d9ka765.pages.dev",
  "xxxffinityccomcasst.weebly.com",
  "yay.snj.mycrazydomains.me",
  "ywsd7220bf-qbxj5skr-7q4l1g-ywsq05c.pages.dev",
  "ywsd77agpxo-qbxj5mja-7r0p2c-ywsq96c.pages.dev",
  "zd.lc",
  "zktp25c80sk-mvrn8wur-1r6p8d-yw611a.pages.dev",
  "zktp26b20sk-mvrn8wur-1r0p2d-yw788a.pages.dev",
  "zktp27e52dr-ywsd7lpw-1n6l4d-yw699a.pages.dev",
  "zktp28fdran-ywsd7lpw-1n4l6d-yw288a.pages.dev"
];

const KNOWN_THREAT_DOMAINS = new Set(SEED_THREAT_DOMAINS);

function initThreatDatabase(domains) {
  if (Array.isArray(domains)) {
    domains.forEach((d) => {
      const clean = (d || "").trim().toLowerCase().replace(/^www\./, "");
      if (clean) KNOWN_THREAT_DOMAINS.add(clean);
    });
  }
}

function isKnownThreatDomain(host) {
  if (!host) return false;
  const clean = host.toLowerCase().replace(/^www\./, "");
  if (KNOWN_THREAT_DOMAINS.has(clean)) return true;
  const parts = clean.split(".");
  for (let i = 1; i < parts.length - 1; i++) {
    const parent = parts.slice(i).join(".");
    if (KNOWN_THREAT_DOMAINS.has(parent)) return true;
  }
  return false;
}

/**
 * Comprehensive Page-Level Safety Evaluation
 */
function evaluatePageSafety(doc = document, host = window.location.hostname, url = window.location.href, trustedDomains = []) {
  const flags = [];
  let score = 0;
  const cleanHost = (host || "").toLowerCase().replace(/^www\./, "");

  // 1. Check user trusted domains and authenticated ecosystem domains
  const isEcosystemTrusted = isTrustedDomain(cleanHost);
  const isUserTrusted = Array.isArray(trustedDomains) && trustedDomains.some((d) => cleanHost === d || cleanHost.endsWith("." + d));

  if (isUserTrusted || isEcosystemTrusted) {
    if (!checkMixedScriptAndHomograph(cleanHost).isHomograph && !isIpAddress(cleanHost)) {
      return {
        status: "safe",
        riskScore: 0,
        flags: [],
        isTrusted: true,
        host: cleanHost,
        url
      };
    }
  }

  // 1b. Check Verified Threat Intelligence Database (OpenPhish / Community IOCs)
  if (isKnownThreatDomain(cleanHost)) {
    return {
      status: "dangerous",
      riskScore: 100,
      flags: [`Confirmed phishing domain matched in Threat Intelligence Database (OpenPhish: ${cleanHost})`],
      host: cleanHost,
      url,
      isTrusted: false,
      isThreatDatabaseMatch: true
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

  // 1b. Check Verified Threat Intelligence Database (OpenPhish / Community IOCs)
  const cleanLinkHost = (host || "").toLowerCase().replace(/^www\./, "");
  if (isKnownThreatDomain(cleanLinkHost)) {
    return {
      isPhishing: true,
      riskScore: 100,
      host,
      url: parsedUrl.href,
      flags: [`Confirmed phishing destination matched in Threat Intelligence Database (OpenPhish: ${cleanLinkHost})`],
      isThreatDatabaseMatch: true
    };
  }

  // 1c. Structural Checks: Homograph Attacks, Raw IPs, Authority Credentials
  const homograph = checkMixedScriptAndHomograph(host);
  if (homograph.isHomograph) {
    score += homograph.score;
    flags.push(homograph.reason);
  }

  if (isIpAddress(host)) {
    score += 75;
    flags.push(`Raw IP address hostname used (${host})`);
  }

  if (parsedUrl.username || parsedUrl.password) {
    score += 80;
    flags.push("URL contains embedded credentials/hostname spoofing via authority '@'");
  }

  // 1d. Authenticated Trusted Ecosystem Domains (meta.com, google.com, github.com, etc.)
  if (isTrustedDomain(cleanLinkHost) && !homograph.isHomograph && !parsedUrl.username && !parsedUrl.password) {
    const anchorText = anchorEl ? anchorEl.innerText || anchorEl.textContent || "" : "";
    const mismatchResult = checkAnchorTextMismatch(anchorText, parsedUrl, currentHost);
    if (mismatchResult.isMismatch) {
      return {
        isPhishing: true,
        riskScore: 75,
        host,
        url: parsedUrl.href,
        flags: [mismatchResult.reason]
      };
    }
    return {
      isPhishing: false,
      riskScore: 0,
      host,
      url: parsedUrl.href,
      flags: [],
      isTrusted: true
    };
  }

  // 2. Ethiopian Brand Lookalikes
  const ethiopianLookalike = checkEthiopianBrandLookalike(host);
  if (ethiopianLookalike.isLookalike) {
    score += ethiopianLookalike.score;
    flags.push(ethiopianLookalike.reason);
  }

  // 3. Deceptive Anchor Text Mismatch
  const anchorText = anchorEl ? anchorEl.innerText || anchorEl.textContent || "" : "";
  const mismatchResult = checkAnchorTextMismatch(anchorText, parsedUrl, currentHost);
  if (mismatchResult.isMismatch) {
    score += 75;
    flags.push(mismatchResult.reason);
  }

  // 4. Global Typosquatting
  const typoResult = checkGlobalTyposquatting(host);
  if (typoResult.isTypo) {
    score += typoResult.score;
    flags.push(typoResult.reason);
  }

  // 5. Shortlink Detection
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
  isTrustedDomain,
  TRUSTED_DOMAINS,
  isIpAddress,
  checkEthiopianBrandLookalike,
  checkMixedScriptAndHomograph,
  checkGlobalTyposquatting,
  checkAnchorTextMismatch,
  checkAmharicCredentialScamInForms,
  evaluatePageSafety,
  evaluateLinkSafety,
  initThreatDatabase,
  isKnownThreatDomain,
  KNOWN_THREAT_DOMAINS,
  ETHIOPIAN_TARGETS,
  AMHARIC_SCAM_PHRASES
};

if (typeof window !== "undefined") {
  window.PhishShieldHeuristics = PhishShieldHeuristics;
}
if (typeof globalThis !== "undefined") {
  globalThis.PhishShieldHeuristics = PhishShieldHeuristics;
}
