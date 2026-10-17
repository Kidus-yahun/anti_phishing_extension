/**
 * PhishShield AI - Internationalization (i18n) Engine
 * Full bilingual support (English & Amharic) with auto-detection and runtime toggle.
 */

(() => {
  const DICTIONARY = {
    en: {
      appName: "PhishShield AI - Real-Time Phishing Protection",
      appDesc: "Real-time browser guardian detecting phishing links, Ethiopian bank lookalikes, homograph attacks, and credential scams.",
      statusSafeTitle: "Current Tab is Safe",
      statusSafeDesc: "No phishing links, homographs, or credential harvesting detected.",
      statusSuspiciousTitle: "Suspicious Activity Detected",
      statusSuspiciousDesc: "Potential risk indicators or unverified links found on this page.",
      statusDangerousTitle: "Dangerous Threat Blocked!",
      statusDangerousDesc: "High-risk phishing, brand impersonation, or credential scam detected.",
      statusPausedTitle: "Protection is Paused",
      statusPausedDesc: "Real-time link scanning, warnings, and blockers are currently turned off.",
      statSitesChecked: "Sites Checked",
      statThreatsBlocked: "Threats Blocked",
      statBlockedOnTab: "Blocked on Tab",
      statTotalBlocked: "Total Blocked",
      whyFlagged: "Why was this flagged?",
      whySafe: "Why is this safe?",
      noThreatsFound: "All analyzed links and page structural elements are verified safe.",
      overlayTitleDanger: "Security Warning: Phishing / Deceptive Site Detected",
      overlayTitleWarning: "Caution: Suspicious Website Flagged",
      overlayDesc: "PhishShield AI detected that this destination appears to be a social engineering attack designed to harvest passwords, banking PINs, or personal data.",
      btnGoBack: "Go back (Recommended)",
      btnProceedAnyway: "Proceed anyway (Unsafe)",
      btnTrustSite: "Trust this site",
      siteTrustedNotice: "This site was added to your trusted domains list.",
      tooltipDestination: "Destination:",
      tooltipExpandsTo: "Expands to:",
      tooltipStatusSafe: "Safe Destination",
      tooltipStatusSuspicious: "Suspicious Link",
      tooltipStatusDangerous: "Dangerous Phishing Link",
      badgePhishing: "PHISHING LINK: DO NOT TOUCH",
      badgeSuspicious: "SUSPICIOUS LINK",
      openDashboard: "Open Threat Dashboard",
      testLab: "Test Lab",
      langToggle: "አማርኛ",
      trustedDomain: "Trusted Domain",
      confirmProceed: "DANGER: Are you sure you want to visit this flagged site? Your accounts and credentials may be compromised.",

      // Detection Reasons
      telebirrLookalike: "Telebirr lookalike domain detected (Levenshtein distance match)",
      cbeLookalike: "Commercial Bank of Ethiopia (CBE) lookalike domain detected",
      awashLookalike: "Awash Bank lookalike domain detected",
      dashenLookalike: "Dashen Bank lookalike domain detected",
      ethiocomeLookalike: "Ethio Telecom lookalike domain detected",
      safaricomLookalike: "Safaricom Ethiopia lookalike domain detected",
      amharicCredentialScam: "Urgent Amharic credential harvesting scam phrase near login/payment form",
      mixedScriptAttack: "Mixed-script homograph spoofing (Ethiopic and Latin scripts mixed)",
      punycodeSpoof: "Punycode domain spoofing detected (IDN homograph attack)",
      ipAddressHost: "Raw IP address hostname used instead of legitimate domain",
      embeddedAuth: "URL contains embedded credentials/hostname spoofing via authority '@'",
      anchorMismatch: "Deceptive link: Display text claims a different domain than real destination",
      brandTyposquatting: "Deceptive typosquatting: Brand spoofed using character substitutions",
      combosquatting: "Combosquatting attack: Impersonating brand paired with lure keywords",
      shortlinkDetected: "Shortened link hiding real destination domain",
      highRiskTld: "Domain registered on high-risk suspicious top-level domain (TLD)"
    },
    am: {
      appName: "ፊሽሺልድ AI - የእውነተኛ ጊዜ የፊሺንግ ጥበቃ",
      appDesc: "አደገኛ የማጭበርበሪያ ድረ-ገጾችን፣ የኢትዮጵያ ባንኮችን እና የቴሌብር አስመሳይ አድራሻዎችን በእውነተኛ ጊዜ የሚከላከል ዘመናዊ የደህንነት ስርዓት።",
      statusSafeTitle: "የአሁኑ ገጽ ደህንነቱ የተጠበቀ ነው",
      statusSafeDesc: "ምንም ዓይነት የፊሺንግ ወይም የተጭበረበረ አድራሻ አልተገኘም።",
      statusSuspiciousTitle: "አጠራጣሪ እንቅስቃሴ ተገኝቷል",
      statusSuspiciousDesc: "በዚህ ገጽ ላይ አጠራጣሪ ወይም ያልተረጋገጡ አገናኞች ተገኝተዋል።",
      statusDangerousTitle: "አደገኛ አደጋ ተከስቷል!",
      statusDangerousDesc: "ከፍተኛ አደጋ ያለው የማጭበርበሪያ ወይም የይለፍ ቃል ሌብነት ሙከራ ተገኝቷል።",
      statusPausedTitle: "ጥበቃው ለጊዜው ቆሟል",
      statusPausedDesc: "የእውነተኛ ጊዜ አገናኝ ምርመራ እና ማስጠንቀቂያዎች ጠፍተዋል።",
      statSitesChecked: "የተመረመሩ ገጾች",
      statThreatsBlocked: "የተከለከሉ አደጋዎች",
      statBlockedOnTab: "በዚህ ገጽ የተከለከሉ",
      statTotalBlocked: "በአጠቃላይ የተከለከሉ",
      whyFlagged: "ይህ ገጽ ለምን ተጠረጠረ?",
      whySafe: "ይህ ገጽ ለምን አስተማማኝ ሆነ?",
      noThreatsFound: "ሁሉም የተፈተሹ አገናኞች እና የገጹ አወቃቀሮች ደህንነታቸው የተጠበቀ ነው።",
      overlayTitleDanger: "የደህንነት ማስጠንቀቂያ፡ አደገኛ የማጭበርበሪያ ድረ-ገጽ ተገኝቷል",
      overlayTitleWarning: "ጥንቃቄ፡ አጠራጣሪ ድረ-ገጽ ተገኝቷል",
      overlayDesc: "ይህ ድረ-ገጽ የባንክ ሚስጥር ቁጥሮችን፣ የቴሌብር ፒን ወይም የግል መረጃዎችን ለመስረቅ የተዘጋጀ አደገኛ የማጭበርበሪያ ገጽ መሆኑን ፊሽሺልድ AI ደርሶበታል።",
      btnGoBack: "ወደ ኋላ ተመለስ (ይመከራል)",
      btnProceedAnyway: "አደጋውን አውቃለሁ፣ ቀጥል (አደገኛ)",
      btnTrustSite: "ይህንን ድረ-ገጽ እመነው",
      siteTrustedNotice: "ይህ ድረ-ገጽ ወደ ታማኝ ድረ-ገጾች ዝርዝርዎ ውስጥ ገብቷል።",
      tooltipDestination: "ትክክለኛ መድረሻ:",
      tooltipExpandsTo: "የሚያመራው ወደ:",
      tooltipStatusSafe: "አስተማማኝ መድረሻ",
      tooltipStatusSuspicious: "አጠራጣሪ አገናኝ",
      tooltipStatusDangerous: "አደገኛ የማጭበርበሪያ አገናኝ",
      badgePhishing: "የማጭበርበሪያ አገናኝ፡ አይንኩት",
      badgeSuspicious: "አጠራጣሪ አገናኝ",
      openDashboard: "የደህንነት ዳሽቦርድ ክፈት",
      testLab: "የሙከራ ላብ",
      langToggle: "English",
      trustedDomain: "የታመነ ድረ-ገጽ",
      confirmProceed: "ማስጠንቀቂያ፡ ይህ ገጽ አደገኛ የማጭበርበሪያ ገጽ እንደሆነ ተረጋግጧል። የግል መረጃዎ ወይም የይለፍ ቃልዎ ሊሰረቅ ይችላል። በእርግጥ መቀጠል ይፈልጋሉ?",

      // Detection Reasons
      telebirrLookalike: "የቴሌብርን (Telebirr) ስም የሚያስመስል አድራሻ ተገኝቷል",
      cbeLookalike: "የኢትዮጵያ ንግድ ባንክን (CBE) የሚያስመስል የተጭበረበረ አድራሻ ተገኝቷል",
      awashLookalike: "የአዋሽ ባንክን (Awash Bank) ስም የሚያስመስል አድራሻ ተገኝቷል",
      dashenLookalike: "የዳሽን ባንክን (Dashen Bank) ስም የሚያስመስል አድራሻ ተገኝቷል",
      ethiocomeLookalike: "የኢትዮ ቴሌኮምን (Ethio Telecom) የሚያስመስል አድራሻ ተገኝቷል",
      safaricomLookalike: "የሳፋሪኮም ኢትዮጵያን (Safaricom) የሚያስመስል አድራሻ ተገኝቷል",
      amharicCredentialScam: "በመግቢያ ወይም በክፍያ ፎርም አጠገብ አደገኛ የአማርኛ የማጭበርበሪያ ቃላት ተገኝተዋል",
      mixedScriptAttack: "የተቀላቀለ ፊደል (የግዕዝ እና ላቲን) የማስመሰል ጥቃት ተገኝቷል",
      punycodeSpoof: "የፑኒኮድ (Punycode) የተጭበረበረ አድራሻ ተገኝቷል",
      ipAddressHost: "ከእውነተኛ ድረ-ገጽ ስም ይልቅ ያልተለመደ የቁጥር አድራሻ (IP address) ተጠቅሟል",
      embeddedAuth: "አገናኙ አድራሻን ለማጭበርበር የተከተተ የይለፍ ቃል ወይም '@' ምልክት አለው",
      anchorMismatch: "የተጭበረበረ አገናኝ፡ በጽሁፉ ላይ የሚታየው ስም እና ትክክለኛው መድረሻ አይገናኙም",
      brandTyposquatting: "የታወቁ ተቋማትን ስም በፊደል ግድፈት በማስመሰል የተፈጠረ የማጭበርበሪያ አድራሻ",
      combosquatting: "የተቋሙን ስም ከማታለያ ቃላት ጋር በማጣመር የተፈጠረ የማጭበርበሪያ አድራሻ",
      shortlinkDetected: "ትክክለኛውን መድረሻ የሚደብቅ አጭር አገናኝ ተገኝቷል",
      highRiskTld: "ለማጭበርበር በብዛት በሚጠቀሙ አደገኛ የዶሜይን መጨረሻዎች የተመዘገበ አድራሻ"
    }
  };

  /**
   * Check if a string contains Ethiopic Unicode characters (U+1200 - U+137F)
   */
  function hasEthiopicText(text) {
    if (!text || typeof text !== "string") return false;
    return /[\u1200-\u137F]/.test(text);
  }

  /**
   * Detect if the current document is an Amharic page
   */
  function isAmharicPage(doc = document) {
    if (!doc) return false;

    // 1. Check HTML lang attribute
    const htmlLang = (doc.documentElement && doc.documentElement.lang) || "";
    if (htmlLang.toLowerCase().startsWith("am")) return true;

    // 2. Check title
    if (doc.title && hasEthiopicText(doc.title)) return true;

    // 3. Check sample text density in headings and paragraphs
    const sampleElements = doc.querySelectorAll("h1, h2, h3, p, form, label");
    let ethiopicMatches = 0;
    for (let i = 0; i < Math.min(sampleElements.length, 15); i++) {
      if (hasEthiopicText(sampleElements[i].textContent)) {
        ethiopicMatches++;
        if (ethiopicMatches >= 2) return true;
      }
    }

    return false;
  }

  /**
   * Resolve active language: user override > auto-detected page language > browser locale
   */
  async function resolveLanguage(doc = (typeof document !== "undefined" ? document : null)) {
    try {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        const stored = await chrome.storage.local.get("userLanguage").catch(() => ({}));
        if (stored.userLanguage === "am" || stored.userLanguage === "en") {
          return stored.userLanguage;
        }
      }
    } catch (e) {}

    if (doc && isAmharicPage(doc)) {
      return "am";
    }

    if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getUILanguage) {
      const uiLang = chrome.i18n.getUILanguage();
      if (uiLang.toLowerCase().startsWith("am")) return "am";
    }

    return "en";
  }

  /**
   * Translate a key into the given or default language
   */
  function t(key, lang = "en") {
    const l = lang === "am" ? "am" : "en";
    if (DICTIONARY[l] && DICTIONARY[l][key]) {
      return DICTIONARY[l][key];
    }
    if (DICTIONARY.en && DICTIONARY.en[key]) {
      return DICTIONARY.en[key];
    }
    // Fallback to chrome.i18n if available
    if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getMessage) {
      const msg = chrome.i18n.getMessage(key);
      if (msg) return msg;
    }
    return key;
  }

  /**
   * Translate a detection reason string or reason object
   */
  function translateReason(reason, lang = "en") {
    if (!reason) return "";
    if (typeof reason === "object" && reason.i18nKey) {
      return t(reason.i18nKey, lang);
    }

    const str = String(reason);

    // Map common heuristic phrases to localized keys
    if (str.includes("Telebirr") || str.includes("telebirr")) return t("telebirrLookalike", lang);
    if (str.includes("Commercial Bank of Ethiopia") || str.includes("CBE") || str.includes("cbe")) return t("cbeLookalike", lang);
    if (str.includes("Awash") || str.includes("awash")) return t("awashLookalike", lang);
    if (str.includes("Dashen") || str.includes("dashen")) return t("dashenLookalike", lang);
    if (str.includes("Ethio Telecom") || str.includes("ethiotelecom")) return t("ethiocomeLookalike", lang);
    if (str.includes("Safaricom") || str.includes("safaricom")) return t("safaricomLookalike", lang);
    if (str.includes("Amharic credential") || str.includes("harvesting") || hasEthiopicText(str)) return t("amharicCredentialScam", lang);
    if (str.includes("Mixed-script") || str.includes("mixed-script") || str.includes("Ethiopic")) return t("mixedScriptAttack", lang);
    if (str.includes("Punycode") || str.includes("punycode") || str.includes("Homograph")) return t("punycodeSpoof", lang);
    if (str.includes("IP address") || str.includes("ip address")) return t("ipAddressHost", lang);
    if (str.includes("authority") || str.includes("@")) return t("embeddedAuth", lang);
    if (str.includes("mismatch") || str.includes("Display text claims")) return t("anchorMismatch", lang);
    if (str.includes("Typosquatting") || str.includes("typosquatting")) return t("brandTyposquatting", lang);
    if (str.includes("Combosquatting") || str.includes("combosquatting")) return t("combosquatting", lang);
    if (str.includes("Shortened") || str.includes("shortlink")) return t("shortlinkDetected", lang);
    if (str.includes("TLD") || str.includes("high-risk")) return t("highRiskTld", lang);

    return str;
  }

  const PhishShieldI18n = {
    DICTIONARY,
    hasEthiopicText,
    isAmharicPage,
    resolveLanguage,
    t,
    translateReason
  };

  if (typeof window !== "undefined") {
    window.PhishShieldI18n = PhishShieldI18n;
  }
  if (typeof globalThis !== "undefined") {
    globalThis.PhishShieldI18n = PhishShieldI18n;
  }
})();
