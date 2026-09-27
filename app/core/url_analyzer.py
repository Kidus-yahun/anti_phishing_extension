import re
from urllib.parse import urlparse
import unicodedata

# Major trusted platform ecosystems (authentic domains and sub-services)
TRUSTED_DOMAINS = {
    # Google / Alphabet
    "google.com", "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com",
    "gmail.com", "googleapis.com", "gstatic.com", "googletagmanager.com", "googleusercontent.com",
    "google-analytics.com", "android.com", "chrome.com",

    # GitHub & Developer Ecosystem
    "github.com", "github.io", "githubstatus.com", "githubassets.com", "githubusercontent.com",
    "github.community", "github.dev", "gh.io", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "stackexchange.com", "npmjs.com", "pypi.org", "python.org",
    "mozilla.org", "w3.org",

    # Microsoft
    "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com", "bing.com",
    "microsoftonline.com", "microsoftteams.com", "azure.com", "visualstudio.com",
    "windows.com", "msn.com", "skype.com", "xbox.com", "azureedge.net",

    # Apple
    "apple.com", "icloud.com", "appleid.apple.com", "itunes.com", "cdn-apple.com",

    # Amazon
    "amazon.com", "aws.amazon.com", "amazonaws.com", "amazonpay.com", "media-amazon.com", "primevideo.com",

    # Meta
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com", "messenger.com", "fbcdn.net",

    # Social & Media
    "twitter.com", "x.com", "t.co", "twimg.com", "linkedin.com", "licdn.com",
    "reddit.com", "redditstatic.com", "netflix.com", "nflxext.com", "spotify.com", "scdn.co",
    "twitch.tv", "discord.com", "discord.gg", "discordapp.com", "discordstatus.com",
    "telegram.org", "t.me",

    # Security, Infrastructure & Services
    "steamcommunity.com", "steampowered.com", "steamstatic.com",
    "cloudflare.com", "cloudflarestatus.com", "statuspage.io",
    "openai.com", "chatgpt.com", "wikipedia.org", "wikimedia.org", "medium.com"
}

# Target popular brands for typosquatting check
POPULAR_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", 
    "netflix", "bankofamerica", "chase", "wellsfargo", "github", 
    "linkedin", "dropbox", "binance", "coinbase", "instagram", "twitter"
]

SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "work", "click", "zip", "mov", "cc", "ru",
    "country", "kim", "science", "gq", "cf", "tk", "ml", "ga"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "goo.gl", "tiny.cc", "rb.gy", "cutt.ly"
}

SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "update", "account", "banking", "confirm", "credential", "billing",
    "password", "wallet", "authenticate", "auth", "portal"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class URLAnalyzer:
    """Heuristic and structural analyzer for detecting phishing URLs."""

    @classmethod
    def is_trusted_domain(cls, host: str) -> bool:
        """Check if hostname belongs to an authenticated trusted ecosystem."""
        if not host:
            return False
        clean = re.sub(r"^www\.", "", host.lower())
        if clean in TRUSTED_DOMAINS:
            return True
        for trusted in TRUSTED_DOMAINS:
            if clean == trusted or clean.endswith("." + trusted):
                return True
        return False

    @staticmethod
    def is_ip_address(host: str) -> bool:
        """Check if hostname is an IPv4 address."""
        pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        return bool(re.match(pattern, host))

    @staticmethod
    def has_homograph_attack(url_str: str, host: str) -> bool:
        """Detect IDN/Homograph attacks (mixed script or non-ASCII characters in domain)."""
        if not host:
            return False
        # Check for punycode domain prefix xn--
        if "xn--" in host.lower():
            return True
        # Check if characters belong to non-Latin scripts mixed with ASCII
        try:
            host.encode("ascii")
            return False
        except UnicodeEncodeError:
            # Contains non-ASCII characters in host
            return True

    @classmethod
    def check_typosquatting(cls, host: str) -> tuple[bool, str, float]:
        """Check if host is a deceptive variation of a known brand."""
        if not host or cls.is_trusted_domain(host):
            return False, "", 0.0
        
        # Clean host (remove www and extract domain tokens)
        clean_host = re.sub(r"^www\.", "", host.lower())
        parts = clean_host.split(".")
        main_domain = parts[-2] if len(parts) >= 2 else parts[0]
        tld = parts[-1] if len(parts) >= 2 else ""
        sub_tokens = main_domain.split("-")

        for brand in POPULAR_BRANDS:
            # 1. Combosquatting: brand name embedded in compound domain paired with lure keyword or high-risk TLD
            if brand in main_domain and main_domain != brand:
                found_lure = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in main_domain]
                is_bad_tld = tld in SUSPICIOUS_TLDS
                if found_lure or is_bad_tld:
                    lure_label = found_lure[0] if found_lure else f".{tld}"
                    return True, f"Suspicious combosquatting: Brand '{brand}' paired with '{lure_label}' in '{host}'", 35.0

            # 2. Deceptive character substitution (e.g. paypa1, micros0ft, g00gle)
            for token in sub_tokens:
                if token != brand and len(token) >= 4:
                    norm_variants = [
                        token.replace("1", "l").replace("0", "o").replace("vv", "w").replace("rn", "m"),
                        token.replace("1", "i").replace("0", "o").replace("vv", "w").replace("rn", "m"),
                        token.replace("1", "l"),
                        token.replace("1", "i")
                    ]
                    if brand in norm_variants:
                        return True, f"Possible typosquatting of brand '{brand}' (detected: '{token}' in '{host}')", 40.0

                    # Single edit distance only if token explicitly targets brand prefix
                    dist = levenshtein_distance(token, brand)
                    if dist == 1 and abs(len(token) - len(brand)) <= 1 and token.startswith(brand[:3]):
                        return True, f"Possible typosquatting of brand '{brand}' (detected: '{token}' in '{host}')", 40.0

        return False, "", 0.0

    @classmethod
    def analyze_url(cls, url_str: str) -> dict:
        """Perform comprehensive analysis of a URL."""
        risk_score = 0.0
        flags = []
        
        if not url_str:
            return {"score": 0.0, "flags": [], "details": {}}
        
        # Prepend scheme if missing for proper parsing
        if not (url_str.startswith("http://") or url_str.startswith("https://")):
            parsed_url = urlparse("http://" + url_str)
        else:
            parsed_url = urlparse(url_str)
            
        host = parsed_url.hostname or ""
        path = parsed_url.path or ""
        query = parsed_url.query or ""
        scheme = parsed_url.scheme.lower()
        tld = host.split(".")[-1].lower() if "." in host else ""
        
        is_homograph = cls.has_homograph_attack(url_str, host)
        is_trusted = cls.is_trusted_domain(host)

        # 1. Homograph / IDN Spoofing check
        if is_homograph:
            risk_score += 50.0
            flags.append("URL uses non-ASCII characters or Punycode IDN (homograph spoofing attempt).")

        # 2. Authenticated Trusted Domains (Zero risk if legitimate HTTPS and not homograph)
        if is_trusted and not is_homograph:
            return {
                "score": 0.0,
                "flags": [],
                "details": {
                    "host": host,
                    "scheme": scheme,
                    "tld": tld,
                    "is_ip": False,
                    "has_homograph": False,
                    "is_typosquatting": False,
                    "is_trusted": True
                }
            }

        # 3. Check HTTP vs HTTPS
        if scheme == "http":
            risk_score += 15.0
            flags.append("URL uses insecure HTTP protocol instead of HTTPS.")

        # 4. Check IP Hostname
        if cls.is_ip_address(host):
            risk_score += 35.0
            flags.append(f"URL uses a raw IP address ({host}) instead of a domain name.")

        # 5. Check Typosquatting / Combosquatting
        is_typo, typo_msg, typo_weight = cls.check_typosquatting(host)
        if is_typo:
            risk_score += typo_weight
            flags.append(typo_msg)

        # 6. Check Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            risk_score += 25.0
            flags.append(f"Domain uses high-risk TLD (.{tld}).")

        # 7. Check URL Shortener
        if host in URL_SHORTENERS:
            risk_score += 20.0
            flags.append(f"URL uses shortener service ({host}) to obscure final destination.")

        # 8. Check Excessive Subdomains
        subdomain_count = len(host.split(".")) - 2 if host else 0
        if subdomain_count >= 3:
            risk_score += 20.0
            flags.append(f"Domain contains an excessive number of subdomains ({subdomain_count}).")

        # 9. Check @ symbol in userinfo/authority (http://google.com@attacker.com)
        # Avoid false positives on path containing /@channel
        if parsed_url.username or parsed_url.password or (parsed_url.netloc and "@" in parsed_url.netloc):
            risk_score += 30.0
            flags.append("URL contains '@' symbol in authority used for credential embedding or host spoofing.")

        # 10. Check suspicious path keywords
        full_path = (path + "?" + query).lower()
        matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in full_path]
        if matched_keywords:
            risk_score += 15.0
            flags.append(f"URL path contains sensitive keywords: {', '.join(matched_keywords)}.")

        # Cap score at 100
        score = min(100.0, risk_score)
        
        return {
            "score": round(score, 1),
            "flags": flags,
            "details": {
                "host": host,
                "scheme": scheme,
                "tld": tld,
                "is_ip": cls.is_ip_address(host),
                "has_homograph": is_homograph,
                "is_typosquatting": is_typo,
                "is_trusted": is_trusted
            }
        }
