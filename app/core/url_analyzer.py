import re
from urllib.parse import urlparse
import unicodedata

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
    "password", "wallet", "authenticate"
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
    def check_typosquatting(cls, host: str) -> tuple[bool, str]:
        """Check if host is a deceptive variation of a known brand."""
        if not host:
            return False, ""
        
        # Clean host (remove www and TLD)
        clean_host = re.sub(r"^www\.", "", host.lower())
        parts = clean_host.split(".")
        main_domain = parts[0] if parts else clean_host
        
        # Check main domain and hyphenated sub-tokens (e.g. paypa1-security)
        sub_tokens = main_domain.split("-")
        for token in sub_tokens:
            for brand in POPULAR_BRANDS:
                if token == brand:
                    continue  # Exact match to legitimate brand name (could still be wrong TLD)
                
                # Distance of 1 or 2 edits indicates likely typosquatting (e.g., paypa1, g00gle)
                dist = levenshtein_distance(token, brand)
                if 0 < dist <= 2 and len(token) >= 4:
                    return True, f"Possible typosquatting of brand '{brand}' (detected: '{token}' in '{host}')"
                
                # Check if brand is embedded inside a compound domain
                if brand in token and len(token) > len(brand):
                    return True, f"Brand name '{brand}' embedded inside domain '{host}'"

        return False, ""

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
        
        # 1. Check HTTP vs HTTPS
        if scheme == "http":
            risk_score += 15.0
            flags.append("URL uses insecure HTTP protocol instead of HTTPS.")

        # 2. Check IP Hostname
        if cls.is_ip_address(host):
            risk_score += 35.0
            flags.append(f"URL uses a raw IP address ({host}) instead of a domain name.")

        # 3. Check Homograph / IDN Attack
        if cls.has_homograph_attack(url_str, host):
            risk_score += 40.0
            flags.append(f"URL uses non-ASCII characters or Punycode IDN (homograph spoofing attempt).")

        # 4. Check Typosquatting
        is_typo, typo_msg = cls.check_typosquatting(host)
        if is_typo:
            risk_score += 35.0
            flags.append(typo_msg)

        # 5. Check Suspicious TLD
        tld = host.split(".")[-1].lower() if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            risk_score += 25.0
            flags.append(f"Domain uses high-risk TLD (.{tld}).")

        # 6. Check URL Shortener
        if host in URL_SHORTENERS:
            risk_score += 20.0
            flags.append(f"URL uses shortener service ({host}) to obscure final destination.")

        # 7. Check Excessive Subdomains
        subdomain_count = len(host.split(".")) - 2 if host else 0
        if subdomain_count >= 3:
            risk_score += 20.0
            flags.append(f"Domain contains an excessive number of subdomains ({subdomain_count}).")

        # 8. Check @ symbol trick (http://google.com@attacker.com)
        if "@" in url_str:
            risk_score += 30.0
            flags.append("URL contains '@' symbol used for credential embedding or host spoofing.")

        # 9. Check suspicious path keywords
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
                "has_homograph": cls.has_homograph_attack(url_str, host),
                "is_typosquatting": is_typo
            }
        }
