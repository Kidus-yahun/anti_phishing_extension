import os
import re
import json
import urllib.request
from urllib.parse import urlparse
from typing import Tuple, Dict, Set, Optional, List

class ThreatDatabase:
    """
    Local Threat Intelligence Database:
    Provides O(1) in-memory lookup of confirmed malicious domains and URLs,
    supporting offline privacy-preserving evaluation and automated community feed syncing
    (OpenPhish Community Feed & Threat Intelligence IOCs).
    """

    _instance = None
    _loaded = False
    _domains: Set[str] = set()
    _urls: Set[str] = set()
    _metadata: Dict = {}

    def __init__(self, data_path: Optional[str] = None):
        if data_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_path = os.path.join(base_dir, "data", "threat_feed.json")
        self.data_path = data_path
        self.load()

    @classmethod
    def get_instance(cls, data_path: Optional[str] = None) -> "ThreatDatabase":
        if cls._instance is None:
            cls._instance = cls(data_path)
        return cls._instance

    @staticmethod
    def normalize_host(host: str) -> str:
        """Strip www, port, and trailing dots, return lowercase hostname."""
        if not host:
            return ""
        clean = host.strip().lower()
        clean = re.sub(r"^www\.", "", clean)
        if ":" in clean:
            clean = clean.split(":")[0]
        return clean.rstrip(".")

    @staticmethod
    def normalize_url(url: str) -> Tuple[str, str]:
        """Extract normalized host and canonical URL string."""
        if not url:
            return "", ""
        clean_url = url.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            parsed = urlparse("http://" + clean_url)
        else:
            parsed = urlparse(clean_url)
        host = ThreatDatabase.normalize_host(parsed.hostname or "")
        canonical = f"{parsed.scheme or 'http'}://{host}{parsed.path}"
        return host, canonical

    def load(self, force_reload: bool = False):
        """Load threat database from disk into memory."""
        if self._loaded and not force_reload:
            return

        ThreatDatabase._domains = set()
        ThreatDatabase._urls = set()
        ThreatDatabase._metadata = {
            "version": "1.0.0",
            "source": "OpenPhish Community Feed & PhishShield Curated IOCs",
            "last_updated": None,
            "total_domains": 0,
            "total_urls": 0
        }

        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    domains = data.get("domains", [])
                    urls = data.get("urls", [])
                    for d in domains:
                        norm = self.normalize_host(d)
                        if norm:
                            ThreatDatabase._domains.add(norm)
                    for u in urls:
                        _, canon = self.normalize_url(u)
                        if canon:
                            ThreatDatabase._urls.add(canon)
                    ThreatDatabase._metadata.update(data.get("metadata", {}))
                    ThreatDatabase._metadata["total_domains"] = len(ThreatDatabase._domains)
                    ThreatDatabase._metadata["total_urls"] = len(ThreatDatabase._urls)
            except Exception as e:
                print(f"[ThreatDatabase] Error loading threat feed from {self.data_path}: {e}")

        ThreatDatabase._loaded = True

    def save(self):
        """Persist current memory database to disk."""
        os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
        ThreatDatabase._metadata["total_domains"] = len(ThreatDatabase._domains)
        ThreatDatabase._metadata["total_urls"] = len(ThreatDatabase._urls)
        payload = {
            "metadata": ThreatDatabase._metadata,
            "domains": sorted(list(ThreatDatabase._domains)),
            "urls": sorted(list(ThreatDatabase._urls))
        }
        with open(self.data_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def is_known_phishing(self, url_or_host: str) -> Tuple[bool, Optional[Dict]]:
        """
        Check if host or URL is registered in the confirmed threat intelligence database.
        Checks exact URL match, exact hostname match, and parent domain match.
        """
        if not url_or_host:
            return False, None

        host, canon_url = self.normalize_url(url_or_host)
        if not host:
            host = self.normalize_host(url_or_host)

        # 1. Check exact canonical URL match
        if canon_url in ThreatDatabase._urls:
            return True, {
                "match_type": "exact_url",
                "matched_entry": canon_url,
                "threat_level": "CRITICAL",
                "source": ThreatDatabase._metadata.get("source", "OpenPhish Threat Feed"),
                "reason": "Exact URL match in verified Threat Intelligence Database."
            }

        # 2. Check exact host match
        if host in ThreatDatabase._domains:
            return True, {
                "match_type": "exact_domain",
                "matched_entry": host,
                "threat_level": "CRITICAL",
                "source": ThreatDatabase._metadata.get("source", "OpenPhish Threat Feed"),
                "reason": f"Domain '{host}' is flagged in verified Threat Intelligence Database."
            }

        # 3. Check parent domain hierarchy (e.g. login.phish-bank.com -> phish-bank.com)
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in ThreatDatabase._domains:
                return True, {
                    "match_type": "parent_domain",
                    "matched_entry": parent,
                    "threat_level": "CRITICAL",
                    "source": ThreatDatabase._metadata.get("source", "OpenPhish Threat Feed"),
                    "reason": f"Host '{host}' is a subdomain of verified phishing domain '{parent}'."
                }

        return False, None

    def sync_openphish_feed(self, feed_url: str = "https://openphish.com/feed.txt", timeout: int = 10) -> int:
        """
        Sync real-time verified phishing indicators from OpenPhish Community Feed.
        Returns the number of new indicators added.
        """
        from datetime import datetime, timezone
        added_count = 0
        try:
            req = urllib.request.Request(
                feed_url,
                headers={"User-Agent": "PhishShield-AI-ThreatSync/1.0 (Defensive Cybersecurity Research)"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as res:
                content = res.read().decode("utf-8", errors="ignore")
                lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]

            for raw_url in lines:
                host, canon = self.normalize_url(raw_url)
                if host and host not in ThreatDatabase._domains:
                    ThreatDatabase._domains.add(host)
                    added_count += 1
                if canon and canon not in ThreatDatabase._urls:
                    ThreatDatabase._urls.add(canon)
                    added_count += 1

            ThreatDatabase._metadata["last_updated"] = datetime.now(timezone.utc).isoformat()
            ThreatDatabase._metadata["total_domains"] = len(ThreatDatabase._domains)
            ThreatDatabase._metadata["total_urls"] = len(ThreatDatabase._urls)
            self.save()
            print(f"[ThreatDatabase] Successfully synced {len(lines)} indicators from OpenPhish ({added_count} new entries).")
            return added_count
        except Exception as e:
            print(f"[ThreatDatabase] Error syncing OpenPhish feed: {e}")
            return added_count

    def export_extension_feed(self, output_path: str = "extension/threat_domains.json"):
        """Export domain list to extension directory for in-browser client-side checking."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        export_data = {
            "metadata": {
                "source": ThreatDatabase._metadata.get("source", "OpenPhish Community Feed"),
                "total_domains": len(ThreatDatabase._domains)
            },
            "domains": sorted(list(ThreatDatabase._domains))
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        print(f"[ThreatDatabase] Exported {len(ThreatDatabase._domains)} domains to '{output_path}'.")

    def get_stats(self) -> Dict:
        """Return threat intelligence statistics."""
        return {
            "loaded": self._loaded,
            "total_domains": len(ThreatDatabase._domains),
            "total_urls": len(ThreatDatabase._urls),
            "source": ThreatDatabase._metadata.get("source", "OpenPhish Community Feed"),
            "last_updated": ThreatDatabase._metadata.get("last_updated")
        }
