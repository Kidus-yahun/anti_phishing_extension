import os
import re
import pickle
import threading
from typing import Tuple, List, Dict, Optional

# Disable symlinks on Windows non-admin for HuggingFace Hub downloads
os.environ["HF_HUB_DISABLE_SYMLINKS"] = "1"
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# Social Engineering Keywords & Weighted Categories
URGENCY_KEYWORDS = [
    "immediate action", "account suspended", "suspended within 24 hours",
    "unauthorized login", "action required", "terminate account",
    "security alert", "suspicious activity", "locked out", "urgent notice",
    "final warning", "verify immediately", "failure to respond"
]

CREDENTIAL_KEYWORDS = [
    "verify password", "update billing", "confirm credit card", "ssn",
    "social security", "pin number", "re-enter credentials", "log in to verify",
    "confirm identity", "bank details", "wire transfer", "gift card"
]

IMPERSONATION_KEYWORDS = [
    "it department", "security team", "helpdesk", "administrator",
    "system alert", "customer support", "fraud department", "ceo request"
]

NON_DOMAIN_FILE_EXTENSIONS = {
    # Windows & PC executables & installers
    "exe", "msi", "bat", "cmd", "scr", "pif", "bin", "run", "gadget",
    "dmg", "pkg", "deb", "rpm", "apk", "apks", "xapk", "aab", "ipa", "msix", "appx", "appimage",
    # Archives & compressed files
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "lz", "lzma", "zst", "tzst",
    "iso", "img", "vmdk", "vdi", "qcow2", "vhd", "toast",
    # Documents & spreadsheets
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv", "tsv",
    # Media (audio, video, images)
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "ico", "tif", "tiff", "psd", "raw",
    # Audio & video
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma", "mid", "midi",
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "3gp",
    # Code & scripts
    "py", "pyw", "js", "mjs", "cjs", "ts", "rb", "php", "java", "cpp", "cxx", "hpp", "cs",
    "sh", "bash", "zsh", "fish", "ps1", "psm1", "json", "xml", "yaml", "yml", "toml", "ini", "cfg", "conf", "log", "md", "markdown",
    # Libraries & distributions
    "jar", "war", "ear", "whl", "egg", "gem", "node", "dylib", "dll",
    # Signatures & torrents
    "sig", "asc", "sha256", "sha512", "md5", "torrent", "patch", "diff"
}

def extract_claimed_domain(anchor_text: str, parsed_url=None) -> Optional[str]:
    """
    Extract genuine domain claims from anchor text while excluding file downloads,
    version releases, and non-domain labels.
    """
    if not anchor_text:
        return None
    text = anchor_text.strip().lower()
    if not text:
        return None

    # 1. If anchor text matches the destination file name or URL path ending, it's a file download link
    if parsed_url and parsed_url.path:
        path_lower = parsed_url.path.lower()
        parts = [p for p in path_lower.split("/") if p]
        filename = parts[-1] if parts else ""
        if filename and (text == filename or path_lower.endswith("/" + text) or text.endswith(filename)):
            return None

    # 2. Explicit URL scheme: https://... or http://...
    url_match = re.search(r"(?:^|\s)https?://([a-z0-9.-]+)", text)
    if url_match:
        raw_host = re.sub(r"^www\.", "", url_match.group(1))
        parts = raw_host.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext not in NON_DOMAIN_FILE_EXTENSIONS:
            return raw_host

    # 3. Explicit www. prefix: www.google.com
    www_match = re.search(r"(?:^|\s)www\.([a-z0-9.-]+\.[a-z]{2,})", text)
    if www_match:
        raw_host = re.sub(r"^www\.", "", www_match.group(1))
        parts = raw_host.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext not in NON_DOMAIN_FILE_EXTENSIONS:
            return raw_host

    # 4. Standalone domain or domain with path: paypal.com or paypal.com/login
    domain_candidate_match = re.match(
        r"^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,})(?:/.*)?$",
        text
    )
    if domain_candidate_match:
        candidate = re.sub(r"^www\.", "", domain_candidate_match.group(1))
        parts = candidate.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in NON_DOMAIN_FILE_EXTENSIONS:
            return None
        return candidate

    return None


class NLPEngine:
    """
    Dual-Engine NLP Threat Detection Engine:
    - Primary (Model #1): Laya Non-Autoregressive System-1 Decision Engine (convaiinnovations/laya)
      Delivers calibrated, sub-second (<500ms on CPU, ~35ms on GPU) multilingual semantic decisions.
    - Fallback: Scikit-Learn TF-IDF + Logistic Regression
    - Heuristics: Weighted psychological manipulation, urgency, and credential requests
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        laya_model_name: str = "convaiinnovations/laya"
    ):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if model_path is None or not os.path.exists(model_path):
            candidate = os.path.join(base_dir, "models", "phishing_model.pkl")
            if os.path.exists(candidate):
                model_path = candidate
        self.model_path = model_path
        self.laya_model_name = laya_model_name
        self.vectorizer = None
        self.classifier = None

        # Laya Decision Engine State
        self._laya_agent = None
        self._laya_ready = False
        self._laya_loading = False
        self._laya_error = None

        # Standard sub-second phishing decision query
        self._laya_question = {
            "is_phishing": {
                "type": "noul",
                "instructions": "Is this email or text a phishing or scam attempt to steal money, credentials, or personal data?",
                "criteria": {
                    "true": "phishing, scam, or fraud attempt",
                    "false": "a legitimate safe email or message"
                }
            }
        }

        # 1. Load instant local baseline model (immediate boot < 5ms)
        self.load_baseline_model()

        # 2. Trigger asynchronous background initialization of Laya
        self.init_laya_async()

    def load_baseline_model(self):
        """Load trained Scikit-learn model and vectorizer if available."""
        if self.model_path and os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.vectorizer = data.get("vectorizer")
                    self.classifier = data.get("classifier")
            except Exception as e:
                print(f"[NLPEngine] Error loading baseline model {self.model_path}: {e}")

    def init_laya_async(self):
        """Asynchronously load Laya System-1 Agent in background thread to avoid blocking server boot."""
        if self._laya_loading or self._laya_ready:
            return

        self._laya_loading = True

        def _loader():
            try:
                print(f"[NLPEngine] Initializing Laya System-1 Model ({self.laya_model_name})...")
                import laya

                agent = laya.load(self.laya_model_name)
                # Warmup pass to eliminate initial JIT/tracing overhead
                agent.decide("Ping", questions=self._laya_question)

                self._laya_agent = agent
                self._laya_ready = True
                self._laya_loading = False
                print(f"[NLPEngine] Laya System-1 Model ({self.laya_model_name}) is online and ready for sub-second triage!")
            except Exception as e:
                self._laya_error = str(e)
                self._laya_loading = False
                print(f"[NLPEngine] Laya initialization deferred (using baseline fallback): {e}")

        thread = threading.Thread(target=_loader, daemon=True)
        thread.start()

    def get_status(self) -> Dict:
        """Return real-time AI engine status for API health endpoints."""
        is_ready = self._laya_ready
        return {
            "laya_ready": is_ready,
            "laya_loading": self._laya_loading,
            "active_model": (
                "Laya-System1 (ModernBERT Decision Engine)"
                if is_ready
                else "TF-IDF + LogisticRegression (Baseline Fallback)"
            ),
            "model_architecture": (
                self.laya_model_name
                if is_ready
                else "Scikit-Learn Baseline"
            ),
            "fallback_available": self.classifier is not None,
            # Backwards compatibility keys for legacy dashboard & tests
            "roberta_ready": is_ready,
            "roberta_loading": self._laya_loading
        }

    def analyze_heuristics(self, text: str) -> Tuple[float, List[str]]:
        """Perform rule-based NLP keyword and sentiment analysis."""
        if not text:
            return 0.0, []

        text_lower = text.lower()
        flags = []
        score = 0.0

        # Check Urgency / Threats
        found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
        if found_urgency:
            score += min(45.0, len(found_urgency) * 15.0)
            flags.append(f"High urgency / pressure language detected: {', '.join(found_urgency)}.")

        # Check Credential / Financial Requests
        found_credentials = [kw for kw in CREDENTIAL_KEYWORDS if kw in text_lower]
        if found_credentials:
            score += min(45.0, len(found_credentials) * 15.0)
            flags.append(f"Sensitive credential or financial requests detected: {', '.join(found_credentials)}.")

        # Check Authority / Impersonation Cues
        found_impersonation = [kw for kw in IMPERSONATION_KEYWORDS if kw in text_lower]
        if found_impersonation:
            score += min(25.0, len(found_impersonation) * 10.0)
            flags.append(f"Impersonation or authority cues detected: {', '.join(found_impersonation)}.")

        # Check Excessive Exclamation or All Caps Words
        caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
        if len(caps_words) >= 3:
            score += 10.0
            flags.append("Excessive uppercase words used to induce panic.")

        return min(100.0, score), flags

    def predict(self, text: str) -> Dict:
        """
        Evaluate text using Laya System-1 Model (Primary #1) with sub-second constraint,
        falling back to Scikit-Learn baseline.
        """
        if not text or not text.strip():
            return {
                "score": 0.0,
                "flags": [],
                "ml_probability": 0.0,
                "model_used": "None",
                "heuristic_score": 0.0
            }

        heuristic_score, flags = self.analyze_heuristics(text)
        ml_probability = 0.0
        model_used = "Heuristics Only"

        # -------------------------------------------------------------
        # Path 1: Laya Non-Autoregressive System-1 Inference (Primary #1)
        # -------------------------------------------------------------
        if self._laya_ready and self._laya_agent:
            try:
                # Sub-second latency guardrail: truncate input snippet to first 800 chars
                snippet = text[:800].strip()

                # Single-pass non-autoregressive forward decision (< 500ms on CPU)
                decision = self._laya_agent.decide(snippet, questions=self._laya_question)
                phish_res = decision.get("is_phishing", {})

                # Extract calibrated noul score (0.0 to 1.0)
                if isinstance(phish_res, dict):
                    ml_probability = float(phish_res.get("noul", 0.0))
                else:
                    ml_probability = float(getattr(phish_res, "noul", 0.0))

                model_used = f"Laya-System1 ({self.laya_model_name})"

                # Contextual blend: 70% Laya Deep Semantic + 30% Heuristics
                laya_score = ml_probability * 100.0
                final_score = (laya_score * 0.70) + (heuristic_score * 0.30)

                if ml_probability >= 0.50:
                    flags.append(
                        f"Laya System-1 AI identified social engineering deception pattern ({round(ml_probability * 100, 1)}% confidence)."
                    )

                return {
                    "score": round(min(100.0, final_score), 1),
                    "flags": flags,
                    "ml_probability": round(ml_probability, 4),
                    "model_used": model_used,
                    "heuristic_score": round(heuristic_score, 1)
                }
            except Exception as e:
                print(f"[NLPEngine] Laya inference error (falling back to baseline): {e}")

        # -------------------------------------------------------------
        # Path 2: Scikit-Learn TF-IDF Baseline Fallback
        # -------------------------------------------------------------
        if self.vectorizer and self.classifier:
            try:
                features = self.vectorizer.transform([text])
                probs = self.classifier.predict_proba(features)[0]
                ml_probability = float(probs[1]) if len(probs) > 1 else float(probs[0])
                model_used = "TF-IDF + LogisticRegression (Baseline Fallback)"

                ml_score = ml_probability * 100.0
                final_score = (ml_score * 0.60) + (heuristic_score * 0.40)

                if ml_probability >= 0.70 and not any("ML model" in f for f in flags):
                    flags.append(
                        f"Baseline ML model flagged phishing pattern ({round(ml_probability * 100, 1)}% confidence)."
                    )

                return {
                    "score": round(min(100.0, final_score), 1),
                    "flags": flags,
                    "ml_probability": round(ml_probability, 4),
                    "model_used": model_used,
                    "heuristic_score": round(heuristic_score, 1)
                }
            except Exception as e:
                print(f"[NLPEngine] Baseline ML prediction error: {e}")

        # -------------------------------------------------------------
        # Path 3: Heuristics Only
        # -------------------------------------------------------------
        return {
            "score": round(min(100.0, heuristic_score), 1),
            "flags": flags,
            "ml_probability": round(ml_probability, 4),
            "model_used": model_used,
            "heuristic_score": round(heuristic_score, 1)
        }

    def evaluate_url(self, url: str, anchor_text: str = "") -> Dict:
        """
        Evaluate a URL autonomously using the Laya System-1 Model.
        Eliminates the need for fragile hardcoded domain whitelists or crude
        string edit-distance heuristics that falsely flag legitimate websites.
        """
        if not url:
            return {"is_phishing": False, "score": 0.0, "confidence": 0.0, "flags": [], "reason": ""}

        # Cache lookup for sub-millisecond repeated queries
        cache_key = (url.strip().lower(), (anchor_text or "").strip().lower())
        if not hasattr(self, "_url_cache"):
            self._url_cache = {}
        if cache_key in self._url_cache:
            return self._url_cache[cache_key]

        # 1. Structural Checks (Invariable cryptographic / protocol attacks)
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        flags = []

        # Non-ASCII / Cyrillic Punycode homograph attack
        if "xn--" in host or any(ord(c) > 127 for c in host):
            res = {
                "is_phishing": True,
                "score": 85.0,
                "confidence": 0.95,
                "flags": ["Homograph attack detected (non-ASCII character or Punycode domain spoofing)."],
                "reason": "Homograph attack: Non-ASCII characters used to disguise domain.",
                "model_used": "Structural Guardrail"
            }
            self._url_cache[cache_key] = res
            return res

        # Raw IP address hostname
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            res = {
                "is_phishing": True,
                "score": 80.0,
                "confidence": 0.90,
                "flags": [f"Raw IP address hostname used ({host})."],
                "reason": "Deceptive destination using raw IP address instead of registered domain.",
                "model_used": "Structural Guardrail"
            }
            self._url_cache[cache_key] = res
            return res

        # Embedded authority credentials (user:pass@host)
        if parsed.username or parsed.password:
            res = {
                "is_phishing": True,
                "score": 85.0,
                "confidence": 0.90,
                "flags": ["URL contains embedded authority credentials spoofing hostname."],
                "reason": "Credential spoofing via authority '@' syntax.",
                "model_used": "Structural Guardrail"
            }
            self._url_cache[cache_key] = res
            return res

        # Deceptive anchor text mismatch (e.g. text claims google.com but href goes to attacker.com)
        if anchor_text:
            displayed_domain = extract_claimed_domain(anchor_text, parsed)
            actual_host = re.sub(r"^www\.", "", host)
            if displayed_domain and actual_host and displayed_domain != actual_host and not actual_host.endswith("." + displayed_domain):
                res = {
                    "is_phishing": True,
                    "score": 80.0,
                    "confidence": 0.90,
                    "flags": [f"Deceptive link: Display text claims '{displayed_domain}' but link points to '{actual_host}'."],
                    "reason": f"Deceptive link mismatch: Claiming '{displayed_domain}' while directing to '{actual_host}'.",
                    "model_used": "Anchor Mismatch Guardrail"
                }
                self._url_cache[cache_key] = res
                return res

        # 2. Deceptive typosquatting / combosquatting check
        from app.core.url_analyzer import URLAnalyzer
        is_typo, typo_msg, typo_weight = URLAnalyzer.check_typosquatting(host)
        if is_typo:
            res = {
                "is_phishing": True,
                "score": 80.0,
                "confidence": 0.88,
                "flags": [typo_msg],
                "reason": typo_msg,
                "model_used": "Typosquatting Guardrail"
            }
            self._url_cache[cache_key] = res
            return res

        # 3. Laya System-1 Autonomous Model Decision
        if self._laya_ready and self._laya_agent:
            try:
                url_context = f"URL: {url}"
                if anchor_text and len(anchor_text.strip()) > 1:
                    url_context += f" | Display Text: {anchor_text.strip()[:100]}"

                url_triage_question = {
                    "verdict": {
                        "type": "choice",
                        "instructions": "Is this link URL a phishing/scam attack or a legitimate website?",
                        "criteria": {
                            "phishing_scam": "deceptive domain, combosquatting, fake brand clone, or credential harvester",
                            "legitimate_site": "authentic website, company, publisher, portfolio, or safe service"
                        }
                    }
                }

                result = self._laya_agent.decide(url_context, questions=url_triage_question)
                verdict = result.get("verdict", {})
                choice = verdict.get("choice")
                probs = verdict.get("probabilities", {})
                phish_prob = float(probs.get("phishing_scam", 0.0))

                # True phishing determination requires clear model confidence
                is_phish = (choice == "phishing_scam" and phish_prob >= 0.65)
                score = round(phish_prob * 100.0, 1) if is_phish else 0.0

                if is_phish:
                    flags.append(
                        f"Laya System-1 Model identified deceptive phishing domain ({round(phish_prob * 100, 1)}% confidence)."
                    )
                    reason = f"Laya System-1 Model flagged link as deceptive phishing clone ({round(phish_prob * 100, 1)}% confidence)."
                else:
                    reason = "Laya System-1 Model verified link destination as legitimate."

                res = {
                    "is_phishing": is_phish,
                    "score": score,
                    "confidence": round(phish_prob, 4),
                    "flags": flags,
                    "reason": reason,
                    "model_used": f"Laya-System1 ({self.laya_model_name})"
                }
                self._url_cache[cache_key] = res
                return res
            except Exception as e:
                print(f"[NLPEngine] Error evaluating URL with Laya: {e}")

        # Safe default if model is offline and no structural attack detected
        res = {
            "is_phishing": False,
            "score": 0.0,
            "confidence": 0.0,
            "flags": [],
            "reason": "No structural threat detected (Model initializing)",
            "model_used": "Baseline"
        }
        self._url_cache[cache_key] = res
        return res
