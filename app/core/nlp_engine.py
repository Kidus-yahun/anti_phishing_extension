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
