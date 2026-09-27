import os
import re
import pickle
import threading
from typing import Tuple, List, Dict, Optional

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
    Dual-Engine NLP and Transformer Engine:
    - Primary: RoBERTa Deep Transformer (Hugging Face Pipeline)
    - Fallback: Scikit-Learn TF-IDF + Logistic Regression
    - Heuristics: Weighted psychological manipulation & urgency patterns
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        roberta_model_name: str = "roberta-base"
    ):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if model_path is None or not os.path.exists(model_path):
            candidate = os.path.join(base_dir, "models", "phishing_model.pkl")
            if os.path.exists(candidate):
                model_path = candidate
        self.model_path = model_path
        self.roberta_model_name = roberta_model_name
        self.vectorizer = None
        self.classifier = None

        # RoBERTa Transformer State
        self._roberta_pipeline = None
        self._roberta_ready = False
        self._roberta_loading = False
        self._roberta_error = None

        # 1. Load fast local baseline model (immediate boot)
        self.load_baseline_model()

        # 2. Trigger asynchronous background initialization of RoBERTa
        self.init_roberta_async()

    def load_baseline_model(self):
        """Load trained Scikit-learn model and vectorizer if available."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.vectorizer = data.get("vectorizer")
                    self.classifier = data.get("classifier")
            except Exception as e:
                print(f"[NLPEngine] Error loading baseline model {self.model_path}: {e}")

    def init_roberta_async(self):
        """Asynchronously load RoBERTa pipeline in background thread to avoid blocking server boot."""
        if self._roberta_loading or self._roberta_ready:
            return

        self._roberta_loading = True

        def _loader():
            try:
                print(f"[NLPEngine] Initializing RoBERTa model ({self.roberta_model_name})...")
                # Import transformers dynamically inside thread
                from transformers import pipeline

                # Zero-shot classification pipeline powered by RoBERTa
                # Evaluates contextual semantic entailment for social engineering detection
                pipe = pipeline(
                    "zero-shot-classification",
                    model=self.roberta_model_name,
                    device=-1  # CPU inference
                )
                self._roberta_pipeline = pipe
                self._roberta_ready = True
                self._roberta_loading = False
                print(f"[NLPEngine] RoBERTa model ({self.roberta_model_name}) is online and ready!")
            except Exception as e:
                self._roberta_error = str(e)
                self._roberta_loading = False
                print(f"[NLPEngine] RoBERTa initialization deferred (using baseline): {e}")

        thread = threading.Thread(target=_loader, daemon=True)
        thread.start()

    def get_status(self) -> Dict:
        """Return real-time AI engine status for API health endpoints."""
        return {
            "roberta_ready": self._roberta_ready,
            "roberta_loading": self._roberta_loading,
            "active_model": "RoBERTa-Transformer" if self._roberta_ready else "TF-IDF + LogisticRegression (Baseline)",
            "model_architecture": self.roberta_model_name if self._roberta_ready else "Scikit-Learn Baseline",
            "fallback_available": self.classifier is not None
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
        Evaluate text using RoBERTa deep transformer (if ready) or fallback to TF-IDF baseline.
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
        # Path 1: RoBERTa Deep Transformer Inference (Primary)
        # -------------------------------------------------------------
        if self._roberta_ready and self._roberta_pipeline:
            try:
                candidate_labels = [
                    "phishing social engineering attack",
                    "legitimate safe message"
                ]

                # Run RoBERTa zero-shot inference
                result = self._roberta_pipeline(text, candidate_labels)
                scores = result.get("scores", [])
                labels = result.get("labels", [])

                if "phishing social engineering attack" in labels:
                    idx = labels.index("phishing social engineering attack")
                    ml_probability = float(scores[idx])

                model_used = f"RoBERTa-Transformer ({self.roberta_model_name})"

                # RoBERTa deep contextual blend (70% RoBERTa + 30% Heuristics)
                roberta_score = ml_probability * 100.0
                final_score = (roberta_score * 0.70) + (heuristic_score * 0.30)

                if ml_probability >= 0.65:
                    flags.append(
                        f"RoBERTa deep transformer identified semantic deception pattern ({round(ml_probability * 100, 1)}% confidence)."
                    )

                return {
                    "score": round(min(100.0, final_score), 1),
                    "flags": flags,
                    "ml_probability": round(ml_probability, 4),
                    "model_used": model_used,
                    "heuristic_score": round(heuristic_score, 1)
                }
            except Exception as e:
                print(f"[NLPEngine] RoBERTa inference error (falling back): {e}")

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

                if ml_probability >= 0.70 and "Machine learning model identified strong phishing text pattern." not in flags:
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
