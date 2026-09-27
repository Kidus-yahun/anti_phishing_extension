import os
import re
import pickle
from typing import Tuple, List, Dict

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
    """NLP and Machine Learning model for social engineering & phishing text classification."""

    def __init__(self, model_path: str = "app/models/phishing_model.pkl"):
        self.model_path = model_path
        self.vectorizer = None
        self.classifier = None
        self.load_model()

    def load_model(self):
        """Load trained Scikit-learn model and vectorizer if available."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    data = pickle.load(f)
                    self.vectorizer = data.get("vectorizer")
                    self.classifier = data.get("classifier")
            except Exception as e:
                print(f"[NLPEngine] Error loading model file {self.model_path}: {e}")

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
        """Run text through both ML Classifier (if available) and NLP Heuristics."""
        if not text or not text.strip():
            return {"score": 0.0, "flags": [], "ml_probability": 0.0, "heuristic_score": 0.0}

        heuristic_score, flags = self.analyze_heuristics(text)
        ml_probability = 0.0

        # If trained ML model is loaded, compute ML prediction probability
        if self.vectorizer and self.classifier:
            try:
                features = self.vectorizer.transform([text])
                probs = self.classifier.predict_proba(features)[0]
                # Index 1 corresponds to 'phishing' class probability
                ml_probability = float(probs[1]) if len(probs) > 1 else float(probs[0])
            except Exception as e:
                print(f"[NLPEngine] ML prediction error: {e}")

        # If ML model is loaded, blend ML prediction (60%) with Heuristics (40%)
        if self.vectorizer and self.classifier:
            ml_score = ml_probability * 100.0
            final_score = (ml_score * 0.6) + (heuristic_score * 0.4)
            if ml_probability >= 0.7 and "Machine learning model identified strong phishing text pattern." not in flags:
                flags.append(f"Machine learning model flagged text pattern as high-risk phishing ({round(ml_probability * 100, 1)}% confidence).")
        else:
            final_score = heuristic_score

        return {
            "score": round(min(100.0, final_score), 1),
            "flags": flags,
            "ml_probability": round(ml_probability, 4),
            "heuristic_score": round(heuristic_score, 1)
        }
