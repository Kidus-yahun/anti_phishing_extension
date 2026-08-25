from typing import List, Dict

class RiskScorer:
    """Aggregates multi-vector analysis (NLP, URL, Header) into a unified risk rating."""

    @staticmethod
    def calculate_risk(nlp_res: Dict, url_res: Dict = None, header_res: Dict = None) -> Dict:
        """
        Combine weights:
        - NLP Text Score: 40%
        - URL & Host Score: 35%
        - Header Authentication Score: 25%
        (Dynamic re-weighting applied when URL or Header inputs are omitted)
        """
        scores = []
        weights = []

        # NLP Score
        nlp_score = nlp_res.get("score", 0.0)
        nlp_flags = nlp_res.get("flags", [])
        scores.append(nlp_score)
        weights.append(0.40)

        # URL Score
        url_flags = []
        if url_res and url_res.get("score") is not None:
            url_score = url_res.get("score", 0.0)
            url_flags = url_res.get("flags", [])
            scores.append(url_score)
            weights.append(0.35)

        # Header Score
        header_flags = []
        if header_res and header_res.get("score") is not None:
            header_score = header_res.get("score", 0.0)
            header_flags = header_res.get("flags", [])
            scores.append(header_score)
            weights.append(0.25)

        # Normalize weights if some vectors were not provided
        total_weight = sum(weights)
        if total_weight > 0:
            normalized_weights = [w / total_weight for w in weights]
            composite_score = sum(s * w for s, w in zip(scores, normalized_weights))
        else:
            composite_score = 0.0

        composite_score = round(min(100.0, max(0.0, composite_score)), 1)

        # Determine Risk Level and Color Code
        if composite_score < 25.0:
            risk_level = "SAFE"
            badge_color = "green"
            verdict = "Low risk detected. Content appears legitimate."
        elif composite_score < 50.0:
            risk_level = "LOW RISK"
            badge_color = "yellow"
            verdict = "Minor risk factors detected. Exercise standard caution."
        elif composite_score < 75.0:
            risk_level = "MEDIUM RISK"
            badge_color = "orange"
            verdict = "Multiple suspicious indicators found. Likely phishing or social engineering."
        else:
            risk_level = "HIGH / CRITICAL RISK"
            badge_color = "red"
            verdict = "CRITICAL PHISHING THREAT! Highly deceptive indicators detected. Do not click links or enter credentials."

        # Aggregate all unique flags
        all_flags = nlp_flags + url_flags + header_flags

        return {
            "risk_score": composite_score,
            "risk_level": risk_level,
            "badge_color": badge_color,
            "verdict": verdict,
            "flags": all_flags,
            "breakdown": {
                "nlp": nlp_res,
                "url": url_res or {"score": 0.0, "flags": []},
                "header": header_res or {"score": 0.0, "flags": []}
            }
        }
