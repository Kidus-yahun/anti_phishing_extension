import pytest
from app.core.url_analyzer import URLAnalyzer
from app.core.header_analyzer import EmailHeaderAnalyzer
from app.core.nlp_engine import NLPEngine
from app.core.risk_scorer import RiskScorer

def test_url_homograph_detection():
    # URL with Cyrillic 'а' replacing Latin 'a'
    homograph_url = "http://pаypal.com/verify"
    result = URLAnalyzer.analyze_url(homograph_url)
    assert result["score"] >= 35.0
    assert any("homograph" in flag.lower() for flag in result["flags"])

def test_url_ip_hostname():
    ip_url = "http://192.168.1.100/login.php"
    result = URLAnalyzer.analyze_url(ip_url)
    assert result["score"] >= 35.0
    assert any("ip address" in flag.lower() for flag in result["flags"])

def test_url_typosquatting():
    typo_url = "http://paypa1-security.com/login"
    result = URLAnalyzer.analyze_url(typo_url)
    assert result["score"] >= 30.0
    assert any("typosquatting" in flag.lower() or "embedded" in flag.lower() for flag in result["flags"])

def test_header_display_name_spoofing():
    raw_header = "From: PayPal Support <attacker@randomdomain.xyz>\nReturn-Path: <attacker@randomdomain.xyz>"
    result = EmailHeaderAnalyzer.analyze_headers(raw_header)
    assert result["score"] >= 30.0
    assert any("display name spoofing" in flag.lower() for flag in result["flags"])

def test_header_from_returnpath_mismatch():
    raw_header = "From: Security <security@mycompany.com>\nReturn-Path: <bounce@malicious-host.com>"
    result = EmailHeaderAnalyzer.analyze_headers(raw_header)
    assert result["score"] >= 25.0
    assert any("mismatch" in flag.lower() for flag in result["flags"])

def test_nlp_urgency_heuristics():
    nlp = NLPEngine(model_path="app/models/non_existent.pkl")
    text = "URGENT: Your account has been suspended due to unauthorized login. Verify password immediately."
    res = nlp.predict(text)
    assert res["score"] >= 30.0
    assert len(res["flags"]) > 0

def test_composite_risk_scorer():
    nlp_res = {"score": 80.0, "flags": ["Urgency detected"]}
    url_res = {"score": 70.0, "flags": ["IP Hostname"]}
    header_res = {"score": 60.0, "flags": ["SPF Failure"]}

    risk = RiskScorer.calculate_risk(nlp_res, url_res, header_res)
    assert risk["risk_score"] > 65.0
    assert risk["risk_level"] in ["MEDIUM RISK", "HIGH / CRITICAL RISK"]
    assert len(risk["flags"]) == 3

def test_roberta_dual_engine_status():
    nlp = NLPEngine(model_path="app/models/phishing_model.pkl")
    status = nlp.get_status()
    assert "active_model" in status
    assert "fallback_available" in status

    # Test social engineering prediction
    text = "Please verify your employee portal credentials before end of day to prevent payroll delay."
    res = nlp.predict(text)
    assert res["score"] >= 15.0
    assert "model_used" in res

def test_legitimate_ecosystem_domains():
    """Verify authentic platform domains and status pages are NEVER flagged."""
    trusted_urls = [
        "https://www.githubstatus.com/",
        "https://github.com/Kidus-yahun",
        "https://raw.githubusercontent.com/README.md",
        "https://www.youtube.com/@veritasium",
        "https://statuspage.io",
        "https://discordstatus.com"
    ]
    for url in trusted_urls:
        result = URLAnalyzer.analyze_url(url)
        assert result["score"] == 0.0, f"False positive on legitimate domain: {url}"
        assert len(result["flags"]) == 0

def test_real_combosquatting_phishing():
    """Verify genuine combosquatting and typosquatting attacks are caught."""
    phishing_url = "http://github-account-verify.xyz/login"
    result = URLAnalyzer.analyze_url(phishing_url)
    assert result["score"] >= 50.0
    assert any("combosquatting" in f.lower() or "typosquatting" in f.lower() for f in result["flags"])

def test_laya_model_integration():
    """Verify Laya status and prediction capabilities in NLPEngine."""
    nlp = NLPEngine(model_path="app/models/phishing_model.pkl")
    status = nlp.get_status()
    assert "laya_ready" in status
    assert "fallback_available" in status

    # Test sub-second execution constraint
    import time
    t0 = time.perf_counter()
    res = nlp.predict("URGENT: Your account has been temporarily restricted. Verify credentials now.")
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.0  # Must be under 1 second
    assert res["score"] >= 30.0
    assert "model_used" in res

def test_legitimate_sites_no_false_positives():
    """Verify arbitrary legitimate sites outside hardcoded whitelists are never falsely flagged."""
    arbitrary_legit_sites = [
        "https://streamable.com/video123",
        "https://dribbble.com/shots/popular",
        "https://nytimes.com/tech",
        "https://addisfortune.news/business",
        "https://apple.com/iphone"
    ]
    for url in arbitrary_legit_sites:
        res = URLAnalyzer.analyze_url(url)
        assert res["score"] <= 20.0, f"False positive score on {url}: {res['score']}"
        assert not any("typosquatting" in f.lower() for f in res["flags"])

def test_laya_evaluate_url():
    """Verify autonomous Laya link verification and anchor precision."""
    nlp = NLPEngine(model_path="app/models/phishing_model.pkl")
    
    # Test legitimate URL evaluation
    legit_res = nlp.evaluate_url("https://dribbble.com/popular")
    assert not legit_res["is_phishing"]

    # Test legitimate software downloads and releases (no false positives)
    rufus_res = nlp.evaluate_url(
        "https://github.com/pbatard/rufus/releases/download/v4.15/rufus-4.15.exe",
        anchor_text="rufus-4.15.exe"
    )
    assert not rufus_res["is_phishing"], "Rufus download link must never be flagged as phishing"

    portable_res = nlp.evaluate_url(
        "https://github.com/pbatard/rufus/releases/download/v4.15/rufus-4.15p.exe",
        anchor_text="rufus-4.15p.exe"
    )
    assert not portable_res["is_phishing"], "Rufus portable link must never be flagged as phishing"

    # Test deceptive anchor text spoofing attack
    spoof_res = nlp.evaluate_url(
        "http://credential-stealer.xyz/login",
        anchor_text="https://www.google.com/security"
    )
    assert spoof_res["is_phishing"]
    assert spoof_res["score"] >= 75.0

    # Test obvious phishing URL evaluation
    phish_res = nlp.evaluate_url("http://paypa1-security-verification.xyz/login.php")
    assert phish_res["is_phishing"]
    assert phish_res["score"] >= 60.0


