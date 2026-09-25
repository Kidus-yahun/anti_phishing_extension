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
