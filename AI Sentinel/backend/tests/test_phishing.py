"""Phishing analyzer unit tests."""
from app.phishing.analyzer import analyze


def _analyze(url):
    return analyze(url)


def test_safe_url():
    r = _analyze("https://www.python.org/downloads/")
    assert r["verdict"] == "SAFE"
    assert r["risk_score"] == 0


def test_obvious_phish():
    r = _analyze("https://paypal-account-verify.info/login/verify.php?email=a%40b.com&password=x")
    assert r["verdict"] == "MALICIOUS"
    assert r["risk_score"] >= 60
    assert r["reasons"]


def test_suspicious_ip_link():
    r = _analyze("https://203.0.113.77/")
    assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert r["risk_score"] >= 25
    assert any("IP address" in reason for reason in r["reasons"])


def test_brand_in_domain_is_not_phishy_alone():
    r = _analyze("https://www.paypal.com/signin")
    assert r["verdict"] == "SAFE"


def test_malformed_url_returns_verdict():
    r = _analyze("not-a-url")
    assert r["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")
