"""Phishing URL analyzer.

Offline, heuristic-first analysis. The analyzer NEVER fetches the submitted
URL (no unsafe visit). It inspects structure, punycode/encodings, look-alike
domains (edit distance to known brands), suspicious TLDs, IP literals,
credential-collection keywords, and optionally queries local threat
intelligence. Verdicts: SAFE | SUSPICIOUS | MALICIOUS with evidence.
"""
import ipaddress
import re
import unicodedata
from difflib import SequenceMatcher
from urllib.parse import parse_qs, unquote, urlparse

from app import db, threat_intel
from app.core.config import settings

_URL_RE = re.compile(
    r"^https?://"                 # scheme
    r"[a-zA-Z0-9]"               # must start with alphanumeric
    r"[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]*$"  # valid URL chars
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z]{2,}$"
)


def validate_url_format(raw: str) -> str | None:
    """Return None if valid, or an error message if invalid."""
    url = raw.strip()
    if not url:
        return "Empty input. Please enter a URL."

    has_scheme = url.startswith("http://") or url.startswith("https://")

    if has_scheme:
        parsed = urlparse(url)
        if not parsed.hostname:
            return "Invalid URL format. Please enter a valid URL."
        if not _DOMAIN_RE.match(parsed.hostname) and not _is_ip_literal(parsed.hostname):
            return "Invalid URL format. Please enter a valid URL."
        return None

    # No scheme: treat as domain-only input (e.g., "example.com")
    if " " in url and not url.startswith("http"):
        return "Invalid URL format. Please enter a valid URL."
    candidate = url.split("/")[0].split("?")[0].split("#")[0]
    if ("." in candidate) and (_DOMAIN_RE.match(candidate) or _is_ip_literal(candidate)):
        return None

    return "Invalid URL format. Please enter a valid URL."


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

KNOWN_BRANDS = [
    "paypal", "apple", "icloud", "microsoft", "office", "outlook", "amazon",
    "google", "gmail", "facebook", "netflix", "linkedin", "dropbox", "github",
    "instagram", "twitter", "chase", "wellsfargo", "bankofamerica", "citibank",
    "hsbc", "barclays", "payoneer", "stripe", "coinbase", "binance", "roblox",
    "steam", "epicgames", "xbox", "playstation", "ebay", "adobe", "whatsapp",
    "dhl", "fedex", "ups", "usps", "at&t", "verizon",
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "link", "tk", "ml", "ga", "cf", "gq", "xyz",
    "top", "club", "online", "site", "stream", "icu", "work", "review",
    "country", "download", "racing", "kim", "men", "loan", "win", "bid",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "soo.gd", "s.id",
    "kutt.it", "tiny.cc", "qrco.de", "s.shopee.ph", "shope.ee", "rb.gy",
    "t.ly", "lnkd.in", "cutt.us",
}

CREDENTIAL_KEYWORDS = re.compile(
    r"(login|signin|sign-in|verify|verification|account|password|secure|update|confirm|unlock|billing|credential)", re.IGNORECASE
)
SENSITIVE_PARAM = re.compile(r"(password|passwd|pwd|token|credit|card|cvv|pin|ssn|account)", re.IGNORECASE)
HEX_HOST = re.compile(r"^[0-9a-f]{6,}$")
HOMOGLYPH = {"0": "o", "1": "l", "5": "s", "3": "e", "8": "b", "7": "t", "4": "a"}


def _normalize_for_brand(domain: str) -> str:
    return unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode().lower()


def _lookalike(host: str) -> list[str]:
    core = host
    if core.startswith("www."):
        core = core[4:]
    # Try stripping a trailing TLD
    core_name = core.split(".")[0] if "." in core else core
    norm = _normalize_for_brand(core_name)
    # homoglyph substitution
    subs = "".join(HOMOGLYPH.get(ch, ch) for ch in norm)
    matches = []
    for brand in KNOWN_BRANDS:
        if brand in norm:
            matches.append(brand)
        elif SequenceMatcher(None, norm, brand).ratio() >= 0.75:
            matches.append(brand)
        elif subs and SequenceMatcher(None, subs, brand).ratio() >= 0.85:
            matches.append(brand)
    return list(dict.fromkeys(matches))


def _domain_age_hint(host: str) -> str | None:
    # Heuristic only: hex-ish or numeric-heavy subdomains are common on
    # disposable/phishing infrastructure. Not a definitive age check.
    if re.search(r"(([0-9]{5,}))", host):
        return "numeric-heavy domain component"
    if HEX_HOST.match(host.split(".")[0]):
        return "hex-like subdomain"
    return None


def analyze(url: str) -> dict:
    """Analyze a URL and return verdict, risk score, and evidence reasons."""
    if not settings.PHISHING_ENABLED:
        return {"verdict": "UNKNOWN", "risk_score": 0, "reasons": ["Phishing analysis disabled"], "redirects": []}

    url = url.strip()

    # Strict format validation — reject non-URLs
    validation_error = validate_url_format(url)
    if validation_error:
        return {"verdict": "ERROR", "risk_score": 0, "reasons": [validation_error], "redirects": []}

    # Ensure URL has a scheme for parsing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    reasons: list[dict] = []
    score = 0

    parsed = urlparse(unquote(url))
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port

    if not host:
        return {"verdict": "ERROR", "risk_score": 0, "reasons": ["Unable to extract hostname from URL"], "redirects": []}

    # 1. Non-standard port
    if port and port not in (80, 443):
        reasons.append({"reason": "Non-standard port", "weight": 15})
        score += 15

    # 2. IP-literal host
    try:
        ipaddress.ip_address(host)
        reasons.append({"reason": "URL uses a raw IP address as hostname", "weight": 30})
        score += 30
    except ValueError:
        pass

    # 3. Suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append({"reason": f"Suspicious top-level domain '.{tld}'", "weight": 20})
        score += 20

    # 4. Look-alike brand domains
    lookalikes = _lookalike(host)
    brand_in_domain = any(b in host.lower() for b in KNOWN_BRANDS)
    if lookalikes and not brand_in_domain:
        reasons.append({"reason": f"Look-alike domain of: {', '.join(lookalikes[:3])}", "weight": 45})
        score += 45
    elif lookalikes and brand_in_domain:
        # Brand is literally present but mixed with other brand names.
        if len(lookalikes) > 1:
            reasons.append({"reason": "Multiple brand references in one hostname", "weight": 25})
            score += 25

    # 5. Punycode / encoded hostname
    if host.startswith("xn--"):
        reasons.append({"reason": "Punycode-encoded hostname (possible IDN spoofing)", "weight": 35})
        score += 35

    # 6. '@' trick (userinfo before host)
    if "@" in url.split("://")[-1].split("/")[0]:
        reasons.append({"reason": "Userinfo '@' obfuscation in host portion", "weight": 25})
        score += 25

    # 7. URL shortener
    if host in SHORTENERS or any(h in host for h in SHORTENERS):
        reasons.append({"reason": f"URL shortening service ({host})", "weight": 15})
        score += 15

    # 8. Credential-collection path / query
    if CREDENTIAL_KEYWORDS.search(parsed.path + parsed.query):
        reasons.append({"reason": "Credential-collection indicators in path/query", "weight": 20})
        score += 20

    # 9. Sensitive parameter names in query
    qs = parse_qs(parsed.query)
    if any(SENSITIVE_PARAM.search(k) for k in qs):
        reasons.append({"reason": "Sensitive parameter names in query string", "weight": 15})
        score += 15

    # 10. Domain age heuristic
    hint = _domain_age_hint(host)
    if hint:
        reasons.append({"reason": hint, "weight": 15})
        score += 15

    # 11. Subdomain count / suspicious subdomain structure
    labels = host.split(".")
    if len(labels) >= 4:
        reasons.append({"reason": "Many subdomain labels", "weight": 10})
        score += 10

    # 12. Encoded characters
    if url != urlparse(url).geturl() and "%" in url:
        if re.search(r"%(25|2e|2f|2e|40|3f|26)", url, re.IGNORECASE):
            reasons.append({"reason": "Encoded characters in URL", "weight": 10})
            score += 10

    # 13. Local / remote threat intelligence
    ti = threat_intel.lookup("url", url)
    if ti and ti.get("verdict") == "malicious":
        reasons.append({"reason": f"Known malicious per threat intelligence ({ti.get('source')})", "weight": 60})
        score += 60
    elif ti and ti.get("verdict") == "unknown" and ti.get("source") != "none":
        reasons.append({"reason": f"Threat intelligence check completed ({ti.get('source')})", "weight": 0})
    domain_ti = threat_intel.lookup("domain", host)
    if domain_ti and domain_ti.get("verdict") == "malicious":
        reasons.append({"reason": f"Domain known malicious per threat intelligence ({domain_ti.get('source')})", "weight": 50})
        score += 50

    # Verdict
    score = min(100, score)
    if score >= 60:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "url": url,
        "host": host,
        "verdict": verdict,
        "risk_score": score,
        "confidence": round(min(0.99, 0.5 + score / 200), 2),
        "reasons": [r["reason"] for r in sorted(reasons, key=lambda x: -x["weight"])],
        "redirects": [],  # never followed
    }


def analyze_and_store(url: str, scanner_ip: str = "") -> dict:
    result = analyze(url)
    db.save_phishing_scan({
        "url": url,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "reasons": result["reasons"],
        "redirects": result["redirects"],
        "scanner_ip": scanner_ip,
    })
    return result
