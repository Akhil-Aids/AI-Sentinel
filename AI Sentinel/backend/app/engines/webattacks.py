"""Web attack pattern detection (OWASP-aligned heuristics).

Patterns are defensive heuristics on real request content. Every match returns
the pattern family plus the exact substring matched, so detections are
explainable and auditable.
"""
import re
from urllib.parse import unquote

SQLI_PATTERNS = [
    (r"(\%27)|(\')|(\\')", "sql:single-quote"),
    (r"(\%22)|(\")", "sql:double-quote"),
    (r"(\%3B)|(;)", "sql:semicolon"),
    (r"union(\%20|\s)+all?(\%20|\s)+select", "sql:union-select"),
    (r"(\%09|\%0A|\%0B|\%0C|\%0D|\s)+select(\%20|\s)+.*from", "sql:select-from"),
    (r"or(\%20|\s)+1(\%20|\s)*=(\%20|\s)*1", "sql:or-1=1"),
    (r"'(\%20|\s)*or(\%20|\s)*'", "sql:quote-or-quote"),
    (r"information_schema", "sql:information-schema"),
    (r"sleep\(|benchmark\(|pg_sleep\(|waitfor(\%20|\s)+delay", "sql:time-based"),
    (r"--(\%20|\s)?$|-{2,}", "sql:comment-injection"),
]

XSS_PATTERNS = [
    (r"<script", "xss:script-tag"),
    (r"javascript:", "xss:javascript-uri"),
    (r"onerror=.*\(", "xss:onerror"),
    (r"onload=.*\(", "xss:onload"),
    (r"<img[^>]+src=.*(onerror|onload)", "xss:img-event"),
    (r"document\.cookie", "xss:document-cookie"),
    (r"<iframe", "xss:iframe"),
    (r"prompt\(|alert\(|confirm\(", "xss:js-function"),
    (r"(\%3C)script", "xss:encoded-script"),
]

CMD_INJECTION_PATTERNS = [
    (r"(;|\||&&|&&?)(\s*)(cmd|sh|bash|powershell|wget|curl|nc|netcat|python|perl|ruby)", "cmd:shell-chain"),
    (r"`.*`", "cmd:backtick"),
    (r"\$\(.*\)", "cmd:command-substitution"),
    (r"(/bin/|/usr/bin/)(sh|bash|cmd)", "cmd:shell-path"),
    (r"(ping|traceroute|nslookup|whoami|id;|cat\s+/etc/passwd)", "cmd:common-utility"),
    (r"%0a|%0d", "cmd:encoded-newline"),
]

TRAVERSAL_PATTERNS = [
    (r"(\.\./)+", "traversal:dotdot-slash"),
    (r"(\.\.\\)+", "traversal:dotdot-backslash"),
    (r"(\%2e\%2e\%)+", "traversal:encoded-dotdot"),
    (r"(\%252e)+", "traversal:double-encoded"),
    (r"(/etc/passwd|/etc/shadow|/proc/self/environ)", "traversal:etc-files"),
    (r"(c:\\|C:/|file:///)", "traversal:absolute-path"),
]


def _scan_patterns(value: str, patterns: list[tuple[str, str]]) -> list[str]:
    found = []
    for pattern, label in patterns:
        if re.search(pattern, value, re.IGNORECASE):
            found.append(label)
    return found


def analyze_web_request(method: str, path: str, query: str, body: str, headers: str = "") -> list[dict]:
    """Analyze a real web request; return list of matched detections."""
    raw = " ".join([method or "", path or "", query or "", body or "", headers or ""])
    decoded = unquote(raw)
    detections = []

    for label in _scan_patterns(decoded, SQLI_PATTERNS):
        detections.append({"kind": "sql_injection", "pattern": label, "score": 0.9})
    for label in _scan_patterns(decoded, XSS_PATTERNS):
        detections.append({"kind": "xss", "pattern": label, "score": 0.8})
    for label in _scan_patterns(decoded, CMD_INJECTION_PATTERNS):
        detections.append({"kind": "command_injection", "pattern": label, "score": 0.9})
    for label in _scan_patterns(decoded, TRAVERSAL_PATTERNS):
        detections.append({"kind": "path_traversal", "pattern": label, "score": 0.8})

    # Deduplicate: keep the highest-score match per kind.
    best: dict[str, dict] = {}
    for d in detections:
        if d["kind"] not in best or d["score"] > best[d["kind"]]["score"]:
            best[d["kind"]] = d
    return list(best.values())
