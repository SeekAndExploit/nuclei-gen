import re
from typing import List, Tuple

SENSITIVE_PATTERNS: List[Tuple[str, str]] = [
    (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "JWT token"),
    (r'"(?:access_?token|token|id_token)"\s*:\s*"[^"]{10,}"', "auth token field"),
    (r'"(?:api_?key|apikey|api_secret)"\s*:\s*"[^"]{8,}"', "API key field"),
    (r'"(?:secret|client_secret)"\s*:\s*"[^"]{8,}"', "secret field"),
    (r'"password"\s*:\s*"[^"]*"', "password field"),
    (r'"refresh_?token"\s*:\s*"[^"]{8,}"', "refresh token"),
    (r'"setup[-_]?token"\s*:\s*"[^"]{8,}"', "setup token"),
    (r'\b[0-9a-f]{40}\b', "git SHA / hash (40-char)"),
    (r'"(?:git_?sha|commit|revision)"\s*:\s*"[^"]{7,}"', "git SHA field"),
    (r'"(?:db_?version|database_version|schema_version)"\s*:\s*"[^"]*"', "database version"),
    (r'"(?:pod_?name|node_?name|hostname)"\s*:\s*"[^"]*"', "k8s / host metadata"),
    (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "internal IP (10.x.x.x)"),
    (r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', "internal IP (172.16-31.x.x)"),
    (r'192\.168\.\d{1,3}\.\d{1,3}', "internal IP (192.168.x.x)"),
    (r'AKIA[0-9A-Z]{16}', "AWS access key"),
    (r'"version"\s*:\s*"\d+\.\d+[\.\d]*[^"]*"', "version string"),
    (r'at\s+\w+\.\w+\s*\(.*\.(?:py|js|java|rb|go):\d+\)', "stack trace line"),
    (r'webpack://[^\s"]+', "webpack internal path"),
    (r'"(?:SELECT|INSERT|UPDATE|DELETE)\s', "SQL query in response (case-sensitive)"),
]

DEBUG_PATTERNS = [
    "stack trace", "traceback (most recent", "at line ",
    "undefined method", "nullpointerexception", "cannot read properties of",
    "typeerror:", "referenceerror:", "syntaxerror:",
    "webpack://", "node_modules/",
    "you have an error in your sql",
    "pg_query()", "sqlite3.operationalerror",
]


def extract_word_matchers(body: str, limit: int = 4) -> List[str]:
    if not body:
        return []

    words = []

    # Short unique strings that appear as JSON values — good matchers
    candidates = re.findall(r'"([a-z_]{4,25})"\s*:\s*(?:true|false|"[^"]{1,80}"|\d+)', body, re.IGNORECASE)
    skip = {
        "type", "code", "message", "error", "data", "id", "name",
        "status", "result", "response", "value", "key", "item",
        "true", "false", "null",
    }
    for c in candidates:
        if c.lower() not in skip and c not in words:
            words.append(c)
        if len(words) >= limit:
            break

    return words


def detect_sensitive(body: str) -> List[str]:
    found = []
    for pattern, label in SENSITIVE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            found.append(label)
    return found


def detect_debug(body: str) -> List[str]:
    lower = body.lower()
    return [p for p in DEBUG_PATTERNS if p in lower]
