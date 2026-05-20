PRESETS = {
    "auth-bypass": {
        "tags": ["misconfig", "auth-bypass"],
        "description": "Authentication bypass — protected endpoint accessible without credentials",
        "extra_matchers": [],
    },
    "unauth-access": {
        "tags": ["misconfig", "unauth"],
        "description": "Unauthenticated access to internal or sensitive endpoint",
        "extra_matchers": [],
    },
    "idor": {
        "tags": ["idor", "auth"],
        "description": "Insecure Direct Object Reference — access to another user's resources",
        "extra_matchers": [],
    },
    "info-disclosure": {
        "tags": ["exposure", "info-disclosure"],
        "description": "Sensitive information disclosed in response",
        "extra_matchers": [],
    },
    "sqli": {
        "tags": ["sqli", "injection"],
        "description": "SQL injection — database error strings reflected in response",
        "extra_matchers": [
            {
                "type": "word",
                "words": [
                    "you have an error in your sql syntax",
                    "mysql_fetch_array()",
                    "ORA-01756",
                    "SQLiteException",
                    "pg_query()",
                    "unterminated quoted string at or near",
                    "syntax error at or near",
                    "SQLSTATE[42000]",
                ],
                "part": "body",
                "condition": "or",
                "case-insensitive": True,
            }
        ],
    },
    "ssrf": {
        "tags": ["ssrf", "oob"],
        "description": "Server-Side Request Forgery — confirmed via out-of-band callback",
        "extra_matchers": [
            {
                "type": "word",
                "words": ["{{interactsh-url}}"],
                "part": "interactsh_protocol",
            }
        ],
    },
    "xss": {
        "tags": ["xss", "injection"],
        "description": "Cross-Site Scripting — user input reflected unsanitised in response",
        "extra_matchers": [],
    },
    "ssti": {
        "tags": ["ssti", "injection"],
        "description": "Server-Side Template Injection — template expression evaluated in response",
        "extra_matchers": [
            {
                "type": "word",
                "words": ["49"],
                "part": "body",
                "comment": "7*7 evaluation result",
            }
        ],
    },
    "open-redirect": {
        "tags": ["redirect", "open-redirect"],
        "description": "Open redirect — Location header points to attacker-controlled domain",
        "extra_matchers": [
            {
                "type": "status",
                "status": [301, 302, 303, 307, 308],
            },
            {
                "type": "regex",
                "regex": ["(?i)^https?://(?!.*\\.example\\.com)"],
                "part": "header",
                "name": "location",
            },
        ],
    },
    "misconfig": {
        "tags": ["misconfig"],
        "description": "Security misconfiguration",
        "extra_matchers": [],
    },
    "cve": {
        "tags": ["cve"],
        "description": "Known CVE exploit",
        "extra_matchers": [],
    },
}
