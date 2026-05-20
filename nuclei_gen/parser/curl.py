import shlex
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class CurlRequest:
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    cookies: dict = field(default_factory=dict)

    @property
    def path(self) -> str:
        parsed = urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        return path

    @property
    def base_url(self) -> str:
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"


def parse_curl(curl_command: str) -> CurlRequest:
    curl_command = re.sub(r"\\\s*\n", " ", curl_command)

    try:
        tokens = shlex.split(curl_command)
    except ValueError:
        tokens = curl_command.split()

    req = CurlRequest()
    i = 1 if tokens and tokens[0].lower() == "curl" else 0

    SKIP_FLAGS = {
        "-L", "--location", "-k", "--insecure", "-s", "--silent",
        "-v", "--verbose", "-i", "--include", "-g", "--globoff",
        "--compressed", "--http2", "--http1.1",
    }

    SKIP_ARG_FLAGS = {
        "--max-time", "--connect-timeout", "--retry", "--limit-rate",
        "--proxy", "-x", "--output", "-o", "--cert", "--key",
        "--cacert", "--capath", "-A", "--user-agent",
    }

    while i < len(tokens):
        t = tokens[i]

        if t in ("-X", "--request") and i + 1 < len(tokens):
            req.method = tokens[i + 1].upper()
            i += 2
        elif t in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                key, _, val = raw.partition(":")
                req.headers[key.strip()] = val.strip()
            i += 2
        elif t in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode") and i + 1 < len(tokens):
            req.body = tokens[i + 1]
            if req.method == "GET":
                req.method = "POST"
            i += 2
        elif t in ("-b", "--cookie") and i + 1 < len(tokens):
            for pair in tokens[i + 1].split(";"):
                pair = pair.strip()
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    req.cookies[k.strip()] = v.strip()
            i += 2
        elif t in ("-u", "--user") and i + 1 < len(tokens):
            import base64
            req.headers["Authorization"] = "Basic " + base64.b64encode(tokens[i + 1].encode()).decode()
            i += 2
        elif t in SKIP_FLAGS:
            i += 1
        elif t in SKIP_ARG_FLAGS and i + 1 < len(tokens):
            i += 2
        elif t.startswith(("http://", "https://")):
            req.url = t
            i += 1
        elif not t.startswith("-"):
            if not req.url:
                req.url = t
            i += 1
        else:
            i += 1

    # Merge cookies into Cookie header
    if req.cookies and "Cookie" not in req.headers:
        req.headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in req.cookies.items())

    return req
