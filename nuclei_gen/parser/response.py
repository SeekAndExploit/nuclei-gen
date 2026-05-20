import re
from dataclasses import dataclass, field


@dataclass
class HttpResponse:
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    body: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type


def parse_response(text: str) -> HttpResponse:
    resp = HttpResponse()

    if not text.strip():
        return resp

    lines = text.split("\n")
    first = lines[0].strip()

    if re.match(r"HTTP/[\d.]+ \d+", first):
        m = re.match(r"HTTP/[\d.]+ (\d+)", first)
        if m:
            resp.status_code = int(m.group(1))

        i = 1
        while i < len(lines) and lines[i].strip():
            line = lines[i].strip()
            if ":" in line:
                key, _, val = line.partition(":")
                resp.headers[key.strip().lower()] = val.strip()
            i += 1

        resp.body = "\n".join(lines[i + 1:]).strip()
    else:
        resp.body = text.strip()

    return resp
