import re
from typing import Optional, List
from urllib.parse import urlparse

import yaml

from nuclei_gen.parser.curl import CurlRequest
from nuclei_gen.parser.response import HttpResponse
from nuclei_gen.matchers.presets import PRESETS
from nuclei_gen.matchers.auto import extract_word_matchers


def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return re.sub(r"-+", "-", text).strip("-")


def build_template(
    request: CurlRequest,
    response: HttpResponse,
    name: str,
    severity: str,
    vuln_class: str,
    author: str = "nuclei-gen",
    description: str = "",
    extra_tags: Optional[List[str]] = None,
) -> dict:
    parsed = urlparse(request.url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    preset = PRESETS.get(vuln_class, PRESETS["misconfig"])
    tags = list(preset["tags"])
    if extra_tags:
        tags += [t for t in extra_tags if t not in tags]

    # --- HTTP block ---
    http_block: dict = {
        "method": request.method,
        "path": [f"{{{{BaseURL}}}}{path}"],
    }

    filtered_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host",)
    }
    if filtered_headers:
        http_block["headers"] = filtered_headers

    if request.body:
        http_block["body"] = request.body

    # --- Matchers ---
    matchers = []

    # 1. Status code
    if vuln_class == "open-redirect":
        matchers.append({"type": "status", "status": [301, 302, 303, 307, 308]})
    else:
        matchers.append({"type": "status", "status": [response.status_code]})

    # 2. Word matchers from response body
    if vuln_class not in ("ssrf", "open-redirect"):
        words = extract_word_matchers(response.body)
        if words:
            matchers.append({
                "type": "word",
                "words": words,
                "part": "body",
                "condition": "and",
            })

    # 3. Preset-specific matchers
    for m in preset.get("extra_matchers", []):
        if m not in matchers:
            matchers.append(m)

    if len(matchers) > 1:
        http_block["matchers-condition"] = "and"
    http_block["matchers"] = matchers

    template = {
        "id": slugify(name),
        "info": {
            "name": name,
            "author": author,
            "severity": severity,
            "description": description or preset.get("description", ""),
            "tags": ",".join(tags),
        },
        "http": [http_block],
    }

    return template


def render_yaml(template: dict) -> str:
    class _Dumper(yaml.Dumper):
        pass

    def _str_representer(dumper, data):
        if "\n" in data or data.startswith("{") or data.startswith("["):
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)

    _Dumper.add_representer(str, _str_representer)

    return yaml.dump(
        template,
        Dumper=_Dumper,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
