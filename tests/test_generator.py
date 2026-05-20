import sys
sys.path.insert(0, "/home/kali/nuclei-gen")

import yaml
from nuclei_gen.parser.curl import parse_curl
from nuclei_gen.parser.response import parse_response
from nuclei_gen.generator.template import build_template, render_yaml


def _make(curl_cmd, resp_text, vuln_class="unauth-access", severity="high", name="test-finding"):
    req = parse_curl(curl_cmd)
    resp = parse_response(resp_text)
    return build_template(req, resp, name=name, severity=severity, vuln_class=vuln_class)


def test_template_has_required_keys():
    t = _make('curl -X POST https://t.com/api', 'HTTP/1.1 200 OK\n\n{"ok":true}')
    assert "id" in t
    assert "info" in t
    assert "http" in t


def test_id_is_slugified():
    t = _make('curl https://t.com/', 'HTTP/1.1 200 OK\n\n{}', name="Password Reset No Auth Check")
    assert t["id"] == "password-reset-no-auth-check"
    assert " " not in t["id"]


def test_status_matcher_uses_response_code():
    t = _make('curl https://t.com/', 'HTTP/1.1 403 Forbidden\n\ndenied', name="x")
    matchers = t["http"][0]["matchers"]
    status_m = next(m for m in matchers if m["type"] == "status")
    assert 403 in status_m["status"]


def test_body_word_matchers_extracted():
    resp = 'HTTP/1.1 200 OK\n\n{"accessToken":"eyJabc","refreshToken":"eyJxyz","email":"user@x.com"}'
    t = _make('curl https://t.com/token', resp, name="token-leak")
    matchers = t["http"][0]["matchers"]
    word_m = next((m for m in matchers if m["type"] == "word"), None)
    assert word_m is not None
    assert any("Token" in w or "token" in w for w in word_m["words"])


def test_ssrf_has_interactsh_matcher():
    t = _make('curl -X POST https://t.com/fetch -d \'{"url":"http://evil.com"}\'',
              'HTTP/1.1 200 OK\n\n{"status":"fetched"}',
              vuln_class="ssrf", name="ssrf-fetch")
    matchers = t["http"][0]["matchers"]
    interactsh_m = next((m for m in matchers if "interactsh" in str(m.get("words", ""))), None)
    assert interactsh_m is not None


def test_path_includes_base_url_placeholder():
    t = _make('curl https://target.com/internal/reset', 'HTTP/1.1 200 OK\n\n{}', name="x")
    path = t["http"][0]["path"][0]
    assert path.startswith("{{BaseURL}}")
    assert "/internal/reset" in path


def test_render_is_valid_yaml():
    t = _make('curl -X POST https://t.com/api -d \'{"x":1}\'', 'HTTP/1.1 200 OK\n\n{}', name="valid-yaml-test")
    raw = render_yaml(t)
    parsed = yaml.safe_load(raw)
    assert parsed["id"] == "valid-yaml-test"


def test_extra_tags_appended():
    req = parse_curl('curl https://t.com/api')
    resp = parse_response('HTTP/1.1 200 OK\n\n{}')
    t = build_template(req, resp, name="x", severity="medium", vuln_class="misconfig",
                       extra_tags=["smtp", "cpanel"])
    assert "smtp" in t["info"]["tags"]
    assert "cpanel" in t["info"]["tags"]


def test_host_header_excluded_from_template():
    req = parse_curl('curl -H "Host: target.com" -H "X-Custom: val" https://target.com/path')
    resp = parse_response('HTTP/1.1 200 OK\n\n{}')
    t = build_template(req, resp, name="x", severity="low", vuln_class="misconfig")
    headers = t["http"][0].get("headers", {})
    assert "Host" not in headers
    assert headers.get("X-Custom") == "val"


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
