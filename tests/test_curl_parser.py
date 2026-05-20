import sys
sys.path.insert(0, "/home/kali/nuclei-gen")

from nuclei_gen.parser.curl import parse_curl


def test_basic_post():
    req = parse_curl('curl -X POST https://target.com/api/reset -H "Content-Type: application/json" -d \'{"email":"x"}\'')
    assert req.method == "POST"
    assert req.url == "https://target.com/api/reset"
    assert req.headers["Content-Type"] == "application/json"
    assert req.body == '{"email":"x"}'
    assert req.path == "/api/reset"


def test_implicit_post_from_data():
    req = parse_curl('curl https://target.com/login -d "user=a&pass=b"')
    assert req.method == "POST"
    assert req.body == "user=a&pass=b"


def test_path_with_query():
    req = parse_curl('curl "https://api.example.com/v1/users?page=2&limit=10"')
    assert req.path == "/v1/users?page=2&limit=10"


def test_multiple_headers():
    req = parse_curl(
        'curl https://target.com/api '
        '-H "Authorization: Bearer abc123" '
        '-H "X-Custom: value"'
    )
    assert req.headers["Authorization"] == "Bearer abc123"
    assert req.headers["X-Custom"] == "value"


def test_host_parsed_but_filtered_by_generator():
    # Parser stores Host; generator drops it (nuclei handles Host automatically)
    req = parse_curl('curl -H "Host: target.com" -H "X-Foo: bar" https://target.com/path')
    assert req.headers["X-Foo"] == "bar"
    assert req.headers.get("Host") == "target.com"


def test_multiline_curl():
    cmd = 'curl -X POST https://target.com/api \\\n  -H "Content-Type: application/json" \\\n  -d \'{"key":"val"}\''
    req = parse_curl(cmd)
    assert req.method == "POST"
    assert req.body == '{"key":"val"}'


def test_cookie_merges_into_header():
    req = parse_curl('curl -b "session=abc; user=123" https://target.com/')
    assert "Cookie" in req.headers
    assert "session=abc" in req.headers["Cookie"]


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
