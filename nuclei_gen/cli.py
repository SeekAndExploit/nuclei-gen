import argparse
import sys

from nuclei_gen.parser.curl import parse_curl
from nuclei_gen.parser.response import parse_response
from nuclei_gen.matchers.auto import detect_sensitive, detect_debug
from nuclei_gen.matchers.presets import PRESETS
from nuclei_gen.generator.template import build_template, render_yaml

SEVERITIES = ["critical", "high", "medium", "low", "info"]
VULN_CLASSES = list(PRESETS.keys())


def parse_raw_request(text: str):
    from nuclei_gen.parser.curl import CurlRequest
    lines = text.strip().split("\n")
    req = CurlRequest()

    if not lines:
        return req

    # Request line: METHOD /path HTTP/1.1
    parts = lines[0].strip().split()
    if len(parts) >= 2:
        req.method = parts[0].upper()
        path = parts[1]

    host = ""
    i = 1
    while i < len(lines) and lines[i].strip():
        line = lines[i].strip()
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if k.lower() == "host":
                host = v
            else:
                req.headers[k] = v
        i += 1

    body_lines = lines[i + 1:] if i + 1 < len(lines) else []
    req.body = "\n".join(body_lines).strip() or None

    if host:
        scheme = "https" if "443" in host or not ":" in host else "http"
        req.url = f"{scheme}://{host}{path}"

    return req


def main():
    ap = argparse.ArgumentParser(
        prog="nuclei-gen",
        description="Generate nuclei YAML templates from a curl command + HTTP response",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Vulnerability classes: {', '.join(VULN_CLASSES)}",
    )

    inp = ap.add_mutually_exclusive_group(required=True)
    inp.add_argument("--curl", metavar="CMD", help="curl command (quoted string)")
    inp.add_argument("--request", metavar="FILE", help="raw HTTP request file (Burp-style)")

    ap.add_argument("--response", required=True, metavar="FILE",
                    help="HTTP response file (full HTTP/1.1 response or body-only)")
    ap.add_argument("--name", required=True, metavar="NAME",
                    help="Template name, e.g. 'password-reset-no-auth'")
    ap.add_argument("--severity", required=True, choices=SEVERITIES)
    ap.add_argument("--class", dest="vuln_class", required=True,
                    choices=VULN_CLASSES, metavar="CLASS")
    ap.add_argument("--author", default="nuclei-gen", metavar="AUTHOR")
    ap.add_argument("--description", default="", metavar="TEXT")
    ap.add_argument("--tags", default="", metavar="tag1,tag2",
                    help="Extra comma-separated tags")
    ap.add_argument("--output", "-o", metavar="FILE",
                    help="Output file (default: <id>.yaml)")

    args = ap.parse_args()

    # Parse request
    if args.curl:
        req = parse_curl(args.curl)
    else:
        with open(args.request) as f:
            req = parse_raw_request(f.read())

    if not req.url:
        ap.error("Could not extract URL from input")

    # Parse response
    try:
        with open(args.response) as f:
            resp = parse_response(f.read())
    except FileNotFoundError:
        ap.error(
            f"Response file not found: {args.response}\n"
            "  Save the HTTP response to a file first, e.g.:\n"
            "    curl -i https://target.com/api/endpoint > resp.txt\n"
            "  Or check examples/ for sample response files."
        )

    # Analysis hints
    sensitive = detect_sensitive(resp.body)
    debug = detect_debug(resp.body)
    if sensitive:
        print(f"[+] Sensitive patterns in response: {', '.join(sensitive)}")
    if debug:
        print(f"[!] Debug/error patterns in response: {', '.join(debug)}")

    extra_tags = [t.strip() for t in args.tags.split(",") if t.strip()]

    template = build_template(
        request=req,
        response=resp,
        name=args.name,
        severity=args.severity,
        vuln_class=args.vuln_class,
        author=args.author,
        description=args.description,
        extra_tags=extra_tags,
    )

    output = render_yaml(template)
    outfile = args.output or f"{template['id']}.yaml"

    with open(outfile, "w") as f:
        f.write(output)

    print(f"[+] Template → {outfile}\n")
    print(output)


if __name__ == "__main__":
    main()
