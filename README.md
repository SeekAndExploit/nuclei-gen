# nuclei-gen

Generate [nuclei](https://github.com/projectdiscovery/nuclei) YAML templates from a curl command + HTTP response. No AI, no API keys, no internet connection required — pure deterministic parsing.

## Install

```bash
git clone https://github.com/yourname/nuclei-gen
cd nuclei-gen
pip install -e .
```

## Usage

### From a curl command

```bash
nuclei-gen \
  --curl 'curl -X POST https://target.com/internal/server/store \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"attacker.com\",\"token\":\"forged\"}"' \
  --response response.txt \
  --name "internal-server-store-unauth" \
  --severity high \
  --class unauth-access
```

### From a Burp Suite raw request

```bash
nuclei-gen \
  --request request.txt \
  --response response.txt \
  --name "password-reset-no-token-validation" \
  --severity high \
  --class auth-bypass \
  --tags "account-takeover"
```

### Response file format

Either a full HTTP response (with status line + headers):

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status":"ok","token":"abc123"}
```

Or just the body — nuclei-gen assumes HTTP 200 if there's no status line.

## What it generates

```yaml
id: internal-server-store-unauth
info:
  name: internal-server-store-unauth
  author: nuclei-gen
  severity: high
  description: Unauthenticated access to internal or sensitive endpoint
  tags: misconfig,unauth
http:
- method: POST
  path:
  - '{{BaseURL}}/internal/server/store'
  headers:
    Content-Type: application/json
  body: '{"hostname":"attacker.com","token":"forged"}'
  matchers:
  - type: status
    status:
    - 200
```

## Vuln classes

| Class | Tags | Preset matchers |
|---|---|---|
| `auth-bypass` | misconfig, auth-bypass | status code |
| `unauth-access` | misconfig, unauth | status code |
| `idor` | idor, auth | status code + body words |
| `info-disclosure` | exposure, info-disclosure | status code + body words |
| `sqli` | sqli, injection | status code + DB error strings |
| `ssrf` | ssrf, oob | interactsh OOB matcher |
| `xss` | xss, injection | status code + body words |
| `ssti` | ssti, injection | status code + `49` (7*7) |
| `open-redirect` | redirect, open-redirect | 3xx status + Location regex |
| `misconfig` | misconfig | status code |
| `cve` | cve | status code |

## Auto-detection

nuclei-gen analyzes the response body and prints hints before generating:

```
[+] Sensitive patterns in response: JWT token, auth token field, refresh token
[!] Debug/error patterns in response: stack trace, webpack://
```

Detected patterns are used to generate stronger word matchers automatically.

## Options

```
--curl CMD          curl command (quoted)
--request FILE      raw HTTP request file (Burp-style)
--response FILE     HTTP response file
--name NAME         template name
--severity          critical | high | medium | low | info
--class CLASS       vulnerability class (see table above)
--author AUTHOR     author field (default: nuclei-gen)
--description TEXT  override auto-description
--tags tag1,tag2    extra tags to append
--output / -o FILE  output file (default: <id>.yaml)
```

## Run tests

```bash
python tests/test_curl_parser.py
python tests/test_generator.py
```
