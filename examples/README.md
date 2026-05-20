# Examples

Sample response files and commands to try nuclei-gen immediately after cloning.

## Unauthenticated access

```bash
nuclei-gen \
  --curl 'curl -X POST https://api.target.com/internal/server/store -H "Content-Type: application/json" -d "{\"hostname\":\"attacker.com\"}"' \
  --response examples/unauth-access-resp.txt \
  --name "internal-endpoint-no-auth" \
  --severity high \
  --class unauth-access
```

## JWT / token disclosure

```bash
nuclei-gen \
  --curl 'curl -X POST https://api.target.com/v1/auth/token/refresh -H "Content-Type: application/json" -d "{\"refresh_token\":\"expired\"}"' \
  --response examples/info-disclosure-resp.txt \
  --name "token-refresh-exposes-jwt" \
  --severity high \
  --class info-disclosure \
  --tags "jwt,ato"
```

## SQL injection (error-based)

```bash
nuclei-gen \
  --curl 'curl "https://api.target.com/search?q=test'"'"'" ' \
  --response examples/sqli-resp.txt \
  --name "search-sqli-error-based" \
  --severity critical \
  --class sqli
```
