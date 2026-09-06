---
name: Business Logic & Race Conditions
description: Exploit application intent — workflow/step skipping, price/quantity tampering, mass assignment, and TOCTOU races that consume one limited resource many times.
tags: [web, business-logic, race-condition, toctou, mass-assignment, owasp-a04]
recommended_tools: [http_request, http_repeater, http_intruder, execute_command]
vuln_classes: [race_condition]
domain: web
phase: exploitation
---
# Business Logic & Race Conditions

These bugs require understanding what the application is *supposed* to enforce — no scanner finds them.
Map the multi-step state machines first (checkout, fund transfer, registration, coupon/voucher,
referral/credit, password reset, plan upgrade, role change). Then break the assumptions with exact
requests via `http_request`/`http_repeater`, always comparing against the legitimate single-request
baseline.

## Logic flaws (`http_request`)
- **Workflow / step skipping** — jump straight to the final state-changing request without the gating
  steps: `POST /checkout/confirm` without `/payment`; `POST /confirm?plan=premium&skip_payment=true`;
  replay an already-completed step; reorder steps; reuse a one-time token across the flow. The app
  trusts that earlier steps ran — prove they didn't.
- **Price / quantity / amount tampering** — negative or zero values (`amount=-100` to credit yourself,
  `quantity=-1`), client-supplied/trusted prices, currency swap, integer overflow on totals, applying a
  percentage discount that loops below zero. Compare the charged amount to the legitimate one.
- **Mass assignment** — GET the object to list fields, then PATCH/POST with fields the UI never sends:
  `{"role":"admin"}`, `{"verified":true}`, `{"balance":99999}`, `{"price":0}`, `{"status":"approved"}`.
  Re-GET to confirm they stuck.
- **Identity/auth confusion** — reset/confirm flows trusting a client-supplied user id/email;
  pre-account-takeover; coupon/voucher reuse; trial/quota/credit resets by replaying the grant call.

## Race conditions — TOCTOU (`execute_command`, `http_request`)
The pattern: the server **CHECKs** a limit then **ACTs** (`if balance>=amt: deduct`), and the gap
between them is exploitable. `race_condition` is confirmed when **the same limited resource is consumed
multiple times via parallel requests** — more successes than the limit allows.

Targets: withdraw/transfer the same balance twice (overdraft/negative balance), redeem a single-use
coupon/gift card N times, claim one unique username/handle from two requests, exceed a one-time
rate/usage/quota limit, double-apply a referral credit, buy more than the in-stock quantity.

Recipe — fire N **identical** requests as simultaneously as possible:
```bash
# Burst with GNU parallel-style fan-out; -P sets concurrency, all hit at once
seq 1 30 | xargs -P 30 -I{} curl -s -X POST 'https://target/redeem' \
  -H 'Authorization: Bearer <A_TOKEN>' -H 'Content-Type: application/json' \
  -d '{"code":"ONE-TIME-COUPON"}' -o /dev/null -w '%{http_code}\n'
```
- Prefer **HTTP/2 single-packet attack** (or Burp Turbo Intruder last-byte sync) when available — it
  eliminates network jitter and lands all requests inside the same TOCTOU window; far more reliable than
  shell loops. Reduce variables: pre-resolve DNS, warm the connection, send the final byte together.
- `http_intruder` can drive the burst when its concurrency is high enough; otherwise `execute_command`.

Method: (1) baseline — one request, observe the single legitimate effect (1 redemption, balance −X
once). (2) Reset state. (3) Fire N parallel copies. (4) Compare: **multiple successes / one resource
consumed more than once = vulnerable.** A single success = not a race.

## Chaining
Mass assignment (`{"role":"admin"}`) → privilege escalation; price tampering → free purchase;
coupon-redeem race → unlimited credit → cash-out. Where authorization is involved, **confirm with two
identities** (see access-control-testing) so a logic flaw isn't mistaken for self-action.

## Evidence & safety
Capture the request sequence, the expected-vs-observed result (one balance withdrawn twice, a coupon
redeemed N times, a non-settable field taking effect), and counts proving over-consumption. Use
engagement/throwaway accounts and minimal volume; races on real money/inventory need approval. These
map to direct money/PII/privilege impact. CWE-840 (business logic) / CWE-362 (race) / CWE-915 (mass
assignment).

## Modern techniques & real-world CVEs (via recon-skills)

Synthesized from 12 disclosed bug-bounty reports (2016–2023) with demonstrated financial impact.

### Disclosed coupon / gift-card / discount race redemptions
The canonical TOCTOU money primitive: capture the single "accept/redeem" POST, replay N× in one burst.
- **Stripe fee-discount race** (H1 #1849626, 2023, $5k): Support applied a one-time $20,000 fee credit;
  the researcher replayed the accept-discount POST 30× in parallel via Turbo Intruder — each acceptance
  re-credited the account. ~$600k of fee-free volume accrued before fix. Root cause: no idempotency and
  no unique constraint on `(account_id, discount_id)`.
- **Reverb.com gift-card race** (H1 #759247, 2019, $1.5k): one valid gift card, parallel-POST to
  `/redeem` from ~10 sockets credits balance N× face value. Root cause: no row-level lock on the
  gift_card table; balance debit and credit live in separate transactions.
- **Detection signal**: any endpoint where a credit/debit and its uniqueness check are in separate
  transactions, or where "already redeemed" is checked before (not inside) a locked write.

### Negative-quantity and price-field mass-assignment
Beyond simple `quantity=-1`: mix positive and negative line items so the total floors near zero.
- **Upserve/OLO negative-quantity** (H1 #364843, 2018): `qty * price` with no `qty >= 1` guard; a
  negative line item drives the order total below zero, floors to ~$0 at capture, food still fulfills.
```http
POST /api/order HTTP/1.1
Content-Type: application/json

{"items":[{"id":1,"qty":1,"price":50},{"id":2,"qty":-3,"price":50}]}
```
- **Krisp pay-less-per-seat** (H1 #1446090, 2021): `PUT /v2/seats` body carries a server-trusted
  `price` field; set `price=1` instead of $60 and the billing engine charges $1/seat for 100 seats.
  Classic mass-assignment — server reads price from the request body instead of a plan_id lookup.
- **Decimal / fraction overflow** (Shipt-class): submit fractional or high-precision values
  (`"price":0.001`, `"quantity":0.0001`) to slip past integer validation but still round or truncate
  favorably at capture. Test `1e-10`, `0.005`, and locale decimal separators (`0,01`).

### Archived-price / cart-state TOCTOU at checkout
- **Stripe archived-price swap** (H1 #1328278, 2021): buyer starts checkout via a new payment-link,
  then mid-flow swaps `price_id` back to an archived cheaper price ($5 vs $50). Stripe charges the old
  price; subscription provisions at the new tier. Root cause: link validates "is active", price object
  validates "exists", but the join `price.active AND price ∈ link.allowed_prices` is missing.
- **General probe**: whenever a checkout references an object id (`price_id`, `product_id`, `plan_id`)
  the client can influence, try swapping it mid-flow to an archived/draft/deprecated/lower-tier id.

### Client-side amount trust on third-party payment redirect
When the app hands price/currency/order-id to a third-party payment page (Smart2Pay, Stripe, PayPal,
Braintree, Asaas, MercadoPago), the in-flight redirect is a tamper window.
- Intercept the redirect, set `amount=0.01` or swap `currency=USD` to a low-value currency, then let
  the provider confirm. If the confirmation webhook lacks HMAC validation, the app credits full value.
```http
POST /payment/initiate HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

amount=0.01&currency=USD&order_id=12345&product_id=99
```
- **Confirmed-critical indicator**: a `cs_test_`-prefixed Stripe checkout URL means test mode (no real
  charge) — useful for safe PoC. A live checkout URL created at R$0/$0.01 with a license/key granted is
  the critical finding.

### Payment-webhook forgery (missing signature / idempotency)
Provider "success" callbacks that skip HMAC verification let anyone POST a fake success.
```bash
# Forge a success notification — succeeds only if HMAC/signature isn't enforced
curl -X POST https://target/payment/callback \
  -H 'Content-Type: application/json' \
  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'

# Anti-replay test: re-POST an UNMODIFIED captured webhook. If it credits twice,
# the endpoint lacks idempotency even when signature validation is present.
```
Empty/absent signature header that still "passes" proves validation is off entirely.

### IP-based rate-limit bypass via spoofable headers
Rate limits keyed on `X-Forwarded-For`/`X-Real-IP` rather than the connection IP are trivially bypassed,
enabling OTP brute-force, enumeration, or subscription-spam abuse.
```bash
for i in $(seq 1 100); do
  curl -s -X POST https://target/api/subscribe \
    -H "X-Forwarded-For: 10.0.0.$i" -H "X-Real-IP: 10.0.0.$i" \
    -H "True-Client-IP: 10.0.0.$i" -H "CF-Connecting-IP: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim+'"$i"'@example.com"}' -o /dev/null -w "%{http_code}\n"
done
```
Rotate one header per request; a per-header 200 with no throttle confirms header-sourced IP.

### Verification-gate skip (UI-only enforcement)
Gates enforced only in the frontend leave the underlying API fully functional.
- **Email-verify bypass** (Mozilla-Monitor-class): the post-verification API accepts setup for any
  address with a valid but *unverified* session — monitor emails you don't own.
```bash
# Hit the post-verification endpoint directly with an unverified session
curl -s -X POST https://monitor.target/api/monitoring/enable \
  -H "Cookie: session=<unverified_session>" -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
# Or replay a valid token against a different account
curl -X POST https://target/verify -d 'token=VALID_TOKEN_FROM_A&email=account_b@example.com'
```
- **Phone/callback verification**: submit a number you don't own; if trust is granted on submission
  rather than OTP confirmation, you can spoof another user's number (SMS/callback abuse).

### Exposed internal / draft storefronts
Internal or channel-specific pages deployed to production without auth still carry full functionality.
- Shopify draft/private-channel storefronts (e.g., an employee-summit free-books page) remain fully
  checkout-capable if the URL is known — anonymous checkout ships physical goods at company expense.
- Hunt via JS-bundle grep, Wayback, Shodan, robots.txt/sitemap for `/employee`, `/internal`, `/staff`,
  `/summit`, `/admin` references, then test each unauthenticated and with a low-priv account.
```bash
curl -s https://target/robots.txt | grep -iE '(disallow|allow)'
curl -s https://target/assets/app.js | grep -oE '"/(employee|internal|staff|admin|summit)[^"]*"' | sort -u
```

### Defense → bypass quick reference
| Defense | Bypass |
|---|---|
| IP-based rate limiting | Rotate `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` per request |
| CAPTCHA on web form only | Call the underlying API endpoint directly (CAPTCHA lives only on the HTML form) |
| Email/phone verification gate | Hit post-verify API with unverified session; replay tokens cross-account; check client-set `verified` cookie |
| Server-side price validation | Low-value currency swap; `0.00`/negative; fractional-decimal overflow; archived `price_id` swap |
| Webhook HMAC validation | Empty/absent signature (is it enforced at all?); replay unmodified webhook (missing idempotency) |
| Auth on internal pages | Unauthenticated; low-priv account; path-traversal variants (`/employee/../employee/`) |
