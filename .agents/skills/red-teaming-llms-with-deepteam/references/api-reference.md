# DeepTeam API Reference — Aegis-360 Integration

Base URL: `http://127.0.0.1:8888`

All POST endpoints accept and return `application/json`. All GET endpoints return `application/json`.

---

## POST /api/deepteam/scan

Run a synchronous red-team scan. Blocks until complete or `scan_timeout` is reached.

### Request body

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `endpoint_url` | string | `""` | HTTP target: POST `{"prompt": …}` → `{"response": …}` |
| `model` | string | `""` | OpenAI-compatible model name (e.g. `gpt-4o-mini`) |
| `api_key` | string | `""` | API key for target provider (overrides `OPENAI_API_KEY`) |
| `base_url` | string | `""` | Custom OpenAI-compatible base URL (Ollama, LiteLLM, etc.) |
| `system_prompt` | string | `""` | System prompt prepended to all target requests |
| `target_purpose` | string | `""` | What the target LLM is for — improves attack tailoring |
| `vulnerabilities` | string \| list | `"Toxicity,PIILeakage,PromptLeakage"` | Comma-separated or JSON array of vulnerability names |
| `attacks` | string \| list | `"PromptInjection,Roleplay"` | Comma-separated or JSON array of attack method names |
| `attacks_per_vulnerability` | int | `1` | Attack variants generated per vulnerability type |
| `simulator_model` | string | `"gpt-3.5-turbo-0125"` | Model for generating attack variants (needs `OPENAI_API_KEY`) |
| `evaluation_model` | string | `"gpt-4o"` | Model for scoring target responses (needs `OPENAI_API_KEY`) |
| `max_concurrent` | int | `5` | Max concurrent evaluation calls |
| `scan_timeout` | int | `600` | Seconds to wait before returning an async reference |
| `request_timeout` | int | `60` | Per-request timeout for target LLM calls |

### Response

```json
{
  "job_id": "3f2a...",
  "status": "completed",
  "result": { ... },
  "note": "Scan still running; poll /api/deepteam/status/<job_id>"
}
```

---

## POST /api/deepteam/scan-async

Submit a scan as a background job. Returns immediately with a `job_id`.

### Request body

Same as `/scan` minus `scan_timeout`.

### Response

```json
{
  "job_id": "3f2a...",
  "status": "queued",
  "poll_url": "/api/deepteam/status/3f2a..."
}
```

---

## GET /api/deepteam/status/{job_id}

Poll a background job for its current status.

### Response

```json
{
  "job_id": "3f2a...",
  "status": "running",
  "progress": "Running red team evaluation",
  "updated_at": "2026-09-06T14:30:00"
}
```

`status` values: `queued` → `running` → `completed` | `failed`

---

## GET /api/deepteam/report/{job_id}

Retrieve the full results of a completed job. Returns `409` if not yet completed.

### Response

```json
{
  "job_id": "3f2a...",
  "status": "completed",
  "result": {
    "test_cases": [
      {
        "vulnerability": "PIILeakage",
        "attack": "Roleplay",
        "input": "...",
        "actual_output": "...",
        "score": 0,
        "passed": false,
        "reason": "Model disclosed email addresses"
      }
    ]
  }
}
```

---

## GET /api/deepteam/jobs

List all submitted jobs (result payloads excluded for brevity).

### Response

```json
{
  "jobs": {
    "3f2a...": {
      "status": "completed",
      "params_summary": { "vulnerabilities": "...", "target": "..." },
      "updated_at": "2026-09-06T14:30:00"
    }
  },
  "count": 1
}
```

---

## GET /api/deepteam/vulnerabilities

List all supported vulnerability types with descriptions and category groupings.

### Response

```json
{
  "vulnerabilities": {
    "Toxicity": "Profanity, insults, threats, mockery",
    "PIILeakage": "API access, direct disclosure, session leak, social manipulation",
    ...
  },
  "categories": {
    "safety": ["Toxicity", "Bias", "IllegalActivity", ...],
    "security": ["SQLInjection", "SSRF", "ShellInjection", ...],
    ...
  },
  "count": 34
}
```

---

## GET /api/deepteam/attacks

List all supported attack methods.

### Response

```json
{
  "single_turn": ["PromptInjection", "Roleplay", "MathProblem", ...],
  "multi_turn": ["LinearJailbreaking", "CrescendoJailbreaking", ...],
  "all": [...],
  "count": 27
}
```

---

## GET /api/deepteam/version

Return the installed deepteam library version.

### Response

```json
{
  "version": "1.0.9",
  "package": "deepteam",
  "source": "confident-ai/deepteam"
}
```

---

## MCP Tool Reference

| MCP Tool | Maps to | Description |
|----------|---------|-------------|
| `deepteam_scan(...)` | POST /api/deepteam/scan | Synchronous red-team scan |
| `deepteam_scan_async(...)` | POST /api/deepteam/scan-async | Background scan, returns job_id |
| `deepteam_status(job_id)` | GET /api/deepteam/status/{id} | Poll job status |
| `deepteam_report(job_id)` | GET /api/deepteam/report/{id} | Fetch full results |
| `deepteam_jobs()` | GET /api/deepteam/jobs | List all jobs |
| `deepteam_vulnerabilities()` | GET /api/deepteam/vulnerabilities | Vulnerability catalog |
| `deepteam_attacks()` | GET /api/deepteam/attacks | Attack method catalog |
| `deepteam_version()` | GET /api/deepteam/version | Library version |
